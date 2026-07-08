import * as fs from "fs";
import * as path from "path";
import { Bot, type Context } from "grammy";
import type { InlineKeyboardMarkup } from "grammy/types";
import {
  listSessions,
  createSession,
  killSession,
  hasSession,
  getSessionCreatedMs,
  isPaneTui,
  paneForegroundCommand,
} from "@/lib/tmux";
import { canAccessSession, scopedSessionName } from "@/lib/session-scope";
import {
  commandForKind,
  saveMeta,
  getMeta,
  isValidKind,
  ensureManagedSession,
  type SessionKind,
} from "@/lib/ai-sessions";
import {
  resolveTelegramIdentity,
  botIsConfigured,
  getTelegramForumChatId,
  telegramAllowedUserCount,
  telegramHasPartialConfig,
  type BotIdentity,
} from "./auth";
import { getConfiguredMaxSessions, isReadOnlyMode } from "@/lib/security-config";
import { getTelegramConfig } from "./config";
import { sessionsKeyboard, CB } from "./keyboard";
import {
  setTopic,
  deleteTopic,
  getTopic,
  getTopicByName,
  listTopics,
  setForumChatId,
  patchTopic,
  type ViewMode,
  type TopicBinding,
} from "./state";
import {
  startStreamer,
  stopStreamer,
  stopAllStreamers,
  resumePersistedStreamers,
  sendCodexText,
  sendKey,
  sendText,
  scroll,
  snap,
  snapScreenMessage,
  defaultViewMode,
  resetChatBaseline,
} from "./streamer";
import {
  startClaudeTranscript,
  isClaudeTranscriptRunning,
  stopClaudeTranscript,
  stopAllClaudeTranscripts,
  readLastAssistantText,
} from "./claude-transcript";
import {
  startCodexTranscript,
  isCodexTranscriptRunning,
  stopCodexTranscript,
  stopAllCodexTranscripts,
  readLastCodexAssistantText,
} from "./codex-transcript";
import { markdownToTelegramV2 } from "./render";
import { downloadFromTelegram, downloadTelegramFileToTemp, sendFromServer } from "./files";
import { transcribeAudioFile } from "./transcription";
import { forumTopicExists } from "./topic-health";
import { createGitWorktreeForSession, removeGitWorktree } from "@/lib/git-worktree";
import { resolveWorkspaceConfig, copyConfiguredFiles } from "@/lib/workspace-config";
import { allocateWorkspacePort } from "@/lib/workspace-port";
import { withWorkspaceEnv, runSetup } from "@/lib/workspace-setup";
import { resolveSessionModelSettings } from "@/lib/settings/session-settings";
import { modelOptionsForKind } from "@/lib/harnesses/session-model";
import { getHarness, listHarnesses } from "@/lib/harnesses/registry";
import { autoWorktreeName, parseWorktreeCommand, slugifySessionName } from "./worktree-command";

let bot: Bot | null = null;

type StartWizard =
  | { action: "new"; step: "name" | "kind"; name?: string }
  | { action: "worktree"; step: "directory" | "name" | "kind"; directory?: string; name?: string };

const startWizards = new Map<string, StartWizard>();

const START_CB = {
  SESSIONS: "w:sess",
  CANCEL: "w:cancel",
  SKIP_NAME: "w:skip",
  KIND_PREFIX: "w:k:",
} as const;

/**
 * Resolve the Telegram identity for the user behind a Context, OR null if
 * they're not on the allowlist or the chat isn't the configured forum.
 */
async function gate(ctx: Context): Promise<BotIdentity | null> {
  const tgId = ctx.from?.id;
  const chatId = ctx.chat?.id;
  if (!tgId || !chatId) return null;
  const expected = getTelegramForumChatId();
  if (!expected || chatId !== expected) return null;
  const identity = await resolveTelegramIdentity(tgId);
  if (!identity) return null;
  return identity;
}

async function reply(ctx: Context, text: string, opts: Parameters<Context["reply"]>[1] = {}) {
  try {
    const topicId = topicIdFromContext(ctx);
    await ctx.reply(text, {
      ...(topicId ? { message_thread_id: topicId } : {}),
      ...opts,
    });
  } catch (err) {
    console.error("[telegram/bot] reply failed", err);
  }
}

function topicIdFromContext(ctx: Context): number | undefined {
  return (ctx.msg as { message_thread_id?: number } | undefined)?.message_thread_id;
}

async function rejectReadOnly(ctx: Context): Promise<boolean> {
  if (!isReadOnlyMode()) return false;
  await reply(ctx, "read-only mode is enabled.");
  return true;
}

function canUseTopic(identity: BotIdentity, binding: TopicBinding): boolean {
  return canAccessSession(identity.username, identity.role, binding.sessionName);
}

function clipTelegramText(text: string, maxLength = 900): string {
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function wizardKey(ctx: Context): string | null {
  const chatId = ctx.chat?.id;
  const userId = ctx.from?.id;
  if (!chatId || !userId) return null;
  return `${chatId}:${userId}`;
}

function startMenuKeyboard(): InlineKeyboardMarkup {
  return {
    inline_keyboard: [[{ text: "Sessions", callback_data: START_CB.SESSIONS }]],
  };
}

function kindKeyboard(includeBash = true): InlineKeyboardMarkup {
  const harnesses = listHarnesses().filter((h) => includeBash || h.id !== "bash");
  const rows = harnesses.map((h) => [
    { text: h.label, callback_data: `${START_CB.KIND_PREFIX}${h.id}` },
  ]);
  rows.push([{ text: "Cancel", callback_data: START_CB.CANCEL }]);
  return { inline_keyboard: rows };
}

function worktreeNameKeyboard(): InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [{ text: "Auto-generate name", callback_data: START_CB.SKIP_NAME }],
      [{ text: "Cancel", callback_data: START_CB.CANCEL }],
    ],
  };
}

async function topicBindingForMessage(
  ctx: Context,
  identity: BotIdentity,
  topicId: number | undefined,
  missingReply?: string,
  opts: { allowEnded?: boolean } = {}
): Promise<TopicBinding | null> {
  if (!topicId) return null;
  const binding = getTopic(topicId);
  if (!binding) {
    if (missingReply) await reply(ctx, missingReply);
    return null;
  }
  if (!canUseTopic(identity, binding)) {
    await reply(ctx, "session not yours.");
    return null;
  }
  if (!opts.allowEnded && (binding.endedAtMs || !hasSession(binding.sessionName))) {
    if (!binding.endedAtMs) await patchTopic(topicId, { endedAtMs: Date.now() });
    await reply(ctx, "session ended. send /delete to remove this topic.");
    return null;
  }
  return binding;
}

function topicQuotaReached(): number | null {
  const maxTopics = getTelegramConfig().maxTopics;
  if (!Number.isFinite(maxTopics)) return null;
  return listTopics().length >= maxTopics ? maxTopics : null;
}

function sessionQuotaReached(): number | null {
  const maxSessions = getConfiguredMaxSessions();
  return listSessions().filter((s) => ensureManagedSession(s.name)).length >= maxSessions
    ? maxSessions
    : null;
}

function fullAccessCommand(kind: SessionKind, cwd: string, env: Record<string, string> = {}) {
  const sessionModel = resolveSessionModelSettings(cwd);
  const modelOpts = modelOptionsForKind(kind, {
    modelId: sessionModel.modelExplicit ? sessionModel.modelId : undefined,
    planMode: sessionModel.planMode,
  });
  const base = commandForKind(kind, {
    dangerouslySkipPermissions: true,
    ...modelOpts,
  });
  return {
    command: withWorkspaceEnv(base ?? "exec bash -l", env),
    sessionModel,
    persistModelMeta: getHarness(kind)?.command.bin != null,
  };
}

function harnessListForHelp(): string {
  return listHarnesses()
    .map((h) => h.id)
    .join("|");
}

function uniqueAutoSessionName(repoName: string, username: string | null): string {
  const base = autoWorktreeName(repoName);
  for (let i = 0; i < 100; i++) {
    const raw = i === 0 ? base : `${base}-${i + 1}`;
    const scoped = scopedSessionName(raw, username);
    if (!hasSession(scoped) && !getMeta(scoped)) return raw;
  }
  return `${base}-${Date.now().toString(36)}`;
}

function sessionBindingDefaults(
  sessionName: string,
  fallback?: Pick<TopicBinding, "kind" | "cwd">
): Pick<TopicBinding, "kind" | "cwd"> {
  const meta = getMeta(sessionName);
  const session = listSessions().find((s) => s.name === sessionName);
  const foreground = paneForegroundCommand(sessionName);
  const inferredKind =
    foreground === "claude" || foreground === "codex" ? (foreground as SessionKind) : "bash";
  return {
    kind: meta?.kind ?? fallback?.kind ?? inferredKind,
    cwd:
      session?.activePath ?? fallback?.cwd ?? process.env.TERMINUS_ROOT ?? process.env.HOME ?? "/",
  };
}

async function reconcileTopicBinding(binding: TopicBinding): Promise<TopicBinding> {
  const defaults = sessionBindingDefaults(binding.sessionName, binding);
  if (defaults.kind !== binding.kind || defaults.cwd !== binding.cwd) {
    await patchTopic(binding.topicId, defaults);
    return { ...binding, ...defaults };
  }
  return binding;
}

/**
 * Tear down a binding whose Telegram topic no longer exists (deleted by a user
 * in the forum). Stops its streamer/transcripts and removes the dead mapping so
 * the caller can create a fresh topic and re-bind.
 */
async function dropStaleBinding(topicId: number): Promise<void> {
  await stopStreamer(topicId);
  stopClaudeTranscript(topicId);
  stopCodexTranscript(topicId);
  await deleteTopic(topicId);
}

async function attachToTopic(b: Bot, identity: BotIdentity, binding: TopicBinding): Promise<void> {
  const chatId = ctxChatId();
  if (!chatId) return;
  if (!canUseTopic(identity, binding)) return;
  const mode = binding.viewMode ?? defaultViewMode(binding.kind);
  await setTopic({ ...binding, viewMode: mode, endedAtMs: undefined });
  startStreamer(b, binding.topicId);
  let resolvedJsonl: string | undefined;
  let resolvedTranscriptKind: "claude" | "codex" | undefined;
  if (binding.kind === "claude") {
    const sinceMs = getSessionCreatedMs(binding.sessionName) ?? Date.now();
    const started = startClaudeTranscript(b, chatId, binding.topicId, {
      cwd: binding.cwd,
      sinceMs,
      persistedJsonl: binding.jsonlPath,
      initialOffset: binding.jsonlOffset,
    });
    if (started) {
      resolvedJsonl = started.jsonl;
      resolvedTranscriptKind = "claude";
      await patchTopic(binding.topicId, { jsonlPath: started.jsonl });
    }
  } else if (binding.kind === "codex" && binding.jsonlPath) {
    const started = startCodexTranscript(b, chatId, binding.topicId, {
      cwd: binding.cwd,
      persistedJsonl: binding.jsonlPath,
      initialOffset: binding.jsonlOffset,
    });
    if (started) {
      resolvedJsonl = started.jsonl;
      resolvedTranscriptKind = "codex";
    }
  }

  // Welcome banner so the user sees the bot did something. /view to
  // switch modes; /detach to stop streaming.
  try {
    await b.api.sendMessage(chatId, `📎 attached to ${binding.sessionName} · view: ${mode}`, {
      message_thread_id: binding.topicId,
    });
  } catch {
    /* ignore */
  }

  // For TUI sessions (claude, codex, vim, ...) the user starts in chat mode but
  // would otherwise see nothing until the next assistant entry. Surface
  // the most recent assistant message from the topic's JSONL so they
  // immediately have context for what was happening.
  if (mode === "chat" && isPaneTui(binding.sessionName) && resolvedJsonl) {
    // Both readers return raw markdown. Send it formatted; fall back to the
    // raw text if Telegram rejects the entities — context beats styling.
    const last =
      resolvedTranscriptKind === "codex"
        ? readLastCodexAssistantText(resolvedJsonl)
        : readLastAssistantText(resolvedJsonl);
    if (last) {
      try {
        await b.api.sendMessage(chatId, markdownToTelegramV2(last), {
          message_thread_id: binding.topicId,
          parse_mode: "MarkdownV2",
        });
      } catch {
        try {
          await b.api.sendMessage(chatId, last, { message_thread_id: binding.topicId });
        } catch {
          /* ignore */
        }
      }
    }
  }
}

function botForTopicManagement(): Bot | null {
  if (bot) return bot;
  const config = getTelegramConfig();
  if (!config.enabled || !config.botToken) return null;
  return new Bot(config.botToken);
}

export interface EnsureTopicResult {
  topic: {
    topicId: number;
    sessionName: string;
    viewMode: ViewMode;
    url: string;
    created: boolean;
  };
}

export async function ensureTopicForSession(
  identity: BotIdentity,
  sessionName: string,
  viewMode?: ViewMode
): Promise<EnsureTopicResult> {
  if (!/^[a-zA-Z0-9_.\-]+$/.test(sessionName)) {
    throw new Error("invalid session name");
  }
  if (!canAccessSession(identity.username, identity.role, sessionName)) {
    throw new Error("access denied");
  }
  if (!hasSession(sessionName)) {
    throw new Error(`session ${sessionName} not found`);
  }
  if (!ensureManagedSession(sessionName)) {
    throw new Error(`session ${sessionName} is not managed by TerminalX`);
  }

  const chatId = ctxChatId();
  if (!chatId) {
    throw new Error("no Telegram forum chat configured");
  }
  await setForumChatId(chatId);

  const b = botForTopicManagement();
  if (!b) {
    throw new Error("Telegram bot is not configured");
  }

  const existing = getTopicByName(sessionName);
  if (existing && (await forumTopicExists(b, chatId, existing.topicId))) {
    const reconciled = await reconcileTopicBinding(existing);
    const nextViewMode = viewMode ?? reconciled.viewMode ?? defaultViewMode(reconciled.kind);
    const binding = {
      ...reconciled,
      viewMode: nextViewMode,
      endedAtMs: undefined,
    };
    await setTopic(binding);
    resetChatBaseline(binding.topicId);
    startStreamer(b, binding.topicId);
    if (viewMode === "screen") snap(b, binding.topicId);
    return {
      topic: {
        topicId: binding.topicId,
        sessionName,
        viewMode: nextViewMode,
        url: topicLink(chatId, binding.topicId),
        created: false,
      },
    };
  }
  if (existing) {
    // Bound topic was deleted in Telegram — drop the dead binding, then recreate below.
    await dropStaleBinding(existing.topicId);
  }

  const maxTopics = topicQuotaReached();
  if (maxTopics !== null) {
    throw new Error(`maximum number of Telegram topics reached (${maxTopics})`);
  }

  const topic = await b.api.createForumTopic(chatId, sessionName);
  const defaults = sessionBindingDefaults(sessionName);
  const nextViewMode = viewMode ?? defaultViewMode(defaults.kind);
  await attachToTopic(b, identity, {
    topicId: topic.message_thread_id,
    sessionName,
    ...defaults,
    viewMode: nextViewMode,
  });
  return {
    topic: {
      topicId: topic.message_thread_id,
      sessionName,
      viewMode: nextViewMode,
      url: topicLink(chatId, topic.message_thread_id),
      created: true,
    },
  };
}

function ctxChatId(): number | null {
  return getTelegramForumChatId();
}

/* ────────────── command handlers ────────────── */

async function handleStart(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  await reply(
    ctx,
    [
      "terminalx bot online.",
      "",
      "/sessions - list sessions",
      "/new - create a session",
      "/new <name> [bash|claude|codex] - create directly",
      "/worktree - create a git worktree session",
      `/worktree <repo-path> [name] [${harnessListForHelp()}] - create directly`,
      "/send <text> - send slash commands or raw input to this session",
      "",
      "Send terminal input inside a session topic. Prefix with // to send a leading /.",
    ].join("\n"),
    { reply_markup: startMenuKeyboard() }
  );
}

async function handleSessions(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  const all = listSessions().filter(
    (s) =>
      canAccessSession(identity.username, identity.role, s.name) && ensureManagedSession(s.name)
  );
  if (all.length === 0) {
    await reply(ctx, "no sessions. the box is lonely.");
    return;
  }
  await reply(ctx, `${all.length} session${all.length === 1 ? "" : "s"}:`, {
    reply_markup: sessionsKeyboard(all),
  });
}

async function handleNew(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  if (!bot) return;
  const text = ctx.message?.text ?? "";
  const args = text.split(/\s+/).slice(1);
  const rawName = (args[0] ?? "").toLowerCase();
  const kindRaw = args[1] ?? "bash";
  const kind: SessionKind = isValidKind(kindRaw) ? (kindRaw as SessionKind) : "bash";
  if (!rawName) {
    const key = wizardKey(ctx);
    if (!key) return;
    startWizards.set(key, { action: "new", step: "name" });
    await reply(ctx, "Enter the session name.");
    return;
  }
  if (!/^[a-zA-Z0-9_.\-]+$/.test(rawName)) {
    await reply(ctx, "usage: /new <name> [bash|claude|codex]");
    return;
  }
  await createNewSessionFromInput(ctx, identity, rawName, kind);
}

async function createNewSessionFromInput(
  ctx: Context,
  identity: BotIdentity,
  rawName: string,
  kind: SessionKind
): Promise<void> {
  if (!bot) return;
  const scoped = scopedSessionName(rawName, identity.username);
  if (hasSession(scoped)) {
    const existing = getTopicByName(scoped);
    const chatId = ctxChatId();
    if (existing && chatId) {
      const url = topicLink(chatId, existing.topicId);
      await reply(ctx, `session ${scoped} already exists -> ${url}`, {
        link_preview_options: { is_disabled: true },
      });
      return;
    }
    await reply(ctx, `session ${scoped} already exists.`);
    return;
  }
  const maxSessions = sessionQuotaReached();
  if (maxSessions !== null) {
    await reply(ctx, `maximum number of sessions reached (${maxSessions}).`);
    return;
  }
  const cwd = process.env.TERMINUS_ROOT || process.env.HOME || "/";
  const { command: cmd } = fullAccessCommand(kind, cwd);
  try {
    createSession(scoped, cmd ?? undefined, cwd);
    await saveMeta({ name: scoped, kind, createdAt: new Date().toISOString(), managed: true });
  } catch (err) {
    await reply(ctx, `failed to create: ${(err as Error).message}`);
    return;
  }

  const chatId = ctxChatId();
  if (!chatId) {
    await reply(ctx, "no forum chat configured.");
    return;
  }
  const maxTopics = topicQuotaReached();
  if (maxTopics !== null) {
    await reply(ctx, `maximum number of Telegram topics reached (${maxTopics}).`);
    return;
  }
  let topicId: number;
  try {
    const topic = await bot.api.createForumTopic(chatId, scoped);
    topicId = topic.message_thread_id;
  } catch (err) {
    await reply(ctx, `failed to create topic: ${(err as Error).message}`);
    return;
  }

  await attachToTopic(bot, identity, {
    topicId,
    sessionName: scoped,
    kind,
    cwd,
  });
  const url = topicLink(chatId, topicId);
  await reply(ctx, `created ${scoped} -> ${url}`, {
    link_preview_options: { is_disabled: true },
  });
}

async function handleWorktree(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  if (!bot) return;

  const parsed = parseWorktreeCommand(ctx.message?.text ?? "");
  if (!parsed) {
    const key = wizardKey(ctx);
    if (!key) return;
    startWizards.set(key, { action: "worktree", step: "directory" });
    await reply(ctx, "Enter the git repository path.");
    return;
  }
  await createWorktreeSessionFromInput(ctx, identity, parsed);
}

async function createWorktreeSessionFromInput(
  ctx: Context,
  identity: BotIdentity,
  parsed: { directory: string; name?: string; kind: SessionKind }
): Promise<void> {
  if (!bot) return;
  const repoName = slugifySessionName(path.basename(parsed.directory)) || "repo";
  const rawName = parsed.name ?? uniqueAutoSessionName(repoName, identity.username);
  if (!/^[a-zA-Z0-9_.\-]+$/.test(rawName)) {
    await reply(ctx, "worktree name can only use letters, numbers, _ - .");
    return;
  }
  const scoped = scopedSessionName(rawName, identity.username);
  if (hasSession(scoped)) {
    await reply(ctx, `session ${scoped} already exists.`);
    return;
  }
  const maxSessions = sessionQuotaReached();
  if (maxSessions !== null) {
    await reply(ctx, `maximum number of sessions reached (${maxSessions}).`);
    return;
  }
  const maxTopics = topicQuotaReached();
  if (maxTopics !== null) {
    await reply(ctx, `maximum number of Telegram topics reached (${maxTopics}).`);
    return;
  }

  const branch = `feature/${rawName}`;
  let created:
    | {
        repoRoot: string;
        worktreePath: string;
        startDir: string;
        branch: string;
        linkedPaths: string[];
      }
    | undefined;

  try {
    created = createGitWorktreeForSession(parsed.directory, branch);
  } catch (err) {
    await reply(ctx, `failed to create worktree: ${(err as Error).message}`);
    return;
  }

  let port: number;
  try {
    port = await allocateWorkspacePort();
  } catch {
    removeGitWorktree(created.worktreePath, created.repoRoot, created.linkedPaths);
    await reply(ctx, "failed to create worktree: no free workspace port available.");
    return;
  }

  const wsConfig = resolveWorkspaceConfig(created.repoRoot, { port });
  try {
    copyConfiguredFiles(created.repoRoot, created.worktreePath, wsConfig.copyFiles);
  } catch (err) {
    removeGitWorktree(created.worktreePath, created.repoRoot, created.linkedPaths);
    await reply(ctx, `failed to prepare worktree: ${(err as Error).message}`);
    return;
  }

  const wsEnv = { TERMINALX_PORT: String(port), ...wsConfig.env };
  const { command, sessionModel, persistModelMeta } = fullAccessCommand(
    parsed.kind,
    created.repoRoot,
    wsEnv
  );

  try {
    createSession(scoped, command, created.startDir);
    const willRunSetup = Boolean(wsConfig.setup);
    await saveMeta({
      name: scoped,
      kind: parsed.kind,
      createdAt: new Date().toISOString(),
      createdBy: identity.username || undefined,
      managed: true,
      cwd: created.startDir,
      worktree: {
        repoRoot: created.repoRoot,
        path: created.worktreePath,
        branch: created.branch,
        linkedPaths: created.linkedPaths,
      },
      port,
      setup: wsConfig.setup ? { status: willRunSetup ? "pending" : "skipped" } : undefined,
      ...(persistModelMeta
        ? {
            modelId: sessionModel.modelId,
            effort: sessionModel.effort,
            personality: sessionModel.personality,
            planMode: sessionModel.planMode,
            fastMode: sessionModel.fastMode,
          }
        : {}),
    });

    if (willRunSetup && wsConfig.setup) {
      void runSetup({
        sessionName: scoped,
        cwd: created.worktreePath,
        command: wsConfig.setup.command,
        env: wsEnv,
        timeoutSeconds: wsConfig.setup.timeoutSeconds ?? 1800,
      });
    }
  } catch (err) {
    removeGitWorktree(created.worktreePath, created.repoRoot, created.linkedPaths);
    await reply(ctx, `failed to create session: ${(err as Error).message}`);
    return;
  }

  const chatId = ctxChatId();
  if (!chatId) {
    await reply(ctx, "no forum chat configured.");
    return;
  }
  let topicId: number;
  try {
    const topic = await bot.api.createForumTopic(chatId, scoped);
    topicId = topic.message_thread_id;
  } catch (err) {
    await reply(ctx, `failed to create topic: ${(err as Error).message}`);
    return;
  }

  await attachToTopic(bot, identity, {
    topicId,
    sessionName: scoped,
    kind: parsed.kind,
    cwd: created.startDir,
  });
  const url = topicLink(chatId, topicId);
  await reply(
    ctx,
    [
      `created ${scoped} -> ${url}`,
      `worktree: ${created.worktreePath}`,
      `branch: ${created.branch}`,
    ].join("\n"),
    { link_preview_options: { is_disabled: true } }
  );
}

/** Build a `https://t.me/c/<id>/<thread>` deep link for a topic. */
function topicLink(chatId: number, topicId: number): string {
  // Supergroup ids look like -100<rest>; the public link uses just <rest>.
  const internal = String(chatId).replace(/^-100/, "");
  return `https://t.me/c/${internal}/${topicId}`;
}

async function handleAttachByName(ctx: Context, name: string) {
  const identity = await gate(ctx);
  if (!identity) return;
  if (!bot) return;
  if (!canAccessSession(identity.username, identity.role, name)) {
    await reply(ctx, "session not yours.");
    return;
  }
  if (!hasSession(name)) {
    await reply(ctx, `session ${name} not found.`);
    return;
  }
  if (!ensureManagedSession(name)) {
    await reply(ctx, "refusing to attach a tmux session not managed by TerminalX.");
    return;
  }
  const chatId = ctxChatId();
  if (!chatId) return;
  const existing = getTopicByName(name);
  if (existing) {
    if (await forumTopicExists(bot, chatId, existing.topicId)) {
      await reconcileTopicBinding(existing);
      const url = topicLink(chatId, existing.topicId);
      await reply(ctx, `already attached → ${url}`, {
        link_preview_options: { is_disabled: true },
      });
      return;
    }
    // Bound topic was deleted in Telegram — drop the dead binding and recreate below.
    await dropStaleBinding(existing.topicId);
  }
  const maxTopics = topicQuotaReached();
  if (maxTopics !== null) {
    await reply(ctx, `maximum number of Telegram topics reached (${maxTopics}).`);
    return;
  }
  const topic = await bot.api.createForumTopic(chatId, name);
  const defaults = sessionBindingDefaults(name);
  await attachToTopic(bot, identity, {
    topicId: topic.message_thread_id,
    sessionName: name,
    ...defaults,
  });
}

async function handleDetach(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  const binding = await topicBindingForMessage(ctx, identity, topicId);
  if (!binding) return;
  await stopStreamer(topicId);
  stopClaudeTranscript(topicId);
  stopCodexTranscript(topicId);
  await deleteTopic(topicId);
  await reply(ctx, "detached. tmux session is still running.");
}

async function handleKill(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  if (!bot) return;
  const topicId = ctx.message?.message_thread_id;
  let target = ctx.message?.text?.split(/\s+/)[1];
  if (!target && topicId) {
    target = getTopic(topicId)?.sessionName;
  }
  if (!target) {
    await reply(ctx, "usage: /kill <name> (or run inside a session topic)");
    return;
  }
  if (!canAccessSession(identity.username, identity.role, target)) {
    await reply(ctx, "session not yours.");
    return;
  }
  if (!ensureManagedSession(target)) {
    await reply(ctx, "refusing to kill a tmux session not managed by TerminalX.");
    return;
  }
  try {
    killSession(target);
  } catch (err) {
    await reply(ctx, `failed: ${(err as Error).message}`);
    return;
  }
  if (topicId) {
    await stopStreamer(topicId);
    stopClaudeTranscript(topicId);
    stopCodexTranscript(topicId);
    await deleteTopic(topicId);
    const chatId = ctxChatId();
    if (chatId) {
      try {
        await bot.api.closeForumTopic(chatId, topicId);
      } catch {
        // ignore
      }
    }
  }
  await reply(ctx, `killed ${target}.`);
}

async function handleDelete(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  if (!bot) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) {
    await reply(ctx, "run /delete inside a session topic after its session has ended.");
    return;
  }
  const binding = await topicBindingForMessage(
    ctx,
    identity,
    topicId,
    "this topic isn't bound to a session anymore.",
    { allowEnded: true }
  );
  if (!binding) return;
  if (hasSession(binding.sessionName)) {
    await reply(ctx, "session is still running. exit or /kill it before deleting the topic.");
    return;
  }
  const chatId = ctxChatId();
  if (!chatId) return;
  try {
    await bot.api.deleteForumTopic(chatId, topicId);
  } catch (err) {
    await reply(ctx, `failed to delete topic: ${(err as Error).message}`);
    return;
  }
  await stopStreamer(topicId);
  stopClaudeTranscript(topicId);
  stopCodexTranscript(topicId);
  await deleteTopic(topicId);
}

async function handleSnap(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  const binding = await topicBindingForMessage(ctx, identity, topicId);
  if (!binding) return;
  snap(bot, topicId);
}

async function toggleView(topicId: number): Promise<"screen" | "chat" | "off"> {
  const binding = getTopic(topicId);
  if (!binding) return "screen";
  const current = binding.viewMode ?? defaultViewMode(binding.kind);
  const next: "screen" | "chat" | "off" =
    current === "chat" ? "screen" : current === "screen" ? "off" : "chat";
  await patchTopic(topicId, { viewMode: next });
  // Reset baseline so chat mode doesn't dump the entire screen on switch.
  resetChatBaseline(topicId);
  return next;
}

async function handleView(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  const binding = await topicBindingForMessage(ctx, identity, topicId);
  if (!binding) return;
  const arg = (ctx.message?.text?.split(/\s+/)[1] ?? "").toLowerCase();
  if (arg === "screen" || arg === "chat" || arg === "off") {
    await patchTopic(topicId, { viewMode: arg });
    resetChatBaseline(topicId);
    await reply(ctx, `view: ${arg}`);
    if (bot) snap(bot, topicId);
    return;
  }
  const next = await toggleView(topicId);
  await reply(ctx, `view: ${next}`);
  if (bot) snap(bot, topicId);
}

async function handleGet(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  const topicId = ctx.message?.message_thread_id;
  const chatId = ctxChatId();
  if (!topicId || !chatId) return;
  const binding = await topicBindingForMessage(ctx, identity, topicId);
  if (!binding) return;
  const arg = ctx.message?.text?.split(/\s+/).slice(1).join(" ").trim();
  if (!arg) {
    await reply(ctx, "usage: /get <relpath>");
    return;
  }
  try {
    await sendFromServer(bot, chatId, topicId, arg);
  } catch (err) {
    await reply(ctx, `couldn't send: ${(err as Error).message}`);
  }
}

async function handleSlashKey(ctx: Context, key: string) {
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  if (!bot) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  const binding = await topicBindingForMessage(ctx, identity, topicId);
  if (!binding) return;
  sendKey(binding.sessionName, key);
  setTimeout(() => snap(bot!, topicId), 250);
}

async function sendPromptToBinding(
  ctx: Context,
  binding: TopicBinding,
  topicId: number,
  text: string,
  opts: { acknowledge?: boolean } = {}
): Promise<boolean> {
  if (!bot) return false;
  const mode = binding.viewMode ?? defaultViewMode(binding.kind);
  const promptSentAtMs = Date.now();

  const sent =
    binding.kind === "codex"
      ? await sendCodexText(binding.sessionName, text)
      : sendText(binding.sessionName, text, true);
  if (!sent) {
    await reply(ctx, "couldn't send input to tmux. please try again.");
    return false;
  }

  const tracksTranscriptPrompt =
    !/^(?:[0-9]+|y|yes|n|no|d)$/i.test(text.trim()) &&
    (binding.kind === "claude" || binding.kind === "codex");
  if (tracksTranscriptPrompt) {
    await patchTopic(topicId, {
      pendingPrompt: text,
      lastPromptAtMs: promptSentAtMs,
    });
  }

  if (tracksTranscriptPrompt && binding.kind === "claude" && mode === "chat") {
    const chatId = ctxChatId();
    if (chatId) {
      const started = startClaudeTranscript(bot, chatId, topicId, {
        cwd: binding.cwd,
        sinceMs: promptSentAtMs,
        promptText: text,
        persistedJsonl: binding.jsonlPath,
        initialOffset: binding.jsonlOffset,
      });
      if (started) {
        await patchTopic(topicId, {
          jsonlPath: started.jsonl,
          pendingPrompt: undefined,
          lastPromptAtMs: undefined,
        });
      } else if (isClaudeTranscriptRunning(topicId)) {
        await patchTopic(topicId, {
          pendingPrompt: undefined,
          lastPromptAtMs: undefined,
        });
      }
    }
  } else if (tracksTranscriptPrompt && binding.kind === "codex" && mode === "chat") {
    const chatId = ctxChatId();
    if (chatId) {
      const started = startCodexTranscript(bot, chatId, topicId, {
        cwd: binding.cwd,
        sinceMs: promptSentAtMs,
        promptText: text,
        sessionStartedMs: getSessionCreatedMs(binding.sessionName) ?? undefined,
        persistedJsonl: binding.jsonlPath,
        initialOffset: binding.jsonlOffset,
      });
      if (started) {
        await patchTopic(topicId, {
          jsonlPath: started.jsonl,
          pendingPrompt: undefined,
          lastPromptAtMs: undefined,
        });
      } else if (isCodexTranscriptRunning(topicId)) {
        await patchTopic(topicId, {
          pendingPrompt: undefined,
          lastPromptAtMs: undefined,
        });
      }
    }
  }

  // In chat mode against a TUI (claude, etc.) the actual response can
  // take many seconds to land via the JSONL transcript. Ack the input
  // right away so the user knows the bot received it instead of staring
  // at silence.
  const shouldAcknowledge = opts.acknowledge ?? true;
  if (shouldAcknowledge && mode === "off") {
    try {
      await reply(ctx, "input sent · responses off. /view chat or /view screen to resume.");
    } catch {
      /* ignore */
    }
  } else if (
    shouldAcknowledge &&
    mode === "chat" &&
    (binding.kind !== "bash" || isPaneTui(binding.sessionName))
  ) {
    try {
      await reply(ctx, "📩 received · processing…");
    } catch {
      /* ignore */
    }
  }

  const forwardedSlashCommand = text.trimStart().startsWith("/");
  const tuiSession = binding.kind !== "bash" || isPaneTui(binding.sessionName);
  setTimeout(() => snap(bot!, topicId), 250);
  if (mode === "chat" && forwardedSlashCommand && tuiSession) {
    for (const delay of [800, 2500, 5000]) {
      setTimeout(() => snapScreenMessage(bot!, topicId), delay);
    }
  }
  return true;
}

async function handleWizardText(
  ctx: Context,
  identity: BotIdentity,
  key: string,
  text: string
): Promise<boolean> {
  const wizard = startWizards.get(key);
  if (!wizard) return false;

  if (wizard.action === "new") {
    if (wizard.step !== "name") return false;
    const name = slugifySessionName(text);
    if (!name) {
      await reply(ctx, "Enter a session name using letters, numbers, spaces, _ - or .");
      return true;
    }
    startWizards.set(key, { action: "new", step: "kind", name });
    await reply(ctx, "Choose the session type.", { reply_markup: kindKeyboard(true) });
    return true;
  }

  if (wizard.step === "directory") {
    const directory = text.trim();
    if (!directory) {
      await reply(ctx, "Enter the git repository path.");
      return true;
    }
    startWizards.set(key, { action: "worktree", step: "name", directory });
    await reply(ctx, "Enter the worktree name, or use the button to auto-generate it.", {
      reply_markup: worktreeNameKeyboard(),
    });
    return true;
  }

  if (wizard.step === "name") {
    const name = slugifySessionName(text);
    if (!name) {
      await reply(ctx, "Enter a worktree name using letters, numbers, spaces, _ - or .");
      return true;
    }
    startWizards.set(key, {
      action: "worktree",
      step: "kind",
      directory: wizard.directory,
      name,
    });
    await reply(ctx, "Choose the worktree session type.", { reply_markup: kindKeyboard(false) });
    return true;
  }

  return false;
}

async function completeWizardWithKind(
  ctx: Context,
  identity: BotIdentity,
  key: string,
  kind: SessionKind
): Promise<void> {
  const wizard = startWizards.get(key);
  if (!wizard) return;
  if (wizard.step !== "kind") {
    await reply(ctx, "This flow is waiting for text input.");
    return;
  }
  startWizards.delete(key);

  if (wizard.action === "new") {
    if (!wizard.name) {
      await reply(ctx, "Missing session name. Run /new again.");
      return;
    }
    await createNewSessionFromInput(ctx, identity, wizard.name, kind);
    return;
  }

  if (!wizard.directory) {
    await reply(ctx, "Missing repository path. Run /worktree again.");
    return;
  }
  await createWorktreeSessionFromInput(ctx, identity, {
    directory: wizard.directory,
    name: wizard.name,
    kind,
  });
}

async function handleText(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  const text = ctx.message?.text;
  if (!text) return;
  const key = wizardKey(ctx);
  if (key && (await handleWizardText(ctx, identity, key, text))) return;
  if (text.startsWith("/")) return; // commands handled by their own hooks
  await sendTextToSessionTopic(ctx, identity, text);
}

async function handleSend(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  const text = ctx.message?.text ?? "";
  const rawInput = text.replace(/^\/(?:send|stdin)(?:@\w+)?(?:\s+)?/i, "");
  if (!rawInput) {
    await reply(ctx, "usage: /send <text>");
    return;
  }
  await sendTextToSessionTopic(ctx, identity, rawInput);
}

async function handleRawSlashText(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  const text = ctx.message?.text;
  if (!text?.startsWith("//")) return;
  await sendTextToSessionTopic(ctx, identity, text.slice(1));
}

async function sendTextToSessionTopic(ctx: Context, identity: BotIdentity, text: string) {
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) {
    // User typed in the General topic. The bot doesn't forward text from
    // there — give a small hint so they know what to do.
    await reply(ctx, "type inside a session topic to send to its terminal. /sessions to list.");
    return;
  }
  const binding = await topicBindingForMessage(
    ctx,
    identity,
    topicId,
    "this topic isn't bound to a session anymore."
  );
  if (!binding) return;
  await sendPromptToBinding(ctx, binding, topicId, text);
}

async function handleVoice(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) {
    await reply(ctx, "send voice notes inside a session topic.");
    return;
  }
  const binding = await topicBindingForMessage(
    ctx,
    identity,
    topicId,
    "this topic isn't bound to a session anymore."
  );
  if (!binding) return;

  const voice = ctx.message?.voice;
  const audio = ctx.message?.audio;
  const fileId = voice?.file_id ?? audio?.file_id;
  if (!fileId) return;

  let tempDir: string | undefined;
  try {
    await reply(ctx, "voice received · transcribing…");
    const preferredName =
      audio?.file_name ?? (voice ? `voice-${voice.file_unique_id}.ogg` : "voice-note.ogg");
    const downloaded = await downloadTelegramFileToTemp(bot, fileId, preferredName);
    tempDir = downloaded.tempDir;
    const transcript = await transcribeAudioFile(downloaded.filePath);
    const text = transcript.text.trim();
    if (!text) {
      await reply(ctx, "voice transcription produced no text.");
      return;
    }
    await reply(ctx, `voice → ${clipTelegramText(text)}`);
    await sendPromptToBinding(ctx, binding, topicId, text, { acknowledge: false });
  } catch (err) {
    await reply(ctx, `voice transcription failed: ${(err as Error).message}`);
  } finally {
    if (tempDir) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  }
}

async function handleFileUpload(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  const binding = await topicBindingForMessage(ctx, identity, topicId);
  if (!binding) return;

  const photo = ctx.message?.photo?.[ctx.message.photo.length - 1];
  const document = ctx.message?.document;
  const fileId = photo?.file_id ?? document?.file_id;
  if (!fileId) return;
  const preferredName =
    document?.file_name ?? (photo ? `photo-${photo.file_unique_id}.jpg` : undefined);
  try {
    const out = await downloadFromTelegram(bot, fileId, binding.cwd, preferredName);
    await reply(ctx, `saved → ${out.savedTo} (${out.bytes} bytes)`);
  } catch (err) {
    await reply(ctx, `upload failed: ${(err as Error).message}`);
  }
}

async function handleCallback(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) {
    await ctx.answerCallbackQuery();
    return;
  }
  const data = ctx.callbackQuery?.data ?? "";
  const topicId = ctx.callbackQuery?.message?.message_thread_id;
  await ctx.answerCallbackQuery();

  if (data === START_CB.CANCEL) {
    const key = wizardKey(ctx);
    if (key) startWizards.delete(key);
    await reply(ctx, "Cancelled.");
    return;
  }
  if (data === START_CB.SESSIONS) {
    await handleSessions(ctx);
    return;
  }
  if (data === START_CB.SKIP_NAME) {
    if (await rejectReadOnly(ctx)) return;
    const key = wizardKey(ctx);
    const wizard = key ? startWizards.get(key) : undefined;
    if (!key || !wizard || wizard.action !== "worktree" || wizard.step !== "name") {
      await reply(ctx, "No worktree flow is waiting for a name.");
      return;
    }
    startWizards.set(key, {
      action: "worktree",
      step: "kind",
      directory: wizard.directory,
    });
    await reply(ctx, "Choose the worktree session type.", { reply_markup: kindKeyboard(false) });
    return;
  }
  if (data.startsWith(START_CB.KIND_PREFIX)) {
    if (await rejectReadOnly(ctx)) return;
    const kind = data.slice(START_CB.KIND_PREFIX.length);
    if (!isValidKind(kind)) {
      await reply(ctx, "Unknown session type.");
      return;
    }
    const key = wizardKey(ctx);
    if (!key) return;
    await completeWizardWithKind(ctx, identity, key, kind);
    return;
  }

  // attach / kill from /sessions list
  if (data.startsWith(CB.ATTACH_PREFIX)) {
    await handleAttachByName(ctx, data.slice(CB.ATTACH_PREFIX.length));
    return;
  }
  if (data.startsWith(CB.KILL_PREFIX)) {
    if (await rejectReadOnly(ctx)) return;
    const name = data.slice(CB.KILL_PREFIX.length);
    if (!canAccessSession(identity.username, identity.role, name)) return;
    if (!ensureManagedSession(name)) {
      await reply(ctx, "refusing to kill a tmux session not managed by TerminalX.");
      return;
    }
    try {
      killSession(name);
    } catch {
      /* ignore */
    }
    const t = getTopicByName(name);
    if (t) {
      await stopStreamer(t.topicId);
      stopClaudeTranscript(t.topicId);
      stopCodexTranscript(t.topicId);
      await deleteTopic(t.topicId);
    }
    return;
  }

  // attached-mode keyboard
  if (!topicId) return;
  const binding = getTopic(topicId);
  if (!binding) return;
  if (!canUseTopic(identity, binding)) return;
  const session = binding.sessionName;
  const mutatingTerminalAction = new Set<string>([
    CB.CTRL_C,
    CB.CTRL_D,
    CB.TAB,
    CB.ENTER,
    CB.UP,
    CB.DOWN,
    CB.LEFT,
    CB.RIGHT,
    CB.SCROLL_UP,
    CB.SCROLL_DOWN,
    CB.DETACH,
    CB.KILL,
  ]);
  if (mutatingTerminalAction.has(data) && (await rejectReadOnly(ctx))) return;
  switch (data) {
    case CB.CTRL_C:
      sendKey(session, "C-c");
      break;
    case CB.CTRL_D:
      sendKey(session, "C-d");
      break;
    case CB.TAB:
      sendKey(session, "Tab");
      break;
    case CB.ENTER:
      sendKey(session, "Enter");
      break;
    case CB.UP:
      sendKey(session, "Up");
      break;
    case CB.DOWN:
      sendKey(session, "Down");
      break;
    case CB.LEFT:
      sendKey(session, "Left");
      break;
    case CB.RIGHT:
      sendKey(session, "Right");
      break;
    case CB.SCROLL_UP:
      scroll(session, "up");
      break;
    case CB.SCROLL_DOWN:
      scroll(session, "down");
      break;
    case CB.SNAP:
      // handled below
      break;
    case CB.VIEW: {
      const next = await toggleView(topicId);
      await ctx.answerCallbackQuery({ text: `view: ${next}` });
      if (bot) snap(bot, topicId);
      return;
    }
    case CB.DETACH:
      await stopStreamer(topicId);
      stopClaudeTranscript(topicId);
      stopCodexTranscript(topicId);
      await deleteTopic(topicId);
      await reply(ctx, "detached.");
      return;
    case CB.KILL:
      if (!ensureManagedSession(session)) {
        await reply(ctx, "refusing to kill a tmux session not managed by TerminalX.");
        return;
      }
      try {
        killSession(session);
      } catch {
        /* ignore */
      }
      await stopStreamer(topicId);
      stopClaudeTranscript(topicId);
      stopCodexTranscript(topicId);
      await deleteTopic(topicId);
      const chatId = ctxChatId();
      if (chatId) {
        try {
          await bot.api.closeForumTopic(chatId, topicId);
        } catch {
          /* ignore */
        }
      }
      return;
  }
  setTimeout(() => snap(bot!, topicId), 250);
}

/* ────────────── lifecycle ────────────── */

export async function startTelegramBot(): Promise<Bot | null> {
  if (!botIsConfigured()) {
    if (telegramHasPartialConfig() || telegramAllowedUserCount() > 0) {
      console.error(
        "[telegram] bot disabled: token, allowed users, and valid forum chat id are required"
      );
    }
    return null;
  }
  if (bot) return bot;
  const config = getTelegramConfig();
  const token = config.botToken;
  bot = new Bot(token);

  // commands
  bot.command("start", handleStart);
  bot.command("sessions", handleSessions);
  bot.command("new", handleNew);
  bot.command("worktree", handleWorktree);
  bot.command("detach", handleDetach);
  bot.command("kill", handleKill);
  bot.command("delete", handleDelete);
  bot.command("snap", handleSnap);
  bot.command("view", handleView);
  bot.command("get", handleGet);
  bot.command("send", handleSend);
  bot.command("stdin", handleSend);
  bot.command("tab", (ctx) => handleSlashKey(ctx, "Tab"));
  bot.command("enter", (ctx) => handleSlashKey(ctx, "Enter"));
  bot.command("ctrlc", (ctx) => handleSlashKey(ctx, "C-c"));
  bot.command("ctrld", (ctx) => handleSlashKey(ctx, "C-d"));
  bot.command("up", (ctx) => handleSlashKey(ctx, "Up"));
  bot.command("down", (ctx) => handleSlashKey(ctx, "Down"));

  // text & file uploads inside topics
  bot.hears(/^\/\//, handleRawSlashText);
  bot.on("message:text", handleText);
  bot.on(["message:voice", "message:audio"], handleVoice);
  bot.on(["message:photo", "message:document"], handleFileUpload);

  // inline keyboard
  bot.on("callback_query:data", handleCallback);

  // grammy needs bot.init() to fetch its own info before handleUpdate works
  // when we're driving updates ourselves (webhook mode without bot.start()).
  await bot.init();

  // remember the configured forum chat id so other modules can reach it
  const forumChatId = getTelegramForumChatId();
  if (!forumChatId) return bot;
  await setForumChatId(forumChatId);

  // webhook setup
  const webhookUrl = config.webhookUrl;
  const secret = config.webhookSecret;
  if (!webhookUrl || !secret) {
    console.error("[telegram] webhook url / secret missing — bot won't receive updates");
    return bot;
  }
  try {
    await bot.api.setWebhook(webhookUrl, { secret_token: secret });
    console.log(`[telegram] webhook set ${webhookUrl}`);
  } catch (err) {
    console.error("[telegram] setWebhook failed", err);
  }

  // resume any persisted topic streamers
  for (const t of listTopics()) {
    await reconcileTopicBinding(t);
  }
  for (const t of listTopics()) {
    if (t.endedAtMs) continue;
    if (t.kind !== "claude" && t.kind !== "codex") continue;
    const hasResumeSource =
      !!t.jsonlPath || (t.viewMode === "chat" && !!t.pendingPrompt && !!t.lastPromptAtMs);
    if (!hasResumeSource) {
      continue;
    }
    const sinceMs = t.lastPromptAtMs ?? getSessionCreatedMs(t.sessionName) ?? 0;
    const started =
      t.kind === "codex"
        ? startCodexTranscript(bot, forumChatId, t.topicId, {
            cwd: t.cwd,
            sinceMs,
            promptText: t.pendingPrompt,
            sessionStartedMs: getSessionCreatedMs(t.sessionName) ?? undefined,
            persistedJsonl: t.jsonlPath,
            initialOffset: t.jsonlOffset,
          })
        : startClaudeTranscript(bot, forumChatId, t.topicId, {
            cwd: t.cwd,
            sinceMs,
            promptText: t.pendingPrompt,
            persistedJsonl: t.jsonlPath,
            initialOffset: t.jsonlOffset,
          });
    if (started) {
      await patchTopic(t.topicId, {
        jsonlPath: started.jsonl,
        pendingPrompt: undefined,
        lastPromptAtMs: undefined,
      });
    }
  }
  resumePersistedStreamers(bot);
  return bot;
}

/** Hand a parsed Telegram update from the webhook into the bot. */
export async function handleTelegramUpdate(update: object): Promise<void> {
  if (!bot) return;
  // Optional debug — set TERMINALX_TELEGRAM_DEBUG=1 to log every incoming
  // update's chat / from / text. Useful for triaging delivery problems
  // without rebuilding; off by default since each update would otherwise
  // print a line.
  if (process.env.TERMINALX_TELEGRAM_DEBUG === "1") {
    try {
      const u = update as {
        update_id?: number;
        message?: {
          from?: { id?: number; username?: string };
          chat?: { id?: number; type?: string };
          text?: string;
        };
      };
      const m = u.message;
      console.log(
        `[telegram] update id=${u.update_id} chat=${m?.chat?.id}/${m?.chat?.type} from=${m?.from?.id}/@${m?.from?.username} text=${JSON.stringify(m?.text)}`
      );
    } catch {
      /* ignore */
    }
  }
  await bot.handleUpdate(update as Parameters<Bot["handleUpdate"]>[0]);
}

export async function stopTelegramBot(): Promise<void> {
  if (!bot) return;
  stopAllStreamers();
  stopAllClaudeTranscripts();
  stopAllCodexTranscripts();
  try {
    await bot.api.deleteWebhook();
  } catch {
    /* ignore */
  }
  bot = null;
}

export async function restartTelegramBot(): Promise<Bot | null> {
  await stopTelegramBot();
  return startTelegramBot();
}

export function getBot(): Bot | null {
  return bot;
}
