import * as fs from "fs";
import { Bot, type Context } from "grammy";
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
  topicSessionIncarnationPatch,
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
  defaultViewMode,
  resetChatBaseline,
  resetStreamerSessionState,
} from "./streamer";
import {
  startClaudeTranscript,
  stopClaudeTranscript,
  stopAllClaudeTranscripts,
  readLastAssistantText,
} from "./claude-transcript";
import {
  startCodexTranscript,
  stopCodexTranscript,
  stopAllCodexTranscripts,
  readLastCodexAssistantText,
} from "./codex-transcript";
import { markdownToTelegramV2 } from "./render";
import { downloadFromTelegram, downloadTelegramFileToTemp, sendFromServer } from "./files";
import { transcribeAudioFile } from "./transcription";
import { forumTopicExists } from "./topic-health";
import {
  getTelegramMessageAuditor,
  installTelegramMessageAudit,
  withTelegramMessageAuditSource,
} from "./message-audit";

let bot: Bot | null = null;

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
  const incarnation = topicSessionIncarnationPatch(
    binding,
    getSessionCreatedMs(binding.sessionName)
  );
  const patch = {
    ...defaults,
    ...incarnation.patch,
  };
  if (
    patch.kind !== binding.kind ||
    patch.cwd !== binding.cwd ||
    patch.sessionCreatedAtMs !== binding.sessionCreatedAtMs
  ) {
    if (incarnation.changed) {
      stopClaudeTranscript(binding.topicId);
      stopCodexTranscript(binding.topicId);
      resetStreamerSessionState(binding.topicId);
    }
    await patchTopic(binding.topicId, patch);
    return { ...binding, ...patch };
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
  const sessionCreatedAtMs =
    binding.sessionCreatedAtMs ?? getSessionCreatedMs(binding.sessionName) ?? Date.now();
  await setTopic({
    ...binding,
    sessionCreatedAtMs,
    viewMode: mode,
    endedAtMs: undefined,
  });
  startStreamer(b, binding.topicId);
  let resolvedJsonl: string | undefined;
  let resolvedTranscriptKind: "claude" | "codex" | undefined;
  if (binding.kind === "claude") {
    const sinceMs = getSessionCreatedMs(binding.sessionName) ?? Date.now();
    const started = startClaudeTranscript(b, chatId, binding.topicId, {
      sessionId: binding.sessionName,
      sessionCreatedAtMs,
      cwd: binding.cwd,
      sinceMs,
      persistedJsonl: binding.jsonlPath,
      initialOffset: binding.jsonlOffset,
    });
    if (started) {
      resolvedJsonl = started.jsonl;
      resolvedTranscriptKind = "claude";
      await patchTopic(binding.topicId, {
        jsonlPath: started.jsonl,
        transcriptSessionId: started.transcriptSessionId,
      });
    }
  } else if (binding.kind === "codex" && binding.jsonlPath) {
    const started = startCodexTranscript(b, chatId, binding.topicId, {
      sessionId: binding.sessionName,
      sessionCreatedAtMs,
      cwd: binding.cwd,
      persistedJsonl: binding.jsonlPath,
      initialOffset: binding.jsonlOffset,
    });
    if (started) {
      resolvedJsonl = started.jsonl;
      resolvedTranscriptKind = "codex";
      await patchTopic(binding.topicId, {
        jsonlPath: started.jsonl,
        transcriptSessionId: started.transcriptSessionId,
      });
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
  const managementBot = new Bot(config.botToken);
  installTelegramMessageAudit(managementBot);
  return managementBot;
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
      "/sessions — list sessions",
      "/new <name> [bash|claude|codex] — create + attach in a new topic",
      "",
      "inside a session topic:",
      "  • text → stdin",
      "  • voice note → local transcription → stdin",
      "  • reply with a file → upload to session cwd",
      "  • /snap, /detach, /kill, /delete, /get <relpath>",
      "  • /view [chat|screen|off] — control session responses in this topic",
      "  • inline keyboard: ^C ^D Tab ↵ arrows scroll snap view detach kill",
    ].join("\n")
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
  if (!rawName || !/^[a-zA-Z0-9_.\-]+$/.test(rawName)) {
    await reply(ctx, "usage: /new <name> [bash|claude|codex]");
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
  const cwd = process.env.TERMINUS_ROOT || process.env.HOME || "/";
  const cmd = commandForKind(kind);
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

  if (binding.kind === "claude" || binding.kind === "codex") {
    await patchTopic(topicId, {
      pendingPrompt: text,
      lastPromptAtMs: promptSentAtMs,
    });
  }

  if (binding.kind === "claude" && mode === "chat") {
    const chatId = ctxChatId();
    if (chatId) {
      const started = startClaudeTranscript(bot, chatId, topicId, {
        sessionId: binding.sessionName,
        sessionCreatedAtMs:
          binding.sessionCreatedAtMs ?? getSessionCreatedMs(binding.sessionName) ?? undefined,
        cwd: binding.cwd,
        sinceMs: promptSentAtMs,
        promptText: text,
        persistedJsonl: binding.jsonlPath,
        initialOffset: binding.jsonlOffset,
      });
      if (started) {
        await patchTopic(topicId, {
          jsonlPath: started.jsonl,
          transcriptSessionId: started.transcriptSessionId,
          pendingPrompt: undefined,
          lastPromptAtMs: undefined,
        });
      }
    }
  } else if (binding.kind === "codex" && mode === "chat") {
    const chatId = ctxChatId();
    if (chatId) {
      const started = startCodexTranscript(bot, chatId, topicId, {
        sessionId: binding.sessionName,
        sessionCreatedAtMs:
          binding.sessionCreatedAtMs ?? getSessionCreatedMs(binding.sessionName) ?? undefined,
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
          transcriptSessionId: started.transcriptSessionId,
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

  setTimeout(() => snap(bot!, topicId), 250);
  return true;
}

async function handleText(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  if (await rejectReadOnly(ctx)) return;
  const text = ctx.message?.text;
  if (!text || text.startsWith("/")) return; // commands handled by their own hooks
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

function botIdFromToken(token: string): number | undefined {
  const raw = token.split(":", 1)[0];
  if (!raw || !/^\d+$/.test(raw)) return undefined;
  const id = Number(raw);
  return Number.isSafeInteger(id) && id > 0 ? id : undefined;
}

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
  const candidate = new Bot(token);
  const auditor = getTelegramMessageAuditor();
  auditor.setTelegramBotId(botIdFromToken(token));
  installTelegramMessageAudit(candidate, auditor);

  // commands
  candidate.command("start", handleStart);
  candidate.command("sessions", handleSessions);
  candidate.command("new", handleNew);
  candidate.command("detach", handleDetach);
  candidate.command("kill", handleKill);
  candidate.command("delete", handleDelete);
  candidate.command("snap", handleSnap);
  candidate.command("view", handleView);
  candidate.command("get", handleGet);
  candidate.command("tab", (ctx) => handleSlashKey(ctx, "Tab"));
  candidate.command("enter", (ctx) => handleSlashKey(ctx, "Enter"));
  candidate.command("ctrlc", (ctx) => handleSlashKey(ctx, "C-c"));
  candidate.command("ctrld", (ctx) => handleSlashKey(ctx, "C-d"));
  candidate.command("up", (ctx) => handleSlashKey(ctx, "Up"));
  candidate.command("down", (ctx) => handleSlashKey(ctx, "Down"));

  // text & file uploads inside topics
  candidate.on("message:text", handleText);
  candidate.on(["message:voice", "message:audio"], handleVoice);
  candidate.on(["message:photo", "message:document"], handleFileUpload);

  // inline keyboard
  candidate.on("callback_query:data", handleCallback);

  // grammy needs bot.init() to fetch its own info before handleUpdate works
  // when we're driving updates ourselves (webhook mode without bot.start()).
  await candidate.init();
  auditor.setTelegramBotId(candidate.botInfo.id);
  bot = candidate;

  // remember the configured forum chat id so other modules can reach it
  const forumChatId = getTelegramForumChatId();
  if (!forumChatId) return candidate;
  await setForumChatId(forumChatId);

  // webhook setup
  const webhookUrl = config.webhookUrl;
  const secret = config.webhookSecret;
  if (!webhookUrl || !secret) {
    console.error("[telegram] webhook url / secret missing — bot won't receive updates");
    return candidate;
  }
  try {
    await candidate.api.setWebhook(webhookUrl, { secret_token: secret });
    console.log(`[telegram] webhook set ${webhookUrl}`);
  } catch (err) {
    console.error("[telegram] setWebhook failed", err);
  }

  // resume any persisted topic streamers
  for (const t of listTopics()) {
    await reconcileTopicBinding(t);
  }
  resumePersistedStreamers(candidate);
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
        ? startCodexTranscript(candidate, forumChatId, t.topicId, {
            sessionId: t.sessionName,
            sessionCreatedAtMs: t.sessionCreatedAtMs,
            cwd: t.cwd,
            sinceMs,
            promptText: t.pendingPrompt,
            sessionStartedMs: getSessionCreatedMs(t.sessionName) ?? undefined,
            persistedJsonl: t.jsonlPath,
            initialOffset: t.jsonlOffset,
          })
        : startClaudeTranscript(candidate, forumChatId, t.topicId, {
            sessionId: t.sessionName,
            sessionCreatedAtMs: t.sessionCreatedAtMs,
            cwd: t.cwd,
            sinceMs,
            promptText: t.pendingPrompt,
            persistedJsonl: t.jsonlPath,
            initialOffset: t.jsonlOffset,
          });
    if (started) {
      await patchTopic(t.topicId, {
        jsonlPath: started.jsonl,
        transcriptSessionId: started.transcriptSessionId,
        pendingPrompt: undefined,
        lastPromptAtMs: undefined,
      });
    }
  }
  return candidate;
}

/** Persist and hand a parsed Telegram update from the webhook into the bot. */
export function handleTelegramUpdate(update: object): Promise<void> {
  let botId = botIdFromToken(getTelegramConfig().botToken);
  if (bot) {
    try {
      botId = bot.botInfo.id;
    } catch {
      // The update is still durable even if bot initialization failed.
    }
  }
  const auditor = getTelegramMessageAuditor();
  const recorded = auditor.recordInboundUpdate(update, botId);
  const activeBot = bot;
  if (!activeBot) {
    throw new Error("Telegram bot is not ready; update was stored for retry");
  }
  const claimed = auditor.claimInboundDispatch(recorded.event.id);
  if (claimed.status === "processed") return Promise.resolve();
  if (claimed.status === "busy") {
    throw new Error("Telegram update is already being processed; retry later");
  }
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
  const event = claimed.event;
  const processing = withTelegramMessageAuditSource(
    {
      source: "telegram-handler",
      sourceRef: event.sourceRef,
      correlationId: event.correlationId,
      sessionId: event.sessionId,
      sessionCreatedAtMs: event.sessionCreatedAtMs,
      expectedChatId: event.expectedChatId,
      expectedTopicId: event.expectedTopicId,
      transcriptSessionId: event.transcriptSessionId,
      transcriptPath: event.transcriptPath,
    },
    () => activeBot.handleUpdate(update as Parameters<Bot["handleUpdate"]>[0])
  );
  return processing.then(
    async () => {
      await auditor.completeInboundDispatch(event.id);
    },
    async (error: unknown) => {
      await auditor.failInboundDispatch(event.id, error);
      throw error;
    }
  );
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
