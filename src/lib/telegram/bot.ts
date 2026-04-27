import { Bot, type Context } from "grammy";
import {
  listSessions,
  createSession,
  killSession,
  hasSession,
  getSessionCreatedMs,
  isPaneTui,
} from "@/lib/tmux";
import { canAccessSession, scopedSessionName } from "@/lib/session-scope";
import { commandForKind, saveMeta, isValidKind, type SessionKind } from "@/lib/ai-sessions";
import { resolveTelegramIdentity, botIsConfigured, type BotIdentity } from "./auth";
import { sessionsKeyboard, CB } from "./keyboard";
import {
  setTopic,
  deleteTopic,
  getTopic,
  getTopicByName,
  listTopics,
  setForumChatId,
  patchTopic,
  type TopicBinding,
} from "./state";
import {
  startStreamer,
  stopStreamer,
  stopAllStreamers,
  resumePersistedStreamers,
  sendKey,
  sendText,
  scroll,
  snap,
  defaultViewMode,
  resetChatBaseline,
} from "./streamer";
import {
  startClaudeTranscript,
  stopClaudeTranscript,
  stopAllClaudeTranscripts,
  readLastAssistantText,
} from "./claude-transcript";
import { downloadFromTelegram, sendFromServer } from "./files";

let bot: Bot | null = null;

/**
 * Resolve the Telegram identity for the user behind a Context, OR null if
 * they're not on the allowlist or the chat isn't the configured forum.
 */
async function gate(ctx: Context): Promise<BotIdentity | null> {
  const tgId = ctx.from?.id;
  const chatId = ctx.chat?.id;
  if (!tgId || !chatId) return null;
  const expected = Number(process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID);
  if (expected && chatId !== expected) return null;
  const identity = await resolveTelegramIdentity(tgId);
  if (!identity) return null;
  return identity;
}

async function reply(ctx: Context, text: string, opts: Parameters<Context["reply"]>[1] = {}) {
  try {
    await ctx.reply(text, { ...opts });
  } catch (err) {
    console.error("[telegram/bot] reply failed", err);
  }
}

async function attachToTopic(b: Bot, identity: BotIdentity, binding: TopicBinding): Promise<void> {
  const chatId = ctxChatId();
  if (!chatId) return;
  const mode = binding.viewMode ?? defaultViewMode(binding.kind);
  await setTopic({ ...binding, viewMode: mode });
  startStreamer(b, binding.topicId);
  let resolvedJsonl: string | undefined = binding.jsonlPath;
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
      await patchTopic(binding.topicId, { jsonlPath: started.jsonl });
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

  // For TUI sessions (claude, vim, …) the user starts in chat mode but
  // would otherwise see nothing until the next assistant entry. Surface
  // the most recent assistant message from the latest JSONL so they
  // immediately have context for what was happening.
  if (mode === "chat" && isPaneTui(binding.sessionName)) {
    const last = readLastAssistantText(resolvedJsonl);
    if (last) {
      try {
        await b.api.sendMessage(chatId, last, {
          message_thread_id: binding.topicId,
          parse_mode: "MarkdownV2",
        });
      } catch {
        /* ignore */
      }
    }
  }
}

function ctxChatId(): number | null {
  const expected = Number(process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID);
  return Number.isFinite(expected) ? expected : null;
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
      "  • reply with a file → upload to session cwd",
      "  • /snap, /detach, /kill, /get <relpath>",
      "  • /view [screen|chat] — toggle pinned-screen vs message-stream view",
      "  • inline keyboard: ^C ^D Tab ↵ arrows scroll snap view detach kill",
    ].join("\n")
  );
}

async function handleSessions(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  const all = listSessions().filter((s) =>
    canAccessSession(identity.username, identity.role, s.name)
  );
  if (all.length === 0) {
    await reply(ctx, "no sessions. the box is lonely.");
    return;
  }
  await ctx.reply(`${all.length} session${all.length === 1 ? "" : "s"}:`, {
    reply_markup: sessionsKeyboard(all),
  });
}

async function handleNew(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
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
  const cwd = process.env.TERMINUS_ROOT || process.env.HOME || "/";
  const cmd = commandForKind(kind);
  try {
    createSession(scoped, cmd ?? undefined, cwd);
    await saveMeta({ name: scoped, kind, createdAt: new Date().toISOString() });
  } catch (err) {
    await reply(ctx, `failed to create: ${(err as Error).message}`);
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
  const chatId = ctxChatId();
  if (!chatId) return;
  const existing = getTopicByName(name);
  if (existing) {
    const url = topicLink(chatId, existing.topicId);
    await reply(ctx, `already attached → ${url}`, {
      link_preview_options: { is_disabled: true },
    });
    return;
  }
  const topic = await bot.api.createForumTopic(chatId, name);
  await attachToTopic(bot, identity, {
    topicId: topic.message_thread_id,
    sessionName: name,
    kind: "bash", // best-effort default; metadata could refine
    cwd: process.env.TERMINUS_ROOT || process.env.HOME || "/",
  });
}

async function handleDetach(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  await stopStreamer(topicId);
  stopClaudeTranscript(topicId);
  await deleteTopic(topicId);
  await reply(ctx, "detached. tmux session is still running.");
}

async function handleKill(ctx: Context) {
  const identity = await gate(ctx);
  if (!identity) return;
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
  try {
    killSession(target);
  } catch (err) {
    await reply(ctx, `failed: ${(err as Error).message}`);
    return;
  }
  if (topicId) {
    await stopStreamer(topicId);
    stopClaudeTranscript(topicId);
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

async function handleSnap(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  snap(bot, topicId);
}

async function toggleView(topicId: number): Promise<"screen" | "chat"> {
  const binding = getTopic(topicId);
  if (!binding) return "screen";
  const current = binding.viewMode ?? defaultViewMode(binding.kind);
  const next: "screen" | "chat" = current === "screen" ? "chat" : "screen";
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
  const arg = (ctx.message?.text?.split(/\s+/)[1] ?? "").toLowerCase();
  if (arg === "screen" || arg === "chat") {
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
  if (!bot) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  const binding = getTopic(topicId);
  if (!binding) return;
  sendKey(binding.sessionName, key);
  setTimeout(() => snap(bot!, topicId), 250);
}

async function handleText(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  const text = ctx.message?.text;
  if (!text || text.startsWith("/")) return; // commands handled by their own hooks
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) {
    // User typed in the General topic. The bot doesn't forward text from
    // there — give a small hint so they know what to do.
    await reply(ctx, "type inside a session topic to send to its terminal. /sessions to list.");
    return;
  }
  const binding = getTopic(topicId);
  if (!binding) {
    await reply(ctx, "this topic isn't bound to a session anymore.");
    return;
  }
  sendText(binding.sessionName, text, true);

  // In chat mode against a TUI (claude, etc.) the actual response can
  // take many seconds to land via the JSONL transcript. Ack the input
  // right away so the user knows the bot received it instead of staring
  // at silence.
  const mode = binding.viewMode ?? "screen";
  if (mode === "chat" && isPaneTui(binding.sessionName)) {
    try {
      await ctx.reply("📩 received · processing…");
    } catch {
      /* ignore */
    }
  }

  setTimeout(() => snap(bot!, topicId), 250);
}

async function handleFileUpload(ctx: Context) {
  if (!bot) return;
  const identity = await gate(ctx);
  if (!identity) return;
  const topicId = ctx.message?.message_thread_id;
  if (!topicId) return;
  const binding = getTopic(topicId);
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
    const name = data.slice(CB.KILL_PREFIX.length);
    if (!canAccessSession(identity.username, identity.role, name)) return;
    try {
      killSession(name);
    } catch {
      /* ignore */
    }
    const t = getTopicByName(name);
    if (t) {
      await stopStreamer(t.topicId);
      stopClaudeTranscript(t.topicId);
      await deleteTopic(t.topicId);
    }
    return;
  }

  // attached-mode keyboard
  if (!topicId) return;
  const binding = getTopic(topicId);
  if (!binding) return;
  const session = binding.sessionName;
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
      await deleteTopic(topicId);
      await reply(ctx, "detached.");
      return;
    case CB.KILL:
      try {
        killSession(session);
      } catch {
        /* ignore */
      }
      await stopStreamer(topicId);
      stopClaudeTranscript(topicId);
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
  if (!botIsConfigured()) return null;
  if (bot) return bot;
  const token = process.env.TERMINALX_TELEGRAM_BOT_TOKEN!;
  bot = new Bot(token);

  // commands
  bot.command("start", handleStart);
  bot.command("sessions", handleSessions);
  bot.command("new", handleNew);
  bot.command("detach", handleDetach);
  bot.command("kill", handleKill);
  bot.command("snap", handleSnap);
  bot.command("view", handleView);
  bot.command("get", handleGet);
  bot.command("tab", (ctx) => handleSlashKey(ctx, "Tab"));
  bot.command("enter", (ctx) => handleSlashKey(ctx, "Enter"));
  bot.command("ctrlc", (ctx) => handleSlashKey(ctx, "C-c"));
  bot.command("ctrld", (ctx) => handleSlashKey(ctx, "C-d"));
  bot.command("up", (ctx) => handleSlashKey(ctx, "Up"));
  bot.command("down", (ctx) => handleSlashKey(ctx, "Down"));

  // text & file uploads inside topics
  bot.on("message:text", handleText);
  bot.on(["message:photo", "message:document"], handleFileUpload);

  // inline keyboard
  bot.on("callback_query:data", handleCallback);

  // grammy needs bot.init() to fetch its own info before handleUpdate works
  // when we're driving updates ourselves (webhook mode without bot.start()).
  await bot.init();

  // remember the configured forum chat id so other modules can reach it
  const forumChatId = Number(process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID);
  if (Number.isFinite(forumChatId)) await setForumChatId(forumChatId);

  // webhook setup
  const webhookUrl = process.env.TERMINALX_TELEGRAM_WEBHOOK_URL;
  const secret = process.env.TERMINALX_TELEGRAM_WEBHOOK_SECRET;
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
  resumePersistedStreamers(bot);
  for (const t of listTopics()) {
    if (t.kind !== "claude") continue;
    const sinceMs = getSessionCreatedMs(t.sessionName) ?? 0;
    startClaudeTranscript(bot, forumChatId, t.topicId, {
      cwd: t.cwd,
      sinceMs,
      persistedJsonl: t.jsonlPath,
      initialOffset: t.jsonlOffset,
    });
  }
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
  try {
    await bot.api.deleteWebhook();
  } catch {
    /* ignore */
  }
  bot = null;
}

export function getBot(): Bot | null {
  return bot;
}
