import { execFileSync } from "child_process";
import type { Bot } from "grammy";
import { hasSession, captureVisiblePane, isPaneTui, getSessionCreatedMs } from "@/lib/tmux";
import { renderScreen, stripAnsi } from "./render";
import { attachedKeyboard } from "./keyboard";
import {
  getTopic,
  listTopics,
  patchTopic,
  deleteTopic,
  getForumChatId,
  type ViewMode,
} from "./state";
import { startClaudeTranscript, isClaudeTranscriptRunning } from "./claude-transcript";

const FLUSH_INTERVAL_MS = 5000;
const TMUX = "tmux";

/**
 * Per-topic streamer state — kept in-process; persisted bits (pinnedMsgId,
 * jsonlOffset) live in `state.ts`.
 */
interface RuntimeState {
  topicId: number;
  flushTimer: NodeJS.Timeout;
  flushBusy: boolean;
  /** Last rendered code-block (screen mode), used to dedup edits. */
  lastRendered: string;
  /** Last plain-text screen we've already sent (chat mode), used for diffs. */
  lastSentText: string;
  lastFlushAt: number;
  /** Have we already nudged the user that a TUI is running? */
  tuiHinted: boolean;
}

/** Default view mode for a freshly-attached topic. */
export function defaultViewMode(_kind: string): ViewMode {
  // Chat reads like a normal conversation; for claude / codex topics it
  // routes through the per-topic JSONL transcript so the user sees only
  // the assistant's final replies.
  return "chat";
}

const runtimes = new Map<number, RuntimeState>();

function tmuxSend(sessionName: string, args: string[]): void {
  try {
    execFileSync(TMUX, ["send-keys", "-t", sessionName, ...args], { timeout: 2000 });
  } catch (err) {
    console.error("[telegram/streamer] send-keys failed", err);
  }
}

/** Send a literal string (handles all printable chars, no key parsing). */
export function sendText(sessionName: string, text: string, withEnter = true): void {
  tmuxSend(sessionName, ["-l", text]);
  if (withEnter) tmuxSend(sessionName, ["Enter"]);
}

/** Send a named key sequence (Tab, Enter, C-c, C-d, Up, Down, Left, Right). */
export function sendKey(sessionName: string, key: string): void {
  tmuxSend(sessionName, [key]);
}

/**
 * Page through tmux's copy-mode scrollback. action: "up" | "down" | "cancel".
 * Mirrors the WS scroll handler in `server/index.ts` so behaviour matches the web.
 */
export function scroll(sessionName: string, action: "up" | "down" | "cancel"): void {
  try {
    if (action === "cancel") {
      execFileSync(TMUX, ["send-keys", "-t", sessionName, "-X", "cancel"], { timeout: 2000 });
      return;
    }
    execFileSync(TMUX, ["copy-mode", "-t", sessionName], { timeout: 2000 });
    const cmd = action === "up" ? "page-up" : "page-down";
    execFileSync(TMUX, ["send-keys", "-t", sessionName, "-X", cmd], { timeout: 2000 });
  } catch (err) {
    console.error("[telegram/streamer] scroll failed", err);
  }
}

/**
 * Render the live screen for a topic in screen mode (pinned-message edit) or
 * chat mode (incremental new-line messages). Detaches the topic if the tmux
 * session has gone away.
 */
async function renderAndFlush(bot: Bot, topicId: number): Promise<void> {
  const rt = runtimes.get(topicId);
  if (!rt || rt.flushBusy) return;
  const binding = getTopic(topicId);
  const chatId = getForumChatId();
  if (!binding || !chatId) return;

  // Detach if the tmux session vanished (user typed `exit`, or it crashed).
  if (!hasSession(binding.sessionName)) {
    await stopStreamer(topicId);
    try {
      await bot.api.sendMessage(chatId, "session ended.", {
        message_thread_id: topicId,
      });
      await bot.api.closeForumTopic(chatId, topicId);
    } catch {
      // ignore — topic may already be closed
    }
    await deleteTopic(topicId);
    return;
  }

  rt.flushBusy = true;
  try {
    const ansi = captureVisiblePane(binding.sessionName);
    if (!ansi) return;
    const mode = binding.viewMode ?? defaultViewMode(binding.kind);
    if (mode === "chat") {
      await flushChat(bot, chatId, topicId, binding.sessionName, ansi, rt);
    } else {
      await flushScreen(bot, chatId, topicId, binding.pinnedMsgId, ansi, rt);
    }
    rt.lastFlushAt = Date.now();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[telegram/streamer] flush failed:", msg);
  } finally {
    rt.flushBusy = false;
  }
}

/**
 * screen mode — edit the pinned code-block message every flush. If the
 * pinned message has been deleted by the user, send a fresh one.
 */
async function flushScreen(
  bot: Bot,
  chatId: number,
  topicId: number,
  pinnedMsgId: number | undefined,
  ansi: string,
  rt: RuntimeState
): Promise<void> {
  const rendered = renderScreen(ansi);
  if (rendered === rt.lastRendered) return;

  if (pinnedMsgId) {
    try {
      await bot.api.editMessageText(chatId, pinnedMsgId, rendered, {
        parse_mode: "MarkdownV2",
        reply_markup: attachedKeyboard(),
      });
      rt.lastRendered = rendered;
      return;
    } catch (err) {
      const desc = String((err as { description?: string })?.description ?? err);
      if (desc.includes("message is not modified")) {
        rt.lastRendered = rendered;
        return;
      }
      // fall through to send a fresh pinned message
    }
  }

  const sent = await bot.api.sendMessage(chatId, rendered, {
    parse_mode: "MarkdownV2",
    message_thread_id: topicId,
    reply_markup: attachedKeyboard(),
  });
  await patchTopic(topicId, { pinnedMsgId: sent.message_id });
  rt.lastRendered = rendered;
}

/**
 * chat mode — diff the visible screen against what we last sent and post
 * only the new lines as a fresh plain-text message. No code block, no
 * inline keyboard — meant to read like a normal Telegram conversation.
 * Use slash commands (/snap, /detach, /kill, /view, /ctrlc, etc.) for
 * control instead.
 *
 * If the pane is on the alt-screen buffer (a TUI is running), we don't
 * try to diff the rendered screen at all — too noisy. Instead we lean
 * on the Claude JSONL transcript stream when available; if no JSONL
 * exists, we send a one-time hint and stay quiet.
 */
async function flushChat(
  bot: Bot,
  chatId: number,
  topicId: number,
  sessionName: string,
  ansi: string,
  rt: RuntimeState
): Promise<void> {
  // For sessions that the user explicitly created as kind=claude, always
  // route through JSONL — regardless of what `pane_current_command`
  // currently says. There's a race on first attach where the parent bash
  // hasn't yet exec'd `claude`, and isPaneTui briefly returns false. We
  // don't want the welcome banner of Claude Code dumped as raw chat text
  // during that window.
  const binding = getTopic(topicId);
  const knownTui = binding?.kind === "claude" || binding?.kind === "codex";
  if (knownTui || isPaneTui(sessionName)) {
    // TUI active. Try to wire up the JSONL transcript watcher; if a
    // recent claude session JSONL exists, the user will start seeing
    // formatted assistant / tool / thinking messages instead of the
    // raw screen redraws.
    if (!isClaudeTranscriptRunning(topicId)) {
      const sinceMs = getSessionCreatedMs(sessionName) ?? Date.now();
      const started = startClaudeTranscript(bot, chatId, topicId, {
        cwd: binding?.cwd,
        sinceMs,
        persistedJsonl: binding?.jsonlPath,
        initialOffset: binding?.jsonlOffset,
      });
      if (started) {
        await patchTopic(topicId, { jsonlPath: started.jsonl });
        return;
      }
      if (!rt.tuiHinted) {
        rt.tuiHinted = true;
        try {
          await bot.api.sendMessage(
            chatId,
            "(TUI app running. /view screen to see the live screen, or attach via web for full fidelity.)",
            { message_thread_id: topicId }
          );
        } catch {
          /* ignore */
        }
      }
    }
    return;
  }

  // TUI not active — diff the visible bash screen and emit new lines.
  const text = stripAnsi(ansi)
    .split("\n")
    .map((l) => l.replace(/\s+$/, ""))
    .filter((_, i, arr) => i < arr.length - 1 || arr[arr.length - 1] !== "")
    .join("\n");

  // First flush in chat mode: baseline only, don't post anything.
  if (rt.lastSentText === "") {
    rt.lastSentText = text;
    return;
  }
  if (text === rt.lastSentText) return;

  const newLines = diffNewLines(rt.lastSentText, text);
  rt.lastSentText = text;
  if (newLines.length === 0) return;

  // Plain text — no parse_mode means special chars stay literal, no
  // backslash-escaping noise, no monospace box.
  const body = newLines.join("\n").trim();
  if (!body) return;
  await bot.api.sendMessage(chatId, body.slice(0, 4000), {
    message_thread_id: topicId,
  });
}

/**
 * Lightweight LCS-style diff: skip the longest common prefix between the
 * old and new screens, then everything in `next` past the divergence is
 * "new" content. Imperfect (it can't handle overwrites or scrollback
 * eviction perfectly), but works well enough for "user types a command,
 * see the new lines after the prompt".
 */
function diffNewLines(prev: string, next: string): string[] {
  const a = prev.split("\n");
  const b = next.split("\n");
  // Skip the common prefix.
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  // Cap the message size — never spam more than 50 lines per flush even
  // if the diff is huge (e.g. screen cleared + redrawn).
  return b.slice(Math.max(i, b.length - 50));
}

/** Start (or restart) the 5s flush timer for a topic. */
export function startStreamer(bot: Bot, topicId: number): void {
  stopStreamerSync(topicId);
  const rt: RuntimeState = {
    topicId,
    flushBusy: false,
    lastRendered: "",
    lastSentText: "",
    lastFlushAt: 0,
    tuiHinted: false,
    flushTimer: setInterval(() => {
      void renderAndFlush(bot, topicId);
    }, FLUSH_INTERVAL_MS),
  };
  runtimes.set(topicId, rt);
  // Fire the first flush right away so the user sees something <5s.
  void renderAndFlush(bot, topicId);
}

/** Reset the chat-mode baseline so the next flush establishes a new one. */
export function resetChatBaseline(topicId: number): void {
  const rt = runtimes.get(topicId);
  if (rt) rt.lastSentText = "";
}

/** Force a flush now (used by `/snap` and after key/scroll input). */
export function snap(bot: Bot, topicId: number): void {
  void renderAndFlush(bot, topicId);
}

function stopStreamerSync(topicId: number): void {
  const rt = runtimes.get(topicId);
  if (!rt) return;
  clearInterval(rt.flushTimer);
  runtimes.delete(topicId);
}

export async function stopStreamer(topicId: number): Promise<void> {
  stopStreamerSync(topicId);
}

/** Clean shutdown — used from the server SIGTERM/SIGINT handler. */
export function stopAllStreamers(): void {
  for (const rt of runtimes.values()) clearInterval(rt.flushTimer);
  runtimes.clear();
}

/** Restart streamers for every persisted topic — called on bot startup. */
export function resumePersistedStreamers(bot: Bot): void {
  for (const t of listTopics()) startStreamer(bot, t.topicId);
}
