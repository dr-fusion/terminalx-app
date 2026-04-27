import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { Bot } from "grammy";
import { watch, FSWatcher } from "chokidar";
import { escapeMarkdownV2 } from "./render";

interface AssistantEntry {
  type: "assistant";
  message?: { content?: Array<{ type: string; text?: string; name?: string; input?: unknown }> };
}

interface ThinkingEntry {
  type: "thinking";
  message?: { content?: Array<{ type: string; text?: string }> };
}

interface ToolResultEntry {
  type: "tool_result";
  message?: { content?: Array<{ type: string; text?: string }> };
}

type TranscriptEntry = AssistantEntry | ThinkingEntry | ToolResultEntry | { type: string };

const watchers = new Map<number, { watcher: FSWatcher; offset: number; jsonl: string }>();

/**
 * Per-topic minimum-spacing send queue. Telegram allows ~1 message/sec to
 * a chat (groups stricter on bursts). We spread messages out + respect
 * 429 retry-after.
 */
const sendQueues = new Map<number, Promise<void>>();
const cooldownUntil = new Map<number, number>();

const MIN_GAP_MS = 1100;

async function enqueueSend(
  bot: Bot,
  chatId: number,
  topicId: number,
  text: string,
  parseMode: "MarkdownV2" | undefined
): Promise<void> {
  const prev = sendQueues.get(topicId) ?? Promise.resolve();
  const next = prev.then(async () => {
    const cool = cooldownUntil.get(topicId) ?? 0;
    const waitMs = Math.max(0, cool - Date.now());
    if (waitMs > 0) await sleep(waitMs);
    try {
      await bot.api.sendMessage(chatId, text, {
        message_thread_id: topicId,
        parse_mode: parseMode,
      });
      await sleep(MIN_GAP_MS);
    } catch (err) {
      const e = err as { error_code?: number; parameters?: { retry_after?: number } };
      if (e.error_code === 429) {
        const retry = e.parameters?.retry_after ?? 30;
        cooldownUntil.set(topicId, Date.now() + (retry + 1) * 1000);
        // Drop this message rather than queue forever — the user can /snap
        // or wait for fresh entries.
        return;
      }
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[telegram/claude] send failed:", msg);
    }
  });
  sendQueues.set(topicId, next);
  return next;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const PROJECTS_DIR = path.join(os.homedir(), ".claude", "projects");

/** Find the most recently modified JSONL anywhere under ~/.claude/projects/. */
function findLatestJsonl(): string | null {
  if (!fs.existsSync(PROJECTS_DIR)) return null;
  let latest: { p: string; mtime: number } | null = null;
  for (const dir of fs.readdirSync(PROJECTS_DIR)) {
    const full = path.join(PROJECTS_DIR, dir);
    let stat: fs.Stats;
    try {
      stat = fs.statSync(full);
    } catch {
      continue;
    }
    if (!stat.isDirectory()) continue;
    for (const name of fs.readdirSync(full)) {
      if (!name.endsWith(".jsonl")) continue;
      const file = path.join(full, name);
      try {
        const fstat = fs.statSync(file);
        if (!latest || fstat.mtimeMs > latest.mtime) {
          latest = { p: file, mtime: fstat.mtimeMs };
        }
      } catch {
        // skip
      }
    }
  }
  return latest?.p ?? null;
}

function renderEntry(entry: TranscriptEntry): string | null {
  // chat mode = "Claude's reply only" — skip tool_use, tool_result, and
  // thinking blocks. The user can /view screen or look at the web UI for
  // the full play-by-play.
  if (entry.type === "assistant") {
    const e = entry as AssistantEntry;
    const parts = e.message?.content ?? [];
    const text = parts
      .filter((p) => p.type === "text" && p.text)
      .map((p) => escapeMarkdownV2(p.text!))
      .join("\n\n");
    return text || null;
  }
  return null;
}

/**
 * Tail a JSONL transcript and forward each new entry as a topic message.
 * For v1 we use the most-recently-modified JSONL globally — works for the
 * common case of one active claude session.
 *
 * If `initialOffset` is omitted (or 0), we start at end-of-file so we
 * don't replay tens of thousands of historical entries on first attach.
 * Caller can pass a known offset (from persisted state) to resume.
 */
export function startClaudeTranscript(
  bot: Bot,
  chatId: number,
  topicId: number,
  initialOffset?: number
): { stop: () => void; jsonl: string } | null {
  const jsonl = findLatestJsonl();
  if (!jsonl) return null;

  let offset: number;
  if (initialOffset && initialOffset > 0) {
    offset = initialOffset;
  } else {
    // Start at EOF — only forward entries written from now on.
    try {
      offset = fs.statSync(jsonl).size;
    } catch {
      offset = 0;
    }
  }
  const flush = async () => {
    try {
      const stat = fs.statSync(jsonl);
      if (stat.size < offset) {
        offset = 0; // file was rotated/truncated
      }
      if (stat.size === offset) return;
      const fd = fs.openSync(jsonl, "r");
      const buf = Buffer.alloc(stat.size - offset);
      fs.readSync(fd, buf, 0, buf.length, offset);
      fs.closeSync(fd);
      offset = stat.size;
      const lines = buf.toString("utf-8").split("\n").filter(Boolean);
      for (const line of lines) {
        let entry: TranscriptEntry;
        try {
          entry = JSON.parse(line) as TranscriptEntry;
        } catch {
          continue;
        }
        const md = renderEntry(entry);
        if (!md) continue;
        await enqueueSend(bot, chatId, topicId, md, "MarkdownV2");
      }
    } catch (err) {
      console.error("[telegram/claude] flush failed", err);
    }
  };

  const watcher = watch(jsonl, { ignoreInitial: true });
  watcher.on("change", () => void flush());
  watcher.on("add", () => void flush());

  watchers.set(topicId, { watcher, offset, jsonl });
  // First flush picks up any tail since the persisted offset.
  void flush();
  return {
    jsonl,
    stop: () => {
      void watcher.close();
      watchers.delete(topicId);
    },
  };
}

export function stopClaudeTranscript(topicId: number): void {
  const w = watchers.get(topicId);
  if (!w) return;
  void w.watcher.close();
  watchers.delete(topicId);
}

/** Idempotent — start the watcher only if one isn't already running. */
export function isClaudeTranscriptRunning(topicId: number): boolean {
  return watchers.has(topicId);
}

export function stopAllClaudeTranscripts(): void {
  for (const w of watchers.values()) void w.watcher.close();
  watchers.clear();
}
