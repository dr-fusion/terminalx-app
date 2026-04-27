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

interface WatcherRecord {
  watcher: FSWatcher;
  offset: number;
  jsonl: string;
}

const watchers = new Map<number, WatcherRecord>();

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

/**
 * Claude Code stores transcripts under
 * `~/.claude/projects/<cwd-with-slashes-as-dashes>/<sessionId>.jsonl`.
 * For `/home/agent/code/foo` the directory is `-home-agent-code-foo`.
 */
function projectDirForCwd(cwd: string): string {
  const transformed = cwd.replace(/[\\/]/g, "-");
  return path.join(PROJECTS_DIR, transformed);
}

interface JsonlCandidate {
  path: string;
  ctimeMs: number;
  mtimeMs: number;
}

function listJsonlIn(dir: string): JsonlCandidate[] {
  if (!fs.existsSync(dir)) return [];
  const out: JsonlCandidate[] = [];
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".jsonl")) continue;
    const p = path.join(dir, name);
    try {
      const s = fs.statSync(p);
      const ctime = s.birthtimeMs && s.birthtimeMs > 0 ? s.birthtimeMs : s.ctimeMs;
      out.push({ path: p, ctimeMs: ctime, mtimeMs: s.mtimeMs });
    } catch {
      /* skip unreadable */
    }
  }
  return out;
}

function claimedJsonls(skipTopicId?: number): Set<string> {
  const set = new Set<string>();
  for (const [tid, rec] of watchers.entries()) {
    if (tid === skipTopicId) continue;
    set.add(rec.jsonl);
  }
  return set;
}

/**
 * Find the JSONL that belongs to a specific tmux session. We narrow to
 * the project directory derived from the session's cwd, exclude JSONLs
 * already claimed by other topics, and pick the one whose ctime is just
 * after `sinceMs` (claude writes the first line within milliseconds of
 * starting). Falls back to most-recent if nothing matches the timestamp
 * window — better than nothing for legacy / pre-existing topics.
 */
function findJsonlForSession(opts: {
  cwd: string;
  sinceMs: number;
  exclude: Set<string>;
}): string | null {
  const { cwd, sinceMs, exclude } = opts;
  const dir = projectDirForCwd(cwd);
  const candidates = listJsonlIn(dir).filter((c) => !exclude.has(c.path));
  if (candidates.length === 0) return null;
  // Allow a few seconds of clock skew between tmux and the file system.
  const grace = 5000;
  const created = candidates
    .filter((c) => c.ctimeMs + grace >= sinceMs)
    .sort((a, b) => a.ctimeMs - b.ctimeMs);
  if (created.length > 0) return created[0]!.path;
  // Fallback: most recently modified — best guess for an older session
  // we attached to without a tmux creation timestamp.
  return candidates.sort((a, b) => b.mtimeMs - a.mtimeMs)[0]!.path;
}

/**
 * Legacy fallback: pick the globally most-recently-modified JSONL across
 * every project directory. Only used by `readLastAssistantText()` when no
 * cwd is supplied — never as a routing decision (which would mix topics).
 */
function findLatestJsonlGlobal(): string | null {
  if (!fs.existsSync(PROJECTS_DIR)) return null;
  let latest: JsonlCandidate | null = null;
  for (const dir of fs.readdirSync(PROJECTS_DIR)) {
    const full = path.join(PROJECTS_DIR, dir);
    let stat: fs.Stats;
    try {
      stat = fs.statSync(full);
    } catch {
      continue;
    }
    if (!stat.isDirectory()) continue;
    for (const c of listJsonlIn(full)) {
      if (!latest || c.mtimeMs > latest.mtimeMs) latest = c;
    }
  }
  return latest?.path ?? null;
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

export interface StartTranscriptOpts {
  /** tmux pane cwd — used to narrow JSONL search to one project dir. */
  cwd?: string;
  /** tmux `session_created` in ms — match the JSONL whose ctime is just after this. */
  sinceMs?: number;
  /** Resume from a previously-stored path (skip rediscovery). */
  persistedJsonl?: string;
  /** Resume byte offset — skip replaying entries we've already sent. */
  initialOffset?: number;
}

/**
 * Tail a JSONL transcript and forward each new entry as a topic message.
 * The JSONL is identified per-session: each topic gets its own file,
 * matched by `cwd + sinceMs`, with already-claimed files excluded so two
 * topics in the same project never tail the same JSONL.
 *
 * Returns null if no candidate JSONL is found yet — callers (the streamer's
 * 5 s flush loop) will retry on the next tick, by which time claude will
 * have written its first line.
 */
export function startClaudeTranscript(
  bot: Bot,
  chatId: number,
  topicId: number,
  opts: StartTranscriptOpts = {}
): { stop: () => void; jsonl: string } | null {
  // If this topic already has a watcher, don't double-start — caller
  // should have stopped it first if they meant to swap.
  if (watchers.has(topicId)) return null;

  let jsonl: string | null = null;
  if (opts.persistedJsonl && fs.existsSync(opts.persistedJsonl)) {
    jsonl = opts.persistedJsonl;
  } else if (opts.cwd && typeof opts.sinceMs === "number") {
    jsonl = findJsonlForSession({
      cwd: opts.cwd,
      sinceMs: opts.sinceMs,
      exclude: claimedJsonls(topicId),
    });
  }
  if (!jsonl) return null;

  let offset: number;
  if (opts.initialOffset && opts.initialOffset > 0) {
    offset = opts.initialOffset;
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
      const stat = fs.statSync(jsonl!);
      if (stat.size < offset) {
        offset = 0; // file was rotated/truncated
      }
      if (stat.size === offset) return;
      const fd = fs.openSync(jsonl!, "r");
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

/**
 * Read a JSONL transcript backwards and return the last assistant text
 * entry, MarkdownV2-escaped. When `jsonlPath` is supplied (the topic's
 * own transcript), reads that; otherwise falls back to the globally
 * most-recently-modified JSONL.
 *
 * Caps the scan at the last 256 KB so we don't read 100 MB to find a
 * quote.
 */
export function readLastAssistantText(jsonlPath?: string): string | null {
  const jsonl = jsonlPath && fs.existsSync(jsonlPath) ? jsonlPath : findLatestJsonlGlobal();
  if (!jsonl) return null;
  try {
    const stat = fs.statSync(jsonl);
    const tailBytes = Math.min(stat.size, 256 * 1024);
    const start = stat.size - tailBytes;
    const fd = fs.openSync(jsonl, "r");
    const buf = Buffer.alloc(tailBytes);
    fs.readSync(fd, buf, 0, tailBytes, start);
    fs.closeSync(fd);
    const lines = buf.toString("utf-8").split("\n").filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const entry = JSON.parse(lines[i]!) as TranscriptEntry;
        const md = renderEntry(entry);
        if (md) return md;
      } catch {
        /* skip non-JSON line */
      }
    }
  } catch {
    /* ignore */
  }
  return null;
}
