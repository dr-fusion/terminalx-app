import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { Bot } from "grammy";
import { watch, FSWatcher } from "chokidar";

interface SessionMetaEntry {
  timestamp?: string;
  type: "session_meta";
  payload?: {
    id?: string;
    timestamp?: string;
    cwd?: string;
  };
}

interface EventMessageEntry {
  timestamp?: string;
  type: "event_msg";
  payload?: {
    type?: string;
    message?: string;
    phase?: string | null;
  };
}

type CodexEntry = SessionMetaEntry | EventMessageEntry | { timestamp?: string; type: string };

interface WatcherRecord {
  watcher: FSWatcher;
  offset: number;
  jsonl: string;
}

interface JsonlCandidate {
  path: string;
  ctimeMs: number;
  mtimeMs: number;
  sessionStartedMs?: number;
  cwd?: string;
}

interface JsonlMatch {
  path: string;
  offset?: number;
}

interface PromptMatch {
  timestampMs: number;
  offset: number;
}

const CODEX_SESSIONS_DIR = path.join(os.homedir(), ".codex", "sessions");
const MIN_GAP_MS = 1100;
const MAX_SCAN_BYTES = 4 * 1024 * 1024;

const watchers = new Map<number, WatcherRecord>();
const sendQueues = new Map<number, Promise<void>>();
const cooldownUntil = new Map<number, number>();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function enqueueSend(bot: Bot, chatId: number, topicId: number, text: string): Promise<void> {
  const prev = sendQueues.get(topicId) ?? Promise.resolve();
  const next = prev.then(async () => {
    const cool = cooldownUntil.get(topicId) ?? 0;
    const waitMs = Math.max(0, cool - Date.now());
    if (waitMs > 0) await sleep(waitMs);
    try {
      for (const chunk of chunkText(text, 3900)) {
        await bot.api.sendMessage(chatId, chunk, {
          message_thread_id: topicId,
        });
        await sleep(MIN_GAP_MS);
      }
    } catch (err) {
      const e = err as { error_code?: number; parameters?: { retry_after?: number } };
      if (e.error_code === 429) {
        const retry = e.parameters?.retry_after ?? 30;
        cooldownUntil.set(topicId, Date.now() + (retry + 1) * 1000);
        return;
      }
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[telegram/codex] send failed:", msg);
    }
  });
  sendQueues.set(topicId, next);
  return next;
}

function chunkText(text: string, maxLen: number): string[] {
  const chunks: string[] = [];
  let rest = text.trim();
  while (rest.length > maxLen) {
    const splitAt = Math.max(rest.lastIndexOf("\n", maxLen), rest.lastIndexOf(" ", maxLen));
    const cut = splitAt > maxLen * 0.5 ? splitAt : maxLen;
    chunks.push(rest.slice(0, cut).trim());
    rest = rest.slice(cut).trim();
  }
  if (rest) chunks.push(rest);
  return chunks;
}

function claimedJsonls(skipTopicId?: number): Set<string> {
  const set = new Set<string>();
  for (const [tid, rec] of watchers.entries()) {
    if (tid === skipTopicId) continue;
    set.add(rec.jsonl);
  }
  return set;
}

function normalizePrompt(text: string): string {
  return text.replace(/\r\n/g, "\n").trim();
}

function timestampMs(entry: { timestamp?: string }): number | undefined {
  if (!entry.timestamp) return undefined;
  const ms = Date.parse(entry.timestamp);
  return Number.isFinite(ms) ? ms : undefined;
}

function readMeta(jsonl: string): Pick<JsonlCandidate, "cwd" | "sessionStartedMs"> {
  try {
    const fd = fs.openSync(jsonl, "r");
    const buf = Buffer.alloc(Math.min(fs.statSync(jsonl).size, 64 * 1024));
    fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    for (const line of buf.toString("utf-8").split("\n")) {
      if (!line) continue;
      let entry: CodexEntry;
      try {
        entry = JSON.parse(line) as CodexEntry;
      } catch {
        continue;
      }
      if (entry.type !== "session_meta") continue;
      const meta = (entry as SessionMetaEntry).payload;
      const rawStarted = meta?.timestamp ?? entry.timestamp;
      const started = rawStarted ? Date.parse(rawStarted) : Number.NaN;
      return {
        cwd: meta?.cwd,
        sessionStartedMs: Number.isFinite(started) ? started : undefined,
      };
    }
  } catch {
    /* ignore unreadable files */
  }
  return {};
}

function listJsonlFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const out: string[] = [];
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const p = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(p);
      } else if (entry.isFile() && entry.name.endsWith(".jsonl")) {
        out.push(p);
      }
    }
  }
  return out;
}

function listCodexJsonls(cwd?: string): JsonlCandidate[] {
  const out: JsonlCandidate[] = [];
  for (const p of listJsonlFiles(CODEX_SESSIONS_DIR)) {
    try {
      const stat = fs.statSync(p);
      const meta = readMeta(p);
      if (cwd && meta.cwd !== cwd) continue;
      const ctime = stat.birthtimeMs && stat.birthtimeMs > 0 ? stat.birthtimeMs : stat.ctimeMs;
      out.push({
        path: p,
        ctimeMs: ctime,
        mtimeMs: stat.mtimeMs,
        ...meta,
      });
    } catch {
      /* skip unreadable files */
    }
  }
  return out;
}

function eventMessage(
  entry: CodexEntry,
  expectedType: "user_message" | "agent_message"
): string | null {
  if (entry.type !== "event_msg") return null;
  const payload = (entry as EventMessageEntry).payload;
  if (payload?.type !== expectedType) return null;
  return typeof payload.message === "string" ? payload.message : null;
}

function findPromptMatch(jsonl: string, promptText: string, sinceMs: number): PromptMatch | null {
  const expected = normalizePrompt(promptText);
  if (!expected) return null;

  try {
    const stat = fs.statSync(jsonl);
    const scanBytes = Math.min(stat.size, MAX_SCAN_BYTES);
    const start = stat.size - scanBytes;
    const fd = fs.openSync(jsonl, "r");
    const buf = Buffer.alloc(scanBytes);
    fs.readSync(fd, buf, 0, scanBytes, start);
    fs.closeSync(fd);

    let offset = start;
    let best: PromptMatch | null = null;
    for (const line of buf.toString("utf-8").split("\n")) {
      const lineBytes = Buffer.byteLength(line + "\n");
      const nextOffset = offset + lineBytes;
      offset = nextOffset;
      if (!line) continue;

      let entry: CodexEntry;
      try {
        entry = JSON.parse(line) as CodexEntry;
      } catch {
        continue;
      }

      const text = eventMessage(entry, "user_message");
      if (text === null || normalizePrompt(text) !== expected) continue;

      const ms = timestampMs(entry) ?? stat.mtimeMs;
      if (ms < sinceMs - 30_000 || ms > sinceMs + 120_000) continue;
      const match = { timestampMs: ms, offset: nextOffset };
      if (!best || Math.abs(match.timestampMs - sinceMs) < Math.abs(best.timestampMs - sinceMs)) {
        best = match;
      }
    }
    return best;
  } catch {
    return null;
  }
}

function resolveJsonlForSession(opts: {
  cwd?: string;
  sinceMs: number;
  exclude: Set<string>;
  promptText: string;
  sessionStartedMs?: number;
}): JsonlMatch | null {
  const candidates = listCodexJsonls(opts.cwd).filter((c) => !opts.exclude.has(c.path));
  if (candidates.length === 0) return null;

  const promptMatches = candidates
    .map((candidate) => {
      const match = findPromptMatch(candidate.path, opts.promptText, opts.sinceMs);
      return match ? { candidate, match } : null;
    })
    .filter((match): match is { candidate: JsonlCandidate; match: PromptMatch } => !!match)
    .sort((a, b) => {
      const promptDelta =
        Math.abs(a.match.timestampMs - opts.sinceMs) - Math.abs(b.match.timestampMs - opts.sinceMs);
      if (promptDelta !== 0) return promptDelta;
      if (typeof opts.sessionStartedMs === "number") {
        const aStarted = a.candidate.sessionStartedMs ?? a.candidate.ctimeMs;
        const bStarted = b.candidate.sessionStartedMs ?? b.candidate.ctimeMs;
        return (
          Math.abs(aStarted - opts.sessionStartedMs) - Math.abs(bStarted - opts.sessionStartedMs)
        );
      }
      return a.candidate.ctimeMs - b.candidate.ctimeMs;
    });

  if (promptMatches.length === 0) return null;

  const best = promptMatches[0]!;
  const second = promptMatches[1];
  if (second) {
    const bestPromptDistance = Math.abs(best.match.timestampMs - opts.sinceMs);
    const secondPromptDistance = Math.abs(second.match.timestampMs - opts.sinceMs);
    const bestStarted = best.candidate.sessionStartedMs ?? best.candidate.ctimeMs;
    const secondStarted = second.candidate.sessionStartedMs ?? second.candidate.ctimeMs;
    const bestStartDistance =
      typeof opts.sessionStartedMs === "number"
        ? Math.abs(bestStarted - opts.sessionStartedMs)
        : Number.POSITIVE_INFINITY;
    const secondStartDistance =
      typeof opts.sessionStartedMs === "number"
        ? Math.abs(secondStarted - opts.sessionStartedMs)
        : Number.POSITIVE_INFINITY;

    // If prompt timing and session-start timing are both too close, refuse
    // to bind. Silence is safer than sending another topic's Codex answer.
    if (
      secondPromptDistance - bestPromptDistance < 1500 &&
      secondStartDistance - bestStartDistance < 5000
    ) {
      return null;
    }
  }

  return { path: best.candidate.path, offset: best.match.offset };
}

export function findCodexJsonlForSession(opts: {
  cwd?: string;
  sinceMs: number;
  exclude: Set<string>;
  promptText: string;
  sessionStartedMs?: number;
}): string | null {
  return resolveJsonlForSession(opts)?.path ?? null;
}

function renderEntry(entry: CodexEntry): string | null {
  const message = eventMessage(entry, "agent_message");
  if (!message) return null;
  return message.trim() || null;
}

export interface StartCodexTranscriptOpts {
  cwd?: string;
  sinceMs?: number;
  promptText?: string;
  sessionStartedMs?: number;
  persistedJsonl?: string;
  initialOffset?: number;
}

export function startCodexTranscript(
  bot: Bot,
  chatId: number,
  topicId: number,
  opts: StartCodexTranscriptOpts = {}
): { stop: () => void; jsonl: string } | null {
  if (watchers.has(topicId)) return null;

  let match: JsonlMatch | null = null;
  if (opts.cwd && typeof opts.sinceMs === "number" && opts.promptText) {
    match = resolveJsonlForSession({
      cwd: opts.cwd,
      sinceMs: opts.sinceMs,
      promptText: opts.promptText,
      sessionStartedMs: opts.sessionStartedMs,
      exclude: claimedJsonls(topicId),
    });
  }
  if (!match && opts.persistedJsonl) {
    if (fs.existsSync(opts.persistedJsonl) && !claimedJsonls(topicId).has(opts.persistedJsonl)) {
      match = { path: opts.persistedJsonl };
    }
  }
  if (!match) return null;

  const jsonl = match.path;
  let offset: number;
  if (opts.initialOffset && opts.initialOffset > 0) {
    offset = opts.initialOffset;
  } else if (typeof match.offset === "number") {
    offset = match.offset;
  } else {
    try {
      offset = fs.statSync(jsonl).size;
    } catch {
      offset = 0;
    }
  }

  const flush = async () => {
    try {
      const stat = fs.statSync(jsonl);
      if (stat.size < offset) offset = 0;
      if (stat.size === offset) return;
      const fd = fs.openSync(jsonl, "r");
      const buf = Buffer.alloc(stat.size - offset);
      fs.readSync(fd, buf, 0, buf.length, offset);
      fs.closeSync(fd);
      offset = stat.size;
      const lines = buf.toString("utf-8").split("\n").filter(Boolean);
      for (const line of lines) {
        let entry: CodexEntry;
        try {
          entry = JSON.parse(line) as CodexEntry;
        } catch {
          continue;
        }
        const text = renderEntry(entry);
        if (!text) continue;
        await enqueueSend(bot, chatId, topicId, text);
      }
    } catch (err) {
      console.error("[telegram/codex] flush failed", err);
    }
  };

  const watcher = watch(jsonl, { ignoreInitial: true });
  watcher.on("change", () => void flush());
  watcher.on("add", () => void flush());

  watchers.set(topicId, { watcher, offset, jsonl });
  void flush();
  return {
    jsonl,
    stop: () => {
      void watcher.close();
      watchers.delete(topicId);
    },
  };
}

export function stopCodexTranscript(topicId: number): void {
  const w = watchers.get(topicId);
  if (!w) return;
  void w.watcher.close();
  watchers.delete(topicId);
}

export function isCodexTranscriptRunning(topicId: number): boolean {
  return watchers.has(topicId);
}

export function stopAllCodexTranscripts(): void {
  for (const w of watchers.values()) void w.watcher.close();
  watchers.clear();
}

export function readLastCodexAssistantText(jsonlPath?: string): string | null {
  const jsonl = jsonlPath && fs.existsSync(jsonlPath) ? jsonlPath : null;
  if (!jsonl) return null;
  try {
    const stat = fs.statSync(jsonl);
    const tailBytes = Math.min(stat.size, 512 * 1024);
    const start = stat.size - tailBytes;
    const fd = fs.openSync(jsonl, "r");
    const buf = Buffer.alloc(tailBytes);
    fs.readSync(fd, buf, 0, tailBytes, start);
    fs.closeSync(fd);
    const lines = buf.toString("utf-8").split("\n").filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const entry = JSON.parse(lines[i]!) as CodexEntry;
        const text = renderEntry(entry);
        if (text) return text;
      } catch {
        /* skip malformed lines */
      }
    }
  } catch {
    /* ignore */
  }
  return null;
}
