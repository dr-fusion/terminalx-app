import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { createHash } from "crypto";
import type { Bot } from "grammy";
import { watch, FSWatcher } from "chokidar";
import { markdownToTelegramV2, splitForTelegram } from "./render";
import { getTopic, listTopics, patchTopic, type TelegramSentMessageHash } from "./state";
import { sendReferencedAttachments } from "./attachments";
import { withTelegramMessageAuditSource } from "./message-audit";

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
  transcriptSessionId?: string;
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
const SENT_HASH_LIMIT = 200;

const watchers = new Map<number, WatcherRecord>();
const sendQueues = new Map<number, Promise<boolean>>();
const cooldownUntil = new Map<number, number>();
const lastSendAt = new Map<number, number>();
const inFlightHashes = new Map<number, Set<string>>();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function messageHash(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

function topicHasSentHash(topicId: number, hash: string): boolean {
  if (inFlightHashes.get(topicId)?.has(hash)) return true;
  return (getTopic(topicId)?.telegramSentMessageHashes ?? []).some((entry) => entry.hash === hash);
}

function markHashInFlight(topicId: number, hash: string): void {
  let hashes = inFlightHashes.get(topicId);
  if (!hashes) {
    hashes = new Set();
    inFlightHashes.set(topicId, hashes);
  }
  hashes.add(hash);
}

function unmarkHashInFlight(topicId: number, hash: string): void {
  const hashes = inFlightHashes.get(topicId);
  if (!hashes) return;
  hashes.delete(hash);
  if (hashes.size === 0) inFlightHashes.delete(topicId);
}

function nextSentHashes(topicId: number, hash: string): TelegramSentMessageHash[] {
  const prior = getTopic(topicId)?.telegramSentMessageHashes ?? [];
  const filtered = prior.filter((entry) => entry.hash !== hash);
  return [...filtered, { hash, atMs: Date.now() }].slice(-SENT_HASH_LIMIT);
}

async function enqueueSend(
  bot: Bot,
  chatId: number,
  topicId: number,
  raw: string,
  baseDir?: string,
  sourceRef?: string,
  transcriptPath?: string,
  sessionId?: string,
  sessionCreatedAtMs?: number,
  transcriptSessionId?: string
): Promise<boolean> {
  return withTelegramMessageAuditSource(
    {
      source: "codex-transcript",
      sourceRef,
      sessionId,
      sessionCreatedAtMs,
      expectedChatId: chatId,
      expectedTopicId: topicId,
      transcriptSessionId,
      transcriptPath,
    },
    async () => {
      const prev = sendQueues.get(topicId) ?? Promise.resolve(true);
      const next = prev
        .catch(() => false)
        .then(async () => {
          const send = async (text: string, parseMode: "MarkdownV2" | undefined) => {
            const cool = cooldownUntil.get(topicId) ?? 0;
            const nextAllowed = Math.max(cool, (lastSendAt.get(topicId) ?? 0) + MIN_GAP_MS);
            const waitMs = Math.max(0, nextAllowed - Date.now());
            if (waitMs > 0) await sleep(waitMs);
            await bot.api.sendMessage(chatId, text, {
              message_thread_id: topicId,
              parse_mode: parseMode,
            });
            lastSendAt.set(topicId, Date.now());
          };
          // Formatted first; if Telegram rejects the entities (a converter gap),
          // fall back to the raw text — losing styling is fine, losing the
          // message is not.
          try {
            for (const chunk of splitForTelegram(markdownToTelegramV2(raw), 3900)) {
              await send(chunk, "MarkdownV2");
            }
            await sendReferencedAttachments(bot, chatId, topicId, raw, { baseDir });
            return true;
          } catch (err) {
            const e = err as { error_code?: number; parameters?: { retry_after?: number } };
            if (e.error_code === 429) {
              const retry = e.parameters?.retry_after ?? 30;
              cooldownUntil.set(topicId, Date.now() + (retry + 1) * 1000);
              return false;
            }
            const msg = err instanceof Error ? err.message : String(err);
            console.error("[telegram/codex] formatted send failed, retrying plain:", msg);
          }
          try {
            for (const chunk of chunkText(raw, 3900)) {
              await send(chunk, undefined);
            }
            await sendReferencedAttachments(bot, chatId, topicId, raw, { baseDir });
            return true;
          } catch (err) {
            const e = err as { error_code?: number; parameters?: { retry_after?: number } };
            if (e.error_code === 429) {
              const retry = e.parameters?.retry_after ?? 30;
              cooldownUntil.set(topicId, Date.now() + (retry + 1) * 1000);
              return false;
            }
            const msg = err instanceof Error ? err.message : String(err);
            console.error("[telegram/codex] send failed:", msg);
            return false;
          }
        });
      sendQueues.set(topicId, next);
      return next;
    }
  );
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

/**
 * JSONLs this topic must never tail: ones watched in-memory by another
 * topic AND ones persisted as another topic's binding on disk. The
 * in-memory set alone races with the boot resume loop — a topic resolving
 * fresh could grab a sibling topic's file before its watcher registers.
 */
function excludedJsonls(skipTopicId?: number): Set<string> {
  const set = claimedJsonls(skipTopicId);
  for (const t of listTopics()) {
    if (t.topicId === skipTopicId) continue;
    if (t.jsonlPath) set.add(t.jsonlPath);
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

function readMeta(
  jsonl: string
): Pick<JsonlCandidate, "cwd" | "sessionStartedMs" | "transcriptSessionId"> {
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
        transcriptSessionId: meta?.id,
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

function resolveJsonlBySessionStart(opts: {
  cwd?: string;
  sessionStartedMs?: number;
  exclude: Set<string>;
}): JsonlMatch | null {
  if (typeof opts.sessionStartedMs !== "number") return null;
  const lowerBound = opts.sessionStartedMs - 30_000;
  const upperBound = opts.sessionStartedMs + 5 * 60_000;
  const candidates = listCodexJsonls(opts.cwd)
    .filter((candidate) => !opts.exclude.has(candidate.path))
    .filter((candidate) => {
      const started = candidate.sessionStartedMs ?? candidate.ctimeMs;
      return started >= lowerBound && started <= upperBound && candidate.mtimeMs >= lowerBound;
    })
    .sort((a, b) => {
      const aStarted = a.sessionStartedMs ?? a.ctimeMs;
      const bStarted = b.sessionStartedMs ?? b.ctimeMs;
      const startDelta =
        Math.abs(aStarted - opts.sessionStartedMs!) - Math.abs(bStarted - opts.sessionStartedMs!);
      if (startDelta !== 0) return startDelta;
      return b.mtimeMs - a.mtimeMs;
    });

  if (candidates.length === 0) return null;
  const best = candidates[0]!;
  const second = candidates[1];
  if (second) {
    const bestStarted = best.sessionStartedMs ?? best.ctimeMs;
    const secondStarted = second.sessionStartedMs ?? second.ctimeMs;
    const bestDistance = Math.abs(bestStarted - opts.sessionStartedMs);
    const secondDistance = Math.abs(secondStarted - opts.sessionStartedMs);
    if (secondDistance - bestDistance < 5000) return null;
  }

  return { path: best.path, offset: 0 };
}

export function findCodexJsonlForSession(opts: {
  cwd?: string;
  sinceMs: number;
  exclude: Set<string>;
  promptText: string;
  sessionStartedMs?: number;
}): string | null {
  return resolveJsonlForSession(opts)?.path ?? resolveJsonlBySessionStart(opts)?.path ?? null;
}

function renderEntry(entry: CodexEntry): string | null {
  if (entry.type === "event_msg") {
    const phase = (entry as EventMessageEntry).payload?.phase;
    if (phase && phase !== "final_answer") return null;
  }
  const message = eventMessage(entry, "agent_message");
  if (!message) return null;
  return message.trim() || null;
}

export interface StartCodexTranscriptOpts {
  /** TerminalX/tmux session that owns this transcript. */
  sessionId?: string;
  /** Creation time distinguishes reused tmux session names. */
  sessionCreatedAtMs?: number;
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
): { stop: () => void; jsonl: string; transcriptSessionId?: string } | null {
  if (watchers.has(topicId)) return null;

  let match: JsonlMatch | null = null;
  if (opts.cwd && typeof opts.sinceMs === "number" && opts.promptText) {
    match = resolveJsonlForSession({
      cwd: opts.cwd,
      sinceMs: opts.sinceMs,
      promptText: opts.promptText,
      sessionStartedMs: opts.sessionStartedMs,
      exclude: excludedJsonls(topicId),
    });
  }
  if (!match && opts.cwd && typeof opts.sessionStartedMs === "number") {
    match = resolveJsonlBySessionStart({
      cwd: opts.cwd,
      sessionStartedMs: opts.sessionStartedMs,
      exclude: excludedJsonls(topicId),
    });
  }
  if (!match && opts.persistedJsonl) {
    if (fs.existsSync(opts.persistedJsonl) && !excludedJsonls(topicId).has(opts.persistedJsonl)) {
      match = { path: opts.persistedJsonl };
    }
  }
  if (!match) return null;

  const jsonl = match.path;
  const transcriptSessionId = readMeta(jsonl).transcriptSessionId;
  let offset: number;
  if (typeof opts.initialOffset === "number" && opts.initialOffset >= 0) {
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
  let initialSize = offset;
  try {
    initialSize = fs.statSync(jsonl).size;
  } catch {
    initialSize = offset;
  }
  void patchTopic(topicId, {
    jsonlPath: jsonl,
    jsonlOffset: offset,
    telegramDelivery: {
      status: initialSize > offset ? "pending" : "sent",
      jsonlPath: jsonl,
      jsonlOffset: offset,
      updatedAtMs: Date.now(),
    },
  });

  const persistOffset = (nextOffset: number) => {
    offset = nextOffset;
    const record = watchers.get(topicId);
    if (record) record.offset = offset;
    void patchTopic(topicId, {
      jsonlPath: jsonl,
      jsonlOffset: offset,
      telegramDelivery: {
        status: "sent",
        jsonlPath: jsonl,
        jsonlOffset: offset,
        updatedAtMs: Date.now(),
      },
    });
  };

  const persistSent = (nextOffset: number, hash: string) => {
    offset = nextOffset;
    const record = watchers.get(topicId);
    if (record) record.offset = offset;
    void patchTopic(topicId, {
      jsonlPath: jsonl,
      jsonlOffset: offset,
      telegramSentMessageHashes: nextSentHashes(topicId, hash),
      telegramDelivery: {
        status: "sent",
        jsonlPath: jsonl,
        jsonlOffset: offset,
        updatedAtMs: Date.now(),
      },
    });
  };

  const persistFailure = (nextOffset: number) => {
    void patchTopic(topicId, {
      jsonlPath: jsonl,
      jsonlOffset: offset,
      telegramDelivery: {
        status: "failed",
        jsonlPath: jsonl,
        jsonlOffset: offset,
        nextJsonlOffset: nextOffset,
        error: "telegram_send_failed",
        updatedAtMs: Date.now(),
      },
    });
  };

  const flush = async () => {
    try {
      const stat = fs.statSync(jsonl);
      if (stat.size < offset) persistOffset(0);
      if (stat.size === offset) return;
      const startOffset = offset;
      const fd = fs.openSync(jsonl, "r");
      const buf = Buffer.alloc(stat.size - offset);
      fs.readSync(fd, buf, 0, buf.length, offset);
      fs.closeSync(fd);
      let lineOffset = startOffset;
      const rawLines = buf.toString("utf-8").split("\n");
      for (const line of rawLines) {
        const sourceRef = `${jsonl}:${lineOffset}`;
        const nextOffset = lineOffset + Buffer.byteLength(line + "\n");
        lineOffset = nextOffset;
        if (!line) continue;
        let entry: CodexEntry;
        try {
          entry = JSON.parse(line) as CodexEntry;
        } catch {
          continue;
        }
        const text = renderEntry(entry);
        if (!text) {
          persistOffset(nextOffset);
          continue;
        }
        const hash = messageHash(text);
        if (topicHasSentHash(topicId, hash)) {
          persistOffset(nextOffset);
          continue;
        }
        markHashInFlight(topicId, hash);
        const sent = await enqueueSend(
          bot,
          chatId,
          topicId,
          text,
          opts.cwd,
          sourceRef,
          jsonl,
          opts.sessionId,
          opts.sessionCreatedAtMs,
          transcriptSessionId
        );
        if (!sent) {
          unmarkHashInFlight(topicId, hash);
          persistFailure(nextOffset);
          break;
        }
        persistSent(nextOffset, hash);
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
    transcriptSessionId,
    stop: () => {
      void watcher.close();
      watchers.delete(topicId);
      inFlightHashes.delete(topicId);
    },
  };
}

export function stopCodexTranscript(topicId: number): void {
  const w = watchers.get(topicId);
  if (!w) return;
  void w.watcher.close();
  watchers.delete(topicId);
  inFlightHashes.delete(topicId);
}

export function isCodexTranscriptRunning(topicId: number): boolean {
  return watchers.has(topicId);
}

export function stopAllCodexTranscripts(): void {
  for (const w of watchers.values()) void w.watcher.close();
  watchers.clear();
  inFlightHashes.clear();
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
