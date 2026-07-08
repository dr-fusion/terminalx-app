import * as fs from "fs";
import * as path from "path";
import { ensureSecureDir } from "@/lib/secure-dir";
import type { SessionKind } from "@/lib/ai-sessions";

/**
 * Persistent binding: one Telegram forum topic ↔ one tmux session.
 * Survives server restarts so reattaching after a deploy doesn't lose
 * topic ↔ session mapping.
 */
export type ViewMode = "screen" | "chat" | "off";

export interface TelegramDeliveryState {
  status: "pending" | "sent" | "failed";
  jsonlPath: string;
  /** Last byte offset known to be safe to skip on restart. */
  jsonlOffset: number;
  /** End offset for the line that failed, if status is failed. */
  nextJsonlOffset?: number;
  error?: string;
  updatedAtMs: number;
}

export interface TelegramSentMessageHash {
  hash: string;
  atMs: number;
}

export interface TopicBinding {
  topicId: number;
  sessionName: string;
  kind: SessionKind;
  cwd: string;
  jsonlPath?: string;
  jsonlOffset?: number;
  telegramDelivery?: TelegramDeliveryState;
  /** Bounded dedupe cache for transcript messages already accepted by Telegram. */
  telegramSentMessageHashes?: TelegramSentMessageHash[];
  /** Last Telegram prompt sent to an AI CLI before its transcript was bound. */
  pendingPrompt?: string;
  /** Unix ms when pendingPrompt was sent to tmux. */
  lastPromptAtMs?: number;
  pinnedMsgId?: number;
  /** Unix ms after the one-time TUI hint was posted for this topic. */
  tuiHintedAtMs?: number;
  /** screen = pinned code-block edits; chat = each new chunk as its own msg. */
  viewMode?: ViewMode;
  /** Unix ms when the backing tmux session ended; topic is kept for cleanup. */
  endedAtMs?: number;
}

interface StateFile {
  /** Telegram chat (supergroup) id where the bot lives. */
  forumChatId?: number;
  /** Live topic bindings, keyed by topicId. */
  topics: Record<string, TopicBinding>;
}

const DATA_DIR = process.env.TERMINALX_DATA_DIR
  ? path.resolve(process.env.TERMINALX_DATA_DIR)
  : path.join(process.cwd(), "data");
const STATE_FILE = path.join(DATA_DIR, "telegram-state.json");

let writeLock: Promise<void> = Promise.resolve();
function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = writeLock.then(fn, fn);
  writeLock = next.then(
    () => {},
    () => {}
  );
  return next;
}

let cache: StateFile | null = null;
let cacheMtimeMs = 0;

function emptyState(): StateFile {
  return { topics: {} };
}

function readFromDisk(): StateFile {
  if (!fs.existsSync(STATE_FILE)) return emptyState();
  try {
    const raw = fs.readFileSync(STATE_FILE, "utf-8");
    const parsed = JSON.parse(raw) as Partial<StateFile>;
    return { forumChatId: parsed.forumChatId, topics: parsed.topics ?? {} };
  } catch {
    return emptyState();
  }
}

function currentMtimeMs(): number {
  try {
    return fs.statSync(STATE_FILE).mtimeMs;
  } catch {
    return 0;
  }
}

/**
 * The Telegram bot (custom `tsx server`) and the Next.js API routes run as
 * separate module instances, each with its own `cache`, but they share
 * STATE_FILE on disk. A binding written by one instance must become visible to
 * the other without a restart, so we reload whenever the file's mtime no longer
 * matches what we last read. Writes reload first (inside withLock) so they merge
 * the other instance's changes rather than clobbering them.
 */
function getState(): StateFile {
  const mtime = currentMtimeMs();
  if (!cache || mtime !== cacheMtimeMs) {
    cache = readFromDisk();
    cacheMtimeMs = mtime;
  }
  return cache;
}

function atomicWrite(state: StateFile): void {
  ensureSecureDir(DATA_DIR);
  const tmp = STATE_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { encoding: "utf-8", mode: 0o600 });
  fs.renameSync(tmp, STATE_FILE);
  cache = state;
  cacheMtimeMs = currentMtimeMs();
}

export function listTopics(): TopicBinding[] {
  return Object.values(getState().topics);
}

export function getTopicByName(sessionName: string): TopicBinding | undefined {
  return Object.values(getState().topics).find((t) => t.sessionName === sessionName);
}

export function getTopic(topicId: number): TopicBinding | undefined {
  return getState().topics[String(topicId)];
}

export async function setTopic(binding: TopicBinding): Promise<void> {
  await withLock(async () => {
    const state = getState();
    state.topics[String(binding.topicId)] = binding;
    atomicWrite(state);
  });
}

export async function patchTopic(topicId: number, patch: Partial<TopicBinding>): Promise<void> {
  await withLock(async () => {
    const state = getState();
    const existing = state.topics[String(topicId)];
    if (!existing) return;
    state.topics[String(topicId)] = { ...existing, ...patch };
    atomicWrite(state);
  });
}

export async function deleteTopic(topicId: number): Promise<void> {
  await withLock(async () => {
    const state = getState();
    delete state.topics[String(topicId)];
    atomicWrite(state);
  });
}

export async function setForumChatId(chatId: number): Promise<void> {
  await withLock(async () => {
    const state = getState();
    state.forumChatId = chatId;
    atomicWrite(state);
  });
}

export function getForumChatId(): number | undefined {
  return getState().forumChatId;
}
