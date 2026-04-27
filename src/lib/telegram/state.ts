import * as fs from "fs";
import * as path from "path";
import { ensureSecureDir } from "@/lib/secure-dir";
import type { SessionKind } from "@/lib/ai-sessions";

/**
 * Persistent binding: one Telegram forum topic ↔ one tmux session.
 * Survives server restarts so reattaching after a deploy doesn't lose
 * topic ↔ session mapping.
 */
export type ViewMode = "screen" | "chat";

export interface TopicBinding {
  topicId: number;
  sessionName: string;
  kind: SessionKind;
  cwd: string;
  jsonlPath?: string;
  jsonlOffset?: number;
  /** Last Telegram prompt sent to an AI CLI before its transcript was bound. */
  pendingPrompt?: string;
  /** Unix ms when pendingPrompt was sent to tmux. */
  lastPromptAtMs?: number;
  pinnedMsgId?: number;
  /** screen = pinned code-block edits; chat = each new chunk as its own msg. */
  viewMode?: ViewMode;
}

interface StateFile {
  /** Telegram chat (supergroup) id where the bot lives. */
  forumChatId?: number;
  /** Live topic bindings, keyed by topicId. */
  topics: Record<string, TopicBinding>;
}

const DATA_DIR = path.join(process.cwd(), "data");
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

function getState(): StateFile {
  if (!cache) cache = readFromDisk();
  return cache;
}

function atomicWrite(state: StateFile): void {
  ensureSecureDir(DATA_DIR);
  const tmp = STATE_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { encoding: "utf-8", mode: 0o600 });
  fs.renameSync(tmp, STATE_FILE);
  cache = state;
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
