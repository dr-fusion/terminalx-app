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

export interface TopicBinding {
  topicId: number;
  sessionName: string;
  /** tmux creation time; together with sessionName this identifies one incarnation. */
  sessionCreatedAtMs?: number;
  kind: SessionKind;
  cwd: string;
  jsonlPath?: string;
  /** Native Claude/Codex transcript session id (not the tmux session name). */
  transcriptSessionId?: string;
  jsonlOffset?: number;
  /** Last Telegram prompt sent to an AI CLI before its transcript was bound. */
  pendingPrompt?: string;
  /** Unix ms when pendingPrompt was sent to tmux. */
  lastPromptAtMs?: number;
  pinnedMsgId?: number;
  /** screen = pinned code-block edits; chat = each new chunk as its own msg. */
  viewMode?: ViewMode;
  /** Unix ms when the backing tmux session ended; topic is kept for cleanup. */
  endedAtMs?: number;
}

/**
 * Build the persisted reset required when tmux reuses a session name for a
 * different process incarnation. Transcript and pinned-message state belongs
 * to the old process and must never be carried across that boundary.
 */
export function topicSessionIncarnationPatch(
  binding: TopicBinding,
  currentSessionCreatedAtMs: number | null | undefined
): { changed: boolean; patch: Partial<TopicBinding> } {
  if (currentSessionCreatedAtMs === null || currentSessionCreatedAtMs === undefined) {
    return { changed: false, patch: {} };
  }
  if (
    binding.sessionCreatedAtMs === undefined ||
    binding.sessionCreatedAtMs === currentSessionCreatedAtMs
  ) {
    return {
      changed: false,
      patch: { sessionCreatedAtMs: currentSessionCreatedAtMs },
    };
  }
  return {
    changed: true,
    patch: {
      sessionCreatedAtMs: currentSessionCreatedAtMs,
      jsonlPath: undefined,
      transcriptSessionId: undefined,
      jsonlOffset: undefined,
      pendingPrompt: undefined,
      lastPromptAtMs: undefined,
      pinnedMsgId: undefined,
      endedAtMs: undefined,
    },
  };
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
