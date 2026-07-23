"use client";

import { useCallback, useEffect, useSyncExternalStore } from "react";

// Issue #4: SessionKind is now the open harness-registry id set, sourced from a
// single shared (client-safe) place instead of being redeclared here. Both the
// server (ai-sessions.ts) and this client hook route through the registry so
// the type can never drift.
export type SessionKind = string;
export type TelegramViewMode = "chat" | "screen" | "off";

export interface TmuxSession {
  name: string;
  windows: number;
  attached: boolean;
  created: string;
  lastActivity?: string;
  activePath?: string;
  cwd?: string;
  worktree?: {
    repoRoot: string;
    path: string;
    branch: string;
  };
  kind?: SessionKind;
  managed?: boolean;
  telegram?: {
    topicId: number;
    viewMode: TelegramViewMode;
    endedAtMs?: number;
  } | null;
}

export interface CreateSessionOptions {
  dangerouslySkipPermissions?: boolean;
  cwd?: string;
  worktree?: {
    create: boolean;
    branch?: string;
    /** Repo-root-relative paths to symlink into the new worktree (heavy dirs). */
    symlinkPaths?: string[];
  };
  /** Workspace config (feature #5): skip auto-running the setup script on create. */
  skipSetup?: boolean;
}

interface UseSessionsReturn {
  sessions: TmuxSession[];
  /** Referentially stable until the ordered set of live session names changes. */
  sessionNames: string[];
  isLoading: boolean;
  error: string | null;
  hasLoadedSuccessfully: boolean;
  /** Changes only when session membership or worktree association changes. */
  membershipVersion: number;
  createSession: (
    name?: string,
    kind?: SessionKind,
    options?: CreateSessionOptions
  ) => Promise<TmuxSession | null>;
  killSession: (name: string) => Promise<boolean>;
  setTelegramViewMode: (sessionName: string, viewMode: TelegramViewMode) => Promise<boolean>;
  refresh: () => Promise<void>;
}

interface SessionsSnapshot {
  sessions: TmuxSession[];
  sessionNames: string[];
  isLoading: boolean;
  error: string | null;
  hasLoadedSuccessfully: boolean;
  membershipVersion: number;
  membershipFingerprint: string;
}

const SERVER_SNAPSHOT: SessionsSnapshot = {
  sessions: [],
  sessionNames: [],
  isLoading: true,
  error: null,
  hasLoadedSuccessfully: false,
  membershipVersion: 0,
  membershipFingerprint: "",
};

let snapshot: SessionsSnapshot = SERVER_SNAPSHOT;
let latestRequest = 0;
let inFlight: Promise<void> | null = null;
let listeningForSessionEvents = false;
const subscribers = new Set<() => void>();

function sessionMembershipFingerprint(sessions: TmuxSession[]): string {
  return sessions
    .map((session) =>
      [
        session.name,
        session.worktree?.repoRoot ?? "",
        session.worktree?.path ?? "",
        session.worktree?.branch ?? "",
      ].join("\u0000")
    )
    .sort()
    .join("\u0001");
}

function publish(next: SessionsSnapshot): void {
  snapshot = next;
  for (const subscriber of subscribers) subscriber();
}

function publishSessionList(
  sessions: TmuxSession[],
  overrides: Partial<Pick<SessionsSnapshot, "isLoading" | "error" | "hasLoadedSuccessfully">> = {}
): void {
  const membershipFingerprint = sessionMembershipFingerprint(sessions);
  const nextSessionNames = sessions.map((session) => session.name);
  const sessionNames =
    nextSessionNames.length === snapshot.sessionNames.length &&
    nextSessionNames.every((name, index) => name === snapshot.sessionNames[index])
      ? snapshot.sessionNames
      : nextSessionNames;
  publish({
    ...snapshot,
    ...overrides,
    sessions,
    sessionNames,
    membershipVersion:
      membershipFingerprint === snapshot.membershipFingerprint
        ? snapshot.membershipVersion
        : snapshot.membershipVersion + 1,
    membershipFingerprint,
  });
}

function setSessionError(message: string): void {
  // A request that started before this mutation failed must not immediately
  // erase the actionable mutation error when it resolves.
  latestRequest += 1;
  publish({ ...snapshot, isLoading: false, error: message });
}

async function loadSessions(force = false): Promise<void> {
  if (!force && inFlight) return inFlight;

  const requestId = ++latestRequest;
  publish({ ...snapshot, isLoading: true, error: null });

  const request = (async () => {
    try {
      const res = await fetch("/api/sessions");
      if (!res.ok) throw new Error(`Failed to fetch sessions: ${res.status}`);
      const data = await res.json();
      const sessions = (data.sessions ?? data) as TmuxSession[];

      // A forced post-mutation request supersedes any older request that was
      // already in flight, so stale pre-create/pre-delete data cannot win.
      if (requestId !== latestRequest) return;

      publishSessionList(sessions, {
        isLoading: false,
        error: null,
        hasLoadedSuccessfully: true,
      });
    } catch (err) {
      if (requestId !== latestRequest) return;
      publish({
        ...snapshot,
        isLoading: false,
        error: err instanceof Error ? err.message : "Failed to fetch sessions",
      });
    }
  })();

  inFlight = request;
  try {
    await request;
  } finally {
    if (inFlight === request) inFlight = null;
  }
}

/** Force an authoritative request that starts after the caller's mutation. */
export async function refreshSessionStore(): Promise<void> {
  await loadSessions(true);
}

/** Apply a confirmed server-side bulk delete before its revalidation completes. */
export function removeSessionsFromStore(sessionNames: Iterable<string>): void {
  const removed = new Set(sessionNames);
  if (removed.size === 0) return;
  publishSessionList(
    snapshot.sessions.filter((session) => !removed.has(session.name)),
    { error: null }
  );
}

function onSessionEnded(): void {
  void refreshSessionStore();
}

function onWindowFocus(): void {
  void loadSessions();
}

function onVisibilityChange(): void {
  if (document.visibilityState === "visible") void loadSessions();
}

function subscribe(subscriber: () => void): () => void {
  subscribers.add(subscriber);
  if (!listeningForSessionEvents && typeof window !== "undefined") {
    window.addEventListener("terminalx:session-ended", onSessionEnded);
    window.addEventListener("focus", onWindowFocus);
    document.addEventListener("visibilitychange", onVisibilityChange);
    listeningForSessionEvents = true;
  }

  return () => {
    subscribers.delete(subscriber);
    if (subscribers.size === 0 && listeningForSessionEvents && typeof window !== "undefined") {
      window.removeEventListener("terminalx:session-ended", onSessionEnded);
      window.removeEventListener("focus", onWindowFocus);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      listeningForSessionEvents = false;
    }
  };
}

function getSnapshot(): SessionsSnapshot {
  return snapshot;
}

function getServerSnapshot(): SessionsSnapshot {
  return SERVER_SNAPSHOT;
}

export function useSessions(): UseSessionsReturn {
  const current = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  useEffect(() => {
    void loadSessions();
  }, []);

  const createSession = useCallback(
    async (
      name?: string,
      kind: SessionKind = "bash",
      options: CreateSessionOptions = {}
    ): Promise<TmuxSession | null> => {
      publish({ ...snapshot, error: null });
      try {
        const res = await fetch("/api/sessions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name,
            kind,
            dangerouslySkipPermissions: options.dangerouslySkipPermissions,
            cwd: options.cwd,
            worktree: options.worktree,
            skipSetup: options.skipSetup,
          }),
        });
        if (!res.ok) {
          const j = await res.json().catch(() => null);
          throw new Error(j?.error ?? `Failed to create session: ${res.status}`);
        }
        const result = await res.json();
        const session: TmuxSession = {
          name: result.name,
          windows: 1,
          attached: false,
          created: new Date().toISOString(),
          cwd: result.cwd,
          worktree: result.worktree,
          kind: result.kind,
          managed: true,
          telegram: result.telegram
            ? {
                topicId: result.telegram.topicId,
                viewMode: result.telegram.viewMode as TelegramViewMode,
              }
            : null,
        };
        publishSessionList(
          [...snapshot.sessions.filter((existing) => existing.name !== session.name), session],
          { error: null }
        );
        await refreshSessionStore();
        return session;
      } catch (err) {
        setSessionError(err instanceof Error ? err.message : "Failed to create session");
        return null;
      }
    },
    []
  );

  const killSession = useCallback(async (name: string): Promise<boolean> => {
    try {
      const res = await fetch(`/api/sessions/${encodeURIComponent(name)}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error(`Failed to kill session: ${res.status}`);
      publishSessionList(
        snapshot.sessions.filter((session) => session.name !== name),
        { error: null }
      );
      await refreshSessionStore();
      return true;
    } catch (err) {
      setSessionError(err instanceof Error ? err.message : "Failed to kill session");
      return false;
    }
  }, []);

  const setTelegramViewMode = useCallback(
    async (sessionName: string, viewMode: TelegramViewMode): Promise<boolean> => {
      try {
        const res = await fetch("/api/telegram/topics", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sessionName, viewMode }),
        });
        if (!res.ok) {
          const j = await res.json().catch(() => null);
          throw new Error(j?.error ?? `Failed to update Telegram topic: ${res.status}`);
        }
        await refreshSessionStore();
        return true;
      } catch (err) {
        setSessionError(err instanceof Error ? err.message : "Failed to update Telegram topic");
        return false;
      }
    },
    []
  );

  return {
    sessions: current.sessions,
    sessionNames: current.sessionNames,
    isLoading: current.isLoading,
    error: current.error,
    hasLoadedSuccessfully: current.hasLoadedSuccessfully,
    membershipVersion: current.membershipVersion,
    createSession,
    killSession,
    setTelegramViewMode,
    refresh: refreshSessionStore,
  };
}
