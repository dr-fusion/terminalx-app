"use client";

import { useCallback, useEffect, useState } from "react";

export type SessionKind = "bash" | "claude" | "codex";

export interface TmuxSession {
  name: string;
  windows: number;
  attached: boolean;
  created: string;
  kind?: SessionKind;
}

export interface CreateSessionOptions {
  dangerouslySkipPermissions?: boolean;
}

interface UseSessionsReturn {
  sessions: TmuxSession[];
  isLoading: boolean;
  error: string | null;
  createSession: (
    name?: string,
    kind?: SessionKind,
    options?: CreateSessionOptions
  ) => Promise<TmuxSession | null>;
  killSession: (name: string) => Promise<boolean>;
  refresh: () => Promise<void>;
}

export function useSessions(): UseSessionsReturn {
  const [sessions, setSessions] = useState<TmuxSession[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const res = await fetch("/api/sessions");
      if (!res.ok) throw new Error(`Failed to fetch sessions: ${res.status}`);
      const data = await res.json();
      setSessions(data.sessions ?? data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch sessions");
    } finally {
      setIsLoading(false);
    }
  }, []);

  const createSession = useCallback(
    async (
      name?: string,
      kind: SessionKind = "bash",
      options: CreateSessionOptions = {}
    ): Promise<TmuxSession | null> => {
      try {
        const res = await fetch("/api/sessions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name,
            kind,
            dangerouslySkipPermissions: options.dangerouslySkipPermissions,
          }),
        });
        if (!res.ok) {
          const j = await res.json().catch(() => null);
          throw new Error(
            j?.error ?? `Failed to create session: ${res.status}`
          );
        }
        const session = await res.json();
        await refresh();
        return session;
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to create session"
        );
        return null;
      }
    },
    [refresh]
  );

  const killSession = useCallback(
    async (name: string): Promise<boolean> => {
      try {
        const res = await fetch(`/api/sessions/${encodeURIComponent(name)}`, {
          method: "DELETE",
        });
        if (!res.ok) throw new Error(`Failed to kill session: ${res.status}`);
        await refresh();
        return true;
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to kill session"
        );
        return false;
      }
    },
    [refresh]
  );

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { sessions, isLoading, error, createSession, killSession, refresh };
}
