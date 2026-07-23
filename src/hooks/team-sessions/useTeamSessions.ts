"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  fetchTeamSessionDiscovery,
  fetchTeamSessionInbox,
} from "@/lib/team-sessions/browser-client";
import type { TeamSessionDiscovery, TeamSessionInboxItem } from "@/types/team-session";

export interface UseTeamSessionsResult {
  discovery: TeamSessionDiscovery | null;
  sessions: TeamSessionInboxItem[];
  isLoading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
}

export function useTeamSessions(): UseTeamSessionsResult {
  const [discovery, setDiscovery] = useState<TeamSessionDiscovery | null>(null);
  const [sessions, setSessions] = useState<TeamSessionInboxItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const requestRef = useRef<{ id: number; controller: AbortController } | null>(null);
  const nextRequestIdRef = useRef(0);

  const refresh = useCallback(async (): Promise<void> => {
    requestRef.current?.controller.abort();
    const request = {
      id: nextRequestIdRef.current + 1,
      controller: new AbortController(),
    };
    nextRequestIdRef.current = request.id;
    requestRef.current = request;
    setIsLoading(true);
    setError(null);

    try {
      const [nextDiscovery, nextSessions] = await Promise.all([
        fetchTeamSessionDiscovery({ signal: request.controller.signal }),
        fetchTeamSessionInbox({ signal: request.controller.signal }),
      ]);
      if (request.controller.signal.aborted || requestRef.current?.id !== request.id) return;
      setDiscovery(nextDiscovery);
      setSessions(nextSessions);
    } catch (cause) {
      if (request.controller.signal.aborted || requestRef.current?.id !== request.id) return;
      request.controller.abort();
      setError(asError(cause, "Could not load multiplayer Sessions"));
    } finally {
      if (requestRef.current?.id === request.id) {
        requestRef.current = null;
        setIsLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
    return () => {
      requestRef.current?.controller.abort();
      requestRef.current = null;
    };
  }, [refresh]);

  return { discovery, sessions, isLoading, error, refresh };
}

function asError(cause: unknown, fallback: string): Error {
  return cause instanceof Error ? cause : new Error(fallback);
}
