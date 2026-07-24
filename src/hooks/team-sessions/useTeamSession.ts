"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fetchTeamSessionDetail } from "@/lib/team-sessions/browser-client";
import type { TeamSessionDetail } from "@/types/team-session";

export interface UseTeamSessionResult {
  session: TeamSessionDetail | null;
  isLoading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
}

export function useTeamSession(sessionId: string | null): UseTeamSessionResult {
  const [loaded, setLoaded] = useState<{
    sessionId: string;
    session: TeamSessionDetail;
  } | null>(null);
  const [loadingSessionId, setLoadingSessionId] = useState<string | null>(sessionId);
  const [scopedError, setScopedError] = useState<{
    sessionId: string;
    error: Error;
  } | null>(null);
  const requestRef = useRef<{ id: number; controller: AbortController } | null>(null);
  const nextRequestIdRef = useRef(0);

  const refresh = useCallback(async (): Promise<void> => {
    requestRef.current?.controller.abort();
    if (sessionId === null) {
      requestRef.current = null;
      setLoaded(null);
      setScopedError(null);
      setLoadingSessionId(null);
      return;
    }

    const request = {
      id: nextRequestIdRef.current + 1,
      controller: new AbortController(),
    };
    nextRequestIdRef.current = request.id;
    requestRef.current = request;
    setLoadingSessionId(sessionId);
    setScopedError(null);

    try {
      const nextSession = await fetchTeamSessionDetail(sessionId, {
        signal: request.controller.signal,
      });
      if (request.controller.signal.aborted || requestRef.current?.id !== request.id) return;
      setLoaded({ sessionId, session: nextSession });
    } catch (cause) {
      if (request.controller.signal.aborted || requestRef.current?.id !== request.id) return;
      setScopedError({
        sessionId,
        error: cause instanceof Error ? cause : new Error("Could not load the Session"),
      });
    } finally {
      if (requestRef.current?.id === request.id) {
        requestRef.current = null;
        setLoadingSessionId(null);
      }
    }
  }, [sessionId]);

  useEffect(() => {
    void refresh();
    return () => {
      requestRef.current?.controller.abort();
      requestRef.current = null;
    };
  }, [sessionId, refresh]);

  // Scope visible data to the route synchronously. A navigation must never
  // paint the previous Session while the new detail request is starting.
  const session = loaded?.sessionId === sessionId ? loaded.session : null;
  const error = scopedError?.sessionId === sessionId ? scopedError.error : null;
  const isLoading =
    sessionId !== null && (loadingSessionId === sessionId || (session === null && error === null));

  return { session, isLoading, error, refresh };
}
