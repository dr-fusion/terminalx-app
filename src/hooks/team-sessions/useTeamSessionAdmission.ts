"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fetchTeamSessionAdmission } from "@/lib/team-sessions/browser-client";
import type { TeamSessionAdmission } from "@/types/team-session";

export interface UseTeamSessionAdmissionResult {
  admission: TeamSessionAdmission | null;
  isLoading: boolean;
  error: Error | null;
  refresh: () => Promise<void>;
}

export function useTeamSessionAdmission(
  sessionId: string | null,
  enabled = true
): UseTeamSessionAdmissionResult {
  const [loaded, setLoaded] = useState<{
    sessionId: string;
    admission: TeamSessionAdmission;
  } | null>(null);
  const [loadingSessionId, setLoadingSessionId] = useState<string | null>(
    enabled ? sessionId : null
  );
  const [scopedError, setScopedError] = useState<{ sessionId: string; error: Error } | null>(null);
  const requestRef = useRef<{ id: number; controller: AbortController } | null>(null);
  const nextRequestIdRef = useRef(0);

  const refresh = useCallback(async (): Promise<void> => {
    requestRef.current?.controller.abort();
    if (!enabled || sessionId === null) {
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
      const admission = await fetchTeamSessionAdmission(sessionId, {
        signal: request.controller.signal,
      });
      if (request.controller.signal.aborted || requestRef.current?.id !== request.id) return;
      setLoaded({ sessionId, admission });
    } catch (cause) {
      if (request.controller.signal.aborted || requestRef.current?.id !== request.id) return;
      setScopedError({
        sessionId,
        error: cause instanceof Error ? cause : new Error("Could not load Session access"),
      });
    } finally {
      if (requestRef.current?.id === request.id) {
        requestRef.current = null;
        setLoadingSessionId(null);
      }
    }
  }, [enabled, sessionId]);

  useEffect(() => {
    void refresh();
    return () => {
      requestRef.current?.controller.abort();
      requestRef.current = null;
    };
  }, [refresh]);

  const admission = enabled && loaded?.sessionId === sessionId ? loaded.admission : null;
  const error = enabled && scopedError?.sessionId === sessionId ? scopedError.error : null;
  const isLoading =
    enabled &&
    sessionId !== null &&
    (loadingSessionId === sessionId || (admission === null && error === null));

  return { admission, isLoading, error, refresh };
}
