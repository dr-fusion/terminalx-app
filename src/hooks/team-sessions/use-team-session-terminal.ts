"use client";

import { useCallback, useEffect, useRef, useState } from "react";

const MAX_TERMINAL_INPUT_BYTES = 16 * 1024;
const MAX_CONSECUTIVE_CONNECTION_FAILURES = 5;
const MAX_POLICY_CLOSES = 2;
const MAX_RECONNECT_DELAY_MS = 30_000;
const POLICY_CLOSE_RESET_MS = 30_000;
const UTF8_ENCODER = new TextEncoder();

export type TeamSessionTerminalStatus =
  | "idle"
  | "connecting"
  | "ready"
  | "reconnecting"
  | "ended"
  | "policy-blocked"
  | "error";

export interface TeamSessionTerminalFences {
  controlEpoch: number;
  runtimeAuthorizationGeneration: number;
}

export type TeamSessionTerminalServerMessage =
  | ({
      type: "terminal.ready";
      sessionId: string;
      canInput: boolean;
    } & TeamSessionTerminalFences)
  | {
      type: "terminal.output";
      data: string;
    }
  | {
      type: "terminal.ended";
      sessionId: string;
    };

export type TeamSessionTerminalMutation =
  | {
      type: "input";
      data: string;
    }
  | {
      type: "resize";
      cols: number;
      rows: number;
    }
  | {
      type: "interrupt";
    };

interface TeamSessionTerminalConnectionState {
  status: TeamSessionTerminalStatus;
  serverCanInput: boolean;
  fences: TeamSessionTerminalFences | null;
  error: string | null;
  hasOutputGap: boolean;
  reconnectAttempt: number;
  lastCloseCode: number | null;
}

interface UseTeamSessionTerminalOptions {
  sessionId: string;
  enabled: boolean;
  allowMutations: boolean;
  initialCols?: number;
  initialRows?: number;
  onOutput: (data: string) => void;
  onEnded?: () => void;
}

export interface UseTeamSessionTerminalResult {
  status: TeamSessionTerminalStatus;
  canInput: boolean;
  fences: TeamSessionTerminalFences | null;
  error: string | null;
  hasOutputGap: boolean;
  reconnectAttempt: number;
  lastCloseCode: number | null;
  retry: () => void;
  clearOutputGap: () => void;
  sendInput: (data: string) => boolean;
  sendResize: (cols: number, rows: number) => boolean;
  sendInterrupt: () => boolean;
}

export interface TeamSessionTerminalCloseDecision {
  action: "retry" | "ended" | "block";
  policyCloseCount: number;
}

export function parseTeamSessionTerminalServerMessage(
  raw: unknown
): TeamSessionTerminalServerMessage | null {
  if (typeof raw !== "string") return null;

  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isRecord(value) || typeof value.type !== "string") return null;

  switch (value.type) {
    case "terminal.ready":
      if (
        !hasExactKeys(value, [
          "type",
          "sessionId",
          "canInput",
          "controlEpoch",
          "runtimeAuthorizationGeneration",
        ]) ||
        typeof value.sessionId !== "string" ||
        value.sessionId.length === 0 ||
        typeof value.canInput !== "boolean" ||
        !isFence(value.controlEpoch) ||
        !isFence(value.runtimeAuthorizationGeneration)
      ) {
        return null;
      }
      return {
        type: "terminal.ready",
        sessionId: value.sessionId,
        canInput: value.canInput,
        controlEpoch: value.controlEpoch,
        runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
      };
    case "terminal.output":
      if (!hasExactKeys(value, ["type", "data"]) || typeof value.data !== "string") {
        return null;
      }
      return { type: "terminal.output", data: value.data };
    case "terminal.ended":
      if (
        !hasExactKeys(value, ["type", "sessionId"]) ||
        typeof value.sessionId !== "string" ||
        value.sessionId.length === 0
      ) {
        return null;
      }
      return { type: "terminal.ended", sessionId: value.sessionId };
    default:
      return null;
  }
}

/**
 * Serialize the canonical mutation only when the caller has the live server
 * projection and both fences. Returning null is deliberately fail-closed.
 */
export function serializeTeamSessionTerminalMutation(
  mutation: TeamSessionTerminalMutation,
  fences: TeamSessionTerminalFences | null,
  canInput: boolean
): string | null {
  if (!canInput || !fences || !isFence(fences.controlEpoch)) return null;
  if (!isFence(fences.runtimeAuthorizationGeneration)) return null;

  switch (mutation.type) {
    case "input":
      if (
        mutation.data.length === 0 ||
        UTF8_ENCODER.encode(mutation.data).byteLength > MAX_TERMINAL_INPUT_BYTES
      ) {
        return null;
      }
      break;
    case "resize":
      if (
        !Number.isSafeInteger(mutation.cols) ||
        !Number.isSafeInteger(mutation.rows) ||
        mutation.cols < 1 ||
        mutation.cols > 500 ||
        mutation.rows < 1 ||
        mutation.rows > 200
      ) {
        return null;
      }
      break;
    case "interrupt":
      break;
  }

  return JSON.stringify({
    ...mutation,
    controlEpoch: fences.controlEpoch,
    runtimeAuthorizationGeneration: fences.runtimeAuthorizationGeneration,
  });
}

export function decideTeamSessionTerminalClose(
  closeCode: number,
  policyCloseCount: number
): TeamSessionTerminalCloseDecision {
  if (closeCode === 4000) {
    return { action: "ended", policyCloseCount };
  }
  if (closeCode !== 1008) {
    return { action: "retry", policyCloseCount };
  }

  const nextPolicyCloseCount = policyCloseCount + 1;
  return {
    action: nextPolicyCloseCount >= MAX_POLICY_CLOSES ? "block" : "retry",
    policyCloseCount: nextPolicyCloseCount,
  };
}

export function shouldPauseTeamSessionTerminalReconnect(consecutiveFailures: number): boolean {
  return consecutiveFailures >= MAX_CONSECUTIVE_CONNECTION_FAILURES;
}

export function useTeamSessionTerminal({
  sessionId,
  enabled,
  allowMutations,
  initialCols = 80,
  initialRows = 24,
  onOutput,
  onEnded,
}: UseTeamSessionTerminalOptions): UseTeamSessionTerminalResult {
  const [retryGeneration, setRetryGeneration] = useState(0);
  const [connection, setConnection] = useState<TeamSessionTerminalConnectionState>(() => ({
    status: enabled ? "connecting" : "idle",
    serverCanInput: false,
    fences: null,
    error: null,
    hasOutputGap: false,
    reconnectAttempt: 0,
    lastCloseCode: null,
  }));

  const socketRef = useRef<WebSocket | null>(null);
  const fencesRef = useRef<TeamSessionTerminalFences | null>(null);
  const readyRef = useRef(false);
  const serverCanInputRef = useRef(false);
  const onOutputRef = useRef(onOutput);
  const onEndedRef = useRef(onEnded);

  useEffect(() => {
    onOutputRef.current = onOutput;
  }, [onOutput]);
  useEffect(() => {
    onEndedRef.current = onEnded;
  }, [onEnded]);

  useEffect(() => {
    if (!enabled || !sessionId) {
      readyRef.current = false;
      serverCanInputRef.current = false;
      fencesRef.current = null;
      return;
    }

    let disposed = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let policyResetTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempt = 0;
    let consecutiveFailures = 0;
    let policyCloseCount = 0;
    let hasEverBeenReady = false;
    let firstAttempt = true;

    const clearTimers = (): void => {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (policyResetTimer) {
        clearTimeout(policyResetTimer);
        policyResetTimer = null;
      }
    };

    const resetLiveAuthorization = (): void => {
      readyRef.current = false;
      serverCanInputRef.current = false;
      fencesRef.current = null;
    };

    const connect = (): void => {
      if (disposed) return;
      clearTimers();
      resetLiveAuthorization();

      const isFirstAttempt = firstAttempt;
      firstAttempt = false;
      setConnection((current) => ({
        ...current,
        status: hasEverBeenReady ? "reconnecting" : "connecting",
        serverCanInput: false,
        fences: null,
        error: null,
        hasOutputGap: isFirstAttempt ? false : current.hasOutputGap,
        reconnectAttempt,
        lastCloseCode: null,
      }));

      if (typeof WebSocket === "undefined") {
        setConnection((current) => ({
          ...current,
          status: "error",
          error: "This browser does not support live terminal connections.",
        }));
        return;
      }

      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const dimensions = new URLSearchParams({
        cols: String(boundedDimension(initialCols, 80, 500)),
        rows: String(boundedDimension(initialRows, 24, 200)),
      });
      const url = `${protocol}//${window.location.host}/ws/team-sessions/${encodeURIComponent(
        sessionId
      )}/terminal?${dimensions.toString()}`;

      let socket: WebSocket;
      try {
        socket = new WebSocket(url);
      } catch {
        setConnection((current) => ({
          ...current,
          status: "error",
          error: "The multiplayer terminal connection could not be opened.",
        }));
        return;
      }
      socketRef.current = socket;

      let fatalProtocolError = false;
      let terminalEnded = false;

      socket.onmessage = (event) => {
        if (disposed || socketRef.current !== socket) return;
        const message = parseTeamSessionTerminalServerMessage(event.data);
        if (!message) {
          fatalProtocolError = true;
          resetLiveAuthorization();
          setConnection((current) => ({
            ...current,
            status: "error",
            serverCanInput: false,
            fences: null,
            error: "The terminal returned an unsupported response.",
          }));
          socket.close(1002, "Unsupported terminal response");
          return;
        }

        switch (message.type) {
          case "terminal.ready": {
            if (message.sessionId !== sessionId || readyRef.current) {
              fatalProtocolError = true;
              resetLiveAuthorization();
              setConnection((current) => ({
                ...current,
                status: "error",
                serverCanInput: false,
                fences: null,
                error: "The terminal connection did not match this session.",
              }));
              socket.close(1002, "Mismatched terminal session");
              return;
            }

            const fences = {
              controlEpoch: message.controlEpoch,
              runtimeAuthorizationGeneration: message.runtimeAuthorizationGeneration,
            };
            readyRef.current = true;
            serverCanInputRef.current = message.canInput;
            fencesRef.current = fences;
            hasEverBeenReady = true;
            reconnectAttempt = 0;
            consecutiveFailures = 0;
            setConnection((current) => ({
              ...current,
              status: "ready",
              serverCanInput: message.canInput,
              fences,
              error: null,
              reconnectAttempt: 0,
              lastCloseCode: null,
            }));

            policyResetTimer = setTimeout(() => {
              policyCloseCount = 0;
              policyResetTimer = null;
            }, POLICY_CLOSE_RESET_MS);
            break;
          }
          case "terminal.output":
            if (!readyRef.current) {
              fatalProtocolError = true;
              resetLiveAuthorization();
              setConnection((current) => ({
                ...current,
                status: "error",
                serverCanInput: false,
                fences: null,
                error: "The terminal sent output before authorization completed.",
              }));
              socket.close(1002, "Terminal output before ready");
              return;
            }
            onOutputRef.current(message.data);
            break;
          case "terminal.ended":
            if (message.sessionId !== sessionId) {
              fatalProtocolError = true;
              resetLiveAuthorization();
              setConnection((current) => ({
                ...current,
                status: "error",
                serverCanInput: false,
                fences: null,
                error: "The terminal end signal did not match this session.",
              }));
              socket.close(1002, "Mismatched terminal session");
              return;
            }
            terminalEnded = true;
            resetLiveAuthorization();
            setConnection((current) => ({
              ...current,
              status: "ended",
              serverCanInput: false,
              fences: null,
              error: null,
              lastCloseCode: 4000,
            }));
            onEndedRef.current?.();
            socket.close(1000, "Terminal ended");
            break;
        }
      };

      socket.onerror = () => {
        if (socketRef.current === socket) socket.close();
      };

      socket.onclose = (event) => {
        if (disposed || socketRef.current !== socket) return;
        socketRef.current = null;
        const connectionWasReady = readyRef.current;
        resetLiveAuthorization();
        if (policyResetTimer) {
          clearTimeout(policyResetTimer);
          policyResetTimer = null;
        }
        if (fatalProtocolError) return;

        const decision = decideTeamSessionTerminalClose(event.code, policyCloseCount);
        policyCloseCount = decision.policyCloseCount;
        if (terminalEnded || decision.action === "ended") {
          setConnection((current) => ({
            ...current,
            status: "ended",
            serverCanInput: false,
            fences: null,
            error: null,
            lastCloseCode: event.code,
          }));
          if (!terminalEnded) onEndedRef.current?.();
          return;
        }
        if (decision.action === "block") {
          setConnection((current) => ({
            ...current,
            status: "policy-blocked",
            serverCanInput: false,
            fences: null,
            error: "Terminal access changed or is no longer available.",
            hasOutputGap: current.hasOutputGap || connectionWasReady,
            lastCloseCode: event.code,
          }));
          return;
        }

        consecutiveFailures += 1;
        if (shouldPauseTeamSessionTerminalReconnect(consecutiveFailures)) {
          setConnection((current) => ({
            ...current,
            status: "error",
            serverCanInput: false,
            fences: null,
            error:
              "The multiplayer terminal remains unavailable. Access may have changed, or the custom server may be offline. Review the Session, then retry.",
            lastCloseCode: event.code,
          }));
          return;
        }

        const delay = Math.min(1_000 * 2 ** reconnectAttempt, MAX_RECONNECT_DELAY_MS);
        reconnectAttempt += 1;
        setConnection((current) => ({
          ...current,
          status: "reconnecting",
          serverCanInput: false,
          fences: null,
          error: null,
          hasOutputGap: current.hasOutputGap || connectionWasReady,
          reconnectAttempt,
          lastCloseCode: event.code,
        }));
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          connect();
        }, delay);
      };
    };

    connect();

    return () => {
      disposed = true;
      clearTimers();
      resetLiveAuthorization();
      const socket = socketRef.current;
      socketRef.current = null;
      if (
        socket &&
        (socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.OPEN)
      ) {
        socket.close(1000, "Terminal view closed");
      }
    };
  }, [enabled, initialCols, initialRows, retryGeneration, sessionId]);

  const retry = useCallback(() => {
    setConnection((current) => ({
      ...current,
      status: "connecting",
      serverCanInput: false,
      fences: null,
      error: null,
      hasOutputGap: false,
      reconnectAttempt: 0,
      lastCloseCode: null,
    }));
    setRetryGeneration((generation) => generation + 1);
  }, []);

  const clearOutputGap = useCallback(() => {
    setConnection((current) => ({ ...current, hasOutputGap: false }));
  }, []);

  const sendMutation = useCallback(
    (mutation: TeamSessionTerminalMutation): boolean => {
      const socket = socketRef.current;
      const payload = serializeTeamSessionTerminalMutation(
        mutation,
        fencesRef.current,
        allowMutations && readyRef.current && serverCanInputRef.current
      );
      if (!payload || !socket || socket.readyState !== WebSocket.OPEN) return false;
      socket.send(payload);
      return true;
    },
    [allowMutations]
  );

  const sendInput = useCallback(
    (data: string) => sendMutation({ type: "input", data }),
    [sendMutation]
  );
  const sendResize = useCallback(
    (cols: number, rows: number) => sendMutation({ type: "resize", cols, rows }),
    [sendMutation]
  );
  const sendInterrupt = useCallback(() => sendMutation({ type: "interrupt" }), [sendMutation]);

  const status = enabled
    ? connection.status === "idle"
      ? "connecting"
      : connection.status
    : "idle";
  const canInput = enabled && status === "ready" && connection.serverCanInput && allowMutations;

  return {
    status,
    canInput,
    fences: enabled ? connection.fences : null,
    error: enabled ? connection.error : null,
    hasOutputGap: enabled && connection.hasOutputGap,
    reconnectAttempt: enabled ? connection.reconnectAttempt : 0,
    lastCloseCode: enabled ? connection.lastCloseCode : null,
    retry,
    clearOutputGap,
    sendInput,
    sendResize,
    sendInterrupt,
  };
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFence(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function boundedDimension(value: number, fallback: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1) return fallback;
  return Math.min(value, maximum);
}
