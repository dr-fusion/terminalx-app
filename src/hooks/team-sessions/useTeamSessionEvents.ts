"use client";

import { useCallback, useEffect, useMemo, useSyncExternalStore } from "react";
import {
  fetchTeamSessionEvents,
  HttpError,
  parseTeamSessionEvent,
  type TeamSessionEventFetchOptions,
} from "@/lib/team-sessions/browser-client";
import type { TeamSessionEvent, TeamSessionEventConnectionState } from "@/types/team-session";

export const TEAM_SESSION_EVENT_WINDOW_SIZE = 500;
const EVENT_BATCH_LIMIT = TEAM_SESSION_EVENT_WINDOW_SIZE;
const MAX_PENDING_EVENTS = TEAM_SESSION_EVENT_WINDOW_SIZE * 2;
const MAX_RECONNECT_DELAY_MS = 30_000;
const MAX_CONSECUTIVE_CONNECTION_FAILURES = 5;

export interface UseTeamSessionEventsResult {
  events: TeamSessionEvent[];
  historyTruncated: boolean;
  connectionState: TeamSessionEventConnectionState;
  error: Error | null;
  retry: () => void;
}

export interface TeamSessionEventStreamSnapshot {
  events: TeamSessionEvent[];
  historyTruncated: boolean;
  connectionState: TeamSessionEventConnectionState;
  error: Error | null;
}

type FetchEvents = (
  sessionId: string,
  options?: TeamSessionEventFetchOptions
) => Promise<TeamSessionEvent[]>;

export interface TeamSessionEventStreamDependencies {
  fetchEvents: FetchEvents;
  createWebSocket: (url: string) => WebSocket;
  resolveWebSocketUrl: (sessionId: string) => string;
  setTimeout: typeof globalThis.setTimeout;
  clearTimeout: typeof globalThis.clearTimeout;
}

const IDLE_SNAPSHOT: TeamSessionEventStreamSnapshot = Object.freeze({
  events: [],
  historyTruncated: false,
  connectionState: "idle",
  error: null,
});

/**
 * Ordered transport core used by the React hook. Exported so its race and gap
 * behavior can be tested without a DOM renderer.
 */
export class CanonicalTeamSessionEventStream {
  private readonly dependencies: TeamSessionEventStreamDependencies;
  private readonly listeners = new Set<() => void>();
  private readonly pending = new Map<number, TeamSessionEvent>();
  private readonly eventIdSequences = new Map<string, number>();
  private readonly sequenceFingerprints = new Map<number, string>();
  private publishedEvents: TeamSessionEvent[] = [];
  private snapshot: TeamSessionEventStreamSnapshot = IDLE_SNAPSHOT;
  private active = false;
  private cursor = 0;
  private hintedLatestSequence = 0;
  private generation = 0;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof globalThis.setTimeout> | null = null;
  private socket: WebSocket | null = null;
  private connectionAbortController: AbortController | null = null;
  private receivedSnapshot = false;
  private syncTarget = 0;
  private syncInProgress = false;

  constructor(
    private readonly sessionId: string | null,
    latestSequence?: number,
    dependencies: Partial<TeamSessionEventStreamDependencies> = {},
    private readonly liveEnabled = true
  ) {
    this.dependencies = {
      fetchEvents: dependencies.fetchEvents ?? fetchTeamSessionEvents,
      createWebSocket:
        dependencies.createWebSocket ?? ((url: string): WebSocket => new WebSocket(url)),
      resolveWebSocketUrl: dependencies.resolveWebSocketUrl ?? defaultWebSocketUrl,
      setTimeout: dependencies.setTimeout ?? globalThis.setTimeout.bind(globalThis),
      clearTimeout: dependencies.clearTimeout ?? globalThis.clearTimeout.bind(globalThis),
    };
    this.hintedLatestSequence = normalizeSequenceHint(latestSequence);
    this.advanceHistoryFloor(this.hintedLatestSequence);
  }

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  readonly getSnapshot = (): TeamSessionEventStreamSnapshot => this.snapshot;

  readonly getServerSnapshot = (): TeamSessionEventStreamSnapshot => IDLE_SNAPSHOT;

  start(): void {
    if (this.active || this.sessionId === null) return;
    this.active = true;
    if (!this.liveEnabled) {
      this.startHttpOnlySync();
      return;
    }
    this.connect(false);
  }

  stop(): void {
    if (!this.active) return;
    this.active = false;
    this.generation += 1;
    this.clearReconnectTimer();
    this.teardownConnection();
  }

  retry(): void {
    if (this.sessionId === null) return;
    if (!this.active) {
      this.start();
      return;
    }
    this.reconnectAttempt = 0;
    this.generation += 1;
    this.clearReconnectTimer();
    this.teardownConnection();
    if (!this.liveEnabled) {
      this.startHttpOnlySync();
      return;
    }
    this.connect(this.cursor > 0);
  }

  hintLatestSequence(latestSequence?: number): void {
    const hint = normalizeSequenceHint(latestSequence);
    this.hintedLatestSequence = Math.max(this.hintedLatestSequence, hint);
    this.advanceHistoryFloor(this.hintedLatestSequence);
    if (!this.active) return;
    this.syncTarget = Math.max(this.syncTarget, this.hintedLatestSequence);
    this.beginSync(this.generation);
  }

  private startHttpOnlySync(): void {
    if (!this.active || this.sessionId === null) return;
    this.clearReconnectTimer();
    this.teardownConnection();
    const generation = ++this.generation;
    this.connectionAbortController = new AbortController();
    this.syncTarget = Math.max(this.cursor, this.hintedLatestSequence);
    if (this.cursor >= this.syncTarget) {
      this.publish({ connectionState: "idle", error: null });
      return;
    }
    this.beginSync(generation);
  }

  private connect(reconnecting: boolean): void {
    if (!this.active || this.sessionId === null) return;
    this.clearReconnectTimer();
    this.teardownConnection();

    const generation = ++this.generation;
    this.receivedSnapshot = false;
    this.syncTarget = Math.max(this.cursor, this.hintedLatestSequence);
    this.syncInProgress = false;
    this.connectionAbortController = new AbortController();
    this.publish({
      connectionState: reconnecting ? "reconnecting" : "connecting",
      error: reconnecting ? this.snapshot.error : null,
    });

    let socket: WebSocket;
    try {
      socket = this.dependencies.createWebSocket(
        this.dependencies.resolveWebSocketUrl(this.sessionId)
      );
    } catch {
      this.failConnection(generation, new Error("Could not open the Session event stream"), true);
      return;
    }
    this.socket = socket;

    socket.onmessage = (message) => {
      if (!this.isCurrent(generation)) return;
      try {
        this.handleMessage(message.data, generation);
      } catch (cause) {
        this.failConnection(
          generation,
          cause instanceof Error ? cause : new EventStreamProtocolError(),
          false
        );
      }
    };
    socket.onerror = () => {
      this.failConnection(
        generation,
        new Error("The Session event stream lost its connection"),
        true
      );
    };
    socket.onclose = (event) => {
      if (!this.isCurrent(generation)) return;
      const retryable = event.code !== 1008;
      this.failConnection(
        generation,
        new Error(
          retryable ? "The Session event stream closed" : "The Session event stream is unavailable"
        ),
        retryable,
        true
      );
    };

    // Populate the durable history immediately. A rejected or hung WebSocket
    // must not leave an otherwise-readable Session timeline empty.
    this.beginSync(generation);
  }

  private handleMessage(data: unknown, generation: number): void {
    if (typeof data !== "string") throw new EventStreamProtocolError();
    let value: unknown;
    try {
      value = JSON.parse(data) as unknown;
    } catch {
      throw new EventStreamProtocolError();
    }
    if (!isRecord(value) || typeof value.type !== "string") {
      throw new EventStreamProtocolError();
    }

    if (value.type === "session.snapshot") {
      if (this.receivedSnapshot || !hasExactFields(value, ["type", "session"])) {
        throw new EventStreamProtocolError();
      }
      const session = value.session;
      if (!isRecord(session) || session.sessionId !== this.sessionId) {
        throw new EventStreamProtocolError();
      }
      const latestSequence = session.latestSequence;
      if (!Number.isSafeInteger(latestSequence) || (latestSequence as number) < 0) {
        throw new EventStreamProtocolError();
      }
      this.receivedSnapshot = true;
      this.advanceHistoryFloor(latestSequence as number);
      this.syncTarget = Math.max(this.cursor, latestSequence as number, this.hintedLatestSequence);
      this.publish({ connectionState: "syncing", error: null });
      this.beginSync(generation);
      return;
    }

    if (
      value.type !== "session.event" ||
      !this.receivedSnapshot ||
      !hasExactFields(value, ["type", "event"])
    ) {
      throw new EventStreamProtocolError();
    }
    const event = parseTeamSessionEvent(value.event, this.sessionId ?? undefined);
    this.remember(event);
    this.syncTarget = Math.max(this.syncTarget, event.sequence);

    if (
      !this.syncInProgress &&
      this.snapshot.connectionState === "live" &&
      event.sequence === this.cursor + 1
    ) {
      this.drainContiguous();
      return;
    }
    this.beginSync(generation);
  }

  private beginSync(generation: number): void {
    if (!this.isCurrent(generation) || this.syncInProgress) {
      return;
    }
    if (this.cursor >= this.syncTarget && this.liveEnabled && !this.receivedSnapshot) return;
    this.syncInProgress = true;
    this.publish({ connectionState: "syncing", error: null });

    void this.sync(generation)
      .then(() => {
        if (!this.isCurrent(generation)) return;
        this.syncInProgress = false;
        if (this.cursor < this.syncTarget) {
          this.beginSync(generation);
          return;
        }
        if (this.liveEnabled && !this.receivedSnapshot) {
          this.publish({ connectionState: "connecting", error: null });
          return;
        }
        this.reconnectAttempt = 0;
        this.publish({ connectionState: this.liveEnabled ? "live" : "idle", error: null });
      })
      .catch((cause) => {
        if (!this.isCurrent(generation)) return;
        this.syncInProgress = false;
        if (isAbortError(cause)) return;
        const error = cause instanceof Error ? cause : new Error("Could not synchronize events");
        if (!this.liveEnabled) {
          this.failHttpOnlySync(generation, error);
          return;
        }
        this.failConnection(generation, error, isRetryableSyncError(error));
      });
  }

  private failHttpOnlySync(generation: number, error: Error): void {
    if (!this.isCurrent(generation)) return;
    this.generation += 1;
    this.detachConnection(true);
    if (this.active) this.publish({ connectionState: "idle", error });
  }

  private async sync(generation: number): Promise<void> {
    while (this.cursor < this.syncTarget) {
      if (!this.isCurrent(generation)) return;
      this.drainContiguous();
      if (this.cursor >= this.syncTarget) return;

      const before = this.cursor;
      const target = this.syncTarget;
      const events = await this.dependencies.fetchEvents(this.sessionId!, {
        afterSequence: before,
        limit: Math.min(EVENT_BATCH_LIMIT, target - before),
        signal: this.connectionAbortController?.signal,
      });
      if (!this.isCurrent(generation)) return;
      for (const event of events) this.remember(event);
      this.drainContiguous();
      if (this.cursor === before) throw new EventStreamGapError();
    }
  }

  private remember(event: TeamSessionEvent): void {
    if (event.sessionId !== this.sessionId) throw new EventStreamProtocolError();
    const fingerprint = fingerprintEvent(event);
    const knownFingerprint = this.sequenceFingerprints.get(event.sequence);
    if (knownFingerprint !== undefined) {
      if (knownFingerprint !== fingerprint) throw new EventStreamProtocolError();
      return;
    }
    // Events older than the retained browser window are already represented by
    // the durable cursor. Do not let repeated old frames refill the dedupe maps.
    if (event.sequence <= this.cursor) return;
    const knownSequence = this.eventIdSequences.get(event.eventId);
    if (knownSequence !== undefined && knownSequence !== event.sequence) {
      throw new EventStreamProtocolError();
    }
    if (this.pending.size >= MAX_PENDING_EVENTS) throw new EventStreamProtocolError();
    this.sequenceFingerprints.set(event.sequence, fingerprint);
    this.eventIdSequences.set(event.eventId, event.sequence);
    this.pending.set(event.sequence, event);
  }

  private drainContiguous(): void {
    let changed = false;
    while (true) {
      const nextSequence = this.cursor + 1;
      const event = this.pending.get(nextSequence);
      if (!event) break;
      this.pending.delete(nextSequence);
      this.cursor = nextSequence;
      this.publishedEvents.push(event);
      changed = true;
    }
    if (!changed) return;

    const excess = this.publishedEvents.length - TEAM_SESSION_EVENT_WINDOW_SIZE;
    if (excess > 0) {
      const evicted = this.publishedEvents.splice(0, excess);
      for (const event of evicted) {
        this.sequenceFingerprints.delete(event.sequence);
        this.eventIdSequences.delete(event.eventId);
      }
    }
    this.publish({
      events: [...this.publishedEvents],
      historyTruncated: this.snapshot.historyTruncated || excess > 0,
    });
  }

  /**
   * Bootstrap or catch up from only the most recent bounded history window.
   * The canonical server log remains complete; this protects a browser from a
   * long-lived or intentionally spammed Session without pretending that the
   * displayed window is the whole history.
   */
  private advanceHistoryFloor(latestSequence: number): void {
    const floor = Math.max(0, latestSequence - TEAM_SESSION_EVENT_WINDOW_SIZE);
    if (floor <= this.cursor) return;
    this.cursor = floor;
    this.pending.clear();
    this.eventIdSequences.clear();
    this.sequenceFingerprints.clear();
    this.publishedEvents = [];
    this.publish({ events: [], historyTruncated: true });
  }

  private failConnection(
    generation: number,
    error: Error,
    retryable: boolean,
    socketAlreadyClosed = false
  ): void {
    if (!this.isCurrent(generation)) return;
    // Invalidate every pending callback from this socket/fetch generation
    // before aborting its HTTP recovery request.
    this.generation += 1;
    this.detachConnection(socketAlreadyClosed);
    if (!this.active) return;
    if (!retryable) {
      this.publish({ connectionState: "idle", error });
      return;
    }

    this.reconnectAttempt += 1;
    if (this.reconnectAttempt >= MAX_CONSECUTIVE_CONNECTION_FAILURES) {
      this.publish({
        connectionState: "idle",
        error: new Error(
          "The Session event stream remains unavailable. Access may have changed, or the custom server may be offline."
        ),
      });
      return;
    }
    const delay = Math.min(1_000 * 2 ** (this.reconnectAttempt - 1), MAX_RECONNECT_DELAY_MS);
    this.publish({ connectionState: "reconnecting", error });
    this.reconnectTimer = this.dependencies.setTimeout(() => {
      this.reconnectTimer = null;
      if (this.active) this.connect(true);
    }, delay);
  }

  private detachConnection(socketAlreadyClosed: boolean): void {
    const socket = this.socket;
    this.socket = null;
    this.connectionAbortController?.abort();
    this.connectionAbortController = null;
    this.receivedSnapshot = false;
    this.syncInProgress = false;
    if (!socket) return;
    socket.onopen = null;
    socket.onmessage = null;
    socket.onerror = null;
    socket.onclose = null;
    if (!socketAlreadyClosed) {
      try {
        socket.close(1000, "Reconnecting");
      } catch {
        // The transport failure that led here remains authoritative.
      }
    }
  }

  private teardownConnection(): void {
    this.detachConnection(false);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer === null) return;
    this.dependencies.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }

  private isCurrent(generation: number): boolean {
    return this.active && generation === this.generation;
  }

  private publish(update: Partial<TeamSessionEventStreamSnapshot>): void {
    this.snapshot = { ...this.snapshot, ...update };
    for (const listener of this.listeners) listener();
  }
}

export function useTeamSessionEvents(
  sessionId: string | null,
  latestSequence?: number,
  enabled = true
): UseTeamSessionEventsResult {
  const stream = useMemo(
    () => new CanonicalTeamSessionEventStream(sessionId, undefined, {}, enabled),
    [enabled, sessionId]
  );
  const snapshot = useSyncExternalStore(
    stream.subscribe,
    stream.getSnapshot,
    stream.getServerSnapshot
  );

  useEffect(() => {
    stream.start();
    return () => stream.stop();
  }, [stream]);
  useEffect(() => {
    stream.hintLatestSequence(latestSequence);
  }, [latestSequence, stream]);

  const retry = useCallback(() => stream.retry(), [stream]);
  return { ...snapshot, retry };
}

class EventStreamProtocolError extends Error {
  constructor() {
    super("The Session event stream returned an invalid message");
    this.name = "EventStreamProtocolError";
  }
}

class EventStreamGapError extends Error {
  constructor() {
    super("The Session event stream could not recover a sequence gap");
    this.name = "EventStreamGapError";
  }
}

function isRetryableSyncError(error: Error): boolean {
  if (error instanceof EventStreamProtocolError) return false;
  return error instanceof EventStreamGapError || !(error instanceof HttpError) || error.retryable;
}

function isAbortError(cause: unknown): boolean {
  return cause instanceof DOMException
    ? cause.name === "AbortError"
    : isRecord(cause) && cause.name === "AbortError";
}

function defaultWebSocketUrl(sessionId: string): string {
  if (typeof window === "undefined") throw new Error("WebSocket is unavailable on the server");
  const url = new URL(
    `/ws/team-sessions/${encodeURIComponent(sessionId)}/events`,
    window.location.href
  );
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

function normalizeSequenceHint(value: number | undefined): number {
  return value !== undefined && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function fingerprintEvent(event: TeamSessionEvent): string {
  return JSON.stringify(event);
}

function hasExactFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
