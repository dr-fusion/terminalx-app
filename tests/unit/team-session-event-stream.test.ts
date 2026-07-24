import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CanonicalTeamSessionEventStream,
  TEAM_SESSION_EVENT_WINDOW_SIZE,
  type TeamSessionEventStreamDependencies,
} from "@/hooks/team-sessions/useTeamSessionEvents";
import type { TeamSessionEvent } from "@/types/team-session";

const SESSION_ID = "33333333-3333-4333-8333-333333333333";
type FetchEvents = TeamSessionEventStreamDependencies["fetchEvents"];

afterEach(() => {
  vi.restoreAllMocks();
});

describe("canonical Team Session event stream", () => {
  it("buffers live events while catching up, then publishes one ordered gap-free log", async () => {
    const initialBatch = deferred<TeamSessionEvent[]>();
    const fetchEvents = vi
      .fn<FetchEvents>()
      .mockImplementationOnce(() => initialBatch.promise)
      .mockResolvedValueOnce([eventFixture(3), eventFixture(4)]);
    const harness = createHarness(fetchEvents);
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, undefined, harness.dependencies);
    stream.start();

    harness.sockets[0]!.receive(snapshotEnvelope(2));
    harness.sockets[0]!.receive(eventEnvelope(4));
    expect(stream.getSnapshot()).toMatchObject({ connectionState: "syncing", events: [] });

    initialBatch.resolve([eventFixture(1), eventFixture(2)]);
    await vi.waitFor(() => {
      expect(stream.getSnapshot().connectionState).toBe("live");
    });

    expect(stream.getSnapshot().events.map((event) => event.sequence)).toEqual([1, 2, 3, 4]);
    expect(fetchEvents).toHaveBeenNthCalledWith(
      1,
      SESSION_ID,
      expect.objectContaining({ afterSequence: 0, limit: 2 })
    );
    expect(fetchEvents).toHaveBeenNthCalledWith(
      2,
      SESSION_ID,
      expect.objectContaining({ afterSequence: 2, limit: 2 })
    );
    stream.stop();
  });

  it("reconnects and retries HTTP gap recovery without discarding the valid prefix", async () => {
    const fetchEvents = vi
      .fn<FetchEvents>()
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([eventFixture(1), eventFixture(2)]);
    const harness = createHarness(fetchEvents);
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, undefined, harness.dependencies);
    stream.start();
    harness.sockets[0]!.receive(snapshotEnvelope(2));

    await vi.waitFor(() => {
      expect(stream.getSnapshot().connectionState).toBe("reconnecting");
    });
    expect(harness.reconnects).toHaveLength(1);
    harness.runNextReconnect();
    expect(harness.sockets).toHaveLength(2);
    harness.sockets[1]!.receive(snapshotEnvelope(2));

    await vi.waitFor(() => {
      expect(stream.getSnapshot().connectionState).toBe("live");
    });
    expect(stream.getSnapshot().events.map((event) => event.sequence)).toEqual([1, 2]);
    expect(fetchEvents).toHaveBeenCalledTimes(2);
    stream.stop();
  });

  it("loads only the latest bounded history window from a long-lived session", async () => {
    const fetchEvents = vi.fn<FetchEvents>(async (_sessionId, options) => {
      const afterSequence = options?.afterSequence ?? 0;
      const limit = options?.limit ?? 1_000;
      const lastSequence = Math.min(1_001, afterSequence + limit);
      return Array.from({ length: lastSequence - afterSequence }, (_entry, index) =>
        eventFixture(afterSequence + index + 1)
      );
    });
    const harness = createHarness(fetchEvents);
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, undefined, harness.dependencies);
    stream.start();
    harness.sockets[0]!.receive(snapshotEnvelope(1_001));

    await vi.waitFor(() => expect(stream.getSnapshot().connectionState).toBe("live"));
    expect(stream.getSnapshot().events).toHaveLength(TEAM_SESSION_EVENT_WINDOW_SIZE);
    expect(stream.getSnapshot().historyTruncated).toBe(true);
    expect(stream.getSnapshot().events[0]?.sequence).toBe(502);
    expect(fetchEvents).toHaveBeenNthCalledWith(
      1,
      SESSION_ID,
      expect.objectContaining({ afterSequence: 501, limit: TEAM_SESSION_EVENT_WINDOW_SIZE })
    );
    expect(fetchEvents).toHaveBeenCalledTimes(1);
    stream.stop();
  });

  it("evicts old events and dedupe entries as a live session outgrows the window", async () => {
    const fetchEvents = vi.fn<FetchEvents>().mockResolvedValue([]);
    const harness = createHarness(fetchEvents);
    const stream = new CanonicalTeamSessionEventStream(
      SESSION_ID,
      TEAM_SESSION_EVENT_WINDOW_SIZE,
      harness.dependencies
    );
    stream.start();
    harness.sockets[0]!.receive(snapshotEnvelope(TEAM_SESSION_EVENT_WINDOW_SIZE));

    for (let sequence = 1; sequence <= TEAM_SESSION_EVENT_WINDOW_SIZE; sequence += 1) {
      harness.sockets[0]!.receive(eventEnvelope(sequence));
    }
    await vi.waitFor(() => expect(stream.getSnapshot().connectionState).toBe("live"));

    harness.sockets[0]!.receive(eventEnvelope(TEAM_SESSION_EVENT_WINDOW_SIZE + 1));
    expect(stream.getSnapshot().events).toHaveLength(TEAM_SESSION_EVENT_WINDOW_SIZE);
    expect(stream.getSnapshot().events[0]?.sequence).toBe(2);
    expect(stream.getSnapshot().historyTruncated).toBe(true);
    stream.stop();
  });

  it("loads HTTP history without ever opening a socket when live transport is disabled", async () => {
    const fetchEvents = vi.fn<FetchEvents>().mockResolvedValue([eventFixture(1), eventFixture(2)]);
    const harness = createHarness(fetchEvents);
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, 2, harness.dependencies, false);
    stream.start();

    await vi.waitFor(() => expect(stream.getSnapshot().connectionState).toBe("idle"));
    expect(stream.getSnapshot()).toMatchObject({ error: null });
    expect(stream.getSnapshot().events.map((event) => event.sequence)).toEqual([1, 2]);
    expect(fetchEvents).toHaveBeenCalledWith(
      SESSION_ID,
      expect.objectContaining({ afterSequence: 0, limit: 2 })
    );
    expect(harness.sockets).toHaveLength(0);
    expect(harness.reconnects).toHaveLength(0);
    stream.stop();
  });

  it("loads hinted HTTP history while the live socket is still waiting for its snapshot", async () => {
    const fetchEvents = vi.fn<FetchEvents>().mockResolvedValue([eventFixture(1), eventFixture(2)]);
    const harness = createHarness(fetchEvents);
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, 2, harness.dependencies);
    stream.start();

    await vi.waitFor(() => expect(stream.getSnapshot().events).toHaveLength(2));
    expect(stream.getSnapshot()).toMatchObject({ connectionState: "connecting", error: null });
    expect(stream.getSnapshot().events.map((event) => event.sequence)).toEqual([1, 2]);
    expect(fetchEvents).toHaveBeenCalledWith(
      SESSION_ID,
      expect.objectContaining({ afterSequence: 0, limit: 2 })
    );
    expect(harness.sockets).toHaveLength(1);

    harness.sockets[0]!.receive(snapshotEnvelope(2));
    await vi.waitFor(() => expect(stream.getSnapshot().connectionState).toBe("live"));
    stream.stop();
  });

  it("retries failed HTTP-only history recovery without enabling live transport", async () => {
    const fetchEvents = vi
      .fn<FetchEvents>()
      .mockRejectedValueOnce(new Error("network unavailable"))
      .mockResolvedValueOnce([eventFixture(1)]);
    const harness = createHarness(fetchEvents);
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, 1, harness.dependencies, false);
    stream.start();

    await vi.waitFor(() => expect(stream.getSnapshot().error).not.toBeNull());
    expect(stream.getSnapshot().connectionState).toBe("idle");
    stream.retry();
    await vi.waitFor(() => {
      expect(stream.getSnapshot()).toMatchObject({ connectionState: "idle", error: null });
      expect(stream.getSnapshot().events).toHaveLength(1);
    });
    expect(fetchEvents).toHaveBeenCalledTimes(2);
    expect(harness.sockets).toHaveLength(0);
    expect(harness.reconnects).toHaveLength(0);
    stream.stop();
  });

  it("does not loop on a policy close and reconnects only after explicit retry", () => {
    const harness = createHarness(vi.fn<FetchEvents>().mockResolvedValue([]));
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, undefined, harness.dependencies);
    stream.start();
    harness.sockets[0]!.closeFromServer(1008);

    expect(stream.getSnapshot()).toMatchObject({ connectionState: "idle" });
    expect(stream.getSnapshot().error?.message).toContain("unavailable");
    expect(harness.reconnects).toHaveLength(0);

    stream.retry();
    expect(harness.sockets).toHaveLength(2);
    expect(stream.getSnapshot().connectionState).toBe("connecting");
    stream.stop();
  });

  it("bounds retryable connection failures until the user explicitly retries", () => {
    const harness = createHarness(vi.fn<FetchEvents>().mockResolvedValue([]));
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, undefined, harness.dependencies);
    stream.start();

    for (let attempt = 0; attempt < 5; attempt += 1) {
      harness.sockets[attempt]!.closeFromServer(1006);
      if (attempt < 4) harness.runNextReconnect();
    }

    expect(stream.getSnapshot().connectionState).toBe("idle");
    expect(stream.getSnapshot().error?.message).toContain("remains unavailable");
    expect(harness.reconnects).toHaveLength(0);

    stream.retry();
    expect(harness.sockets).toHaveLength(6);
    expect(stream.getSnapshot().connectionState).toBe("connecting");
    stream.stop();
  });

  it("rejects conflicting duplicate sequences instead of replacing canonical history", async () => {
    const harness = createHarness(vi.fn<FetchEvents>().mockResolvedValue([eventFixture(1)]));
    const stream = new CanonicalTeamSessionEventStream(SESSION_ID, undefined, harness.dependencies);
    stream.start();
    harness.sockets[0]!.receive(snapshotEnvelope(1));
    await vi.waitFor(() => expect(stream.getSnapshot().connectionState).toBe("live"));

    harness.sockets[0]!.receive({
      type: "session.event",
      event: { ...eventFixture(1), eventId: "conflicting-event" },
    });
    expect(stream.getSnapshot()).toMatchObject({ connectionState: "idle" });
    expect(stream.getSnapshot().events.map((event) => event.sequence)).toEqual([1]);
    stream.stop();
  });
});

function createHarness(fetchEvents: FetchEvents) {
  const sockets: FakeWebSocket[] = [];
  const reconnects: Array<() => void> = [];
  const dependencies: Partial<TeamSessionEventStreamDependencies> = {
    fetchEvents,
    createWebSocket: () => {
      const socket = new FakeWebSocket();
      sockets.push(socket);
      return socket as unknown as WebSocket;
    },
    resolveWebSocketUrl: () => `wss://terminal.test/ws/team-sessions/${SESSION_ID}/events`,
    setTimeout: ((handler: TimerHandler) => {
      if (typeof handler === "function") {
        reconnects.push(() => (handler as () => void)());
      }
      return reconnects.length as unknown as ReturnType<typeof globalThis.setTimeout>;
    }) as unknown as typeof globalThis.setTimeout,
    clearTimeout: vi.fn() as unknown as typeof globalThis.clearTimeout,
  };
  return {
    sockets,
    reconnects,
    dependencies,
    runNextReconnect(): void {
      const reconnect = reconnects.shift();
      if (!reconnect) throw new Error("No reconnect is scheduled");
      reconnect();
    },
  };
}

class FakeWebSocket {
  onopen: ((this: WebSocket, event: Event) => unknown) | null = null;
  onmessage: ((this: WebSocket, event: MessageEvent) => unknown) | null = null;
  onerror: ((this: WebSocket, event: Event) => unknown) | null = null;
  onclose: ((this: WebSocket, event: CloseEvent) => unknown) | null = null;

  receive(value: unknown): void {
    this.onmessage?.call(
      this as unknown as WebSocket,
      {
        data: JSON.stringify(value),
      } as MessageEvent
    );
  }

  closeFromServer(code: number): void {
    this.onclose?.call(this as unknown as WebSocket, { code } as CloseEvent);
  }

  close(): void {
    // The stream detaches callbacks before closing its side of the socket.
  }
}

function snapshotEnvelope(latestSequence: number) {
  return {
    type: "session.snapshot",
    session: { sessionId: SESSION_ID, latestSequence },
  };
}

function eventEnvelope(sequence: number) {
  return { type: "session.event", event: eventFixture(sequence) };
}

function eventFixture(sequence: number): TeamSessionEvent {
  return {
    schemaVersion: 1,
    eventId: `event-${sequence}`,
    sessionId: SESSION_ID,
    sequence,
    type: "comment.added",
    occurredAtMs: 1_000 + sequence,
    actor: { kind: "human", userId: "alice", displayName: "Alice" },
    sourceAdapter: "web",
    payload: { commentId: `comment-${sequence}`, body: `Comment ${sequence}` },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}
