import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import WebSocket from "ws";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createTeamSessionWebSockets,
  type CanonicalTerminalConnection,
  type CanonicalTerminalGateway,
  type CanonicalTerminalPty,
  type CanonicalTerminalPtyAdapter,
  type TeamSessionEventKernel,
  type TeamSessionWebSockets,
} from "../../server/team-session-websockets";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type FollowSessionOptions,
  type SessionEvent,
  type SessionGetQuery,
  type SessionView,
} from "@/lib/team-sessions";
import type { RequestActor, RequestHeaders } from "@/lib/request-actor";

const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ACTOR: RequestActor = {
  kind: "human",
  userId: "user-alice",
  username: "alice",
  displayName: "Alice",
  legacyRole: "member",
};

const openHarnesses = new Set<TestHarness>();

afterEach(async () => {
  delete process.env.TERMINALX_PUBLIC_URL;
  delete process.env.TERMINALX_TRUST_PROXY_HEADERS;
  await Promise.all([...openHarnesses].map((harness) => harness.close()));
  openHarnesses.clear();
});

describe("canonical Team Session WebSockets", () => {
  it("authenticates only from an immutable cookie/bearer header snapshot", async () => {
    const seenHeaders: Array<{
      authorization: string | null;
      cookie: string | null;
      projected: string | null;
    }> = [];
    const harness = await createHarness({
      resolveActor: async (headers) => {
        seenHeaders.push({
          authorization: headers.get("authorization"),
          cookie: headers.get("cookie"),
          projected: headers.get("x-user-id"),
        });
        return defaultActorResolver(headers);
      },
    });

    await expectUpgradeStatus(`${harness.wsUrl}/terminal`, {}, 401);
    await expectUpgradeStatus(
      `${harness.wsUrl}/terminal`,
      { "x-user-id": ACTOR.userId, "x-user-role": "admin" },
      401
    );

    const client = await harness.connect("terminal", {
      authorization: "Bearer valid",
      "x-user-id": "attacker-selected-user",
    });
    const ready = await client.nextJson();
    expect(ready).toMatchObject({
      type: "terminal.ready",
      sessionId: SESSION_ID,
      canInput: true,
    });
    expect(JSON.stringify(ready)).not.toContain("team-session-runtime");
    expect(JSON.stringify(ready)).not.toContain("terminalx-canonical");
    expect(seenHeaders.at(-1)).toEqual({
      authorization: "Bearer valid",
      cookie: null,
      projected: null,
    });
  });

  it("attaches the PTY through the socket derived for the admitted canonical Session", async () => {
    const resolveTmuxSocketName = vi.fn(
      (sessionId: string) => `terminalx-${sessionId.replaceAll("-", "").slice(0, 16)}`
    );
    const harness = await createHarness({ resolveTmuxSocketName });
    const client = await harness.connect("terminal", bearerHeaders());

    await expect(client.nextJson()).resolves.toMatchObject({ type: "terminal.ready" });
    expect(resolveTmuxSocketName).toHaveBeenCalledOnce();
    expect(resolveTmuxSocketName).toHaveBeenCalledWith(SESSION_ID);
    expect(harness.pty.created[0]?.binding).toMatchObject({
      teamSessionId: SESSION_ID,
      tmuxSocketName: "terminalx-3333333333334333",
    });
  });

  it("fails closed when a canonical Session socket cannot be resolved safely", async () => {
    const harness = await createHarness({ resolveTmuxSocketName: () => "bad/socket" });
    const client = await harness.connect("terminal", bearerHeaders());

    await expect(client.closed).resolves.toMatchObject({ code: 1008 });
    expect(harness.pty.created).toEqual([]);
  });

  it("rejects URL credentials before invoking authentication", async () => {
    const resolveActor = vi.fn(defaultActorResolver);
    const harness = await createHarness({ resolveActor });

    await expectUpgradeStatus(`${harness.wsUrl}/terminal?token=valid`, {}, 400);
    await expectUpgradeStatus(`${harness.wsUrl}/events?TOKEN=valid`, {}, 400);
    expect(resolveActor).not.toHaveBeenCalled();
  });

  it("requires same-origin cookie upgrades and trusts forwarding only when configured", async () => {
    const harness = await createHarness();

    await expectUpgradeStatus(
      `${harness.wsUrl}/terminal`,
      { cookie: "terminalx-session=valid" },
      403
    );
    await expectUpgradeStatus(
      `${harness.wsUrl}/terminal`,
      {
        cookie: "terminalx-session=valid",
        origin: "https://app.example",
        "x-forwarded-host": "app.example",
        "x-forwarded-proto": "https",
      },
      403
    );

    process.env.TERMINALX_TRUST_PROXY_HEADERS = "true";
    const client = await harness.connect("terminal", {
      cookie: "terminalx-session=valid",
      origin: "https://app.example",
      "x-forwarded-host": "app.example",
      "x-forwarded-proto": "https",
    });
    await expect(client.nextJson()).resolves.toMatchObject({ type: "terminal.ready" });
  });

  it("uses TERMINALX_PUBLIC_URL as the explicit browser origin boundary", async () => {
    process.env.TERMINALX_PUBLIC_URL = "https://terminal.example/base/path";
    const harness = await createHarness();

    const client = await harness.connect("events", {
      cookie: "terminalx-session=valid",
      origin: "https://terminal.example",
    });
    await expect(client.nextJson()).resolves.toMatchObject({ type: "session.snapshot" });
  });

  it("rejects stale client fences before a terminal mutation can run", async () => {
    const harness = await createHarness();
    const client = await harness.connect("terminal", bearerHeaders());
    await client.nextJson();

    client.webSocket.send(
      JSON.stringify({
        type: "input",
        data: "whoami\n",
        controlEpoch: 6,
        runtimeAuthorizationGeneration: 11,
      })
    );

    await expect(client.closed).resolves.toMatchObject({ code: 1008 });
    expect(harness.connection.performCalls).toEqual([]);
    expect(harness.pty.writes).toEqual([]);
    expect(harness.pty.destroyed).toHaveLength(1);
  });

  it("strictly validates the JSON protocol and bounded input", async () => {
    const extraFieldHarness = await createHarness();
    const extraFieldClient = await extraFieldHarness.connect("terminal", bearerHeaders());
    await extraFieldClient.nextJson();
    extraFieldClient.webSocket.send(
      JSON.stringify({
        type: "input",
        data: "pwd\n",
        controlEpoch: 7,
        runtimeAuthorizationGeneration: 11,
        arbitrary: true,
      })
    );
    await expect(extraFieldClient.closed).resolves.toMatchObject({ code: 1008 });
    expect(extraFieldHarness.pty.writes).toEqual([]);

    const oversizedHarness = await createHarness();
    const oversizedClient = await oversizedHarness.connect("terminal", bearerHeaders());
    await oversizedClient.nextJson();
    oversizedClient.webSocket.send(
      JSON.stringify({
        type: "input",
        data: "x".repeat(16 * 1024 + 1),
        controlEpoch: 7,
        runtimeAuthorizationGeneration: 11,
      })
    );
    await expect(oversizedClient.closed).resolves.toMatchObject({ code: 1008 });
    expect(oversizedHarness.pty.writes).toEqual([]);
  });

  it("serializes messages and re-verifies credentials immediately before fenced effects", async () => {
    const order: string[] = [];
    let resolverCalls = 0;
    const firstMutationCredential = deferred<void>();
    const harness = await createHarness({
      resolveActor: async (headers) => {
        resolverCalls += 1;
        // Initial upgrade, post-upgrade admission, and pre-attach checks are 1..3.
        if (resolverCalls === 4) {
          order.push("credential:first:start");
          await firstMutationCredential.promise;
          order.push("credential:first:verified");
        } else if (resolverCalls === 5) {
          order.push("credential:second:verified");
        }
        return defaultActorResolver(headers);
      },
    });
    harness.connection.onPerform = (action, effect) => {
      order.push(`perform:${action}:start`);
      effect();
      order.push(`perform:${action}:end`);
    };
    harness.pty.onWrite = (_pty, data) => order.push(`write:${data}`);

    const client = await harness.connect("terminal", bearerHeaders());
    await client.nextJson();
    client.webSocket.send(terminalInput("first"));
    client.webSocket.send(terminalInput("second"));

    await waitFor(() => order.includes("credential:first:start"));
    expect(resolverCalls).toBe(4);
    expect(harness.connection.performCalls).toEqual([]);
    firstMutationCredential.resolve();

    await waitFor(() => harness.pty.writes.length === 2);
    expect(harness.pty.writes).toEqual(["first", "second"]);
    expect(order).toEqual([
      "credential:first:start",
      "credential:first:verified",
      "perform:input:start",
      "write:first",
      "perform:input:end",
      "credential:second:verified",
      "perform:input:start",
      "write:second",
      "perform:input:end",
    ]);
  });

  it("attaches observers through a read-only tmux client and never attempts writes", async () => {
    const connection = new FakeTerminalConnection();
    connection.canWrite = false;
    const harness = await createHarness({ connection });
    const client = await harness.connect("terminal", bearerHeaders());

    await expect(client.nextJson()).resolves.toMatchObject({
      type: "terminal.ready",
      canInput: false,
    });
    expect(harness.pty.created[0]?.binding.readOnly).toBe(true);
    client.webSocket.send(terminalInput("forbidden"));
    await expect(client.closed).resolves.toMatchObject({ code: 1008 });
    expect(connection.performCalls).toEqual([]);
    expect(harness.pty.writes).toEqual([]);
  });

  it("re-checks Session admission after upgrading and before creating a PTY", async () => {
    const connection = new FakeTerminalConnection();
    let opens = 0;
    const terminalGateway: CanonicalTerminalGateway = {
      async open() {
        opens += 1;
        if (opens === 2) throw new Error("private revocation reason");
        return connection;
      },
    };
    const harness = await createHarness({ connection, terminalGateway });
    const client = await harness.connect("terminal", bearerHeaders());

    await expect(client.closed).resolves.toMatchObject({ code: 1008 });
    expect(opens).toBe(2);
    expect(harness.pty.created).toEqual([]);
  });

  it("rejects a gateway result that is not bound to the requested canonical Session", async () => {
    const connection = new FakeTerminalConnection("44444444-4444-4444-8444-444444444444");
    const harness = await createHarness({ connection });
    const client = await harness.connect("terminal", bearerHeaders());

    await expect(client.closed).resolves.toMatchObject({ code: 1008 });
    expect(harness.pty.created).toEqual([]);
  });

  it("destroys the PTY promptly on JWT revocation or gateway invalidation", async () => {
    let credentialActive = true;
    const revokedHarness = await createHarness({
      credentialCheckIntervalMs: 20,
      resolveActor: async (headers) => (credentialActive ? defaultActorResolver(headers) : null),
    });
    const revokedClient = await revokedHarness.connect("terminal", bearerHeaders());
    await revokedClient.nextJson();
    credentialActive = false;
    await expect(revokedClient.closed).resolves.toMatchObject({ code: 1008 });
    expect(revokedHarness.pty.destroyed).toHaveLength(1);

    const invalidatedHarness = await createHarness();
    const invalidatedClient = await invalidatedHarness.connect("terminal", bearerHeaders());
    await invalidatedClient.nextJson();
    invalidatedHarness.connection.invalidate();
    await expect(invalidatedClient.closed).resolves.toMatchObject({ code: 1008 });
    expect(invalidatedHarness.pty.destroyed).toHaveLength(1);
  });

  it("authorizes event admission before upgrade and again before sending a snapshot", async () => {
    const deniedKernel = new FakeEventKernel();
    deniedKernel.session = null;
    const deniedHarness = await createHarness({ kernel: deniedKernel });
    await expectUpgradeStatus(`${deniedHarness.wsUrl}/events`, bearerHeaders(), 403);
    expect(deniedKernel.follows).toEqual([]);

    const revokedKernel = new FakeEventKernel();
    let reads = 0;
    revokedKernel.inspectOverride = () => {
      reads += 1;
      return reads === 1 ? makeSession() : null;
    };
    const revokedHarness = await createHarness({ kernel: revokedKernel });
    const revokedClient = await revokedHarness.connect("events", bearerHeaders());
    await expect(revokedClient.closed).resolves.toMatchObject({ code: 1008 });
    expect(revokedClient.messages).toEqual([]);
    expect(revokedKernel.follows).toEqual([]);
  });

  it("streams a minimized snapshot and redacted ordered events from latestSequence", async () => {
    const kernel = new FakeEventKernel();
    kernel.followImplementation = async function* () {
      yield makeEvent(24, {
        visible: "ok",
        apiToken: "must-not-leak",
        apiKey: "must-not-leak",
        authorization: "must-not-leak",
        nested: [{ privateKey: "must-not-leak", safe: true }],
        runtimeAuthorizationGeneration: 12,
      });
      await new Promise<void>(() => undefined);
    };
    const harness = await createHarness({ kernel });
    const client = await harness.connect("events", bearerHeaders());

    const snapshot = await client.nextJson();
    expect(snapshot).toMatchObject({
      type: "session.snapshot",
      session: {
        sessionId: SESSION_ID,
        latestSequence: 23,
        runtime: { authorizationGeneration: 11, authorizationState: "enforced" },
      },
    });
    const snapshotSession = asRecord(snapshot.session);
    expect(snapshotSession).not.toHaveProperty("invitations");
    expect(snapshotSession.runtime).not.toHaveProperty("tmuxName");

    const envelope = await client.nextJson();
    expect(envelope).toMatchObject({
      type: "session.event",
      event: {
        sessionId: SESSION_ID,
        sequence: 24,
        sourceAdapter: "internal",
        payload: {
          visible: "ok",
          apiToken: "[redacted]",
          apiKey: "[redacted]",
          authorization: "[redacted]",
          nested: [{ privateKey: "[redacted]", safe: true }],
          runtimeAuthorizationGeneration: 12,
        },
      },
    });
    const publicEvent = asRecord(envelope.event);
    expect(Object.keys(publicEvent).sort()).toEqual([
      "actor",
      "eventId",
      "occurredAtMs",
      "payload",
      "schemaVersion",
      "sequence",
      "sessionId",
      "sourceAdapter",
      "type",
    ]);
    expect(publicEvent.actor).toEqual({
      kind: "human",
      userId: ACTOR.userId,
      displayName: ACTOR.displayName,
    });
    expect(publicEvent).not.toHaveProperty("source");
    expect(kernel.follows[0]).toMatchObject({
      sessionId: SESSION_ID,
      afterSequence: 23,
      actor: { kind: "human", userId: ACTOR.userId },
    });

    client.webSocket.send(JSON.stringify({ type: "client-message" }));
    await expect(client.closed).resolves.toMatchObject({ code: 1008 });
  });

  it("keeps the event stream available for historical Comments after a Session ends", async () => {
    const kernel = new FakeEventKernel();
    kernel.session = { ...makeSession(), status: "ended" };
    kernel.followImplementation = async function* () {
      yield {
        ...makeEvent(24, { commentId: "comment-after-end", body: "Postmortem note" }),
        type: "comment.added",
      };
      await new Promise<void>(() => undefined);
    };
    const harness = await createHarness({ kernel });
    const client = await harness.connect("events", bearerHeaders());

    await expect(client.nextJson()).resolves.toMatchObject({
      type: "session.snapshot",
      session: { status: "ended", latestSequence: 23 },
    });
    await expect(client.nextJson()).resolves.toMatchObject({
      type: "session.event",
      event: {
        type: "comment.added",
        sequence: 24,
        payload: { commentId: "comment-after-end", body: "Postmortem note" },
      },
    });

    client.webSocket.send(JSON.stringify({ type: "client-message" }));
    await expect(client.closed).resolves.toMatchObject({ code: 1008 });
  });

  it("fails closed when the authorized event follower completes", async () => {
    const kernel = new FakeEventKernel();
    kernel.followImplementation = async function* () {
      yield makeEvent(24, { visible: true });
    };
    const harness = await createHarness({ kernel });
    const client = await harness.connect("events", bearerHeaders());

    await client.nextJson();
    await client.nextJson();
    await expect(client.closed).resolves.toMatchObject({ code: 1008 });
  });
});

class FakeTerminalConnection implements CanonicalTerminalConnection {
  constructor(readonly sessionId = SESSION_ID) {}

  readonly tmuxName = "team-session-runtime";
  readonly controlEpoch = 7;
  readonly runtimeAuthorizationGeneration = 11;
  canWrite = true;
  readonly performCalls: string[] = [];
  onPerform: ((action: "input" | "resize" | "interrupt", effect: () => void) => void) | undefined;
  private monitorResolution = deferred<unknown>();

  async canPerform(): Promise<boolean> {
    return this.canWrite;
  }

  perform(action: "input" | "resize" | "interrupt", effect: () => void): void {
    this.performCalls.push(action);
    if (this.onPerform) {
      this.onPerform(action, effect);
      return;
    }
    effect();
  }

  monitor(options: { signal?: AbortSignal } = {}): Promise<unknown> {
    if (options.signal?.aborted) return Promise.resolve(null);
    options.signal?.addEventListener("abort", () => this.monitorResolution.resolve(null), {
      once: true,
    });
    return this.monitorResolution.promise;
  }

  invalidate(): void {
    this.monitorResolution.resolve({ kind: "terminal-authorization-changed" });
  }
}

class FakePty implements CanonicalTerminalPty {
  readonly dataListeners = new Set<(data: string) => void>();
  readonly exitListeners = new Set<() => void>();

  onData(listener: (data: string) => void): { dispose(): void } {
    this.dataListeners.add(listener);
    return { dispose: () => this.dataListeners.delete(listener) };
  }

  onExit(listener: () => void): { dispose(): void } {
    this.exitListeners.add(listener);
    return { dispose: () => this.exitListeners.delete(listener) };
  }
}

class FakePtyAdapter implements CanonicalTerminalPtyAdapter {
  readonly created: Array<Parameters<CanonicalTerminalPtyAdapter["create"]>[0]> = [];
  readonly handles: FakePty[] = [];
  readonly writes: string[] = [];
  readonly resizes: Array<{ cols: number; rows: number }> = [];
  readonly interrupted: CanonicalTerminalPty[] = [];
  readonly destroyed: CanonicalTerminalPty[] = [];
  onWrite: ((pty: CanonicalTerminalPty, data: string) => void) | undefined;

  create(options: Parameters<CanonicalTerminalPtyAdapter["create"]>[0]): CanonicalTerminalPty {
    this.created.push(options);
    const handle = new FakePty();
    this.handles.push(handle);
    return handle;
  }

  write(pty: CanonicalTerminalPty, data: string): void {
    this.writes.push(data);
    this.onWrite?.(pty, data);
  }

  resize(_pty: CanonicalTerminalPty, cols: number, rows: number): void {
    this.resizes.push({ cols, rows });
  }

  interrupt(pty: CanonicalTerminalPty): void {
    this.interrupted.push(pty);
  }

  destroy(pty: CanonicalTerminalPty): void {
    if (!this.destroyed.includes(pty)) this.destroyed.push(pty);
  }
}

class FakeEventKernel implements TeamSessionEventKernel {
  session: SessionView | null = makeSession();
  readonly queries: SessionGetQuery[] = [];
  readonly follows: FollowSessionOptions[] = [];
  inspectOverride: ((query: SessionGetQuery) => SessionView | null) | undefined;
  followImplementation: (options: FollowSessionOptions) => AsyncIterable<SessionEvent> = (
    options
  ) => waitForAbort(options.signal);

  async inspect(query: SessionGetQuery): Promise<SessionView | null> {
    this.queries.push(query);
    return this.inspectOverride ? this.inspectOverride(query) : this.session;
  }

  follow(options: FollowSessionOptions): AsyncIterable<SessionEvent> {
    this.follows.push(options);
    return this.followImplementation(options);
  }
}

interface HarnessOptions {
  connection?: FakeTerminalConnection;
  terminalGateway?: CanonicalTerminalGateway;
  kernel?: FakeEventKernel;
  pty?: FakePtyAdapter;
  resolveActor?: (headers: RequestHeaders) => Promise<RequestActor | null>;
  credentialCheckIntervalMs?: number;
  resolveTmuxSocketName?: (sessionId: string) => string;
}

interface TestHarness {
  server: Server;
  transport: TeamSessionWebSockets;
  wsUrl: string;
  connection: FakeTerminalConnection;
  kernel: FakeEventKernel;
  pty: FakePtyAdapter;
  connect(kind: "terminal" | "events", headers: Record<string, string>): Promise<TestClient>;
  close(): Promise<void>;
}

async function createHarness(options: HarnessOptions = {}): Promise<TestHarness> {
  const connection = options.connection ?? new FakeTerminalConnection();
  const kernel = options.kernel ?? new FakeEventKernel();
  const pty = options.pty ?? new FakePtyAdapter();
  const terminalGateway =
    options.terminalGateway ??
    ({
      open: async () => connection,
    } satisfies CanonicalTerminalGateway);
  const transport = createTeamSessionWebSockets({
    teamSessions: kernel,
    terminalGateway,
    pty,
    shell: "/bin/bash",
    resolveTmuxSocketName:
      options.resolveTmuxSocketName ?? ((sessionId) => `terminalx-${sessionId.slice(0, 8)}`),
    resolveActor: options.resolveActor ?? defaultActorResolver,
    credentialCheckIntervalMs: options.credentialCheckIntervalMs ?? 1_000,
    eventPollIntervalMs: 20,
  });
  const server = createServer((_request, response) => {
    response.writeHead(404).end();
  });
  server.on("upgrade", (request, socket, head) => {
    void transport
      .handleUpgrade(request, socket, head)
      .then((handled) => {
        if (!handled) socket.destroy();
      })
      .catch(() => socket.destroy());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const wsUrl = `ws://127.0.0.1:${address.port}/ws/team-sessions/${SESSION_ID}`;

  let closed = false;
  const harness: TestHarness = {
    server,
    transport,
    wsUrl,
    connection,
    kernel,
    pty,
    connect: (kind, headers) => connectClient(`${wsUrl}/${kind}`, headers),
    async close() {
      if (closed) return;
      closed = true;
      await transport.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
  openHarnesses.add(harness);
  return harness;
}

interface TestClient {
  webSocket: WebSocket;
  messages: Array<Record<string, unknown>>;
  nextJson(): Promise<Record<string, unknown>>;
  closed: Promise<{ code: number; reason: string }>;
}

async function connectClient(url: string, headers: Record<string, string>): Promise<TestClient> {
  const webSocket = new WebSocket(url, { headers });
  const messages: Array<Record<string, unknown>> = [];
  const waiters: Array<(message: Record<string, unknown>) => void> = [];
  webSocket.on("message", (raw) => {
    const message = asRecord(JSON.parse(raw.toString("utf8")));
    const waiter = waiters.shift();
    if (waiter) waiter(message);
    else messages.push(message);
  });
  const closed = new Promise<{ code: number; reason: string }>((resolve) => {
    webSocket.once("close", (code, reason) => resolve({ code, reason: reason.toString("utf8") }));
  });
  await new Promise<void>((resolve, reject) => {
    webSocket.once("open", resolve);
    webSocket.once("error", reject);
  });
  return {
    webSocket,
    messages,
    nextJson: () =>
      messages.length > 0
        ? Promise.resolve(messages.shift() as Record<string, unknown>)
        : new Promise<Record<string, unknown>>((resolve) => waiters.push(resolve)),
    closed,
  };
}

async function expectUpgradeStatus(
  url: string,
  headers: Record<string, string>,
  expectedStatus: number
): Promise<void> {
  const status = await new Promise<number>((resolve, reject) => {
    const webSocket = new WebSocket(url, { headers });
    let receivedResponse = false;
    webSocket.once("unexpected-response", (_request, response) => {
      receivedResponse = true;
      response.resume();
      resolve(response.statusCode ?? 0);
    });
    webSocket.once("open", () => {
      webSocket.terminate();
      reject(new Error("WebSocket unexpectedly opened"));
    });
    webSocket.once("error", (error) => {
      if (!receivedResponse) reject(error);
    });
  });
  expect(status).toBe(expectedStatus);
}

async function defaultActorResolver(headers: RequestHeaders): Promise<RequestActor | null> {
  const bearer = headers.get("authorization") === "Bearer valid";
  const cookie = /(?:^|;)\s*terminalx-session=valid(?:;|$)/.test(headers.get("cookie") ?? "");
  return bearer || cookie ? ACTOR : null;
}

function bearerHeaders(): Record<string, string> {
  return { authorization: "Bearer valid" };
}

function terminalInput(data: string): string {
  return JSON.stringify({
    type: "input",
    data,
    controlEpoch: 7,
    runtimeAuthorizationGeneration: 11,
  });
}

function makeSession(): SessionView {
  return {
    sessionId: SESSION_ID,
    teamId: "team-1",
    projectId: "project-1",
    name: "Canonical Team Session",
    status: "active",
    steeringPolicy: "shared",
    accessRevision: 5,
    assigneeRevision: 2,
    supervisionRevision: 2,
    steeringRevision: 3,
    controlRevision: 6,
    controlEpoch: 7,
    runtime: {
      kind: "local-tmux",
      isolation: "trusted-shared-host",
      tmuxName: "team-session-runtime",
      yoloEligible: false,
      authorizationGeneration: 11,
      authorizationState: "enforced",
    },
    participants: [
      {
        participantId: "participant-alice",
        userId: ACTOR.userId,
        membershipRole: "member",
        active: true,
        observer: false,
        responsibilities: ["assignee", "steerer", "controller"],
        responsibilityVersions: { assignee: 1, steerer: 1, controller: 1 },
        joinedAtMs: 1_000,
        version: 3,
      },
    ],
    shares: [],
    invitations: [
      {
        invitationId: "private-invitation-id",
        membershipRole: "guest",
        status: "active",
        version: 1,
        expiresAtMs: 99_999,
        createdByUserId: ACTOR.userId,
        createdAtMs: 1_000,
      },
    ],
    handoffs: [],
    latestSequence: 23,
    createdAtMs: 1_000,
  };
}

function makeEvent(sequence: number, payload: Record<string, unknown>): SessionEvent {
  return {
    schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
    eventId: `event-${sequence}`,
    sessionId: SESSION_ID,
    sequence,
    type: "session.test-event",
    occurredAtMs: 2_000,
    actor: { kind: "human", userId: ACTOR.userId, displayName: ACTOR.displayName },
    source: { scope: "private:adapter", key: "private-idempotency-key" },
    payload,
  };
}

async function* waitForAbort(signal: AbortSignal | undefined): AsyncIterable<SessionEvent> {
  if (signal?.aborted) return;
  await new Promise<void>((resolve) =>
    signal?.addEventListener("abort", () => resolve(), { once: true })
  );
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((innerResolve) => {
    resolve = innerResolve;
  });
  return { promise, resolve };
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Expected a JSON object");
  }
  return value as Record<string, unknown>;
}
