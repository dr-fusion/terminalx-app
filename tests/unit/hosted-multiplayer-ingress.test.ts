import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import WebSocket from "ws";
import { afterEach, describe, expect, it } from "vitest";
import {
  createHostedMultiplayerIngress,
  HostedMultiplayerIngressError,
} from "../../server/hosted-multiplayer-ingress";
import type { HostedMultiplayerIngress } from "@/lib/runtime/hosted-multiplayer-service";
import { digestHostedRuntimeAssignmentPlan } from "@/lib/runtime/hosted-runtime-adapter";
import type {
  HostedAssignmentLookup,
  HostedAssignmentPlanSource,
  HostedRuntimeAssignmentPlan,
} from "@/lib/runtime/hosted-runtime-control-plane";
import type {
  HostedTerminalAdapter,
  HostedTerminalConnection,
} from "@/lib/runtime/hosted-terminal";
import type { TeamSessionTerminalKernel } from "@/lib/team-session-terminal-gateway";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type FollowSessionOptions,
  type SessionEvent,
  type SessionGetQuery,
  type SessionTerminalAuthorizationQuery,
  type SessionView,
  type TerminalAuthorization,
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
const PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFf4/tX72aI7ln4nW9XH7z9xWMNJm9Q7A7jTZSlmWyNg=\n-----END PUBLIC KEY-----\n";
const openHarnesses = new Set<IngressHarness>();

afterEach(async () => {
  await Promise.all([...openHarnesses].map((harness) => harness.close()));
  openHarnesses.clear();
});

describe("hosted multiplayer ingress composition", () => {
  it("composes the exact hosted plan, gateway, PTY, and canonical WebSocket", async () => {
    const harness = await createHarness();
    const client = await connectClient(`${harness.wsUrl}/terminal?cols=100&rows=30`);

    const ready = await client.nextJson();
    expect(ready).toMatchObject({
      type: "terminal.ready",
      sessionId: SESSION_ID,
      canInput: true,
      controlEpoch: 7,
      runtimeAuthorizationGeneration: 11,
    });
    expect(JSON.stringify(ready)).not.toContain("assignment-1");
    expect(JSON.stringify(ready)).not.toContain("provider");
    expect(harness.hosted.connectCalls[0]).toMatchObject({ cols: 100, rows: 30 });

    client.webSocket.send(
      JSON.stringify({
        type: "input",
        data: "echo integrated\n",
        controlEpoch: 7,
        runtimeAuthorizationGeneration: 11,
      })
    );
    await waitFor(() => harness.hosted.connection.inputs.length === 1);
    expect(harness.hosted.connection.inputs).toEqual(["echo integrated\n"]);

    harness.hosted.connection.emitData("integrated output");
    await expect(client.nextJson()).resolves.toEqual({
      type: "terminal.output",
      data: "integrated output",
    });
  });

  it("serves the canonical chat/event stream through the same ingress", async () => {
    const kernel = new FakeKernel();
    kernel.followImplementation = async function* (options) {
      yield {
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        eventId: "event-comment-24",
        sessionId: SESSION_ID,
        sequence: 24,
        type: "comment.added",
        occurredAtMs: 2_000,
        actor: { kind: "human", userId: ACTOR.userId, displayName: ACTOR.displayName },
        source: { scope: "private:adapter", key: "private-event-key" },
        payload: {
          commentId: "comment-24",
          body: "A proper hosted chat message",
          providerSandboxId: "must-not-leak",
        },
      };
      yield* waitForAbort(options.signal);
    };
    const harness = await createHarness({ kernel });
    const client = await connectClient(`${harness.wsUrl}/events`);

    await expect(client.nextJson()).resolves.toMatchObject({
      type: "session.snapshot",
      session: { sessionId: SESSION_ID, status: "active", latestSequence: 23 },
    });
    const message = await client.nextJson();
    expect(message).toMatchObject({
      type: "session.event",
      event: {
        type: "comment.added",
        sequence: 24,
        payload: { commentId: "comment-24", body: "A proper hosted chat message" },
      },
    });
    expect(JSON.stringify(message)).not.toContain("must-not-leak");
    expect(JSON.stringify(message)).not.toContain("private-event-key");
  });

  it("withdraws readiness and destroys active terminals on the service abort", async () => {
    const harness = await createHarness();
    const client = await connectClient(`${harness.wsUrl}/terminal`);
    await client.nextJson();

    harness.lifetime.abort();
    await expect(client.closed).resolves.toMatchObject({ code: 1006 });
    await waitFor(() => harness.hosted.connection.destroyed === 1);
    expect(harness.ingress.readiness()).toBe(false);
    await harness.ingress.close();
  });

  it("rejects malformed raw ingress and invalid construction capabilities fail closed", async () => {
    const harness = await createHarness();
    await expect(
      harness.ingress.handle(
        { request: {}, socket: {}, head: new Uint8Array() },
        harness.lifetime.signal
      )
    ).resolves.toBe(false);
    await expect(
      harness.ingress.handle(
        new Proxy({ request: {}, socket: {}, head: new Uint8Array() }, {}),
        harness.lifetime.signal
      )
    ).resolves.toBe(false);
    expect(harness.hosted.connectCalls).toEqual([]);

    expect(() =>
      createHostedMultiplayerIngress(new Proxy({ reportInternalError: () => undefined }, {}))
    ).toThrow(HostedMultiplayerIngressError);
  });
});

class FakeKernel implements TeamSessionTerminalKernel {
  session: SessionView = makeSession();
  followImplementation: (options: FollowSessionOptions) => AsyncIterable<SessionEvent> = (
    options
  ) => waitForAbort(options.signal);

  async inspect(query: SessionGetQuery): Promise<SessionView | null>;
  async inspect(query: SessionTerminalAuthorizationQuery): Promise<TerminalAuthorization>;
  async inspect(
    query: SessionGetQuery | SessionTerminalAuthorizationQuery
  ): Promise<SessionView | null | TerminalAuthorization> {
    if (query.type === "session.get") return this.session;
    return {
      sessionId: SESSION_ID,
      action: query.action,
      allowed: true,
      participantId: "participant-alice",
      controlEpoch: 7,
      runtimeAuthorizationGeneration: 11,
    };
  }

  performTerminalMutation(_query: SessionTerminalAuthorizationQuery, mutation: () => void): void {
    mutation();
  }

  follow(options: FollowSessionOptions): AsyncIterable<SessionEvent> {
    return this.followImplementation(options);
  }
}

class FakePlans implements HostedAssignmentPlanSource {
  current = true;
  constructor(readonly plan: HostedRuntimeAssignmentPlan) {}
  resolve(_lookup: HostedAssignmentLookup): HostedRuntimeAssignmentPlan | null {
    return this.current ? this.plan : null;
  }
  isCurrent(_lookup: HostedAssignmentLookup): boolean {
    return this.current;
  }
}

class FakeHostedTerminalAdapter implements HostedTerminalAdapter {
  readonly connection: FakeHostedTerminalConnection;
  readonly connectCalls: Array<Parameters<HostedTerminalAdapter["connect"]>[0]> = [];

  constructor(binding: HostedTerminalConnection["binding"]) {
    this.connection = new FakeHostedTerminalConnection(binding);
  }

  async connect(
    options: Parameters<HostedTerminalAdapter["connect"]>[0]
  ): Promise<HostedTerminalConnection> {
    this.connectCalls.push(options);
    return this.connection;
  }
}

class FakeHostedTerminalConnection implements HostedTerminalConnection {
  readonly dataListeners = new Set<(data: string) => void>();
  readonly exitListeners = new Set<() => void>();
  readonly inputs: string[] = [];
  destroyed = 0;

  constructor(readonly binding: HostedTerminalConnection["binding"]) {}

  onData(listener: (data: string) => void): { dispose(): void } {
    this.dataListeners.add(listener);
    return { dispose: () => this.dataListeners.delete(listener) };
  }

  onExit(listener: () => void): { dispose(): void } {
    this.exitListeners.add(listener);
    return { dispose: () => this.exitListeners.delete(listener) };
  }

  async input(data: string): Promise<void> {
    this.inputs.push(data);
  }

  async resize(): Promise<void> {}
  async interrupt(): Promise<void> {}

  async destroy(): Promise<void> {
    this.destroyed += 1;
  }

  emitData(data: string): void {
    for (const listener of this.dataListeners) listener(data);
  }
}

interface IngressHarness {
  readonly server: Server;
  readonly wsUrl: string;
  readonly ingress: HostedMultiplayerIngress;
  readonly lifetime: AbortController;
  readonly kernel: FakeKernel;
  readonly hosted: FakeHostedTerminalAdapter;
  close(): Promise<void>;
}

async function createHarness(options: { kernel?: FakeKernel } = {}): Promise<IngressHarness> {
  const plan = makePlan();
  const binding = Object.freeze({
    kind: "hosted" as const,
    binding: plan.binding,
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(plan),
    incarnation: plan.incarnation,
    specificationDigest: plan.specificationDigest,
  });
  const plans = new FakePlans(plan);
  const kernel = options.kernel ?? new FakeKernel();
  const hosted = new FakeHostedTerminalAdapter(binding);
  const ingress = createHostedMultiplayerIngress({
    resolveActor: actorResolver,
    credentialCheckIntervalMs: 1_000,
    eventPollIntervalMs: 20,
    monitorPollIntervalMs: 20,
  });
  const lifetime = new AbortController();
  await ingress.start(
    {
      teamSessions: kernel as never,
      hostedAssignmentPlans: plans,
      hostedTerminal: hosted,
      isRuntimeWriteAllowed: () => true,
    },
    lifetime.signal
  );
  const server = createServer((_request, response) => response.writeHead(404).end());
  server.on("upgrade", (request, socket, head) => {
    void ingress
      .handle(Object.freeze({ request, socket, head: new Uint8Array(head) }), lifetime.signal)
      .then((handled) => {
        if (!handled) socket.destroy();
      });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  let closed = false;
  const harness: IngressHarness = {
    server,
    wsUrl: `ws://127.0.0.1:${address.port}/ws/team-sessions/${SESSION_ID}`,
    ingress,
    lifetime,
    kernel,
    hosted,
    async close() {
      if (closed) return;
      closed = true;
      lifetime.abort();
      let failure: unknown;
      try {
        await ingress.close();
      } catch (error) {
        failure = error;
      }
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (failure !== undefined) throw failure;
    },
  };
  openHarnesses.add(harness);
  return harness;
}

function makeSession(): SessionView {
  return {
    sessionId: SESSION_ID,
    teamId: "team-1",
    projectId: "project-1",
    name: "Hosted Team Session",
    status: "active",
    steeringPolicy: "shared",
    accessRevision: 5,
    assigneeRevision: 2,
    supervisionRevision: 2,
    steeringRevision: 3,
    controlRevision: 6,
    controlEpoch: 7,
    runStateRevision: 1,
    runtime: {
      kind: "daytona",
      isolation: "isolated-hosted",
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
    invitations: [],
    handoffs: [],
    latestSequence: 23,
    createdAtMs: 1_000,
  };
}

function makePlan(): HostedRuntimeAssignmentPlan {
  return {
    binding: {
      teamId: "team-1",
      projectId: "project-1",
      sessionId: SESSION_ID,
      runtimeAssignmentId: "assignment-1",
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-1",
      sandboxGeneration: 1,
      runtimePrincipalId: "principal-1",
    },
    runtimeAuthorizationGeneration: 11,
    incarnation: "a".repeat(64),
    specificationDigest: "b".repeat(64),
    effectEnforcerPolicyDigest: "c".repeat(64),
    adapterConfigurationRef: "daytona-adapter:v1",
    observation: {
      keyProvisioningRef: "observation-key-provisioning:assignment-1:g11",
      issuerKeyId: "observation-key:assignment-1:g11",
      publicKeySpkiPem: PUBLIC_KEY,
    },
    isolation: {
      isolationPolicyDigest: "c".repeat(64),
      publicAccess: false,
      hostMounts: false,
      linkedSandbox: false,
      rootIdentity: false,
      network: { mode: "blocked", policyDigest: "d".repeat(64), allowedDestinations: [] },
      resources: { cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 512 },
    },
    capabilities: {
      isolatedExecution: true,
      brokeredCredentials: false,
      proxyOnlyEgress: false,
      checkpoints: true,
      yoloEligible: false,
    },
  };
}

async function actorResolver(headers: RequestHeaders): Promise<RequestActor | null> {
  return headers.get("authorization") === "Bearer valid" ? ACTOR : null;
}

interface TestClient {
  readonly webSocket: WebSocket;
  readonly closed: Promise<{ code: number; reason: string }>;
  nextJson(): Promise<Record<string, unknown>>;
}

function connectClient(url: string): Promise<TestClient> {
  return new Promise((resolve, reject) => {
    const webSocket = new WebSocket(url, { headers: { authorization: "Bearer valid" } });
    const messages: Array<Record<string, unknown>> = [];
    const waiters: Array<(value: Record<string, unknown>) => void> = [];
    const closed = new Promise<{ code: number; reason: string }>((resolveClosed) => {
      webSocket.once("close", (code, reason) =>
        resolveClosed({ code, reason: reason.toString("utf8") })
      );
    });
    webSocket.on("message", (raw) => {
      const value = JSON.parse(raw.toString()) as Record<string, unknown>;
      const waiter = waiters.shift();
      if (waiter) waiter(value);
      else messages.push(value);
    });
    webSocket.once("open", () =>
      resolve({
        webSocket,
        closed,
        nextJson: () => {
          const message = messages.shift();
          return message
            ? Promise.resolve(message)
            : new Promise((resolveMessage) => waiters.push(resolveMessage));
        },
      })
    );
    webSocket.once("error", reject);
  });
}

async function* waitForAbort(signal: AbortSignal | undefined): AsyncIterable<SessionEvent> {
  if (signal?.aborted) return;
  await new Promise<void>((resolve) =>
    signal?.addEventListener("abort", () => resolve(), { once: true })
  );
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("Timed out waiting for condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
