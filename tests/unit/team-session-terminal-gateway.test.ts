import { describe, expect, it } from "vitest";
import {
  createTeamSessionTerminalGateway,
  TeamSessionTerminalGatewayError,
  type TeamSessionTerminalKernel,
  type TerminalMutationAction,
} from "@/lib/team-session-terminal-gateway";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type ActorContext,
  type FollowSessionOptions,
  type SessionEvent,
  type SessionGetQuery,
  type SessionTerminalAuthorizationQuery,
  type SessionView,
  type TerminalAuthorization,
} from "@/lib/team-sessions";

const ACTOR = {
  kind: "human",
  userId: "user-alice",
  displayName: "Alice",
} as const satisfies ActorContext;

const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const PARTICIPANT_ID = "participant-alice";

type TerminalQuery = SessionGetQuery | SessionTerminalAuthorizationQuery;

class FakeTeamSessionKernel implements TeamSessionTerminalKernel {
  session: SessionView | null = makeSession();
  readonly queries: TerminalQuery[] = [];
  readonly follows: FollowSessionOptions[] = [];
  inspectFailure: Error | undefined;
  authorizeOverride:
    | ((query: SessionTerminalAuthorizationQuery) => TerminalAuthorization)
    | undefined;
  followImplementation: (options: FollowSessionOptions) => AsyncIterable<SessionEvent> = () =>
    emptyEvents();

  inspect(query: SessionGetQuery): Promise<SessionView | null>;
  inspect(query: SessionTerminalAuthorizationQuery): Promise<TerminalAuthorization>;
  async inspect(query: TerminalQuery): Promise<SessionView | null | TerminalAuthorization> {
    this.queries.push(query);
    if (this.inspectFailure) throw this.inspectFailure;
    if (query.type === "session.get") return this.session;
    if (this.authorizeOverride) return this.authorizeOverride(query);
    return defaultAuthorization(query, this.session);
  }

  follow(options: FollowSessionOptions): AsyncIterable<SessionEvent> {
    this.follows.push(options);
    return this.followImplementation(options);
  }

  performTerminalMutation(query: SessionTerminalAuthorizationQuery, mutation: () => void): void {
    this.queries.push(query);
    if (this.inspectFailure) throw this.inspectFailure;
    const authorization = this.authorizeOverride
      ? this.authorizeOverride(query)
      : defaultAuthorization(query, this.session);
    if (!authorization.allowed) throw new Error("not authorized");
    mutation();
  }
}

describe("canonical Team Session terminal gateway", () => {
  it("opens an observer connection by canonical Session id and resolves its tmux binding", async () => {
    const kernel = new FakeTeamSessionKernel();
    const gateway = createTeamSessionTerminalGateway({ teamSessions: kernel });

    const connection = await gateway.open({ sessionId: SESSION_ID, actor: ACTOR });

    expect(connection).toMatchObject({
      sessionId: SESSION_ID,
      tmuxName: "team-session-runtime",
      controlEpoch: 7,
      runtimeAuthorizationGeneration: 11,
    });
    expect(kernel.queries).toEqual([
      expect.objectContaining({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        type: "session.terminal-authorization",
        sessionId: SESSION_ID,
        action: "observe",
        actor: ACTOR,
      }),
      expect.objectContaining({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        type: "session.get",
        sessionId: SESSION_ID,
        actor: ACTOR,
      }),
    ]);
    expect(kernel.queries.some((query) => query.sessionId === "team-session-runtime")).toBe(false);
  });

  it("permits an observer without any steering responsibility", async () => {
    const kernel = new FakeTeamSessionKernel();
    kernel.session = makeSession({ responsibilities: [], observer: true });

    await expect(
      createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
        sessionId: SESSION_ID,
        actor: ACTOR,
      })
    ).resolves.toMatchObject({ tmuxName: "team-session-runtime" });
  });

  it("never treats a legacy administrator role as Team Session access", async () => {
    const kernel = new FakeTeamSessionKernel();
    kernel.session = null;
    const legacyAdministrator = {
      kind: "human" as const,
      userId: "legacy-admin",
      displayName: "Legacy Admin",
      username: "admin",
      legacyRole: "admin",
    };

    await expectUnavailable(
      createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
        sessionId: SESSION_ID,
        actor: legacyAdministrator,
      })
    );
    expect(kernel.queries[0]?.actor).toEqual({
      kind: "human",
      userId: "legacy-admin",
      displayName: "Legacy Admin",
    });
  });

  it("performs input, resize, and interrupt under immutable captured fences", async () => {
    const kernel = new FakeTeamSessionKernel();
    const connection = await createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
      sessionId: SESSION_ID,
      actor: ACTOR,
    });

    const originalView = kernel.session;
    if (!originalView) throw new Error("Expected a fake Session");
    originalView.controlEpoch = 99;
    originalView.runtime.authorizationGeneration = 101;

    const effects: string[] = [];
    for (const action of ["input", "resize", "interrupt"] as const) {
      connection.perform(action, () => {
        effects.push(action);
      });
    }

    expect(effects).toEqual(["input", "resize", "interrupt"]);
    expect(kernel.queries.slice(2)).toEqual(
      (["input", "resize", "interrupt"] as const).map((action) =>
        expect.objectContaining({
          type: "session.terminal-authorization",
          sessionId: SESSION_ID,
          action,
          expectedControlEpoch: 7,
          expectedRuntimeAuthorizationGeneration: 11,
          actor: ACTOR,
        })
      )
    );
  });

  it.each([
    ["pending Runtime", makeSession({ authorizationState: "pending" })],
    ["quarantined Runtime", makeSession({ authorizationState: "quarantined" })],
    ["ended Session", makeSession({ status: "ended" })],
    ["awaiting Assignee", makeSession({ status: "awaiting_assignee" })],
    ["invalid tmux binding", makeSession({ tmuxName: "bad:target" })],
  ])("fails closed when opening against %s", async (_label, session) => {
    const kernel = new FakeTeamSessionKernel();
    kernel.session = session;

    await expectUnavailable(
      createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
        sessionId: SESSION_ID,
        actor: ACTOR,
      })
    );
  });

  it("does not reveal whether a Session is missing, revoked, or failed privately", async () => {
    const missing = new FakeTeamSessionKernel();
    missing.session = null;
    await expectUnavailable(
      createTeamSessionTerminalGateway({ teamSessions: missing }).open({
        sessionId: SESSION_ID,
        actor: ACTOR,
      })
    );

    const privateFailure = new FakeTeamSessionKernel();
    privateFailure.inspectFailure = new Error(
      "Session exists at secret tmux name and user lacks Project access"
    );
    const error = await captureError(
      createTeamSessionTerminalGateway({ teamSessions: privateFailure }).open({
        sessionId: SESSION_ID,
        actor: ACTOR,
      })
    );
    expect(error).toEqual({
      name: "TeamSessionTerminalGatewayError",
      code: "terminal-unavailable",
      message: "Terminal session unavailable",
    });
  });

  it.each([
    "not-authorized",
    "stale-control-epoch",
    "stale-runtime-authorization-generation",
    "session-not-active",
    "runtime-authorization-pending",
    "runtime-authorization-quarantined",
  ] as const)("returns one opaque action error for kernel denial: %s", async (reason) => {
    const kernel = new FakeTeamSessionKernel();
    const connection = await createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
      sessionId: SESSION_ID,
      actor: ACTOR,
    });
    kernel.authorizeOverride = (query) => ({
      sessionId: query.sessionId,
      action: query.action,
      allowed: false,
      reason,
      controlEpoch: 984,
      runtimeAuthorizationGeneration: 721,
    });

    const error = captureSynchronousError(() => connection.perform("input", () => undefined));
    expect(error).toEqual({
      name: "TeamSessionTerminalGatewayError",
      code: "terminal-unavailable",
      message: "Terminal session unavailable",
    });
  });

  it("rejects non-mutation actions before they reach the kernel", async () => {
    const kernel = new FakeTeamSessionKernel();
    const connection = await createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
      sessionId: SESSION_ID,
      actor: ACTOR,
    });

    expect(() => connection.perform("observe" as TerminalMutationAction, () => undefined)).toThrow(
      TeamSessionTerminalGatewayError
    );
    expect(kernel.queries).toHaveLength(2);
  });

  it("never runs an effect after authorization or Runtime fencing is denied", async () => {
    const kernel = new FakeTeamSessionKernel();
    let runtimeAllowed = true;
    const connection = await createTeamSessionTerminalGateway({
      teamSessions: kernel,
      isRuntimeWriteAllowed: () => runtimeAllowed,
    }).open({ sessionId: SESSION_ID, actor: ACTOR });
    let effects = 0;

    kernel.authorizeOverride = (query) => ({
      ...defaultAuthorization(query, kernel.session),
      allowed: false,
      reason: "not-authorized",
    });
    expect(() => connection.perform("input", () => void (effects += 1))).toThrow(
      TeamSessionTerminalGatewayError
    );
    expect(effects).toBe(0);

    kernel.authorizeOverride = undefined;
    runtimeAllowed = false;
    expect(await connection.canPerform("input")).toBe(false);
    expect(() => connection.perform("input", () => void (effects += 1))).toThrow(
      TeamSessionTerminalGatewayError
    );
    expect(effects).toBe(0);
  });

  it.each([
    ["revoked access", (): SessionView | null => null],
    ["changed control epoch", () => makeSession({ controlEpoch: 8 })],
    ["changed Runtime generation", () => makeSession({ authorizationGeneration: 12 })],
    ["pending Runtime", () => makeSession({ authorizationState: "pending" })],
    ["quarantined Runtime", () => makeSession({ authorizationState: "quarantined" })],
    ["changed tmux binding", () => makeSession({ tmuxName: "replacement-runtime" })],
    ["re-admitted Participant", () => makeSession({ participantVersion: 4 })],
  ] as const)("invalidates a monitored connection after %s", async (_label, nextSession) => {
    const kernel = new FakeTeamSessionKernel();
    const connection = await createTeamSessionTerminalGateway({
      teamSessions: kernel,
      monitorPollIntervalMs: 25,
    }).open({ sessionId: SESSION_ID, actor: ACTOR });
    kernel.followImplementation = async function* () {
      kernel.session = nextSession();
      yield makeEvent();
    };

    await expect(connection.monitor()).resolves.toEqual({
      kind: "terminal-authorization-changed",
      publicReason: "Terminal authorization changed",
    });
    expect(kernel.follows).toEqual([
      expect.objectContaining({
        sessionId: SESSION_ID,
        afterSequence: 23,
        actor: ACTOR,
        pollIntervalMs: 25,
      }),
    ]);
  });

  it("invalidates before following when a captured fence is already stale", async () => {
    const kernel = new FakeTeamSessionKernel();
    const connection = await createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
      sessionId: SESSION_ID,
      actor: ACTOR,
    });
    kernel.session = makeSession({ controlEpoch: 8 });

    await expect(connection.monitor()).resolves.toMatchObject({
      kind: "terminal-authorization-changed",
    });
    expect(kernel.follows).toHaveLength(0);
  });

  it("keeps a current connection open across unrelated Session events", async () => {
    const kernel = new FakeTeamSessionKernel();
    const connection = await createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
      sessionId: SESSION_ID,
      actor: ACTOR,
    });
    const abortController = new AbortController();
    kernel.followImplementation = async function* () {
      yield makeEvent();
      abortController.abort();
    };

    await expect(connection.monitor({ signal: abortController.signal })).resolves.toBeNull();
    expect(kernel.queries.filter((query) => query.type === "session.get")).toHaveLength(3);
  });

  it("fails closed when the event follower errors or completes unexpectedly", async () => {
    const throwingKernel = new FakeTeamSessionKernel();
    const throwingConnection = await createTeamSessionTerminalGateway({
      teamSessions: throwingKernel,
    }).open({ sessionId: SESSION_ID, actor: ACTOR });
    throwingKernel.followImplementation = async function* () {
      throw new Error("private database failure with /secret/path");
    };
    await expect(throwingConnection.monitor()).resolves.toEqual({
      kind: "terminal-authorization-changed",
      publicReason: "Terminal authorization changed",
    });

    const completedKernel = new FakeTeamSessionKernel();
    const completedConnection = await createTeamSessionTerminalGateway({
      teamSessions: completedKernel,
    }).open({ sessionId: SESSION_ID, actor: ACTOR });
    await expect(completedConnection.monitor()).resolves.toEqual({
      kind: "terminal-authorization-changed",
      publicReason: "Terminal authorization changed",
    });
  });

  it("treats intentional monitor cancellation as a clean shutdown", async () => {
    const kernel = new FakeTeamSessionKernel();
    const connection = await createTeamSessionTerminalGateway({ teamSessions: kernel }).open({
      sessionId: SESSION_ID,
      actor: ACTOR,
    });
    const abortController = new AbortController();
    abortController.abort();

    await expect(connection.monitor({ signal: abortController.signal })).resolves.toBeNull();
    expect(kernel.follows).toHaveLength(0);
  });

  it("validates monitor polling configuration at the module interface", () => {
    const kernel = new FakeTeamSessionKernel();
    expect(() =>
      createTeamSessionTerminalGateway({ teamSessions: kernel, monitorPollIntervalMs: 9 })
    ).toThrow(TypeError);
    expect(() =>
      createTeamSessionTerminalGateway({ teamSessions: kernel, monitorPollIntervalMs: 5_001 })
    ).toThrow(TypeError);
  });
});

function makeSession(
  overrides: {
    status?: SessionView["status"];
    authorizationState?: SessionView["runtime"]["authorizationState"];
    authorizationGeneration?: number;
    controlEpoch?: number;
    tmuxName?: string;
    participantVersion?: number;
    responsibilities?: SessionView["participants"][number]["responsibilities"];
    observer?: boolean;
  } = {}
): SessionView {
  return {
    sessionId: SESSION_ID,
    teamId: "team-1",
    projectId: "project-1",
    name: "Canonical Team Session",
    status: overrides.status ?? "active",
    steeringPolicy: "shared",
    accessRevision: 5,
    assigneeRevision: 2,
    supervisionRevision: 2,
    steeringRevision: 3,
    controlRevision: 6,
    controlEpoch: overrides.controlEpoch ?? 7,
    runtime: {
      kind: "local-tmux",
      isolation: "trusted-shared-host",
      tmuxName: overrides.tmuxName ?? "team-session-runtime",
      yoloEligible: false,
      authorizationGeneration: overrides.authorizationGeneration ?? 11,
      authorizationState: overrides.authorizationState ?? "enforced",
    },
    participants: [
      {
        participantId: PARTICIPANT_ID,
        userId: ACTOR.userId,
        membershipRole: "member",
        active: true,
        observer: overrides.observer ?? false,
        responsibilities: overrides.responsibilities ?? ["steerer", "controller"],
        responsibilityVersions: { steerer: 1, controller: 1 },
        joinedAtMs: 1_700_000_000_000,
        version: overrides.participantVersion ?? 3,
      },
    ],
    shares: [],
    invitations: [],
    handoffs: [],
    latestSequence: 23,
    createdAtMs: 1_700_000_000_000,
  };
}

function defaultAuthorization(
  query: SessionTerminalAuthorizationQuery,
  session: SessionView | null
): TerminalAuthorization {
  const controlEpoch =
    query.action === "observe"
      ? (session?.controlEpoch ?? 0)
      : (query.expectedControlEpoch ?? session?.controlEpoch ?? 0);
  const runtimeAuthorizationGeneration =
    query.action === "observe"
      ? (session?.runtime.authorizationGeneration ?? 0)
      : (query.expectedRuntimeAuthorizationGeneration ??
        session?.runtime.authorizationGeneration ??
        0);
  return {
    sessionId: query.sessionId,
    action: query.action,
    allowed: session !== null,
    ...(session ? { participantId: PARTICIPANT_ID } : { reason: "not-authorized" as const }),
    controlEpoch,
    runtimeAuthorizationGeneration,
  };
}

function makeEvent(): SessionEvent {
  return {
    schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
    eventId: "event-24",
    sessionId: SESSION_ID,
    sequence: 24,
    type: "session.access.changed",
    occurredAtMs: 1_700_000_000_100,
    actor: ACTOR,
    source: { scope: "vitest", key: "event-24" },
    payload: {},
  };
}

async function* emptyEvents(): AsyncIterable<SessionEvent> {
  return;
}

async function expectUnavailable(promise: Promise<unknown>): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    name: "TeamSessionTerminalGatewayError",
    code: "terminal-unavailable",
    message: "Terminal session unavailable",
  });
}

async function captureError(
  promise: Promise<unknown>
): Promise<{ name: string; code: unknown; message: string }> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(TeamSessionTerminalGatewayError);
    const typed = error as TeamSessionTerminalGatewayError;
    return { name: typed.name, code: typed.code, message: typed.message };
  }
  throw new Error("Expected rejection");
}

function captureSynchronousError(work: () => void): {
  name: string;
  code: unknown;
  message: string;
} {
  try {
    work();
  } catch (error) {
    expect(error).toBeInstanceOf(TeamSessionTerminalGatewayError);
    const typed = error as TeamSessionTerminalGatewayError;
    return { name: typed.name, code: typed.code, message: typed.message };
  }
  throw new Error("Expected synchronous failure");
}
