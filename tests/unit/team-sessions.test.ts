import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  createTeamSessions,
  type ActorContext,
  type CommandResult,
  type ProjectAccessView,
  type RuntimeOutboxDelivery,
  type SessionCommand,
  type SessionParticipantView,
  type SessionView,
  type TeamAccessView,
  type TeamSessions,
} from "@/lib/team-sessions";

const ALICE: ActorContext = {
  kind: "human",
  userId: "user-alice",
  displayName: "Alice",
};

const BOB: ActorContext = {
  kind: "human",
  userId: "user-bob",
  displayName: "Bob",
};

const CAROL: ActorContext = {
  kind: "human",
  userId: "user-carol",
  displayName: "Carol",
};

const DAVE: ActorContext = {
  kind: "human",
  userId: "user-dave",
  displayName: "Dave",
};

const LEGACY_ADMIN: ActorContext = {
  kind: "human",
  userId: "admin",
  displayName: "Admin",
};

const SYSTEM: ActorContext = {
  kind: "system",
  userId: "terminalx-runtime",
  displayName: "TerminalX Runtime",
};

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const SECOND_SESSION_ID = "44444444-4444-4444-8444-444444444444";

type CommandInput = SessionCommand extends infer Command
  ? Command extends SessionCommand
    ? Omit<Command, "schemaVersion" | "actor" | "idempotency" | "occurredAtMs">
    : never
  : never;

interface Invitation {
  invitationId: string;
  token: string;
  result: CommandResult;
}

describe("Team Session kernel", () => {
  let directory: string;
  let filename: string;
  let teamSessions: TeamSessions | undefined;
  let nowMs: number;
  let commandNumber: number;
  let generatedId: number;
  let generatedToken: number;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-team-sessions-"));
    filename = path.join(directory, "team-sessions.sqlite");
    nowMs = 2_000_000_000_000;
    commandNumber = 0;
    generatedId = 0;
    generatedToken = 0;
    teamSessions = openKernel();
  });

  afterEach(() => {
    teamSessions?.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function openKernel(): TeamSessions {
    return createTeamSessions({
      filename,
      clock: () => nowMs,
      idGenerator: () => {
        generatedId += 1;
        return `00000000-0000-4000-8000-${String(generatedId).padStart(12, "0")}`;
      },
      invitationTokenGenerator: () => {
        generatedToken += 1;
        return `txi_${String(generatedToken).padStart(4, "0")}_${"x".repeat(64)}`;
      },
    });
  }

  function kernel(): TeamSessions {
    if (!teamSessions) throw new Error("Team Session kernel is not open");
    return teamSessions;
  }

  function makeCommand(
    input: CommandInput,
    actor: ActorContext = ALICE,
    key = `command-${++commandNumber}`
  ): SessionCommand {
    return {
      ...input,
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      idempotency: { scope: "vitest:team-sessions", key },
      occurredAtMs: nowMs,
    } as SessionCommand;
  }

  async function dispatch(
    input: CommandInput,
    actor: ActorContext = ALICE,
    key?: string
  ): Promise<CommandResult> {
    return kernel().dispatch(makeCommand(input, actor, key));
  }

  async function bootstrap(options: { steeringPolicy?: "single" | "shared" } = {}): Promise<void> {
    await dispatch({ type: "team.create", teamId: TEAM_ID, name: "Acme" });
    await dispatch({
      type: "project.create",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      name: "Terminal X",
      sourceRef: "/srv/terminalx",
    });
    await dispatch({
      type: "session.start",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sessionId: SESSION_ID,
      name: "Multiplayer kernel",
      tmuxName: "multiplayer-kernel",
      steeringPolicy: options.steeringPolicy,
    });
  }

  async function getSession(
    sessionId = SESSION_ID,
    actor: ActorContext = ALICE
  ): Promise<SessionView | null> {
    return kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "session.get",
      sessionId,
    });
  }

  async function requireSession(
    sessionId = SESSION_ID,
    actor: ActorContext = ALICE
  ): Promise<SessionView> {
    const view = await getSession(sessionId, actor);
    expect(view).not.toBeNull();
    if (!view) throw new Error("Expected an authorized Session view");
    return view;
  }

  function requireParticipant(view: SessionView, userId: string): SessionParticipantView {
    const participant = view.participants.find((candidate) => candidate.userId === userId);
    expect(participant).toBeDefined();
    if (!participant) throw new Error(`Expected participant for ${userId}`);
    return participant;
  }

  async function teamAccess(actor: ActorContext = ALICE): Promise<TeamAccessView> {
    return kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "team.access",
      teamId: TEAM_ID,
    });
  }

  async function projectAccess(actor: ActorContext = ALICE): Promise<ProjectAccessView> {
    return kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "project.access",
      projectId: PROJECT_ID,
    });
  }

  async function admission(actor: ActorContext = ALICE, sessionId = SESSION_ID) {
    return kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "session.admission",
      sessionId,
    });
  }

  async function createInvitation(
    membershipRole: "member" | "guest",
    options: {
      actor?: ActorContext;
      sessionId?: string;
      expiresAtMs?: number;
      key?: string;
    } = {}
  ): Promise<Invitation> {
    const actor = options.actor ?? ALICE;
    const sessionId = options.sessionId ?? SESSION_ID;
    const projection = await admission(actor, sessionId);
    const result = await dispatch(
      {
        type: "session.invitation.create",
        sessionId,
        membershipRole,
        expiresAtMs: options.expiresAtMs ?? nowMs + 60_000,
        expectedAccessRevision: projection.accessRevision,
      },
      actor,
      options.key
    );
    expect(result.data).toMatchObject({
      invitationId: expect.any(String),
      invitationToken: expect.any(String),
      invitationVersion: 1,
    });
    return {
      invitationId: result.data.invitationId as string,
      token: result.data.invitationToken as string,
      result,
    };
  }

  async function redeemInvitation(
    invitation: Invitation,
    actor: ActorContext,
    key?: string
  ): Promise<CommandResult> {
    return dispatch({ type: "session.invitation.redeem", token: invitation.token }, actor, key);
  }

  async function grantMembership(
    user: ActorContext,
    role: "owner" | "admin" | "member" | "guest",
    actor: ActorContext = ALICE
  ): Promise<CommandResult> {
    const projection = await teamAccess(actor);
    const stored = projection.memberships.find((membership) => membership.userId === user.userId);
    return dispatch(
      {
        type: "team.membership.grant",
        teamId: TEAM_ID,
        userId: user.userId,
        role,
        expectedMembershipVersion: stored?.version ?? 0,
      },
      actor
    );
  }

  async function revokeMembership(
    user: ActorContext,
    actor: ActorContext = ALICE
  ): Promise<CommandResult> {
    const projection = await teamAccess(actor);
    const stored = projection.memberships.find((membership) => membership.userId === user.userId);
    if (!stored) throw new Error(`Expected Team Membership for ${user.userId}`);
    return dispatch(
      {
        type: "team.membership.revoke",
        teamId: TEAM_ID,
        userId: user.userId,
        expectedMembershipVersion: stored.version,
      },
      actor
    );
  }

  async function grantProjectAccess(
    user: ActorContext,
    role: "maintainer" | "contributor" = "contributor",
    actor: ActorContext = ALICE
  ): Promise<CommandResult> {
    const projection = await projectAccess(actor);
    const stored = projection.access.find((entry) => entry.userId === user.userId);
    return dispatch(
      {
        type: "project.access.grant",
        projectId: PROJECT_ID,
        userId: user.userId,
        role,
        expectedAccessVersion: stored?.version ?? 0,
      },
      actor
    );
  }

  async function revokeProjectAccess(
    user: ActorContext,
    actor: ActorContext = ALICE
  ): Promise<CommandResult> {
    const projection = await projectAccess(actor);
    const stored = projection.access.find((entry) => entry.userId === user.userId);
    if (!stored) throw new Error(`Expected Project Access for ${user.userId}`);
    return dispatch(
      {
        type: "project.access.revoke",
        projectId: PROJECT_ID,
        userId: user.userId,
        expectedAccessVersion: stored.version,
      },
      actor
    );
  }

  async function createShare(
    user: ActorContext,
    actor: ActorContext = ALICE
  ): Promise<CommandResult> {
    const view = await requireSession(SESSION_ID, actor);
    return dispatch(
      {
        type: "session.share.create",
        sessionId: SESSION_ID,
        userId: user.userId,
        expectedAccessRevision: view.accessRevision,
      },
      actor
    );
  }

  async function admitMember(user: ActorContext): Promise<Invitation> {
    const invitation = await createInvitation("member");
    await redeemInvitation(invitation, user);
    await grantProjectAccess(user);
    await dispatch(
      { type: "session.join", sessionId: SESSION_ID, invitationId: invitation.invitationId },
      user
    );
    return invitation;
  }

  async function admitGuest(user: ActorContext): Promise<Invitation> {
    const invitation = await createInvitation("guest");
    await redeemInvitation(invitation, user);
    await createShare(user);
    await dispatch(
      { type: "session.join", sessionId: SESSION_ID, invitationId: invitation.invitationId },
      user
    );
    return invitation;
  }

  async function revokeParticipant(
    user: ActorContext,
    actor: ActorContext = ALICE
  ): Promise<CommandResult> {
    const view = await requireSession(SESSION_ID, actor);
    const participant = requireParticipant(view, user.userId);
    return dispatch(
      {
        type: "session.participant.revoke",
        sessionId: SESSION_ID,
        userId: user.userId,
        expectedParticipantVersion: participant.version,
      },
      actor
    );
  }

  async function grantParticipant(
    user: ActorContext,
    actor: ActorContext = ALICE
  ): Promise<CommandResult> {
    const view = await requireSession(SESSION_ID, actor);
    const participant = view.participants.find((candidate) => candidate.userId === user.userId);
    return dispatch(
      {
        type: "session.participant.grant",
        sessionId: SESSION_ID,
        userId: user.userId,
        expectedParticipantVersion: participant?.version ?? 0,
        expectedAccessRevision: view.accessRevision,
      },
      actor
    );
  }

  async function grantSteerer(
    user: ActorContext,
    actor: ActorContext = ALICE
  ): Promise<CommandResult> {
    const view = await requireSession(SESSION_ID, actor);
    const participant = requireParticipant(view, user.userId);
    return dispatch(
      {
        type: "session.responsibility.grant",
        sessionId: SESSION_ID,
        userId: user.userId,
        responsibility: "steerer",
        expectedSteeringRevision: view.steeringRevision,
        expectedParticipantVersion: participant.version,
      },
      actor
    );
  }

  async function transferControl(user: ActorContext, actor: ActorContext): Promise<CommandResult> {
    const view = await requireSession(SESSION_ID, actor);
    const participant = requireParticipant(view, user.userId);
    return dispatch(
      {
        type: "session.control.transfer",
        sessionId: SESSION_ID,
        userId: user.userId,
        expectedControlRevision: view.controlRevision,
        expectedControlEpoch: view.controlEpoch,
        expectedParticipantVersion: participant.version,
      },
      actor
    );
  }

  async function offerHandoff(
    recipient: ActorContext,
    actor: ActorContext = ALICE,
    expiresAtMs?: number,
    briefing?: {
      summary: string;
      blockers?: string[];
      artifactRefs?: string[];
    }
  ): Promise<CommandResult> {
    const view = await requireSession(SESSION_ID, actor);
    const offerer = requireParticipant(view, actor.userId);
    const recipientParticipant = requireParticipant(view, recipient.userId);
    const offeredUnder = offerer.responsibilities.includes("assignee") ? "assignee" : "supervisor";
    const authorityVersion = offerer.responsibilityVersions[offeredUnder];
    if (!authorityVersion) throw new Error("Expected Handoff authority responsibility version");
    return dispatch(
      {
        type: "session.handoff.offer",
        sessionId: SESSION_ID,
        recipientParticipantId: recipientParticipant.participantId,
        expectedAssigneeRevision: view.assigneeRevision,
        expectedRecipientParticipantVersion: recipientParticipant.version,
        expectedOffererResponsibilityVersion: authorityVersion,
        ...(expiresAtMs === undefined ? {} : { expiresAtMs }),
        ...(briefing === undefined ? {} : { briefing }),
      },
      actor
    );
  }

  async function makeBobOwnerAndLoseStarter(): Promise<SessionView> {
    await admitMember(BOB);
    await grantMembership(BOB, "owner");
    await enforceNextRuntimeDelivery("runtime.session.ensure");
    await revokeMembership(ALICE, BOB);
    return requireSession(SESSION_ID, BOB);
  }

  async function enforceNextRuntimeDelivery(
    expectedKind: RuntimeOutboxDelivery["kind"]
  ): Promise<CommandResult> {
    const delivery = await claimNextRuntimeDelivery(expectedKind);
    return dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: delivery.outboxId,
        workerId: SYSTEM.userId,
        expectedAttempt: delivery.attempts,
      },
      SYSTEM
    );
  }

  async function claimNextRuntimeDelivery(
    expectedKind: RuntimeOutboxDelivery["kind"]
  ): Promise<RuntimeOutboxDelivery> {
    const deliveries = await kernel().claimRuntimeOutbox({
      workerId: SYSTEM.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    expect(deliveries).toEqual([
      expect.objectContaining({
        sessionId: SESSION_ID,
        kind: expectedKind,
        leaseOwner: SYSTEM.userId,
      }),
    ]);
    const delivery = deliveries[0];
    if (!delivery) throw new Error("Expected one Runtime outbox delivery");
    return delivery;
  }

  async function authorizeTerminal(
    action: "observe" | "input" | "resize" | "interrupt",
    actor: ActorContext,
    view: SessionView
  ) {
    return kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "session.terminal-authorization",
      sessionId: view.sessionId,
      action,
      expectedControlEpoch: view.controlEpoch,
      expectedRuntimeAuthorizationGeneration: view.runtime.authorizationGeneration,
    });
  }

  async function forceSessionStatus(status: "active" | "ended"): Promise<void> {
    teamSessions?.close();
    teamSessions = undefined;
    const database = new Database(filename);
    try {
      database.prepare("UPDATE sessions SET status = ? WHERE id = ?").run(status, SESSION_ID);
    } finally {
      database.close();
    }
    teamSessions = openKernel();
  }

  async function captureRejection(
    input: CommandInput,
    actor: ActorContext
  ): Promise<{ code: unknown; message: string }> {
    try {
      await dispatch(input, actor);
    } catch (error) {
      if (!(error instanceof Error)) throw new Error("Expected an Error rejection");
      return { code: (error as Error & { code?: unknown }).code, message: error.message };
    }
    throw new Error("Expected the private Session probe to be rejected");
  }

  it("starts with one human holding the four starter responsibilities and a safe LocalTmux projection", async () => {
    await bootstrap();

    const view = await requireSession();
    const starter = requireParticipant(view, ALICE.userId);
    expect(starter).toMatchObject({
      membershipRole: "owner",
      active: true,
      observer: false,
      version: 1,
    });
    expect(starter.responsibilities).toEqual(["assignee", "supervisor", "steerer", "controller"]);
    expect(view.runtime).toEqual({
      kind: "local-tmux",
      isolation: "trusted-shared-host",
      tmuxName: "multiplayer-kernel",
      yoloEligible: false,
      authorizationGeneration: 1,
      authorizationState: "pending",
    });
  });

  it("owns the final terminal effect inside an immediate fenced authorization transaction", async () => {
    await bootstrap();
    await enforceNextRuntimeDelivery("runtime.session.ensure");
    const view = await requireSession();
    const query = {
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.terminal-authorization" as const,
      sessionId: SESSION_ID,
      action: "input" as const,
      expectedControlEpoch: view.controlEpoch,
      expectedRuntimeAuthorizationGeneration: view.runtime.authorizationGeneration,
    };
    let effects = 0;

    kernel().performTerminalMutation(query, () => {
      effects += 1;
    });
    expect(effects).toBe(1);

    expect(() =>
      kernel().performTerminalMutation(
        { ...query, expectedControlEpoch: view.controlEpoch + 1 },
        () => {
          effects += 1;
        }
      )
    ).toThrowError(expect.objectContaining({ code: "not-authorized" }));
    expect(effects).toBe(1);

    expect(() =>
      kernel().performTerminalMutation(query, (() => Promise.resolve()) as unknown as () => void)
    ).toThrowError(expect.objectContaining({ code: "invalid-command" }));
    expect(() =>
      kernel().performTerminalMutation({ ...query, action: "observe" }, () => undefined)
    ).toThrowError(expect.objectContaining({ code: "invalid-command" }));
  });

  it("admits a Member through independent invitation, Project Access, and first Session join transitions", async () => {
    await bootstrap();
    const invitation = await createInvitation("member");

    await redeemInvitation(invitation, BOB);
    expect((await teamAccess()).memberships).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ userId: BOB.userId, role: "member", status: "active" }),
      ])
    );
    expect((await projectAccess()).access.some((entry) => entry.userId === BOB.userId)).toBe(false);
    await expect(getSession(SESSION_ID, BOB)).resolves.toBeNull();

    await grantProjectAccess(BOB);
    await expect(getSession(SESSION_ID, BOB)).resolves.toBeNull();

    await dispatch(
      { type: "session.join", sessionId: SESSION_ID, invitationId: invitation.invitationId },
      BOB
    );
    expect(requireParticipant(await requireSession(SESSION_ID, BOB), BOB.userId)).toMatchObject({
      membershipRole: "member",
      active: true,
      observer: true,
      responsibilities: [],
    });
  });

  it("admits a Guest through independent invitation, Session Share, and first Session join transitions", async () => {
    await bootstrap();
    const invitation = await createInvitation("guest");

    await redeemInvitation(invitation, BOB);
    await expect(getSession(SESSION_ID, BOB)).resolves.toBeNull();
    expect((await requireSession()).shares).toEqual([]);

    await createShare(BOB);
    await expect(getSession(SESSION_ID, BOB)).resolves.toBeNull();

    await dispatch(
      { type: "session.join", sessionId: SESSION_ID, invitationId: invitation.invitationId },
      BOB
    );
    expect(requireParticipant(await requireSession(SESSION_ID, BOB), BOB.userId)).toMatchObject({
      membershipRole: "guest",
      active: true,
      observer: true,
    });
    expect((await projectAccess()).access.some((entry) => entry.userId === BOB.userId)).toBe(false);
  });

  it("provides versioned Team, Project, and Session-admission projections only to their administrators", async () => {
    await bootstrap();
    const invitation = await createInvitation("member");
    await redeemInvitation(invitation, BOB);
    await grantProjectAccess(BOB);
    await dispatch(
      { type: "session.join", sessionId: SESSION_ID, invitationId: invitation.invitationId },
      BOB
    );

    await expect(teamAccess()).resolves.toMatchObject({
      teamId: TEAM_ID,
      memberships: expect.arrayContaining([
        expect.objectContaining({ userId: ALICE.userId, version: 1 }),
        expect.objectContaining({ userId: BOB.userId, version: 1 }),
      ]),
    });
    await expect(projectAccess()).resolves.toMatchObject({
      projectId: PROJECT_ID,
      access: expect.arrayContaining([
        expect.objectContaining({ userId: ALICE.userId, version: 1 }),
        expect.objectContaining({ userId: BOB.userId, version: 1 }),
      ]),
    });
    const sessionAdmission = await admission();
    expect(sessionAdmission.invitations).toEqual([
      expect.objectContaining({
        invitationId: invitation.invitationId,
        status: "redeemed",
        version: 2,
      }),
    ]);
    expect(JSON.stringify(sessionAdmission)).not.toContain(invitation.token);

    await expect(teamAccess(BOB)).rejects.toMatchObject({ code: "not-authorized" });
    await expect(projectAccess(BOB)).rejects.toMatchObject({ code: "not-authorized" });
    await expect(admission(BOB)).rejects.toMatchObject({ code: "not-authorized" });
  });

  it("never returns an invitation secret on idempotent replay and keeps acceptedSequence monotonic", async () => {
    await bootstrap();
    const projection = await admission();
    const command = makeCommand(
      {
        type: "session.invitation.create",
        sessionId: SESSION_ID,
        membershipRole: "guest",
        expiresAtMs: nowMs + 60_000,
        expectedAccessRevision: projection.accessRevision,
      },
      ALICE,
      "secret-invitation"
    );

    const first = await kernel().dispatch(command);
    const replay = await kernel().dispatch(command);
    expect(first).toMatchObject({ replayed: false, acceptedSequence: 4 });
    expect(first.data.invitationToken).toEqual(expect.any(String));
    expect(replay).toMatchObject({
      replayed: true,
      acceptedSequence: first.acceptedSequence,
      data: {
        invitationId: first.data.invitationId,
        invitationTokenUnavailable: true,
        recoveryAction: "revoke-and-reissue",
      },
    });
    expect(replay.data).not.toHaveProperty("invitationToken");

    const next = await createInvitation("member");
    expect(next.result.acceptedSequence).toBe(first.acceptedSequence + 1);
  });

  it("returns the same non-secret receipt to an actor who still has current Session access", async () => {
    await bootstrap();
    const view = await requireSession();
    const command = makeCommand(
      {
        type: "session.control.release",
        sessionId: SESSION_ID,
        expectedControlRevision: view.controlRevision,
        expectedControlEpoch: view.controlEpoch,
      },
      ALICE,
      "authorized-session-replay"
    );

    const first = await kernel().dispatch(command);
    const replay = await kernel().dispatch(command);

    expect(replay).toEqual({ ...first, replayed: true });
  });

  it("replays a consumed invitation receipt while Membership remains active, then hides it after revocation", async () => {
    await bootstrap();
    const invitation = await createInvitation("member");
    const command = makeCommand(
      { type: "session.invitation.redeem", token: invitation.token },
      BOB,
      "redeemed-invitation-replay"
    );

    const first = await kernel().dispatch(command);
    expect(first).toMatchObject({
      data: {
        invitationId: invitation.invitationId,
        sessionId: SESSION_ID,
        teamId: TEAM_ID,
        projectAccessGranted: false,
        participantGranted: false,
      },
      events: [],
    });
    await expect(kernel().dispatch(command)).resolves.toEqual({ ...first, replayed: true });

    await revokeMembership(BOB);
    await expect(kernel().dispatch(command)).resolves.toMatchObject({
      replayed: true,
      data: { receiptUnavailable: true },
      events: [],
    });
  });

  it("does not apply human visibility projection to system Runtime receipts", async () => {
    await bootstrap();
    const delivery = await claimNextRuntimeDelivery("runtime.session.ensure");
    const command = makeCommand(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: delivery.outboxId,
        workerId: SYSTEM.userId,
        expectedAttempt: delivery.attempts,
      },
      SYSTEM,
      "system-runtime-replay"
    );

    const first = await kernel().dispatch(command);
    const replay = await kernel().dispatch(command);

    expect(replay).toEqual({ ...first, replayed: true });
    expect(replay.data).toMatchObject({
      outboxId: delivery.outboxId,
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 1,
    });
  });

  it("does not replay Participant ids or revisions after the actor loses Session access", async () => {
    await bootstrap();
    const invitation = await createInvitation("member");
    await redeemInvitation(invitation, BOB);
    await grantProjectAccess(BOB);
    const command = makeCommand(
      {
        type: "session.join",
        sessionId: SESSION_ID,
        invitationId: invitation.invitationId,
      },
      BOB,
      "revoked-session-replay"
    );
    const first = await kernel().dispatch(command);
    expect(first.data).toMatchObject({
      sessionId: SESSION_ID,
      participantId: expect.any(String),
      participantVersion: 1,
      accessRevision: expect.any(Number),
    });

    await revokeParticipant(BOB);
    await expect(getSession(SESSION_ID, BOB)).resolves.toBeNull();
    const replay = await kernel().dispatch(command);

    expect(replay).toMatchObject({
      accepted: true,
      acceptedSequence: first.acceptedSequence,
      commandType: "session.join",
      replayed: true,
      data: { receiptUnavailable: true },
      events: [],
    });
    expect(replay.data).toEqual({ receiptUnavailable: true });
  });

  it("re-evaluates Project visibility on every replay and hides scoped receipts after revocation", async () => {
    await bootstrap();
    await grantMembership(BOB, "member");
    await grantProjectAccess(BOB, "maintainer");
    await grantMembership(CAROL, "member");
    const command = makeCommand(
      {
        type: "project.access.grant",
        projectId: PROJECT_ID,
        userId: CAROL.userId,
        role: "contributor",
        expectedAccessVersion: 0,
      },
      BOB,
      "revoked-project-replay"
    );
    const first = await kernel().dispatch(command);
    expect(first.data).toMatchObject({
      projectId: PROJECT_ID,
      userId: CAROL.userId,
      accessVersion: 1,
    });
    await expect(kernel().dispatch(command)).resolves.toEqual({ ...first, replayed: true });

    await revokeProjectAccess(BOB);
    const replay = await kernel().dispatch(command);

    expect(replay).toMatchObject({
      accepted: true,
      acceptedSequence: first.acceptedSequence,
      commandType: "project.access.grant",
      replayed: true,
      data: { receiptUnavailable: true },
      events: [],
    });
    expect(replay.data).toEqual({ receiptUnavailable: true });
  });

  it("does not replay Team-scoped ids or versions after Membership revocation", async () => {
    await bootstrap();
    await grantMembership(BOB, "admin");
    const command = makeCommand(
      {
        type: "team.membership.grant",
        teamId: TEAM_ID,
        userId: DAVE.userId,
        role: "member",
        expectedMembershipVersion: 0,
      },
      BOB,
      "revoked-team-replay"
    );
    const first = await kernel().dispatch(command);
    expect(first.data).toMatchObject({
      teamId: TEAM_ID,
      userId: DAVE.userId,
      membershipVersion: 1,
    });

    await revokeMembership(BOB);
    const replay = await kernel().dispatch(command);

    expect(replay).toMatchObject({
      accepted: true,
      acceptedSequence: first.acceptedSequence,
      commandType: "team.membership.grant",
      replayed: true,
      data: { receiptUnavailable: true },
      events: [],
    });
    expect(replay.data).toEqual({ receiptUnavailable: true });
  });

  it("persists only an invitation digest while the plaintext remains redeemable", async () => {
    await bootstrap();
    const invitation = await createInvitation("guest");
    expect(JSON.stringify(invitation.result.events)).not.toContain(invitation.token);

    teamSessions?.close();
    teamSessions = undefined;
    const persistedBytes = [filename, `${filename}-wal`, `${filename}-shm`, `${filename}-journal`]
      .filter((candidate) => fs.existsSync(candidate))
      .map((candidate) => fs.readFileSync(candidate).toString("utf8"))
      .join("");
    expect(persistedBytes).not.toContain(invitation.token);

    teamSessions = openKernel();
    await expect(redeemInvitation(invitation, BOB)).resolves.toMatchObject({
      accepted: true,
      replayed: false,
    });
  });

  it("rejects an old invitation after same-clock revocation while a fresh invitation can be redeemed", async () => {
    await bootstrap();
    const admissionInvitation = await createInvitation("guest");
    const oldInvitation = await createInvitation("guest");
    await redeemInvitation(admissionInvitation, BOB);
    await createShare(BOB);
    await dispatch(
      {
        type: "session.join",
        sessionId: SESSION_ID,
        invitationId: admissionInvitation.invitationId,
      },
      BOB
    );
    await revokeParticipant(BOB);

    await expect(redeemInvitation(oldInvitation, BOB)).rejects.toMatchObject({
      code: "invitation-revoked",
    });

    const freshInvitation = await createInvitation("guest");
    await expect(redeemInvitation(freshInvitation, BOB)).resolves.toMatchObject({
      accepted: true,
      data: { invitationId: freshInvitation.invitationId },
    });
    await grantParticipant(BOB);
    expect(requireParticipant(await requireSession(), BOB.userId).active).toBe(true);
  });

  it("does not let a revoked Participant self-rejoin, and fences stale Participant ABA commands", async () => {
    await bootstrap();
    await admitMember(BOB);
    const before = await requireSession();
    const staleVersion = requireParticipant(before, BOB.userId).version;

    await revokeParticipant(BOB);
    await expect(
      dispatch({ type: "session.join", sessionId: SESSION_ID }, BOB)
    ).rejects.toMatchObject({ code: "not-authorized" });
    await grantParticipant(BOB);

    await expect(
      dispatch({
        type: "session.participant.revoke",
        sessionId: SESSION_ID,
        userId: BOB.userId,
        expectedParticipantVersion: staleVersion,
      })
    ).rejects.toMatchObject({ code: "stale-revision" });
    expect(requireParticipant(await requireSession(), BOB.userId)).toMatchObject({
      active: true,
      version: 3,
    });
  });

  it("fences stale Responsibility ABA commands while preserving multiple shared Steerers", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await admitMember(CAROL);
    await grantSteerer(BOB);
    const stale = await requireSession();

    await dispatch({
      type: "session.responsibility.revoke",
      sessionId: SESSION_ID,
      userId: BOB.userId,
      responsibility: "steerer",
      expectedSteeringRevision: stale.steeringRevision,
      expectedControlRevision: stale.controlRevision,
      expectedControlEpoch: stale.controlEpoch,
    });
    await grantSteerer(BOB);

    await expect(
      dispatch({
        type: "session.responsibility.revoke",
        sessionId: SESSION_ID,
        userId: BOB.userId,
        responsibility: "steerer",
        expectedSteeringRevision: stale.steeringRevision,
        expectedControlRevision: stale.controlRevision,
        expectedControlEpoch: stale.controlEpoch,
      })
    ).rejects.toMatchObject({ code: "stale-revision" });
    const view = await requireSession();
    expect(
      view.participants
        .filter((participant) => participant.responsibilities.includes("steerer"))
        .map((participant) => participant.userId)
        .sort()
    ).toEqual([ALICE.userId, BOB.userId].sort());
  });

  it("uses dedicated Control transfer commands and rejects a stale Control ABA lease", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await grantSteerer(BOB);
    await enforceNextRuntimeDelivery("runtime.session.ensure");
    const original = await requireSession();
    const bob = requireParticipant(original, BOB.userId);
    const staleTransfer = makeCommand({
      type: "session.control.transfer",
      sessionId: SESSION_ID,
      userId: BOB.userId,
      expectedControlRevision: original.controlRevision,
      expectedControlEpoch: original.controlEpoch,
      expectedParticipantVersion: bob.version,
    });

    await transferControl(BOB, ALICE);
    const bobControl = await requireSession(SESSION_ID, BOB);
    await expect(authorizeTerminal("input", BOB, bobControl)).resolves.toMatchObject({
      allowed: true,
    });
    await transferControl(ALICE, BOB);

    await expect(kernel().dispatch(staleTransfer)).rejects.toMatchObject({
      code: "stale-revision",
    });
    const restored = await requireSession();
    expect(
      restored.participants
        .filter((participant) => participant.responsibilities.includes("controller"))
        .map((participant) => participant.userId)
    ).toEqual([ALICE.userId]);
  });

  it("prevents a temporary shared Controller from expanding Steering while preserving manager transfer", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await admitMember(CAROL);

    await transferControl(BOB, ALICE);
    const delegated = await requireSession(SESSION_ID, BOB);
    expect(requireParticipant(delegated, BOB.userId).responsibilities).toEqual(
      expect.arrayContaining(["steerer", "controller"])
    );
    expect(requireParticipant(delegated, BOB.userId).responsibilities).not.toEqual(
      expect.arrayContaining(["assignee", "supervisor"])
    );
    expect(requireParticipant(delegated, CAROL.userId).responsibilities).toEqual([]);

    await expect(transferControl(CAROL, BOB)).rejects.toMatchObject({
      code: "not-authorized",
    });
    const afterDeniedExpansion = await requireSession(SESSION_ID, BOB);
    expect(afterDeniedExpansion.steeringRevision).toBe(delegated.steeringRevision);
    expect(afterDeniedExpansion.controlRevision).toBe(delegated.controlRevision);
    expect(requireParticipant(afterDeniedExpansion, CAROL.userId).responsibilities).toEqual([]);

    await transferControl(ALICE, BOB);
    await transferControl(CAROL, ALICE);
    const managerDelegated = await requireSession(SESSION_ID, CAROL);
    expect(requireParticipant(managerDelegated, CAROL.userId).responsibilities).toEqual(
      expect.arrayContaining(["steerer", "controller"])
    );
    expect(managerDelegated.steeringRevision).toBeGreaterThan(delegated.steeringRevision);
  });

  it("removes the sole Steerer when a single-policy Controller releases control", async () => {
    await bootstrap();
    await enforceNextRuntimeDelivery("runtime.session.ensure");
    const before = await requireSession();

    await dispatch({
      type: "session.control.release",
      sessionId: SESSION_ID,
      expectedControlRevision: before.controlRevision,
      expectedControlEpoch: before.controlEpoch,
    });

    const released = await requireSession();
    const alice = requireParticipant(released, ALICE.userId);
    expect(alice.responsibilities).not.toContain("controller");
    expect(alice.responsibilities).not.toContain("steerer");
    expect(released.controlEpoch).toBeGreaterThan(before.controlEpoch);
    expect(released.steeringRevision).toBeGreaterThan(before.steeringRevision);
    await expect(authorizeTerminal("input", ALICE, released)).resolves.toMatchObject({
      allowed: false,
      reason: "not-authorized",
    });
  });

  it("offers and accepts a Member Handoff atomically across Assignee, Supervisor, Steering, and Control", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    const before = await requireSession();
    const offer = await offerHandoff(BOB, ALICE, undefined, {
      summary: "Continue the deployment safety review.",
      blockers: ["Production approval remains open."],
      artifactRefs: ["event:latest"],
    });

    await dispatch(
      {
        type: "session.handoff.accept",
        sessionId: SESSION_ID,
        handoffId: offer.data.handoffId as string,
        expectedHandoffVersion: offer.data.handoffVersion as number,
      },
      BOB
    );

    const after = await requireSession(SESSION_ID, BOB);
    expect(requireParticipant(after, ALICE.userId).responsibilities).not.toContain("assignee");
    expect(requireParticipant(after, BOB.userId).responsibilities).toEqual(
      expect.arrayContaining(["assignee", "supervisor", "steerer", "controller"])
    );
    expect(after.assigneeRevision).toBeGreaterThan(before.assigneeRevision);
    expect(after.controlEpoch).toBeGreaterThan(before.controlEpoch);
    expect(after.handoffs).toEqual([
      expect.objectContaining({
        handoffId: offer.data.handoffId,
        status: "accepted",
        version: 2,
        briefing: {
          summary: "Continue the deployment safety review.",
          blockers: ["Production approval remains open."],
          artifactRefs: ["event:latest"],
        },
      }),
    ]);
  });

  it("allows an explicitly shared Guest Participant to accept a Handoff", async () => {
    await bootstrap();
    await admitGuest(CAROL);
    const offer = await offerHandoff(CAROL);

    await dispatch(
      {
        type: "session.handoff.accept",
        sessionId: SESSION_ID,
        handoffId: offer.data.handoffId as string,
        expectedHandoffVersion: 1,
      },
      CAROL
    );

    const view = await requireSession(SESSION_ID, CAROL);
    expect(requireParticipant(view, CAROL.userId)).toMatchObject({
      membershipRole: "guest",
      responsibilities: expect.arrayContaining(["assignee", "supervisor", "steerer", "controller"]),
    });
  });

  it("lets either endpoint cancel a Handoff and rejects the stale pre-cancel accept command", async () => {
    await bootstrap();
    await admitMember(BOB);
    const offer = await offerHandoff(BOB);
    const staleAccept = makeCommand(
      {
        type: "session.handoff.accept",
        sessionId: SESSION_ID,
        handoffId: offer.data.handoffId as string,
        expectedHandoffVersion: 1,
      },
      BOB
    );

    await dispatch(
      {
        type: "session.handoff.cancel",
        sessionId: SESSION_ID,
        handoffId: offer.data.handoffId as string,
        expectedHandoffVersion: 1,
      },
      BOB
    );

    await expect(kernel().dispatch(staleAccept)).rejects.toMatchObject({ code: "stale-revision" });
    expect((await requireSession()).handoffs).toEqual([
      expect.objectContaining({ status: "cancelled", version: 2 }),
    ]);
  });

  it("makes the first accepted Handoff win and cancels every competing offer", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await admitMember(CAROL);
    const bobOffer = await offerHandoff(BOB);
    const carolOffer = await offerHandoff(CAROL);

    await dispatch(
      {
        type: "session.handoff.accept",
        sessionId: SESSION_ID,
        handoffId: bobOffer.data.handoffId as string,
        expectedHandoffVersion: 1,
      },
      BOB
    );

    await expect(
      dispatch(
        {
          type: "session.handoff.accept",
          sessionId: SESSION_ID,
          handoffId: carolOffer.data.handoffId as string,
          expectedHandoffVersion: 1,
        },
        CAROL
      )
    ).rejects.toMatchObject({ code: "stale-revision" });
    const handoffs = (await requireSession(SESSION_ID, BOB)).handoffs;
    expect(handoffs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ handoffId: bobOffer.data.handoffId, status: "accepted" }),
        expect.objectContaining({ handoffId: carolOffer.data.handoffId, status: "cancelled" }),
      ])
    );
  });

  it("resolves an expired Handoff without transferring responsibility", async () => {
    await bootstrap();
    await admitMember(BOB);
    const offer = await offerHandoff(BOB, ALICE, nowMs + 10);
    nowMs += 11;

    await expect(
      dispatch(
        {
          type: "session.handoff.accept",
          sessionId: SESSION_ID,
          handoffId: offer.data.handoffId as string,
          expectedHandoffVersion: 1,
        },
        BOB
      )
    ).resolves.toMatchObject({
      data: { handoffAccepted: false, handoffVersion: 2, reason: "expired" },
      events: [expect.objectContaining({ type: "session.handoff.expired" })],
    });
    const view = await requireSession();
    expect(requireParticipant(view, ALICE.userId).responsibilities).toContain("assignee");
    expect(requireParticipant(view, BOB.userId).responsibilities).not.toContain("assignee");
    expect(view.handoffs).toEqual([
      expect.objectContaining({
        handoffId: offer.data.handoffId,
        status: "expired",
        version: 2,
        cancellationReason: "expired",
      }),
    ]);
  });

  it("lets an eligible Member claim an awaiting Session without implicitly receiving Steering or Control", async () => {
    await bootstrap();
    const awaiting = await makeBobOwnerAndLoseStarter();
    expect(awaiting.status).toBe("awaiting_assignee");

    await dispatch(
      {
        type: "session.assignee.claim",
        sessionId: SESSION_ID,
        expectedAssigneeRevision: awaiting.assigneeRevision,
        expectedAccessRevision: awaiting.accessRevision,
      },
      BOB
    );

    const claimed = await requireSession(SESSION_ID, BOB);
    expect(claimed.status).toBe("active");
    expect(requireParticipant(claimed, BOB.userId).responsibilities).toEqual([
      "assignee",
      "supervisor",
    ]);
    await expect(authorizeTerminal("input", BOB, claimed)).resolves.toMatchObject({
      allowed: false,
      reason: "runtime-authorization-pending",
    });
  });

  it("does not let a Guest claim an awaiting Session", async () => {
    await bootstrap();
    await admitGuest(CAROL);
    const awaiting = await makeBobOwnerAndLoseStarter();

    await expect(
      dispatch(
        {
          type: "session.assignee.claim",
          sessionId: SESSION_ID,
          expectedAssigneeRevision: awaiting.assigneeRevision,
          expectedAccessRevision: awaiting.accessRevision,
        },
        CAROL
      )
    ).rejects.toMatchObject({ code: "not-authorized" });
  });

  it("moves Assignee loss into awaiting_assignee and advances a pending Runtime authorization fence", async () => {
    await bootstrap();
    const before = await requireSession();
    const awaiting = await makeBobOwnerAndLoseStarter();

    expect(awaiting).toMatchObject({
      status: "awaiting_assignee",
      runtime: {
        authorizationGeneration: before.runtime.authorizationGeneration + 1,
        authorizationState: "pending",
      },
    });
    expect(awaiting.assigneeRevision).toBeGreaterThan(before.assigneeRevision);
    expect(awaiting.controlEpoch).toBeGreaterThan(before.controlEpoch);
    expect(requireParticipant(awaiting, ALICE.userId)).toMatchObject({
      active: false,
      responsibilities: [],
    });
    const events = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: BOB,
      type: "session.events",
      sessionId: SESSION_ID,
      afterSequence: before.latestSequence,
      limit: 100,
    });
    expect(events.map((event) => event.type)).toEqual(
      expect.arrayContaining(["session.runtime-authorization.advanced", "assignee.required"])
    );
  });

  it("supersedes a failed leased delivery from an older generation and unblocks the newer fence", async () => {
    await bootstrap();
    await admitMember(BOB);
    await grantMembership(BOB, "owner");
    const olderEnsure = await claimNextRuntimeDelivery("runtime.session.ensure");
    expect(olderEnsure.payload.runtimeAuthorizationGeneration).toBe(1);

    await revokeMembership(ALICE, BOB);
    const advanced = await requireSession(SESSION_ID, BOB);
    expect(advanced.runtime).toMatchObject({
      authorizationGeneration: 2,
      authorizationState: "pending",
    });
    await expect(
      kernel().claimRuntimeOutbox({
        workerId: "another-runtime-worker",
        limit: 1,
        leaseDurationMs: 30_000,
      })
    ).resolves.toEqual([]);

    await expect(
      dispatch(
        {
          type: "runtime.outbox.fail",
          outboxId: olderEnsure.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: olderEnsure.attempts,
          retryable: false,
          errorCode: "runtime_conflict",
        },
        SYSTEM
      )
    ).resolves.toMatchObject({
      data: {
        runtimeAuthorizationGeneration: 1,
        superseded: true,
        quarantined: false,
      },
      events: [expect.objectContaining({ type: "runtime.outbox.superseded" })],
    });
    expect((await requireSession(SESSION_ID, BOB)).runtime.authorizationState).toBe("pending");

    const currentFence = await claimNextRuntimeDelivery("runtime.authorization.fence");
    expect(currentFence.payload.runtimeAuthorizationGeneration).toBe(2);
    await dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: currentFence.outboxId,
        workerId: SYSTEM.userId,
        expectedAttempt: currentFence.attempts,
      },
      SYSTEM
    );
    expect((await requireSession(SESSION_ID, BOB)).runtime).toMatchObject({
      authorizationGeneration: 2,
      authorizationState: "enforced",
    });
  });

  it("keeps a current-generation Runtime failure quarantined across Assignee loss and claim", async () => {
    await bootstrap();
    const currentEnsure = await claimNextRuntimeDelivery("runtime.session.ensure");

    await expect(
      dispatch(
        {
          type: "runtime.outbox.fail",
          outboxId: currentEnsure.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: currentEnsure.attempts,
          retryable: false,
          errorCode: "runtime_unavailable",
        },
        SYSTEM
      )
    ).resolves.toMatchObject({
      data: {
        runtimeAuthorizationGeneration: 1,
        superseded: false,
        quarantined: true,
      },
      events: [expect.objectContaining({ type: "session.runtime-authorization.quarantined" })],
    });
    const firstQuarantine = await requireSession();
    expect(firstQuarantine.runtime.authorizationState).toBe("quarantined");
    await expect(authorizeTerminal("input", ALICE, firstQuarantine)).resolves.toMatchObject({
      allowed: false,
      reason: "runtime-authorization-quarantined",
    });

    await admitMember(BOB);
    await grantMembership(BOB, "owner");
    await revokeMembership(ALICE, BOB);
    const awaiting = await requireSession(SESSION_ID, BOB);
    expect(awaiting).toMatchObject({
      status: "awaiting_assignee",
      runtime: {
        authorizationGeneration: 2,
        authorizationState: "quarantined",
      },
    });

    const claim = await dispatch(
      {
        type: "session.assignee.claim",
        sessionId: SESSION_ID,
        expectedAssigneeRevision: awaiting.assigneeRevision,
        expectedAccessRevision: awaiting.accessRevision,
      },
      BOB
    );
    expect(claim.data).toMatchObject({
      runtimeAuthorizationGeneration: 2,
      runtimeAuthorizationState: "quarantined",
    });
    await transferControl(BOB, BOB);

    const controlled = await requireSession(SESSION_ID, BOB);
    expect(controlled).toMatchObject({
      status: "active",
      runtime: {
        authorizationGeneration: 2,
        authorizationState: "quarantined",
      },
    });
    expect(requireParticipant(controlled, BOB.userId).responsibilities).toEqual(
      expect.arrayContaining(["assignee", "supervisor", "steerer", "controller"])
    );
    await expect(authorizeTerminal("input", BOB, controlled)).resolves.toMatchObject({
      allowed: false,
      reason: "runtime-authorization-quarantined",
    });
  });

  it("fences a same-worker lease ABA by attempt and retries without quarantining", async () => {
    await bootstrap();
    const firstClaims = await kernel().claimRuntimeOutbox({
      workerId: SYSTEM.userId,
      limit: 1,
      leaseDurationMs: 1_000,
    });
    const firstAttempt = firstClaims[0];
    if (!firstAttempt) throw new Error("Expected the first Runtime delivery attempt");
    expect(firstAttempt).toMatchObject({
      kind: "runtime.session.ensure",
      attempts: 1,
    });

    nowMs = firstAttempt.leaseExpiresAtMs;
    const secondClaims = await kernel().claimRuntimeOutbox({
      workerId: SYSTEM.userId,
      limit: 1,
      leaseDurationMs: 1_000,
    });
    const secondAttempt = secondClaims[0];
    if (!secondAttempt) throw new Error("Expected the reclaimed Runtime delivery");
    expect(secondAttempt).toMatchObject({
      outboxId: firstAttempt.outboxId,
      kind: "runtime.session.ensure",
      attempts: 2,
    });

    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: firstAttempt.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: firstAttempt.attempts,
        },
        SYSTEM
      )
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      dispatch(
        {
          type: "runtime.outbox.fail",
          outboxId: firstAttempt.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: firstAttempt.attempts,
          retryable: true,
          errorCode: "runtime_conflict",
        },
        SYSTEM
      )
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: secondAttempt.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: secondAttempt.attempts,
        },
        ALICE
      )
    ).rejects.toMatchObject({ code: "not-authorized" });
    const invalidRuntimeFailure = {
      ...makeCommand(
        {
          type: "runtime.outbox.fail",
          outboxId: secondAttempt.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: secondAttempt.attempts,
          retryable: true,
          errorCode: "runtime_internal",
        },
        SYSTEM
      ),
      errorCode: "txi_secret_123",
    } as unknown as SessionCommand;
    await expect(kernel().dispatch(invalidRuntimeFailure)).rejects.toMatchObject({
      code: "invalid-command",
    });

    await expect(
      dispatch(
        {
          type: "runtime.outbox.fail",
          outboxId: secondAttempt.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: secondAttempt.attempts,
          retryable: true,
          errorCode: "runtime_timeout",
        },
        SYSTEM
      )
    ).resolves.toMatchObject({
      data: {
        attempt: 2,
        retryable: true,
        superseded: false,
        quarantined: false,
      },
      events: [expect.objectContaining({ type: "runtime.outbox.retry-scheduled" })],
    });
    expect((await requireSession()).runtime.authorizationState).toBe("pending");

    const thirdAttempt = await claimNextRuntimeDelivery("runtime.session.ensure");
    expect(thirdAttempt).toMatchObject({
      outboxId: firstAttempt.outboxId,
      attempts: 3,
    });
    await dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: thirdAttempt.outboxId,
        workerId: SYSTEM.userId,
        expectedAttempt: thirdAttempt.attempts,
      },
      SYSTEM
    );
    expect((await requireSession()).runtime.authorizationState).toBe("enforced");
  });

  it("rejects expired, revoked, and already-used invitations without admitting another User", async () => {
    await bootstrap();
    const expired = await createInvitation("member", { expiresAtMs: nowMs + 1 });
    nowMs += 2;
    await expect(redeemInvitation(expired, BOB)).rejects.toMatchObject({
      code: "invitation-expired",
    });

    const revoked = await createInvitation("guest");
    const projection = await admission();
    const revokedProjection = projection.invitations.find(
      (invitation) => invitation.invitationId === revoked.invitationId
    );
    if (!revokedProjection) throw new Error("Expected Invitation projection");
    await dispatch({
      type: "session.invitation.revoke",
      sessionId: SESSION_ID,
      invitationId: revoked.invitationId,
      expectedInvitationVersion: revokedProjection.version,
    });
    await expect(redeemInvitation(revoked, BOB)).rejects.toMatchObject({
      code: "invitation-revoked",
    });

    const used = await createInvitation("member");
    await redeemInvitation(used, BOB);
    await expect(redeemInvitation(used, CAROL)).rejects.toMatchObject({
      code: "invitation-used",
    });
  });

  it("does not give legacy platform administrators implicit Team, Project, or Session access", async () => {
    await bootstrap();

    await expect(getSession(SESSION_ID, LEGACY_ADMIN)).resolves.toBeNull();
    await expect(teamAccess(LEGACY_ADMIN)).rejects.toMatchObject({ code: "not-authorized" });
    await expect(projectAccess(LEGACY_ADMIN)).rejects.toMatchObject({ code: "not-authorized" });
    const visible = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: LEGACY_ADMIN,
      type: "session.list",
      teamId: TEAM_ID,
    });
    expect(visible).toEqual([]);
  });

  it("does not expose private Session lifecycle or revisions through unauthorized grant, Control, or Handoff probes", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await revokeParticipant(BOB);
    await expect(getSession(SESSION_ID, BOB)).resolves.toBeNull();

    const probes = (actor: ActorContext): CommandInput[] => [
      {
        type: "session.participant.grant",
        sessionId: SESSION_ID,
        userId: actor.userId,
        expectedParticipantVersion: 999,
        expectedAccessRevision: 999,
      },
      {
        type: "session.responsibility.grant",
        sessionId: SESSION_ID,
        userId: actor.userId,
        responsibility: "steerer",
        expectedSteeringRevision: 999,
        expectedParticipantVersion: 999,
      },
      {
        type: "session.control.transfer",
        sessionId: SESSION_ID,
        userId: actor.userId,
        expectedControlRevision: 999,
        expectedControlEpoch: 999,
        expectedParticipantVersion: 999,
      },
      {
        type: "session.handoff.offer",
        sessionId: SESSION_ID,
        recipientParticipantId: "private-participant-probe",
        expectedAssigneeRevision: 999,
        expectedRecipientParticipantVersion: 999,
        expectedOffererResponsibilityVersion: 999,
      },
    ];
    const actors = [DAVE, BOB];
    const activeRejections: Array<Array<{ code: unknown; message: string }>> = [];
    for (const actor of actors) {
      const actorRejections = [];
      for (const probe of probes(actor)) {
        actorRejections.push(await captureRejection(probe, actor));
      }
      activeRejections.push(actorRejections);
    }

    await forceSessionStatus("ended");
    const endedRejections: Array<Array<{ code: unknown; message: string }>> = [];
    for (const actor of actors) {
      const actorRejections = [];
      for (const probe of probes(actor)) {
        actorRejections.push(await captureRejection(probe, actor));
      }
      endedRejections.push(actorRejections);
    }

    const unavailable = { code: "not-authorized", message: "Resource is unavailable" };
    expect(activeRejections).toEqual(actors.map(() => probes(DAVE).map(() => unavailable)));
    expect(endedRejections).toEqual(activeRejections);

    const endedView = await requireSession(SESSION_ID, ALICE);
    const revokedBob = requireParticipant(endedView, BOB.userId);
    await expect(
      dispatch(
        {
          type: "session.participant.grant",
          sessionId: SESSION_ID,
          userId: BOB.userId,
          expectedParticipantVersion: revokedBob.version,
          expectedAccessRevision: endedView.accessRevision,
        },
        ALICE
      )
    ).rejects.toMatchObject({ code: "conflict" });
    expect((await requireSession(SESSION_ID, ALICE)).participants).toContainEqual(revokedBob);
  });

  it("denies system actors at every human command, query, and event-follow boundary", async () => {
    await bootstrap();

    await expect(
      dispatch({ type: "team.create", name: "System Team" }, SYSTEM)
    ).rejects.toMatchObject({ code: "not-authorized" });
    await expect(
      kernel().inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: SYSTEM,
        type: "session.get",
        sessionId: SESSION_ID,
      })
    ).rejects.toMatchObject({ code: "not-authorized" });
    const iterator = kernel()
      .follow({ sessionId: SESSION_ID, afterSequence: 0, actor: SYSTEM })
      [Symbol.asyncIterator]();
    await expect(iterator.next()).rejects.toMatchObject({ code: "not-authorized" });
  });

  it("rejects a globally colliding tmux name even for another Session id and name", async () => {
    await bootstrap();

    await expect(
      dispatch({
        type: "session.start",
        teamId: TEAM_ID,
        projectId: PROJECT_ID,
        sessionId: SECOND_SESSION_ID,
        name: "Different Session",
        tmuxName: "multiplayer-kernel",
      })
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("retains canonical event actors and gap-free per-Session sequences after access revocation", async () => {
    await bootstrap();
    const invitation = await createInvitation("member");
    await redeemInvitation(invitation, BOB, "bob-redemption");
    await grantProjectAccess(BOB);
    await dispatch(
      { type: "session.join", sessionId: SESSION_ID, invitationId: invitation.invitationId },
      BOB
    );
    await revokeProjectAccess(BOB);

    const events = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.events",
      sessionId: SESSION_ID,
      afterSequence: 0,
      limit: 1_000,
    });
    expect(events.map((event) => event.sequence)).toEqual(events.map((_, index) => index + 1));
    expect(events.find((event) => event.source.key === "bob-redemption")?.actor).toEqual(BOB);
    await expect(getSession(SESSION_ID, BOB)).resolves.toBeNull();
  });

  it("follows durable cross-instance events and stops cleanly on abort", async () => {
    await bootstrap();
    const afterSequence = (await requireSession()).latestSequence;
    const follower = openKernel();
    const abortController = new AbortController();
    const iterator = follower
      .follow({
        sessionId: SESSION_ID,
        afterSequence,
        actor: ALICE,
        signal: abortController.signal,
        pollIntervalMs: 10,
      })
      [Symbol.asyncIterator]();

    try {
      const nextEvent = iterator.next();
      await createInvitation("guest", { key: "cross-instance-follow" });
      await expect(nextEvent).resolves.toMatchObject({
        done: false,
        value: {
          sessionId: SESSION_ID,
          source: { scope: "vitest:team-sessions", key: "cross-instance-follow" },
        },
      });

      const pendingAfterAbort = iterator.next();
      abortController.abort();
      await expect(pendingAfterAbort).resolves.toEqual({ done: true, value: undefined });
    } finally {
      abortController.abort();
      await iterator.return?.();
      follower.close();
    }
  });

  it.skipIf(process.platform === "win32")(
    "keeps the SQLite main file and every present sidecar private on POSIX",
    async () => {
      await bootstrap();
      const databaseFiles = [
        filename,
        `${filename}-wal`,
        `${filename}-shm`,
        `${filename}-journal`,
      ].filter((candidate) => fs.existsSync(candidate));

      expect(databaseFiles).toContain(filename);
      for (const databaseFile of databaseFiles) {
        expect(fs.statSync(databaseFile).mode & 0o777, databaseFile).toBe(0o600);
      }
    }
  );

  it("rejects invalid tmux names and missing optimistic-concurrency inputs at runtime", async () => {
    await bootstrap();
    const invalidCommands = [
      {
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        idempotency: { scope: "vitest:invalid", key: "tmux" },
        type: "session.start",
        teamId: TEAM_ID,
        projectId: PROJECT_ID,
        name: "Bad tmux",
        tmuxName: "bad name",
      },
      {
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        idempotency: { scope: "vitest:invalid", key: "session-id" },
        type: "session.start",
        teamId: TEAM_ID,
        projectId: PROJECT_ID,
        sessionId: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        name: "Bad canonical id",
        tmuxName: "valid-tmux-name",
      },
      {
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        idempotency: { scope: "vitest:invalid", key: "version" },
        type: "team.membership.grant",
        teamId: TEAM_ID,
        userId: DAVE.userId,
        role: "member",
      },
    ];

    for (const command of invalidCommands) {
      await expect(kernel().dispatch(command as SessionCommand)).rejects.toMatchObject({
        code: "invalid-command",
      });
    }
  });

  it("rejects an invalid generated Session id before committing Runtime state", async () => {
    await dispatch({ type: "team.create", teamId: TEAM_ID, name: "Acme" });
    await dispatch({
      type: "project.create",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      name: "Terminal X",
      sourceRef: "/srv/terminalx",
    });
    teamSessions?.close();
    teamSessions = createTeamSessions({
      filename,
      clock: () => nowMs,
      idGenerator: () => "custom-session-id",
      invitationTokenGenerator: () => `txi_test_${"x".repeat(64)}`,
    });

    await expect(
      dispatch({
        type: "session.start",
        teamId: TEAM_ID,
        projectId: PROJECT_ID,
        name: "Invalid generated id",
        tmuxName: "valid-tmux-name",
      })
    ).rejects.toMatchObject({ code: "invalid-command" });

    await expect(
      kernel().inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        type: "session.list",
        actor: ALICE,
      })
    ).resolves.toEqual([]);
    await expect(
      kernel().claimRuntimeOutbox({
        workerId: "runtime-test-worker",
        leaseDurationMs: 1_000,
        limit: 10,
      })
    ).resolves.toEqual([]);
  });
});
