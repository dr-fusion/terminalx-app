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

const EVE: ActorContext = {
  kind: "human",
  userId: "user-eve",
  displayName: "Eve",
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

  async function sessionEvents(actor: ActorContext = ALICE) {
    return kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "session.events",
      sessionId: SESSION_ID,
      afterSequence: 0,
      limit: 1_000,
    });
  }

  function runtimeOutboxState(outboxId: string): {
    status: string;
    delivered_at_ms: number | null;
  } {
    const verification = new Database(filename, { readonly: true });
    try {
      const row = verification
        .prepare(`SELECT status, delivered_at_ms FROM runtime_outbox WHERE id = ?`)
        .get(outboxId) as { status: string; delivered_at_ms: number | null } | undefined;
      if (!row) throw new Error("Expected Runtime outbox state");
      return row;
    } finally {
      verification.close();
    }
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
        expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
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
    if (delivery.dispatchMode === "apply") {
      await kernel().markRuntimeOutboxDispatch({
        outboxId: delivery.outboxId,
        workerId: SYSTEM.userId,
        expectedAttempt: delivery.attempts,
        expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      });
    }
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

  async function forceSessionStatus(
    status: "active" | "awaiting_assignee" | "ended"
  ): Promise<void> {
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

  function closeAndDowngradeConversationSchemaToV1(): void {
    teamSessions?.close();
    teamSessions = undefined;
    const database = new Database(filename);
    try {
      database.exec(`
        PRAGMA foreign_keys = OFF;
        DROP TABLE attention_deliveries;
        DROP TABLE attention_escalations;
        DROP TABLE user_attention_reads;
        DROP TABLE comment_attachments;
        DROP TABLE comment_mentions;
        DROP TRIGGER IF EXISTS session_events_hash_chain_insert;
        DROP TRIGGER IF EXISTS session_events_append_only_update;
        DROP TRIGGER IF EXISTS session_events_append_only_delete;
        DROP TABLE session_platform_security_actions;
        DROP TABLE evidence_review_history;
        DROP TABLE goal_version_lineage;
        DROP TABLE session_event_checkpoints;
        DROP TABLE yolo_challenges;
        DROP TABLE circuit_breaker_state;
        DROP TABLE limit_settlements;
        DROP TABLE limit_reservations;
        DROP TABLE grant_consumptions;
        DROP TABLE grant_lineage;
        DROP TABLE approval_provenance;
        DROP TABLE installation_webhook_auth_digests;
        DROP TABLE provider_webhook_deliveries;
        DROP TABLE mobile_auth_migrations;
        DROP TABLE paired_devices;
        DROP TABLE mobile_pairing_codes;
        DROP TABLE connection_authority_ledger;
        DROP TABLE channel_bindings;
        DROP TABLE identity_connections;
        DROP TABLE link_challenges;
        DROP TABLE channel_installations;
        DROP TABLE credential_handles;
        DROP TABLE legacy_google_identity_bridges;
        DROP TABLE local_auth_credentials;
        DROP TABLE auth_identities;
        DROP TABLE users;
        DROP TABLE identity_migrations;
        DROP TRIGGER runtime_receipt_follow_streams_valid_transition;
        DROP TRIGGER IF EXISTS runtime_outbox_dispatch_interlock_valid_insert;
        DROP TRIGGER IF EXISTS runtime_outbox_dispatch_interlock_valid_update;
        DROP TRIGGER IF EXISTS runtime_outbox_payload_valid_insert;
        DROP TRIGGER IF EXISTS runtime_outbox_immutable_update;
        DROP TRIGGER IF EXISTS runtime_outbox_immutable_delete;
        DROP TRIGGER IF EXISTS runtime_outbox_source_event_immutable_update;
        DROP TRIGGER IF EXISTS runtime_outbox_source_event_immutable_delete;
        DROP TRIGGER IF EXISTS runtime_outbox_source_event_valid_insert;
        DROP TRIGGER IF EXISTS runtime_outbox_mutation_valid_update;
        DROP TRIGGER IF EXISTS runtime_outbox_settlements_valid_insert;
        DROP TRIGGER IF EXISTS runtime_outbox_settlements_immutable_update;
        DROP TRIGGER IF EXISTS runtime_outbox_settlements_immutable_delete;
        DROP TRIGGER IF EXISTS runtime_outbox_supersession_evidence_valid_insert;
        DROP TRIGGER IF EXISTS runtime_outbox_supersession_evidence_immutable_update;
        DROP TRIGGER IF EXISTS runtime_outbox_supersession_evidence_immutable_delete;
        DROP TRIGGER IF EXISTS accepted_commands_runtime_outbox_evidence;
        DROP TRIGGER IF EXISTS accepted_commands_immutable_update;
        DROP TRIGGER IF EXISTS accepted_commands_immutable_delete;
        DROP TABLE runtime_outbox_supersession_evidence;
        DROP TABLE runtime_outbox_settlements;
        DROP INDEX runtime_outbox_dispatch_interlock_acquired_at_idx;
        DROP INDEX runtime_outbox_created_at_idx;
        ALTER TABLE runtime_outbox DROP COLUMN dispatch_interlock_acquired_at_ms;
        ALTER TABLE runtime_outbox DROP COLUMN dispatch_interlock_attempt;
        DROP TRIGGER runtime_compensation_referenced_events_immutable_update;
        DROP TRIGGER runtime_compensation_referenced_events_immutable_delete;
        DROP TABLE runtime_receipt_follow_events;
        DROP TABLE runtime_compensation_follow_events;
        DROP TABLE runtime_compensation_effects;
        DROP TABLE runtime_compensation_receipts;
        DROP TABLE runtime_compensation_dispatch;
        DROP TABLE runtime_compensation_commands;
        DROP TABLE runtime_compensation_incidents;
        DROP TRIGGER IF EXISTS runtime_assignments_create_binding_safety_fence;
        DROP TABLE runtime_binding_safety_fences;
        DROP TABLE runtime_receipt_follow_streams;
        DROP TABLE runtime_principal_observation_keys;
        DROP TRIGGER IF EXISTS run_policy_revisions_enforcer_set_binding;
        DROP TRIGGER IF EXISTS sessions_runtime_lifecycle_dispatch_interlock;
        DROP TRIGGER IF EXISTS runtime_assignments_lifecycle_dispatch_interlock;
        DROP TRIGGER IF EXISTS agent_runs_lifecycle_dispatch_interlock;
        DROP TRIGGER runtime_run_referenced_session_events_immutable_update;
        DROP TRIGGER runtime_run_referenced_session_events_immutable_delete;
        DROP TABLE runtime_run_command_effects;
        DROP TABLE runtime_run_command_receipts;
        DROP TABLE runtime_run_command_dispatch;
        DROP TABLE runtime_run_commands;
        DROP TABLE grant_reviews;
        DROP TABLE action_grant_states;
        DROP TABLE action_grants;
        DROP TABLE attention_requests;
        DROP TABLE approval_requests;
        DROP TABLE action_manifests;
        DROP TABLE goal_evidence;
        DROP TABLE goals;
        DROP TABLE goal_sets;
        DROP TABLE run_policy_revisions;
        DROP TABLE agent_runs;
        DROP TABLE runtime_effect_enforcer_set_activations;
        DROP TABLE runtime_authorization_epochs;
        DROP TABLE hosted_runtime_assignment_plans;
        DROP TABLE runtime_assignments;
        DROP TRIGGER sessions_runtime_configuration_immutable;
        DROP TRIGGER sessions_runtime_authorization_monotonic;
        ALTER TABLE sessions DROP COLUMN run_state_revision;
        DROP TABLE conversation_suggestion_resolutions;
        DROP TABLE conversation_directives;
        DROP TABLE conversation_identities;
        PRAGMA user_version = 1;
      `);
    } finally {
      database.close();
    }
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
    await revokeProjectAccess(BOB);
    await expect(admission()).resolves.toMatchObject({
      accessCandidates: [
        expect.objectContaining({
          userId: BOB.userId,
          expectedProjectAccessVersion: 2,
        }),
      ],
    });
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

  it("provides minimized actor-scoped Session admission data to authorized managers", async () => {
    await bootstrap();
    const invitation = await createInvitation("member");
    await redeemInvitation(invitation, BOB);

    await expect(admission()).resolves.toMatchObject({
      sessionId: SESSION_ID,
      capabilities: {
        canRevokeInvitations: true,
        canGrantGuestShare: true,
        canGrantProjectAccess: true,
      },
      activeInvitations: [],
      accessCandidates: [
        {
          invitationId: invitation.invitationId,
          userId: BOB.userId,
          displayName: BOB.displayName,
          membershipRole: "member",
          requiredGrant: "project-access",
          expectedProjectAccessVersion: 0,
        },
      ],
    });

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
    const activeInvitation = await createInvitation("guest");
    const sessionAdmission = await admission();
    expect(sessionAdmission.activeInvitations).toEqual([
      {
        invitationId: activeInvitation.invitationId,
        membershipRole: "guest",
        version: 1,
        expiresAtMs: nowMs + 60_000,
      },
    ]);
    expect(sessionAdmission.accessCandidates).toEqual([]);
    expect(JSON.stringify(sessionAdmission)).not.toContain(invitation.token);
    expect(sessionAdmission).not.toHaveProperty("teamId");
    expect(sessionAdmission).not.toHaveProperty("projectId");
    expect(sessionAdmission).not.toHaveProperty("invitations");

    await expect(teamAccess(BOB)).rejects.toMatchObject({ code: "not-authorized" });
    await expect(projectAccess(BOB)).rejects.toMatchObject({ code: "not-authorized" });
    await expect(admission(BOB)).rejects.toMatchObject({ code: "not-authorized" });
  });

  it("lets a non-admin Session manager see grant candidates without overstating Project authority", async () => {
    await bootstrap();
    await admitMember(BOB);
    const beforeSupervisor = await requireSession();
    const bobParticipant = requireParticipant(beforeSupervisor, BOB.userId);
    await dispatch({
      type: "session.responsibility.grant",
      sessionId: SESSION_ID,
      userId: BOB.userId,
      responsibility: "supervisor",
      expectedSupervisionRevision: beforeSupervisor.supervisionRevision,
      expectedParticipantVersion: bobParticipant.version,
    });

    const guestInvitation = await createInvitation("guest");
    await redeemInvitation(guestInvitation, CAROL);
    const memberInvitation = await createInvitation("member");
    await redeemInvitation(memberInvitation, DAVE);
    await createInvitation("guest");

    const managerAdmission = await admission(BOB);
    expect(managerAdmission.capabilities).toEqual({
      canRevokeInvitations: false,
      canGrantGuestShare: true,
      canGrantProjectAccess: false,
    });
    expect(managerAdmission.activeInvitations).toEqual([]);
    expect(managerAdmission.accessCandidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          userId: CAROL.userId,
          membershipRole: "guest",
          requiredGrant: "session-share",
        }),
        expect.objectContaining({
          userId: DAVE.userId,
          membershipRole: "member",
          requiredGrant: "project-access",
          expectedProjectAccessVersion: 0,
        }),
      ])
    );

    await expect(grantProjectAccess(DAVE, "contributor", BOB)).rejects.toMatchObject({
      code: "not-authorized",
    });
    await expect(createShare(CAROL, BOB)).resolves.toMatchObject({ accepted: true });
    expect((await admission(BOB)).accessCandidates.map((candidate) => candidate.userId)).toEqual([
      DAVE.userId,
    ]);
  });

  it("lets a participating Team admin inspect invitations without exposing manager candidates", async () => {
    await bootstrap();
    await admitMember(BOB);
    await grantMembership(BOB, "admin");
    const activeInvitation = await createInvitation("member");
    const pendingGuest = await createInvitation("guest");
    await redeemInvitation(pendingGuest, CAROL);

    const administratorAdmission = await admission(BOB);
    expect(administratorAdmission.capabilities).toEqual({
      canRevokeInvitations: true,
      canGrantGuestShare: false,
      canGrantProjectAccess: false,
    });
    expect(administratorAdmission.activeInvitations).toEqual([
      expect.objectContaining({ invitationId: activeInvitation.invitationId }),
    ]);
    expect(administratorAdmission.accessCandidates).toEqual([]);
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
        expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
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

  it("reopens a marked crash only for reconciliation and gives competing connections one canonical acknowledgement", async () => {
    await bootstrap();
    const original = kernel();
    const [firstAttempt] = await original.claimRuntimeOutbox({
      workerId: "runtime-before-crash",
      limit: 1,
      leaseDurationMs: 1_000,
    });
    if (!firstAttempt) throw new Error("Expected Runtime delivery before crash");
    expect(firstAttempt).toMatchObject({ attempts: 1, dispatchMode: "apply" });
    await original.markRuntimeOutboxDispatch({
      outboxId: firstAttempt.outboxId,
      workerId: "runtime-before-crash",
      expectedAttempt: firstAttempt.attempts,
      expectedLeaseExpiresAtMs: firstAttempt.leaseExpiresAtMs,
    });
    original.close();
    teamSessions = undefined;

    nowMs = firstAttempt.leaseExpiresAtMs;
    const peers = [openKernel(), openKernel()] as const;
    teamSessions = peers[0];
    try {
      const claims = await Promise.all([
        peers[0].claimRuntimeOutbox({
          workerId: "runtime-recovery-a",
          limit: 1,
          leaseDurationMs: 30_000,
        }),
        peers[1].claimRuntimeOutbox({
          workerId: "runtime-recovery-b",
          limit: 1,
          leaseDurationMs: 30_000,
        }),
      ]);
      const claimed = claims.flat();
      expect(claimed).toHaveLength(1);
      const recovered = claimed[0];
      if (!recovered) throw new Error("Expected one reconciler lease");
      expect(recovered).toMatchObject({
        outboxId: firstAttempt.outboxId,
        attempts: 2,
        dispatchMode: "reconcile",
      });
      const owner = recovered.leaseOwner === "runtime-recovery-a" ? peers[0] : peers[1];
      const command = makeCommand(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: recovered.outboxId,
          workerId: recovered.leaseOwner,
          expectedAttempt: recovered.attempts,
          expectedLeaseExpiresAtMs: recovered.leaseExpiresAtMs,
        },
        { ...SYSTEM, userId: recovered.leaseOwner },
        "crash-reconciliation-ack"
      );

      const acknowledged = await owner.dispatch(command);
      await expect(owner.dispatch(command)).resolves.toEqual({
        ...acknowledged,
        replayed: true,
      });
      expect(acknowledged.events).toEqual([
        expect.objectContaining({ type: "runtime.session.ensured" }),
      ]);
      const events = await owner.inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        type: "session.events",
        sessionId: SESSION_ID,
        afterSequence: 0,
        limit: 1_000,
      });
      expect(events.filter((event) => event.type === "runtime.session.ensured")).toHaveLength(1);
      await expect(
        peers[0].claimRuntimeOutbox({
          workerId: "runtime-after-ack",
          limit: 1,
          leaseDurationMs: 30_000,
        })
      ).resolves.toEqual([]);
    } finally {
      peers[1].close();
    }
  });

  it("canonically supersedes a marked old generation after crash without returning it to apply", async () => {
    await bootstrap();
    await admitMember(BOB);
    await grantMembership(BOB, "owner");
    const [firstAttempt] = await kernel().claimRuntimeOutbox({
      workerId: SYSTEM.userId,
      limit: 1,
      leaseDurationMs: 1_000,
    });
    if (!firstAttempt) throw new Error("Expected original ensure attempt");
    await kernel().markRuntimeOutboxDispatch({
      outboxId: firstAttempt.outboxId,
      workerId: SYSTEM.userId,
      expectedAttempt: firstAttempt.attempts,
      expectedLeaseExpiresAtMs: firstAttempt.leaseExpiresAtMs,
    });
    await revokeMembership(ALICE, BOB);
    kernel().close();
    teamSessions = undefined;

    nowMs = firstAttempt.leaseExpiresAtMs;
    teamSessions = openKernel();
    const [recovered] = await kernel().claimRuntimeOutbox({
      workerId: SYSTEM.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    if (!recovered) throw new Error("Expected superseded reconciliation lease");
    expect(recovered).toMatchObject({
      outboxId: firstAttempt.outboxId,
      attempts: 2,
      dispatchMode: "reconcile",
    });

    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: recovered.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: recovered.attempts,
          expectedLeaseExpiresAtMs: recovered.leaseExpiresAtMs,
        },
        SYSTEM
      )
    ).resolves.toMatchObject({
      data: { superseded: true, runtimeAuthorizationGeneration: 1 },
      events: [expect.objectContaining({ type: "runtime.outbox.delivered" })],
    });
    expect(runtimeOutboxState(recovered.outboxId)).toEqual({
      status: "delivered",
      delivered_at_ms: nowMs,
    });
    const [next] = await kernel().claimRuntimeOutbox({
      workerId: SYSTEM.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    expect(next).toMatchObject({
      kind: "runtime.authorization.fence",
      dispatchMode: "apply",
    });
  });

  it("supersedes a reconciled delivery from an older generation and unblocks the newer fence", async () => {
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
          expectedLeaseExpiresAtMs: olderEnsure.leaseExpiresAtMs,
          retryable: true,
          errorCode: "runtime_conflict",
        },
        SYSTEM
      )
    ).resolves.toMatchObject({
      data: { superseded: false, retryable: true },
      events: [expect.objectContaining({ type: "runtime.outbox.retry-scheduled" })],
    });
    const [reconciledEnsure] = await kernel().claimRuntimeOutbox({
      workerId: SYSTEM.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    expect(reconciledEnsure).toMatchObject({
      outboxId: olderEnsure.outboxId,
      attempts: olderEnsure.attempts + 1,
      dispatchMode: "reconcile",
    });
    if (!reconciledEnsure) throw new Error("Expected old ensure reconciliation");
    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: reconciledEnsure.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: reconciledEnsure.attempts,
          expectedLeaseExpiresAtMs: reconciledEnsure.leaseExpiresAtMs,
        },
        SYSTEM
      )
    ).resolves.toMatchObject({
      data: {
        runtimeAuthorizationGeneration: 1,
        superseded: true,
      },
      events: [expect.objectContaining({ type: "runtime.outbox.delivered" })],
    });
    expect(runtimeOutboxState(reconciledEnsure.outboxId)).toEqual({
      status: "delivered",
      delivered_at_ms: nowMs,
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
        expectedLeaseExpiresAtMs: currentFence.leaseExpiresAtMs,
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
          expectedLeaseExpiresAtMs: currentEnsure.leaseExpiresAtMs,
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

  it("renews only the exact live Runtime lease and carries its new expiry through dispatch", async () => {
    await bootstrap();
    const [delivery] = await kernel().claimRuntimeOutbox({
      workerId: "runtime-renewal-owner",
      limit: 1,
      leaseDurationMs: 1_000,
    });
    if (!delivery) throw new Error("Expected Runtime delivery for lease renewal");
    const originalLeaseExpiresAtMs = delivery.leaseExpiresAtMs;
    nowMs += 500;

    await expect(
      kernel().renewRuntimeOutboxLease({
        outboxId: delivery.outboxId,
        workerId: "wrong-runtime-owner",
        expectedAttempt: delivery.attempts,
        expectedLeaseExpiresAtMs: originalLeaseExpiresAtMs,
        leaseDurationMs: 1_000,
      })
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      kernel().renewRuntimeOutboxLease({
        outboxId: delivery.outboxId,
        workerId: "runtime-renewal-owner",
        expectedAttempt: delivery.attempts + 1,
        expectedLeaseExpiresAtMs: originalLeaseExpiresAtMs,
        leaseDurationMs: 1_000,
      })
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      kernel().renewRuntimeOutboxLease({
        outboxId: delivery.outboxId,
        workerId: "runtime-renewal-owner",
        expectedAttempt: delivery.attempts,
        expectedLeaseExpiresAtMs: originalLeaseExpiresAtMs + 1,
        leaseDurationMs: 1_000,
      })
    ).rejects.toMatchObject({ code: "stale-revision" });
    for (const leaseDurationMs of [999, 300_001]) {
      await expect(
        kernel().renewRuntimeOutboxLease({
          outboxId: delivery.outboxId,
          workerId: "runtime-renewal-owner",
          expectedAttempt: delivery.attempts,
          expectedLeaseExpiresAtMs: originalLeaseExpiresAtMs,
          leaseDurationMs,
        })
      ).rejects.toMatchObject({ code: "invalid-command" });
    }

    const renewed = await kernel().renewRuntimeOutboxLease({
      outboxId: delivery.outboxId,
      workerId: "runtime-renewal-owner",
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: originalLeaseExpiresAtMs,
      leaseDurationMs: 1_000,
    });
    expect(renewed).toEqual({ leaseExpiresAtMs: nowMs + 1_000 });

    nowMs = originalLeaseExpiresAtMs;
    const competingKernel = openKernel();
    try {
      await expect(
        competingKernel.claimRuntimeOutbox({
          workerId: "runtime-competing-worker",
          limit: 1,
          leaseDurationMs: 1_000,
        })
      ).resolves.toEqual([]);
    } finally {
      competingKernel.close();
    }
    await expect(
      kernel().markRuntimeOutboxDispatch({
        outboxId: delivery.outboxId,
        workerId: "runtime-renewal-owner",
        expectedAttempt: delivery.attempts,
        expectedLeaseExpiresAtMs: originalLeaseExpiresAtMs,
      })
    ).rejects.toMatchObject({ code: "stale-revision" });
    await kernel().markRuntimeOutboxDispatch({
      outboxId: delivery.outboxId,
      workerId: "runtime-renewal-owner",
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: renewed.leaseExpiresAtMs,
    });
    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: delivery.outboxId,
          workerId: "runtime-renewal-owner",
          expectedAttempt: delivery.attempts,
          expectedLeaseExpiresAtMs: originalLeaseExpiresAtMs,
        },
        { ...SYSTEM, userId: "runtime-renewal-owner" }
      )
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: delivery.outboxId,
          workerId: "runtime-renewal-owner",
          expectedAttempt: delivery.attempts,
          expectedLeaseExpiresAtMs: renewed.leaseExpiresAtMs,
        },
        { ...SYSTEM, userId: "runtime-renewal-owner" }
      )
    ).resolves.toMatchObject({ data: { superseded: false } });
  });

  it("self-heals an invalid far-future Runtime lease instead of blocking the Session", async () => {
    await bootstrap();
    const injected = new Database(filename);
    const outbox = injected
      .prepare(
        `SELECT id FROM runtime_outbox
         WHERE session_id = ? AND status = 'pending'
         ORDER BY session_sequence, id LIMIT 1`
      )
      .get(SESSION_ID) as { id: string } | undefined;
    if (!outbox) throw new Error("Expected pending Runtime delivery");
    injected
      .prepare(
        `UPDATE runtime_outbox
         SET status = 'processing', attempts = 1,
             lease_owner = 'invalid-lease-owner', lease_expires_at_ms = ?
         WHERE id = ?`
      )
      .run(Number.MAX_SAFE_INTEGER, outbox.id);
    injected.close();

    const [recovered] = await kernel().claimRuntimeOutbox({
      workerId: "runtime-recovery-owner",
      limit: 1,
      leaseDurationMs: 30_000,
    });
    expect(recovered).toMatchObject({
      outboxId: outbox.id,
      attempts: 2,
      leaseOwner: "runtime-recovery-owner",
      dispatchMode: "apply",
    });

    const verified = new Database(filename, { readonly: true });
    const settlement = verified
      .prepare(
        `SELECT attempt, lease_owner, lease_expires_at_ms, outcome, recorded_at_ms
         FROM runtime_outbox_settlements
         WHERE outbox_id = ? AND attempt = 1`
      )
      .get(outbox.id);
    verified.close();
    expect(settlement).toEqual({
      attempt: 1,
      lease_owner: "invalid-lease-owner",
      lease_expires_at_ms: Number.MAX_SAFE_INTEGER,
      outcome: "lease-invalid",
      recorded_at_ms: nowMs,
    });
  });

  it("tolerates bounded clock rollback without stealing a valid maximum Runtime lease", async () => {
    await bootstrap();
    nowMs += 120_000;
    const [delivery] = await kernel().claimRuntimeOutbox({
      workerId: "runtime-before-clock-adjustment",
      limit: 1,
      leaseDurationMs: 300_000,
    });
    if (!delivery) throw new Error("Expected Runtime delivery before clock adjustment");

    nowMs -= 30_000;
    await expect(
      kernel().claimRuntimeOutbox({
        workerId: "runtime-after-clock-adjustment",
        limit: 1,
        leaseDurationMs: 30_000,
      })
    ).resolves.toEqual([]);
    expect(runtimeOutboxState(delivery.outboxId)).toEqual({
      status: "processing",
      delivered_at_ms: null,
    });
  });

  it("fails closed when the Runtime clock predates durable outbox work", async () => {
    await bootstrap();
    nowMs -= 1;

    await expect(
      kernel().claimRuntimeOutbox({
        workerId: "runtime-with-regressed-clock",
        limit: 1,
        leaseDurationMs: 30_000,
      })
    ).rejects.toMatchObject({
      code: "conflict",
      message: "Runtime outbox clock moved backwards",
    });
  });

  it("fails closed when the Runtime clock predates a durable dispatch marker", async () => {
    await bootstrap();
    nowMs += 120_000;
    const [delivery] = await kernel().claimRuntimeOutbox({
      workerId: "runtime-before-marker-rollback",
      limit: 1,
      leaseDurationMs: 300_000,
    });
    if (!delivery) throw new Error("Expected Runtime delivery before marker rollback");
    await kernel().markRuntimeOutboxDispatch({
      outboxId: delivery.outboxId,
      workerId: delivery.leaseOwner,
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
    });

    nowMs -= 60_000;
    await expect(
      kernel().claimRuntimeOutbox({
        workerId: "runtime-after-marker-rollback",
        limit: 1,
        leaseDurationMs: 30_000,
      })
    ).rejects.toMatchObject({
      code: "conflict",
      message: "Runtime outbox clock moved backwards",
    });
    expect(runtimeOutboxState(delivery.outboxId)).toEqual({
      status: "processing",
      delivered_at_ms: null,
    });
  });

  it("rejects every outcome until the exact owner and attempt acquire the dispatch interlock", async () => {
    await bootstrap();
    const [delivery] = await kernel().claimRuntimeOutbox({
      workerId: SYSTEM.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    if (!delivery) throw new Error("Expected unmarked Runtime delivery");

    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: delivery.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: delivery.attempts,
          expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
        },
        SYSTEM
      )
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      dispatch(
        {
          type: "runtime.outbox.fail",
          outboxId: delivery.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: delivery.attempts,
          expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
          retryable: true,
          errorCode: "runtime_timeout",
        },
        SYSTEM
      )
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      kernel().markRuntimeOutboxDispatch({
        outboxId: delivery.outboxId,
        workerId: "wrong-worker",
        expectedAttempt: delivery.attempts,
        expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      })
    ).rejects.toMatchObject({ code: "stale-revision" });

    await kernel().markRuntimeOutboxDispatch({
      outboxId: delivery.outboxId,
      workerId: SYSTEM.userId,
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
    });
    await expect(
      kernel().markRuntimeOutboxDispatch({
        outboxId: delivery.outboxId,
        workerId: SYSTEM.userId,
        expectedAttempt: delivery.attempts,
        expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      })
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: delivery.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: delivery.attempts,
          expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
        },
        SYSTEM
      )
    ).resolves.toMatchObject({ data: { superseded: false } });
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
      dispatchMode: "apply",
    });

    await kernel().markRuntimeOutboxDispatch({
      outboxId: secondAttempt.outboxId,
      workerId: SYSTEM.userId,
      expectedAttempt: secondAttempt.attempts,
      expectedLeaseExpiresAtMs: secondAttempt.leaseExpiresAtMs,
    });

    await expect(
      dispatch(
        {
          type: "runtime.outbox.acknowledge",
          outboxId: firstAttempt.outboxId,
          workerId: SYSTEM.userId,
          expectedAttempt: firstAttempt.attempts,
          expectedLeaseExpiresAtMs: firstAttempt.leaseExpiresAtMs,
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
          expectedLeaseExpiresAtMs: firstAttempt.leaseExpiresAtMs,
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
          expectedLeaseExpiresAtMs: secondAttempt.leaseExpiresAtMs,
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
          expectedLeaseExpiresAtMs: secondAttempt.leaseExpiresAtMs,
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
          expectedLeaseExpiresAtMs: secondAttempt.leaseExpiresAtMs,
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
      dispatchMode: "reconcile",
    });
    await dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: thirdAttempt.outboxId,
        workerId: SYSTEM.userId,
        expectedAttempt: thirdAttempt.attempts,
        expectedLeaseExpiresAtMs: thirdAttempt.leaseExpiresAtMs,
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
    const revokedProjection = projection.activeInvitations.find(
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

  it("stores Comments and Suggestions as attributed canonical events without executable work or chat tables", async () => {
    await bootstrap();
    await admitMember(BOB);
    await enforceNextRuntimeDelivery("runtime.session.ensure");

    const commentBody = "I reproduced this locally.\n\tThe failing check is deterministic.";
    const comment = await dispatch(
      { type: "comment.add", sessionId: SESSION_ID, body: commentBody },
      BOB,
      "bob-comment"
    );
    const suggestion = await dispatch(
      {
        type: "suggestion.add",
        sessionId: SESSION_ID,
        body: "Please isolate the parser before changing the Runtime.",
      },
      BOB,
      "bob-suggestion"
    );

    expect(comment.data).toMatchObject({
      sessionId: SESSION_ID,
      commentId: expect.any(String),
      sequence: expect.any(Number),
    });
    expect(comment.events).toEqual([
      expect.objectContaining({
        type: "comment.added",
        actor: BOB,
        source: { scope: "vitest:team-sessions", key: "bob-comment" },
        payload: { commentId: comment.data.commentId, body: commentBody },
      }),
    ]);
    expect(suggestion.data).toMatchObject({
      suggestionId: expect.any(String),
      suggestionVersion: 1,
    });
    expect(suggestion.events).toEqual([
      expect.objectContaining({
        type: "suggestion.added",
        actor: BOB,
        source: { scope: "vitest:team-sessions", key: "bob-suggestion" },
        payload: {
          suggestionId: suggestion.data.suggestionId,
          suggestionVersion: 1,
          body: "Please isolate the parser before changing the Runtime.",
        },
      }),
    ]);
    await expect(
      kernel().claimRuntimeOutbox({ workerId: SYSTEM.userId, limit: 10, leaseDurationMs: 1_000 })
    ).resolves.toEqual([]);

    const database = new Database(filename, { readonly: true });
    try {
      const conversationTables = database
        .prepare(
          `SELECT name FROM sqlite_master
           WHERE type = 'table'
             AND (name LIKE '%chat%' OR name LIKE '%comment%')
           ORDER BY name`
        )
        .all();
      // The only comment-scoped tables are the Phase 11A append-only evidence
      // rows (mention resolutions and artifact attachments). Comment bodies
      // themselves remain in the canonical event chain, never a chat table.
      expect(conversationTables).toEqual([
        { name: "comment_attachments" },
        { name: "comment_mentions" },
      ]);
      for (const normalizedTable of [
        "conversation_identities",
        "conversation_suggestion_resolutions",
        "conversation_directives",
        "comment_mentions",
        "comment_attachments",
      ]) {
        const columns = database.prepare(`PRAGMA table_info(${normalizedTable})`).all() as Array<{
          name: string;
        }>;
        expect(columns.map((column) => column.name)).not.toContain("body");
        expect(columns.map((column) => column.name)).not.toContain("payload_json");
      }
    } finally {
      database.close();
    }
  });

  it("preserves LF multiline plain text and enforces a 16 KiB UTF-8 body boundary", async () => {
    await bootstrap();
    const exactUtf8Boundary = "é".repeat(8_192);
    const exact = await dispatch({
      type: "comment.add",
      sessionId: SESSION_ID,
      body: exactUtf8Boundary,
    });
    expect(exact.events[0]?.payload.body).toBe(exactUtf8Boundary);

    const multiline = "first line\n\tsecond line\nthird line";
    const preserved = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: multiline,
    });
    expect(preserved.events[0]?.payload.body).toBe(multiline);

    for (const body of ["é".repeat(8_193), " \n\t ", "contains\0nul", "crlf\r\ntext"]) {
      await expect(
        dispatch({ type: "comment.add", sessionId: SESSION_ID, body })
      ).rejects.toMatchObject({ code: "invalid-command" });
    }
    await expect(
      kernel().dispatch({
        ...makeCommand({ type: "comment.add", sessionId: SESSION_ID, body: "safe" }),
        commentId: "client-owned-comment-id",
      } as unknown as SessionCommand)
    ).rejects.toMatchObject({ code: "invalid-command" });
    await expect(
      kernel().dispatch({
        ...makeCommand({
          type: "directive.enqueue",
          sessionId: SESSION_ID,
          body: "safe",
          expectedSteeringRevision: (await requireSession()).steeringRevision,
        }),
        directiveId: "client-owned-directive-id",
      } as unknown as SessionCommand)
    ).rejects.toMatchObject({ code: "invalid-command" });
  });

  it("retries generated conversation identifiers that collide with prior payload ids", async () => {
    await bootstrap();
    const existing = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Existing identity",
    });
    const existingSuggestionId = existing.data.suggestionId as string;
    teamSessions?.close();
    teamSessions = undefined;
    const generatedCandidates = [
      existingSuggestionId,
      "collision-safe-comment",
      "collision-safe-comment-event",
      existingSuggestionId,
      "collision-safe-suggestion",
      "collision-safe-suggestion-event",
      "same-new-resolution-id",
      "same-new-resolution-id",
      "collision-safe-directive",
      "collision-safe-resolution-event",
      "collision-safe-directive-event",
    ];
    let fallbackId = 0;
    teamSessions = createTeamSessions({
      filename,
      clock: () => nowMs,
      idGenerator: () => generatedCandidates.shift() ?? `collision-safe-fallback-${++fallbackId}`,
      invitationTokenGenerator: () => `txi_collision_${"x".repeat(64)}`,
    });

    const comment = await dispatch({
      type: "comment.add",
      sessionId: SESSION_ID,
      body: "A unique Comment id",
    });
    expect(comment.data.commentId).toBe("collision-safe-comment");
    const suggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "A unique Suggestion id",
    });
    expect(suggestion.data.suggestionId).toBe("collision-safe-suggestion");
    const resolved = await dispatch({
      type: "suggestion.resolve",
      sessionId: SESSION_ID,
      suggestionId: suggestion.data.suggestionId as string,
      resolution: "accept",
      expectedSuggestionVersion: 1,
      expectedSteeringRevision: (await requireSession()).steeringRevision,
    });
    expect(resolved.data).toMatchObject({
      resolutionId: "same-new-resolution-id",
      directiveId: "collision-safe-directive",
    });
    expect(resolved.data.resolutionId).not.toBe(resolved.data.directiveId);
    expect(
      (await sessionEvents())
        .flatMap((event) => [
          event.payload.commentId,
          event.payload.suggestionId,
          event.payload.resolutionId,
          event.payload.directiveId,
        ])
        .filter((value) => typeof value === "string" && value === existingSuggestionId)
    ).toHaveLength(1);
  });

  it("migrates a v1 event ledger into indexed conversation state without changing canonical events", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await dispatch({
      type: "comment.add",
      sessionId: SESSION_ID,
      body: "A Comment that predates normalization",
    });
    const suggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Normalize canonical identity state",
    });
    await dispatch({
      type: "suggestion.resolve",
      sessionId: SESSION_ID,
      suggestionId: suggestion.data.suggestionId as string,
      resolution: "accept",
      expectedSuggestionVersion: 1,
      expectedSteeringRevision: (await requireSession()).steeringRevision,
    });
    const beforeRevocation = await requireSession();
    await dispatch({
      type: "session.responsibility.revoke",
      sessionId: SESSION_ID,
      userId: ALICE.userId,
      responsibility: "steerer",
      expectedSteeringRevision: beforeRevocation.steeringRevision,
      expectedControlRevision: beforeRevocation.controlRevision,
      expectedControlEpoch: beforeRevocation.controlEpoch,
    });
    const eventsBeforeMigration = await sessionEvents();

    closeAndDowngradeConversationSchemaToV1();
    teamSessions = openKernel();
    expect(await sessionEvents()).toEqual(eventsBeforeMigration);

    const database = new Database(filename, { readonly: true });
    try {
      expect(database.pragma("user_version", { simple: true })).toBe(18);
      expect(database.pragma("foreign_key_check")).toEqual([]);
      expect(
        database
          .prepare(
            "SELECT kind, COUNT(*) AS count FROM conversation_identities GROUP BY kind ORDER BY kind"
          )
          .all()
      ).toEqual([
        { kind: "comment", count: 1 },
        { kind: "directive", count: 1 },
        { kind: "resolution", count: 1 },
        { kind: "suggestion", count: 1 },
      ]);
      expect(
        database
          .prepare(`SELECT suggestion_version, decision FROM conversation_suggestion_resolutions`)
          .all()
      ).toEqual([{ suggestion_version: 2, decision: "accept" }]);
      expect(
        database
          .prepare(`SELECT author_user_id, status, terminal_sequence FROM conversation_directives`)
          .all()
      ).toEqual([
        {
          author_user_id: ALICE.userId,
          status: "cancelled",
          terminal_sequence: expect.any(Number),
        },
      ]);
      expect(
        database
          .prepare(
            `SELECT name FROM sqlite_master
             WHERE type = 'index' AND name LIKE 'conversation_%'
             ORDER BY name`
          )
          .all()
      ).toEqual(
        expect.arrayContaining([
          { name: "conversation_directives_by_author_status" },
          { name: "conversation_directives_by_session_status" },
          { name: "conversation_identities_by_session_kind" },
        ])
      );
    } finally {
      database.close();
    }
  });

  it("rolls back v1 migration when legacy payload identities are ambiguous", async () => {
    await bootstrap();
    const first = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "First legacy Suggestion",
    });
    await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Second legacy Suggestion",
    });
    teamSessions?.close();
    teamSessions = undefined;
    const corrupt = new Database(filename);
    try {
      const second = corrupt
        .prepare(
          `SELECT sequence, payload_json FROM session_events
           WHERE session_id = ? AND type = 'suggestion.added'
           ORDER BY sequence DESC LIMIT 1`
        )
        .get(SESSION_ID) as { sequence: number; payload_json: string };
      const payload = JSON.parse(second.payload_json) as Record<string, unknown>;
      payload.suggestionId = first.data.suggestionId;
      // Simulate out-of-band, on-disk tampering (which does not run SQLite
      // triggers) by dropping the Phase 10 append-only guard on this raw
      // connection before planting the ambiguous legacy payload.
      corrupt.prepare(`DROP TRIGGER session_events_append_only_update`).run();
      corrupt
        .prepare(`UPDATE session_events SET payload_json = ? WHERE session_id = ? AND sequence = ?`)
        .run(JSON.stringify(payload), SESSION_ID, second.sequence);
    } finally {
      corrupt.close();
    }
    closeAndDowngradeConversationSchemaToV1();

    expect(() => openKernel()).toThrow();
    const database = new Database(filename, { readonly: true });
    try {
      expect(database.pragma("user_version", { simple: true })).toBe(1);
      expect(
        database
          .prepare(
            `SELECT name FROM sqlite_master
             WHERE type = 'table' AND name = 'conversation_identities'`
          )
          .get()
      ).toBeUndefined();
    } finally {
      database.close();
    }
  });

  it("requires the current Controller and Steerer under single steering", async () => {
    await bootstrap();
    await admitMember(BOB);
    const beforeTransfer = await requireSession();

    await expect(
      dispatch(
        {
          type: "directive.enqueue",
          sessionId: SESSION_ID,
          body: "Bob cannot steer yet",
          expectedSteeringRevision: beforeTransfer.steeringRevision,
        },
        BOB
      )
    ).rejects.toMatchObject({ code: "not-authorized" });
    const aliceDirective = await dispatch({
      type: "directive.enqueue",
      sessionId: SESSION_ID,
      body: "Alice is the current Controller and Steerer",
      expectedSteeringRevision: beforeTransfer.steeringRevision,
    });
    expect(aliceDirective.events[0]).toMatchObject({
      type: "directive.queued",
      actor: ALICE,
      payload: { status: "queued", steeringPolicy: "single" },
    });

    await transferControl(BOB, ALICE);
    const afterTransfer = await requireSession(SESSION_ID, BOB);
    await expect(
      dispatch(
        {
          type: "directive.enqueue",
          sessionId: SESSION_ID,
          body: "A stale policy envelope",
          expectedSteeringRevision: beforeTransfer.steeringRevision,
        },
        BOB
      )
    ).rejects.toMatchObject({ code: "stale-revision" });
    await expect(
      dispatch(
        {
          type: "directive.enqueue",
          sessionId: SESSION_ID,
          body: "Alice no longer controls the Session",
          expectedSteeringRevision: afterTransfer.steeringRevision,
        },
        ALICE
      )
    ).rejects.toMatchObject({ code: "not-authorized" });
    await expect(
      dispatch(
        {
          type: "directive.enqueue",
          sessionId: SESSION_ID,
          body: "Bob now holds both responsibilities",
          expectedSteeringRevision: afterTransfer.steeringRevision,
        },
        BOB
      )
    ).resolves.toMatchObject({
      data: { directiveStatus: "queued", steeringRevision: afterTransfer.steeringRevision },
    });
  });

  it("serializes shared Steerers by canonical event order even with no Controller", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    const beforeGrant = await requireSession();
    await grantSteerer(BOB);
    const shared = await requireSession();
    await expect(
      dispatch(
        {
          type: "directive.enqueue",
          sessionId: SESSION_ID,
          body: "Stale shared envelope",
          expectedSteeringRevision: beforeGrant.steeringRevision,
        },
        BOB
      )
    ).rejects.toMatchObject({ code: "stale-revision" });

    await dispatch({
      type: "session.control.release",
      sessionId: SESSION_ID,
      expectedControlRevision: shared.controlRevision,
      expectedControlEpoch: shared.controlEpoch,
    });
    expect(
      (await requireSession()).participants.some((participant) =>
        participant.responsibilities.includes("controller")
      )
    ).toBe(false);

    const bobDirective = await dispatch(
      {
        type: "directive.enqueue",
        sessionId: SESSION_ID,
        body: "Bob's queued work",
        expectedSteeringRevision: shared.steeringRevision,
      },
      BOB
    );
    const aliceDirective = await dispatch({
      type: "directive.enqueue",
      sessionId: SESSION_ID,
      body: "Alice's later queued work",
      expectedSteeringRevision: shared.steeringRevision,
    });
    const bobEvent = bobDirective.events[0];
    const aliceEvent = aliceDirective.events[0];
    expect(bobEvent).toMatchObject({ type: "directive.queued", actor: BOB });
    expect(aliceEvent).toMatchObject({ type: "directive.queued", actor: ALICE });
    expect(bobDirective.data.queueSequence).toBe(bobEvent?.sequence);
    expect(aliceDirective.data.queueSequence).toBe(aliceEvent?.sequence);
    expect(bobEvent?.sequence).toBeLessThan(aliceEvent?.sequence ?? 0);
  });

  it("enforces the global 64-Directive author ceiling and bounds higher-scope revocation across Sessions", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await grantMembership(BOB, "owner");
    await dispatch({
      type: "session.start",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sessionId: SECOND_SESSION_ID,
      name: "Second bounded queue",
      tmuxName: "second-bounded-queue",
      steeringPolicy: "shared",
    });
    const firstRevision = (await requireSession()).steeringRevision;
    const secondRevision = (await requireSession(SECOND_SESSION_ID)).steeringRevision;
    for (let index = 0; index < 32; index += 1) {
      await dispatch({
        type: "directive.enqueue",
        sessionId: SESSION_ID,
        body: `First Session Directive ${index}`,
        expectedSteeringRevision: firstRevision,
      });
      await dispatch({
        type: "directive.enqueue",
        sessionId: SECOND_SESSION_ID,
        body: `Second Session Directive ${index}`,
        expectedSteeringRevision: secondRevision,
      });
    }
    await expect(
      dispatch({
        type: "directive.enqueue",
        sessionId: SESSION_ID,
        body: "The sixty-fifth global pending Directive",
        expectedSteeringRevision: firstRevision,
      })
    ).rejects.toMatchObject({ code: "conflict" });

    const suggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Acceptance would exceed the pending ceiling",
    });
    await expect(
      dispatch({
        type: "suggestion.resolve",
        sessionId: SESSION_ID,
        suggestionId: suggestion.data.suggestionId as string,
        resolution: "accept",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: firstRevision,
      })
    ).rejects.toMatchObject({ code: "conflict" });
    expect(
      (await sessionEvents()).filter(
        (event) =>
          event.type === "suggestion.resolved" &&
          event.payload.suggestionId === suggestion.data.suggestionId
      )
    ).toEqual([]);
    await expect(
      dispatch({
        type: "suggestion.resolve",
        sessionId: SESSION_ID,
        suggestionId: suggestion.data.suggestionId as string,
        resolution: "reject",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: firstRevision,
      })
    ).resolves.toMatchObject({ commandType: "suggestion.resolve" });

    await revokeMembership(ALICE, BOB);
    const database = new Database(filename, { readonly: true });
    try {
      expect(
        database
          .prepare(`SELECT status, COUNT(*) AS count FROM conversation_directives GROUP BY status`)
          .all()
      ).toEqual([{ status: "cancelled", count: 64 }]);
      expect(
        database
          .prepare(
            `SELECT COUNT(*) AS count FROM session_events WHERE type = 'directive.cancelled'`
          )
          .get()
      ).toEqual({ count: 64 });
      expect(
        database
          .prepare(
            `SELECT COUNT(*) AS count FROM conversation_directives
             WHERE terminal_sequence IS NULL`
          )
          .get()
      ).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  it("enforces the 256-Directive Session ceiling across multiple Steerers", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    for (const participant of [BOB, CAROL, DAVE, EVE]) {
      await admitMember(participant);
      await grantSteerer(participant);
    }
    const steeringRevision = (await requireSession()).steeringRevision;
    for (const author of [ALICE, BOB, CAROL, DAVE]) {
      for (let index = 0; index < 64; index += 1) {
        await dispatch(
          {
            type: "directive.enqueue",
            sessionId: SESSION_ID,
            body: `${author.displayName} pending Directive ${index}`,
            expectedSteeringRevision: steeringRevision,
          },
          author
        );
      }
    }
    await expect(
      dispatch(
        {
          type: "directive.enqueue",
          sessionId: SESSION_ID,
          body: "The Session-wide two-hundred-fifty-seventh Directive",
          expectedSteeringRevision: steeringRevision,
        },
        EVE
      )
    ).rejects.toMatchObject({ code: "conflict" });

    const database = new Database(filename, { readonly: true });
    try {
      expect(
        database
          .prepare(
            `SELECT COUNT(*) AS count FROM conversation_directives
               WHERE session_id = ? AND status = 'queued'`
          )
          .get(SESSION_ID)
      ).toEqual({ count: 256 });
    } finally {
      database.close();
    }
  }, 15_000);

  it("resolves Suggestions atomically and queues accepted text without claiming Runtime dispatch", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await grantSteerer(BOB);
    await enforceNextRuntimeDelivery("runtime.session.ensure");
    const steeringRevision = (await requireSession()).steeringRevision;

    const editedSuggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Run every test.",
    });
    const editedCommand = makeCommand(
      {
        type: "suggestion.resolve",
        sessionId: SESSION_ID,
        suggestionId: editedSuggestion.data.suggestionId as string,
        resolution: "accept-edited",
        editedBody: "Run the focused tests first.\nThen run the full suite.",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: steeringRevision,
      },
      BOB,
      "accept-edited-suggestion"
    );
    const edited = await kernel().dispatch(editedCommand);
    expect(edited.events.map((event) => event.type)).toEqual([
      "suggestion.resolved",
      "directive.queued",
    ]);
    expect(edited.events[1]?.sequence).toBe((edited.events[0]?.sequence ?? 0) + 1);
    expect(edited.events[0]).toMatchObject({
      actor: BOB,
      payload: {
        suggestionId: editedSuggestion.data.suggestionId,
        suggestionVersion: 2,
        resolution: "accept-edited",
        directiveId: edited.data.directiveId,
      },
    });
    expect(edited.events[1]).toMatchObject({
      actor: BOB,
      payload: {
        directiveId: edited.data.directiveId,
        status: "queued",
        body: "Run the focused tests first.\nThen run the full suite.",
        origin: {
          kind: "suggestion",
          suggestionId: editedSuggestion.data.suggestionId,
          resolutionId: edited.data.resolutionId,
        },
      },
    });
    await expect(kernel().dispatch(editedCommand)).resolves.toEqual({
      ...edited,
      replayed: true,
    });

    const acceptedSuggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Keep the original proposal exactly.",
    });
    const accepted = await dispatch(
      {
        type: "suggestion.resolve",
        sessionId: SESSION_ID,
        suggestionId: acceptedSuggestion.data.suggestionId as string,
        resolution: "accept",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: steeringRevision,
      },
      BOB
    );
    expect(accepted.events[1]?.payload.body).toBe("Keep the original proposal exactly.");

    const rejectedSuggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Delete the repository.",
    });
    const rejected = await dispatch(
      {
        type: "suggestion.resolve",
        sessionId: SESSION_ID,
        suggestionId: rejectedSuggestion.data.suggestionId as string,
        resolution: "reject",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: steeringRevision,
      },
      BOB
    );
    expect(rejected.events.map((event) => event.type)).toEqual(["suggestion.resolved"]);
    expect(rejected.data).not.toHaveProperty("directiveId");
    await expect(
      kernel().claimRuntimeOutbox({ workerId: SYSTEM.userId, limit: 10, leaseDurationMs: 1_000 })
    ).resolves.toEqual([]);
  });

  it("lets only the first valid Suggestion resolution win across kernel instances", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await grantSteerer(BOB);
    const suggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Use the event ledger as canonical state.",
    });
    const steeringRevision = (await requireSession()).steeringRevision;
    const suggestionId = suggestion.data.suggestionId as string;
    const contender = openKernel();
    try {
      const accept = makeCommand(
        {
          type: "suggestion.resolve",
          sessionId: SESSION_ID,
          suggestionId,
          resolution: "accept",
          expectedSuggestionVersion: 1,
          expectedSteeringRevision: steeringRevision,
        },
        ALICE,
        "concurrent-suggestion-accept"
      );
      const reject = makeCommand(
        {
          type: "suggestion.resolve",
          sessionId: SESSION_ID,
          suggestionId,
          resolution: "reject",
          expectedSuggestionVersion: 1,
          expectedSteeringRevision: steeringRevision,
        },
        BOB,
        "concurrent-suggestion-reject"
      );
      const attempts = await Promise.allSettled([
        kernel().dispatch(accept),
        contender.dispatch(reject),
      ]);
      expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
      const rejectedAttempt = attempts.find((attempt) => attempt.status === "rejected");
      expect(rejectedAttempt).toMatchObject({
        status: "rejected",
        reason: expect.objectContaining({ code: "stale-revision" }),
      });
      expect(
        (await sessionEvents()).filter(
          (event) =>
            event.type === "suggestion.resolved" && event.payload.suggestionId === suggestionId
        )
      ).toHaveLength(1);
      await expect(
        dispatch(
          {
            type: "suggestion.resolve",
            sessionId: SESSION_ID,
            suggestionId,
            resolution: "reject",
            expectedSuggestionVersion: 2,
            expectedSteeringRevision: steeringRevision,
          },
          BOB
        )
      ).rejects.toMatchObject({ code: "conflict" });
    } finally {
      contender.close();
    }
  });

  it("keeps cross-Session Suggestion probes as opaque as unknown identifiers", async () => {
    await bootstrap();
    const suggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "Private to the first Session",
    });
    await dispatch({
      type: "session.start",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sessionId: SECOND_SESSION_ID,
      name: "Second private Session",
      tmuxName: "second-private-session",
    });
    const second = await requireSession(SECOND_SESSION_ID);
    const foreignProbe = await captureRejection(
      {
        type: "suggestion.resolve",
        sessionId: SECOND_SESSION_ID,
        suggestionId: suggestion.data.suggestionId as string,
        resolution: "reject",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: second.steeringRevision,
      },
      ALICE
    );
    const unknownProbe = await captureRejection(
      {
        type: "suggestion.resolve",
        sessionId: SECOND_SESSION_ID,
        suggestionId: "unknown-suggestion-id",
        resolution: "reject",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: second.steeringRevision,
      },
      ALICE
    );
    expect(foreignProbe).toEqual(unknownProbe);
    expect(foreignProbe).toMatchObject({ code: "not-authorized" });
  });

  it("keeps replay idempotent but hides receipts and rejects new content after participation or access revocation", async () => {
    await bootstrap();
    await admitMember(BOB);
    const commentCommand = makeCommand(
      { type: "comment.add", sessionId: SESSION_ID, body: "A durable review note." },
      BOB,
      "revocable-comment"
    );
    const comment = await kernel().dispatch(commentCommand);
    await expect(kernel().dispatch(commentCommand)).resolves.toEqual({
      ...comment,
      replayed: true,
    });
    const conflictingComment = makeCommand(
      { type: "comment.add", sessionId: SESSION_ID, body: "Changed payload" },
      BOB,
      "revocable-comment"
    );
    await expect(kernel().dispatch(conflictingComment)).rejects.toMatchObject({
      code: "idempotency-conflict",
    });

    await revokeParticipant(BOB);
    await expect(kernel().dispatch(commentCommand)).resolves.toMatchObject({
      replayed: true,
      data: { receiptUnavailable: true },
      events: [],
    });
    await expect(
      dispatch({ type: "comment.add", sessionId: SESSION_ID, body: "No longer admitted" }, BOB)
    ).rejects.toMatchObject({ code: "not-authorized" });

    await grantParticipant(BOB);
    const suggestionCommand = makeCommand(
      {
        type: "suggestion.add",
        sessionId: SESSION_ID,
        body: "Visible until Project Access is revoked.",
      },
      BOB,
      "revocable-suggestion"
    );
    await kernel().dispatch(suggestionCommand);
    await revokeProjectAccess(BOB);
    await expect(kernel().dispatch(suggestionCommand)).resolves.toMatchObject({
      replayed: true,
      data: { receiptUnavailable: true },
      events: [],
    });
    await expect(
      dispatch({ type: "suggestion.add", sessionId: SESSION_ID, body: "No current access" }, BOB)
    ).rejects.toMatchObject({ code: "not-authorized" });
  });

  it("atomically cancels a revoked Steerer's queued Directives while retaining discussion access", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await grantSteerer(BOB);
    const beforeRevocation = await requireSession();
    const first = await dispatch(
      {
        type: "directive.enqueue",
        sessionId: SESSION_ID,
        body: "First pending Directive",
        expectedSteeringRevision: beforeRevocation.steeringRevision,
      },
      BOB
    );
    const second = await dispatch(
      {
        type: "directive.enqueue",
        sessionId: SESSION_ID,
        body: "Second pending Directive",
        expectedSteeringRevision: beforeRevocation.steeringRevision,
      },
      BOB
    );
    const revoked = await dispatch({
      type: "session.responsibility.revoke",
      sessionId: SESSION_ID,
      userId: BOB.userId,
      responsibility: "steerer",
      expectedSteeringRevision: beforeRevocation.steeringRevision,
      expectedControlRevision: beforeRevocation.controlRevision,
      expectedControlEpoch: beforeRevocation.controlEpoch,
    });
    const cancellations = revoked.events.filter((event) => event.type === "directive.cancelled");
    expect(cancellations).toEqual([
      expect.objectContaining({
        payload: expect.objectContaining({
          directiveId: first.data.directiveId,
          queueSequence: first.data.queueSequence,
          originalAuthorUserId: BOB.userId,
          status: "cancelled",
          reason: "steerer-revoked",
        }),
      }),
      expect.objectContaining({
        payload: expect.objectContaining({
          directiveId: second.data.directiveId,
          queueSequence: second.data.queueSequence,
          originalAuthorUserId: BOB.userId,
          status: "cancelled",
          reason: "steerer-revoked",
        }),
      }),
    ]);
    const afterRevocation = await requireSession();
    await expect(
      dispatch(
        {
          type: "directive.enqueue",
          sessionId: SESSION_ID,
          body: "No longer a Steerer",
          expectedSteeringRevision: afterRevocation.steeringRevision,
        },
        BOB
      )
    ).rejects.toMatchObject({ code: "not-authorized" });
    await expect(
      dispatch({ type: "comment.add", sessionId: SESSION_ID, body: "Still a Participant" }, BOB)
    ).resolves.toMatchObject({ commandType: "comment.add" });
    await expect(
      dispatch({ type: "suggestion.add", sessionId: SESSION_ID, body: "Can still suggest" }, BOB)
    ).resolves.toMatchObject({ commandType: "suggestion.add" });
  });

  it("allows bounded discussion while inactive without creating permanently unresolvable work", async () => {
    await bootstrap();
    await forceSessionStatus("awaiting_assignee");
    await expect(
      dispatch({
        type: "comment.add",
        sessionId: SESSION_ID,
        body: "Discussion remains open while awaiting an Assignee",
      })
    ).resolves.toMatchObject({ commandType: "comment.add" });
    const awaitingSuggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "A non-executable proposal can wait for accountability",
    });
    let view = await requireSession();
    await expect(
      dispatch({
        type: "directive.enqueue",
        sessionId: SESSION_ID,
        body: "Must not queue without an active Session",
        expectedSteeringRevision: view.steeringRevision,
      })
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      dispatch({
        type: "suggestion.resolve",
        sessionId: SESSION_ID,
        suggestionId: awaitingSuggestion.data.suggestionId as string,
        resolution: "reject",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: view.steeringRevision,
      })
    ).rejects.toMatchObject({ code: "conflict" });

    await forceSessionStatus("active");
    const openSuggestion = await dispatch({
      type: "suggestion.add",
      sessionId: SESSION_ID,
      body: "This proposal existed before the Session ended",
    });
    await forceSessionStatus("ended");
    await expect(
      dispatch({
        type: "comment.add",
        sessionId: SESSION_ID,
        body: "A final historical discussion note",
      })
    ).resolves.toMatchObject({ commandType: "comment.add" });
    await expect(
      dispatch({
        type: "suggestion.add",
        sessionId: SESSION_ID,
        body: "This would be permanently unresolvable",
      })
    ).rejects.toMatchObject({ code: "conflict" });
    view = await requireSession();
    await expect(
      dispatch({
        type: "suggestion.resolve",
        sessionId: SESSION_ID,
        suggestionId: openSuggestion.data.suggestionId as string,
        resolution: "reject",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: view.steeringRevision,
      })
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("discovers only actor-scoped Team and Project navigation metadata", async () => {
    await bootstrap();
    await grantMembership(BOB, "admin");
    await grantMembership(CAROL, "member");
    await grantMembership(DAVE, "guest");

    const alice = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "workspace.discovery",
    });
    expect(alice.teams).toEqual([
      expect.objectContaining({
        teamId: TEAM_ID,
        viewerMembership: { role: "owner", version: 1 },
        capabilities: { createProject: true, manageMemberships: true },
        projects: [
          expect.objectContaining({
            projectId: PROJECT_ID,
            visibility: "content",
            viewerAccess: { role: "maintainer", version: 1 },
            capabilities: { viewContent: true, startSession: true, manageAccess: true },
          }),
        ],
      }),
    ]);

    const bob = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: BOB,
      type: "workspace.discovery",
    });
    expect(bob.teams[0]).toMatchObject({
      viewerMembership: { role: "admin", version: 1 },
      projects: [
        {
          projectId: PROJECT_ID,
          name: "Terminal X",
          createdAtMs: nowMs,
          visibility: "administration",
          capabilities: { viewContent: false, startSession: false, manageAccess: true },
        },
      ],
    });
    expect(bob.teams[0]?.projects[0]).not.toHaveProperty("viewerAccess");
    await expect(
      kernel().inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: BOB,
        type: "session.inbox",
      })
    ).resolves.toEqual([]);

    const carolBefore = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: CAROL,
      type: "workspace.discovery",
    });
    expect(carolBefore.teams[0]?.projects).toEqual([]);
    await grantProjectAccess(CAROL);
    const carolAfter = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: CAROL,
      type: "workspace.discovery",
    });
    expect(carolAfter.teams[0]?.projects).toEqual([
      expect.objectContaining({
        projectId: PROJECT_ID,
        visibility: "content",
        viewerAccess: { role: "contributor", version: 1 },
        capabilities: { viewContent: true, startSession: true, manageAccess: false },
      }),
    ]);

    const guestBefore = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: DAVE,
      type: "workspace.discovery",
    });
    expect(guestBefore.teams[0]?.projects).toEqual([]);
    await createShare(DAVE);
    await grantParticipant(DAVE);
    const guestAfter = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: DAVE,
      type: "workspace.discovery",
    });
    expect(guestAfter.teams[0]?.projects).toEqual([
      {
        projectId: PROJECT_ID,
        name: "Terminal X",
        createdAtMs: nowMs,
        visibility: "session-only",
        capabilities: { viewContent: false, startSession: false, manageAccess: false },
      },
    ]);
    expect(JSON.stringify(guestAfter)).not.toContain("/srv/terminalx");
    expect(JSON.stringify(guestAfter)).not.toContain(SESSION_ID);

    await expect(
      kernel().inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: LEGACY_ADMIN,
        type: "workspace.discovery",
      })
    ).resolves.toEqual({ teams: [] });
  });

  it("projects a minimized public inbox and detail with canonical display snapshots", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    const fullBefore = await requireSession();
    const bobParticipant = requireParticipant(fullBefore, BOB.userId);
    await grantSteerer(BOB);

    const inbox = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.inbox",
    });
    const detail = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    expect(detail).not.toBeNull();
    if (!detail) throw new Error("Expected public Session detail");
    expect(inbox).toHaveLength(1);
    expect(inbox[0]?.responsibilities.steerers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ userId: BOB.userId, displayName: BOB.displayName }),
      ])
    );
    expect(detail.participants).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          participantId: bobParticipant.participantId,
          userId: BOB.userId,
          displayName: BOB.displayName,
        }),
      ])
    );
    for (const projection of [inbox[0], detail]) {
      const serialized = JSON.stringify(projection);
      expect(serialized).not.toContain("tmuxName");
      expect(serialized).not.toContain("multiplayer-kernel");
      expect(serialized).not.toContain("invitations");
      expect(serialized).not.toContain("token");
      expect(serialized).not.toContain("sourceRef");
      expect(serialized).not.toContain("revokedAtMs");
    }

    await revokeParticipant(BOB);
    const afterRevocation = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    expect(
      afterRevocation?.participants.some((participant) => participant.userId === BOB.userId)
    ).toBe(false);
    await expect(
      kernel().inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: BOB,
        type: "session.detail",
        sessionId: SESSION_ID,
      })
    ).resolves.toBeNull();
  });

  it("projects viewer capabilities from current shared and Runtime state", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    await grantSteerer(BOB);

    let alice = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    const bob = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: BOB,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    expect(alice?.viewer.capabilities).toMatchObject({
      resolveSuggestion: true,
      enqueueDirective: true,
      observeTerminal: true,
      mutateTerminal: false,
      manageParticipants: true,
      transferControl: true,
    });
    expect(bob?.viewer.capabilities).toMatchObject({
      resolveSuggestion: true,
      enqueueDirective: true,
      mutateTerminal: false,
      manageParticipants: false,
      transferControl: false,
    });

    await enforceNextRuntimeDelivery("runtime.session.ensure");
    alice = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    expect(alice?.viewer.capabilities.mutateTerminal).toBe(true);

    await forceSessionStatus("awaiting_assignee");
    alice = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    expect(alice?.viewer.capabilities).toMatchObject({
      addComment: true,
      addSuggestion: true,
      resolveSuggestion: false,
      enqueueDirective: false,
      observeTerminal: true,
      mutateTerminal: false,
    });

    await forceSessionStatus("ended");
    alice = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    expect(alice?.viewer.capabilities).toMatchObject({
      addComment: true,
      addSuggestion: false,
      resolveSuggestion: false,
      enqueueDirective: false,
      observeTerminal: false,
      mutateTerminal: false,
      createInvitation: false,
      revokeInvitation: true,
    });
  });

  it("uses one expiration instant for Handoff detail and capabilities", async () => {
    await bootstrap();
    await admitMember(BOB);
    await offerHandoff(BOB, ALICE, nowMs + 1);
    teamSessions?.close();
    teamSessions = undefined;
    let clockCalls = 0;
    teamSessions = createTeamSessions({
      filename,
      clock: () => {
        clockCalls += 1;
        return clockCalls === 1 ? nowMs : nowMs + 2;
      },
      idGenerator: () => `projection-id-${++generatedId}`,
      invitationTokenGenerator: () => `txi_projection_${"x".repeat(64)}`,
    });

    const detail = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: BOB,
      type: "session.detail",
      sessionId: SESSION_ID,
    });

    expect(clockCalls).toBe(1);
    expect(detail?.viewer.capabilities.acceptHandoff).toBe(true);
    expect(detail?.openHandoffs).toHaveLength(1);
  });

  it("treats rendered capabilities as projections and reauthorizes later writes", async () => {
    await bootstrap({ steeringPolicy: "shared" });
    await admitMember(BOB);
    const rendered = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: BOB,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    expect(rendered?.viewer.capabilities.addComment).toBe(true);
    await revokeProjectAccess(BOB);

    await expect(
      dispatch(
        { type: "comment.add", sessionId: SESSION_ID, body: "Use my stale rendered state" },
        BOB
      )
    ).rejects.toMatchObject({ code: "not-authorized" });
    await expect(
      kernel().inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: BOB,
        type: "session.inbox",
      })
    ).resolves.toEqual([]);
    const discovery = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: BOB,
      type: "workspace.discovery",
    });
    expect(discovery.teams[0]?.projects).toEqual([]);
  });

  it("keeps single-policy Directive capability Controller-only", async () => {
    await bootstrap({ steeringPolicy: "single" });
    await admitMember(BOB);
    const alice = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    const bob = await kernel().inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: BOB,
      type: "session.detail",
      sessionId: SESSION_ID,
    });
    expect(alice?.viewer.capabilities).toMatchObject({
      resolveSuggestion: true,
      enqueueDirective: true,
    });
    expect(bob?.viewer.capabilities).toMatchObject({
      resolveSuggestion: false,
      enqueueDirective: false,
    });
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
