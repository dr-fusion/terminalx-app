import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  createTeamSessionKernel,
  type ActorContext,
  type RunPolicyDraft,
  type SessionCommand,
  type SessionRunStateView,
  type SessionView,
  type TeamSessions,
} from "@/lib/team-sessions";
import {
  digestAggregateEnforcementProof,
  commitRuntimeEffectRef,
  digestRuntimeEnforcementSubject,
  type RuntimeLifecycleCommand,
  type RuntimeLifecycleJournal,
} from "@/lib/runtime";
import { digestRunPolicyDraft } from "@/lib/team-sessions/run-policy";
import { createTestRuntimeCommandAuthorityIssuer } from "../helpers/runtime-authority";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ALICE: ActorContext = { kind: "human", userId: "alice", displayName: "Alice" };
const BOB: ActorContext = { kind: "human", userId: "bob", displayName: "Bob" };
const RUNTIME: ActorContext = {
  kind: "system",
  userId: "runtime-worker",
  displayName: "Runtime Worker",
};
const unconfigured = { kind: "unconfigured" } as const;
const EFFECT_ENFORCER_SET_DIGEST = "b".repeat(64);

interface RuntimeBindingRow {
  id: string;
  generation: number;
  sandbox_id: string;
  sandbox_generation: number;
  runtime_principal_id: string;
  runtime_authorization_generation: number;
  status: string;
}

describe("Team Session active Run recovery", () => {
  let directory: string;
  let filename: string;
  let sessions: TeamSessions;
  let runtimeJournal: RuntimeLifecycleJournal;
  let now: number;
  let sequence: number;
  let generated: number;

  beforeEach(async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-run-recovery-"));
    filename = path.join(directory, "team-sessions.sqlite");
    now = 2_000_000_000_000;
    sequence = 0;
    generated = 0;
    const kernel = createTeamSessionKernel({
      filename,
      clock: () => now,
      idGenerator: () => {
        generated += 1;
        return `00000000-0000-4000-8000-${String(generated).padStart(12, "0")}`;
      },
      runtimeCommandAuthorityIssuer: createTestRuntimeCommandAuthorityIssuer(),
      runtimeAuthorizationSnapshotSource: {
        resolve: ({ runtimeAuthorizationGeneration }) => ({
          generation: runtimeAuthorizationGeneration,
          networkPolicyRef: "test-network-policy:v1",
          networkPolicyDigest: "c".repeat(64),
          credentialPolicyRef: "test-credential-policy:v1",
          credentialPolicyDigest: "d".repeat(64),
          effectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
        }),
      },
      runtimeEnforcementProofVerifier: () => true,
    });
    sessions = kernel.teamSessions;
    runtimeJournal = kernel.runtimeLifecycleJournal;

    await dispatch({ type: "team.create", teamId: TEAM_ID, name: "Acme" });
    await dispatch({
      type: "project.create",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      name: "Terminal X",
    });
    await dispatch({
      type: "session.start",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sessionId: SESSION_ID,
      name: "Recover the active Run",
      tmuxName: "recover-active-run",
      steeringPolicy: "shared",
    });
    await dispatch({
      type: "team.membership.grant",
      teamId: TEAM_ID,
      userId: BOB.userId,
      role: "owner",
      expectedMembershipVersion: 0,
    });
    await dispatch({
      type: "project.access.grant",
      projectId: PROJECT_ID,
      userId: BOB.userId,
      role: "contributor",
      expectedAccessVersion: 0,
    });
    const session = await requireSession(ALICE);
    await dispatch({
      type: "session.participant.grant",
      sessionId: SESSION_ID,
      userId: BOB.userId,
      expectedParticipantVersion: 0,
      expectedAccessRevision: session.accessRevision,
    });
    const admitted = await requireSession(ALICE);
    const bob = admitted.participants.find((participant) => participant.userId === BOB.userId);
    expect(bob).toBeDefined();
    if (!bob) throw new Error("Expected Bob to be an active Participant");
    await dispatch({
      type: "session.responsibility.grant",
      sessionId: SESSION_ID,
      userId: BOB.userId,
      responsibility: "supervisor",
      expectedSupervisionRevision: admitted.supervisionRevision,
      expectedParticipantVersion: bob.version,
    });
  });

  afterEach(() => {
    sessions.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function command(input: Record<string, unknown>, actor = ALICE): SessionCommand {
    sequence += 1;
    return {
      ...input,
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      idempotency: { scope: "vitest:run-recovery", key: `command-${sequence}` },
      occurredAtMs: now,
    } as SessionCommand;
  }

  async function dispatch(input: Record<string, unknown>, actor = ALICE) {
    return sessions.dispatch(command(input, actor));
  }

  async function requireSession(actor: ActorContext): Promise<SessionView> {
    const view = await sessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "session.get",
      sessionId: SESSION_ID,
    });
    expect(view).not.toBeNull();
    if (!view) throw new Error("Expected an authorized Session view");
    return view;
  }

  async function requireRunState(actor: ActorContext): Promise<SessionRunStateView> {
    const state = await sessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "session.run-state",
      sessionId: SESSION_ID,
    });
    expect(state).not.toBeNull();
    if (!state) throw new Error("Expected an authorized Run state");
    return state;
  }

  async function enforceNextRuntime(
    kind: "runtime.session.ensure" | "runtime.authorization.fence" | "runtime.session.retire"
  ) {
    const [delivery] = await sessions.claimRuntimeOutbox({
      workerId: RUNTIME.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    expect(delivery?.kind).toBe(kind);
    if (!delivery) throw new Error("Expected a Runtime delivery");
    await dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: delivery.outboxId,
        workerId: RUNTIME.userId,
        expectedAttempt: delivery.attempts,
      },
      RUNTIME
    );
    return delivery;
  }

  function policy(): RunPolicyDraft {
    return {
      mode: "autonomous",
      completionPolicy: { kind: "continue-until-all-goals-achieved" },
      scopedExternalPolicyRef: "project-policy:1",
      limits: {
        wallClock: unconfigured,
        modelTokens: unconfigured,
        modelSpend: unconfigured,
        outboundBytes: unconfigured,
        actionCounts: {
          local: unconfigured,
          "scoped-external": unconfigured,
          protected: unconfigured,
          forbidden: unconfigured,
        },
      },
    };
  }

  function commit(runPolicy: RunPolicyDraft, runtimeAuthorizationGeneration: number) {
    return {
      policy: runPolicy,
      policyDigest: digestRunPolicyDraft(runPolicy),
      expectedProjectCeilingRevision: "local-tmux-ceiling:v1",
      expectedRuntimeAssignmentGeneration: 1,
      expectedSandboxGeneration: 1,
      expectedRuntimeAuthorizationGeneration: runtimeAuthorizationGeneration,
    };
  }

  async function startRun(runPolicy: RunPolicyDraft) {
    await enforceNextRuntime("runtime.session.ensure");
    const started = await dispatch({
      type: "run.start",
      sessionId: SESSION_ID,
      expectedSessionRevision: 1,
      initialGoals: [
        {
          goalId: "goal:recover",
          position: 1,
          title: "Finish safely after Assignee replacement",
          acceptanceCriteria: ["The replacement Assignee explicitly resumes the rebound Run"],
          dependencyGoalIds: [],
        },
      ],
      commit: commit(runPolicy, 1),
    });
    await enforceLifecycleCommand("run.start");
    return started;
  }

  async function enforceLifecycleCommand(expectedKind: RuntimeLifecycleCommand["kind"]) {
    const [delivery] = await runtimeJournal.claim({
      workerId: RUNTIME.userId,
      limit: 1,
      leaseDurationMs: 30_000,
      nowMs: now,
    });
    expect(delivery?.command.kind).toBe(expectedKind);
    if (!delivery) throw new Error("Expected a Runtime lifecycle delivery");
    const requiredEffectEnforcerSetDigest = delivery.command.requiredEffectEnforcerSetDigest;
    expect(requiredEffectEnforcerSetDigest).toBe(EFFECT_ENFORCER_SET_DIGEST);
    if (!requiredEffectEnforcerSetDigest) {
      throw new Error("Expected a trusted effect-enforcer-set digest");
    }
    const effectRef = `effect:${delivery.command.commandId}`;
    const enforcementSubjectDigest = digestRuntimeEnforcementSubject({
      version: 1,
      commandId: delivery.command.commandId,
      commandClaimsDigest: delivery.command.authority.claimsDigest,
      binding: delivery.command.binding,
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest,
      effectRefCommitment: commitRuntimeEffectRef(effectRef),
      enforcedFence: delivery.command.toRunStateVersion,
    });
    const proofPayload = {
      generation: delivery.command.runtimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest,
      enforcementSubjectDigest,
      acknowledgements: [
        {
          enforcerRef: "test-runtime-enforcer",
          enforcerKind: "runtime" as const,
          acknowledgementDigest: "e".repeat(64),
        },
      ],
    };
    const renewal = await runtimeJournal.renew({
      commandId: delivery.command.commandId,
      workerId: RUNTIME.userId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      leaseDurationMs: 30_000,
      nowMs: now,
    });
    expect(renewal.kind).toBe("renewed");
    if (renewal.kind !== "renewed") {
      throw new Error("Expected the Runtime lifecycle dispatch interlock");
    }
    await runtimeJournal.complete({
      commandId: delivery.command.commandId,
      workerId: RUNTIME.userId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: renewal.leaseExpiresAtMs,
      observedAtMs: now,
      outcome: {
        kind: "receipt",
        receipt: {
          commandId: delivery.command.commandId,
          binding: delivery.command.binding,
          runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
          outcome: "enforced",
          effectRef,
          enforcedFence: delivery.command.toRunStateVersion,
          aggregateEnforcementProof: {
            ...proofPayload,
            aggregateProofDigest: digestAggregateEnforcementProof(proofPayload),
          },
        },
      },
    });
    return delivery.command;
  }

  async function revokeAliceSessionAccess() {
    const access = await sessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: BOB,
      type: "team.access",
      teamId: TEAM_ID,
    });
    const alice = access.memberships.find((membership) => membership.userId === ALICE.userId);
    expect(alice).toBeDefined();
    if (!alice) throw new Error("Expected Alice to have an active Team Membership");
    return dispatch(
      {
        type: "team.membership.revoke",
        teamId: TEAM_ID,
        userId: ALICE.userId,
        expectedMembershipVersion: alice.version,
      },
      BOB
    );
  }

  function readRuntimeBinding(agentRunId: string): RuntimeBindingRow {
    const db = new Database(filename, { readonly: true });
    try {
      const binding = db
        .prepare(
          `SELECT assignment.*
           FROM runtime_assignments assignment
           JOIN agent_runs run ON run.runtime_assignment_id = assignment.id
           WHERE run.id = ?`
        )
        .get(agentRunId) as RuntimeBindingRow | undefined;
      expect(binding).toBeDefined();
      if (!binding) throw new Error("Expected a Runtime Assignment");
      return binding;
    } finally {
      db.close();
    }
  }

  function seedActiveRunGrant(agentRunId: string): string {
    const grantId = "grant:active-run";
    const manifestId = "manifest:active-run";
    const approvalId = "approval:active-run";
    const manifestDigest = digestFor("manifest");
    const binding = readRuntimeBinding(agentRunId);
    const db = new Database(filename);
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO action_manifests
             (id, version, session_id, agent_run_id, digest, action_class, provider, operation,
              exact_target, action_schema_id, action_schema_version, action_schema_digest,
              canonical_effect_input_digest, effect_idempotency_key, expected_effect_json,
              expires_at_ms, created_at_ms)
           VALUES (?, 1, ?, ?, ?, 'scoped-external', 'github', 'branch.push',
                   'repo:session-branch', 'github.branch.push', 1, ?, ?,
                   'effect:session-branch', '{}', ?, ?)`
        ).run(
          manifestId,
          SESSION_ID,
          agentRunId,
          manifestDigest,
          digestFor("schema"),
          digestFor("effect"),
          now + 60_000,
          now
        );
        const insertApproval = db.prepare(
          `INSERT INTO approval_requests
             (id, version, previous_version, request_digest, session_id, agent_run_id,
              run_policy_revision, runtime_assignment_id, runtime_assignment_generation,
              sandbox_id, sandbox_generation, runtime_principal_id,
              runtime_authorization_generation, action_class, provider, operation, exact_target,
              subject_kind, manifest_id, manifest_digest, subject_digest,
              status, expires_at_ms, created_at_ms,
              resolved_at_ms, resolved_by_actor_ref)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?,
                   'scoped-external', 'github', 'branch.push', 'repo:session-branch',
                   'manifest', ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        const approvalCommon = [
          approvalId,
          SESSION_ID,
          agentRunId,
          binding.id,
          binding.generation,
          binding.sandbox_id,
          binding.sandbox_generation,
          binding.runtime_principal_id,
          binding.runtime_authorization_generation,
          manifestId,
          manifestDigest,
          manifestDigest,
        ] as const;
        insertApproval.run(
          approvalCommon[0],
          1,
          null,
          digestFor("approval:open"),
          ...approvalCommon.slice(1),
          "open",
          now + 60_000,
          now,
          null,
          null
        );
        insertApproval.run(
          approvalCommon[0],
          2,
          1,
          digestFor("approval:approved"),
          ...approvalCommon.slice(1),
          "approved",
          now + 60_000,
          now,
          now,
          ALICE.userId
        );
        db.prepare(
          `INSERT INTO action_grants
             (id, session_id, agent_run_id, run_policy_revision,
              runtime_assignment_id, runtime_assignment_generation, sandbox_id,
              sandbox_generation, runtime_principal_id, runtime_authorization_generation,
              approval_request_id, approval_request_version, approval_status,
              approval_subject_kind, action_class, provider, operation,
              target, budget_json, usage_ledger_ref, scope_kind, scope_digest, manifest_digest,
              effect_idempotency_key, action_pattern_json, action_pattern_digest,
              eligible_run_use, issuer_actor_ref,
              issuer_approval_authority_revision, expires_at_ms, signature, created_at_ms)
           VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 2,
                   'approved', 'manifest', 'scoped-external', 'github', 'branch.push',
                   'repo:session-branch', '{}', 'ledger:active-run', 'once', ?, ?,
                   'effect:session-branch', NULL, NULL, NULL,
                   ?, 'session-manager:1', ?, 'test-signature', ?)`
        ).run(
          grantId,
          SESSION_ID,
          agentRunId,
          binding.id,
          binding.generation,
          binding.sandbox_id,
          binding.sandbox_generation,
          binding.runtime_principal_id,
          binding.runtime_authorization_generation,
          approvalId,
          manifestDigest,
          manifestDigest,
          ALICE.userId,
          now + 60_000,
          now
        );
        db.prepare(
          `INSERT INTO action_grant_states
             (grant_id, version, previous_version, status, reason, actor_ref, created_at_ms)
           VALUES (?, 1, NULL, 'issued', 'issued', ?, ?)`
        ).run(grantId, ALICE.userId, now);
        db.prepare(
          `INSERT INTO action_grant_states
             (grant_id, version, previous_version, status, reason, actor_ref, created_at_ms)
           VALUES (?, 2, 1, 'active', 'enforcement', ?, ?)`
        ).run(grantId, ALICE.userId, now);
      })();
      return grantId;
    } finally {
      db.close();
    }
  }

  function readLatestGrant(grantId: string) {
    const db = new Database(filename, { readonly: true });
    try {
      return db
        .prepare(
          `SELECT grant.id, state.version, state.previous_version, state.status,
                  grant.runtime_authorization_generation
           FROM action_grants grant
           JOIN action_grant_states state ON state.grant_id = grant.id
           WHERE grant.id = ? ORDER BY state.version DESC LIMIT 1`
        )
        .get(grantId) as
        | {
            id: string;
            version: number;
            previous_version: number | null;
            status: string;
            runtime_authorization_generation: number;
          }
        | undefined;
    } finally {
      db.close();
    }
  }

  it("pauses and rebinds an active Run after Assignee access loss", async () => {
    const runPolicy = policy();
    const started = await startRun(runPolicy);
    const agentRunId = started.data.agentRunId as string;
    const grantId = seedActiveRunGrant(agentRunId);

    await revokeAliceSessionAccess();

    const awaiting = await requireSession(BOB);
    expect(awaiting).toMatchObject({
      status: "awaiting_assignee",
      runStateRevision: 4,
      runtime: { authorizationGeneration: 2, authorizationState: "pending" },
    });
    const recovering = await requireRunState(BOB);
    expect(recovering).toMatchObject({
      agentRunId,
      lifecycle: "pausing",
      stateVersion: 3,
      runPolicyRevision: 1,
      runtimeAuthorizationGeneration: 2,
      sandboxState: "recovering",
    });
    expect(readRuntimeBinding(agentRunId)).toMatchObject({
      status: "recovering",
      runtime_authorization_generation: 2,
    });
    expect(readLatestGrant(grantId)).toMatchObject({
      id: grantId,
      version: 3,
      previous_version: 2,
      status: "invalidated",
      runtime_authorization_generation: 1,
    });

    await enforceNextRuntime("runtime.authorization.fence");
    expect((await requireSession(BOB)).runStateRevision).toBe(5);
    expect(await requireRunState(BOB)).toMatchObject({
      lifecycle: "paused",
      stateVersion: 4,
      sandboxState: "ready",
      runtimeAuthorizationGeneration: 2,
    });
    expect(readRuntimeBinding(agentRunId)).toMatchObject({
      status: "ready",
      runtime_authorization_generation: 2,
    });

    const claimBasis = await requireSession(BOB);
    await dispatch(
      {
        type: "session.assignee.claim",
        sessionId: SESSION_ID,
        expectedAssigneeRevision: claimBasis.assigneeRevision,
        expectedAccessRevision: claimBasis.accessRevision,
      },
      BOB
    );
    const claimed = await requireSession(BOB);
    expect(claimed.status).toBe("active");
    expect(
      claimed.participants.find((participant) => participant.userId === BOB.userId)
        ?.responsibilities
    ).toEqual(expect.arrayContaining(["assignee", "supervisor"]));

    const beforeRebind = await requireRunState(BOB);
    await expect(
      dispatch(
        {
          type: "run.resume",
          sessionId: SESSION_ID,
          agentRunId,
          expectedRunStateVersion: beforeRebind.stateVersion,
          expectedRunPolicyRevision: beforeRebind.runPolicyRevision,
          expectedRuntimeAuthorizationGeneration: beforeRebind.runtimeAuthorizationGeneration,
        },
        BOB
      )
    ).rejects.toMatchObject({ code: "conflict" });

    const rebound = await dispatch(
      {
        type: "run.policy.revise",
        sessionId: SESSION_ID,
        agentRunId,
        expectedRunPolicyRevision: beforeRebind.runPolicyRevision,
        commit: commit(runPolicy, 2),
      },
      BOB
    );
    expect(rebound.data).toMatchObject({ runPolicyRevision: 2, stateVersion: 5 });

    const db = new Database(filename, { readonly: true });
    try {
      expect(
        db
          .prepare(
            `SELECT revision, policy_body_digest AS digest, runtime_authorization_generation
             FROM run_policy_revisions WHERE agent_run_id = ? ORDER BY revision ASC`
          )
          .all(agentRunId)
      ).toEqual([
        {
          revision: 1,
          digest: digestRunPolicyDraft(runPolicy),
          runtime_authorization_generation: 1,
        },
        {
          revision: 2,
          digest: digestRunPolicyDraft(runPolicy),
          runtime_authorization_generation: 2,
        },
      ]);
    } finally {
      db.close();
    }

    const reboundState = await requireRunState(BOB);
    const resumed = await dispatch(
      {
        type: "run.resume",
        sessionId: SESSION_ID,
        agentRunId,
        expectedRunStateVersion: reboundState.stateVersion,
        expectedRunPolicyRevision: reboundState.runPolicyRevision,
        expectedRuntimeAuthorizationGeneration: reboundState.runtimeAuthorizationGeneration,
      },
      BOB
    );
    expect(resumed.data).toMatchObject({ lifecycle: "paused", stateVersion: 5 });
    await enforceLifecycleCommand("run.resume");
    expect(await requireRunState(BOB)).toMatchObject({ lifecycle: "active", stateVersion: 6 });
  });

  it("preserves agent-work-finished while rebinding its Runtime authorization", async () => {
    const started = await startRun(policy());
    const agentRunId = started.data.agentRunId as string;
    const db = new Database(filename);
    try {
      db.prepare(
        `UPDATE agent_runs
         SET lifecycle = 'agent-work-finished', state_version = 3, updated_at_ms = ?
         WHERE id = ?`
      ).run(now, agentRunId);
    } finally {
      db.close();
    }

    await revokeAliceSessionAccess();
    expect(await requireRunState(BOB)).toMatchObject({
      lifecycle: "agent-work-finished",
      stateVersion: 4,
      sandboxState: "recovering",
      runtimeAuthorizationGeneration: 2,
      finalReviewState: "open",
    });

    await enforceNextRuntime("runtime.authorization.fence");
    expect(await requireRunState(BOB)).toMatchObject({
      lifecycle: "agent-work-finished",
      stateVersion: 4,
      sandboxState: "ready",
      runtimeAuthorizationGeneration: 2,
      finalReviewState: "open",
    });
  });

  it("does not terminalize a paused Run while Assignee-loss enforcement is pending", async () => {
    const started = await startRun(policy());
    const agentRunId = started.data.agentRunId as string;
    await dispatch({
      type: "run.pause",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: 2,
      reason: "Review before handoff",
    });
    await enforceLifecycleCommand("run.pause");

    await revokeAliceSessionAccess();
    const recovering = await requireRunState(BOB);
    expect(recovering).toMatchObject({
      lifecycle: "paused",
      stateVersion: 4,
      sandboxState: "recovering",
    });
    await expect(
      dispatch(
        {
          type: "run.stop",
          sessionId: SESSION_ID,
          agentRunId,
          expectedRunStateVersion: recovering.stateVersion,
          reason: "Stop while fence is pending",
        },
        BOB
      )
    ).rejects.toMatchObject({ code: "conflict" });

    await enforceNextRuntime("runtime.authorization.fence");
    expect(await requireRunState(BOB)).toMatchObject({
      lifecycle: "paused",
      stateVersion: 4,
      sandboxState: "ready",
    });
  });

  it("does not replace emergency pausing with ordinary recovery after Assignee loss", async () => {
    const started = await startRun(policy());
    const agentRunId = started.data.agentRunId as string;
    const binding = readRuntimeBinding(agentRunId);

    await dispatch({
      type: "run.emergency-stop",
      sessionId: SESSION_ID,
      agentRunId,
      runtimeBinding: {
        runtimeAssignmentId: binding.id,
        runtimeAssignmentGeneration: binding.generation,
        sandboxId: binding.sandbox_id,
        sandboxGeneration: binding.sandbox_generation,
      },
      observedSubordinateFences: {},
      revokeAllRunGrants: true,
      reason: "Unexpected protected target",
    });
    await revokeAliceSessionAccess();

    expect(await requireRunState(BOB)).toMatchObject({
      lifecycle: "pausing",
      sandboxState: "quarantined",
    });
    expect(readRuntimeBinding(agentRunId)).toMatchObject({ status: "quarantined" });

    await enforceNextRuntime("runtime.session.retire");
    expect(await requireRunState(BOB)).toMatchObject({
      lifecycle: "emergency-stopped",
      sandboxState: "retired",
    });
  });

  it("lets Emergency Stop supersede a permanently failed authorization fence", async () => {
    const started = await startRun(policy());
    const agentRunId = started.data.agentRunId as string;
    const binding = readRuntimeBinding(agentRunId);

    await revokeAliceSessionAccess();
    const [failedFence] = await sessions.claimRuntimeOutbox({
      workerId: RUNTIME.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    expect(failedFence?.kind).toBe("runtime.authorization.fence");
    if (!failedFence) throw new Error("Expected Assignee-loss authorization fence");
    await dispatch(
      {
        type: "runtime.outbox.fail",
        outboxId: failedFence.outboxId,
        workerId: RUNTIME.userId,
        expectedAttempt: failedFence.attempts,
        retryable: false,
        errorCode: "runtime_invalid_state",
      },
      RUNTIME
    );

    await dispatch(
      {
        type: "run.emergency-stop",
        sessionId: SESSION_ID,
        agentRunId,
        runtimeBinding: {
          runtimeAssignmentId: binding.id,
          runtimeAssignmentGeneration: binding.generation,
          sandboxId: binding.sandbox_id,
          sandboxGeneration: binding.sandbox_generation,
        },
        observedSubordinateFences: { runtimeAuthorizationGeneration: 2 },
        revokeAllRunGrants: true,
        reason: "Authorization fence could not be enforced",
      },
      BOB
    );

    await enforceNextRuntime("runtime.session.retire");
    expect(await requireRunState(BOB)).toMatchObject({
      lifecycle: "emergency-stopped",
      sandboxState: "retired",
    });
  });
});

function digestFor(value: string): string {
  return Buffer.from(value).toString("hex").padEnd(64, "0").slice(0, 64);
}
