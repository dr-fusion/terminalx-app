import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  TeamSessionError,
  createTeamSessionKernel,
  type ActorContext,
  type AgentRunCommandPayload,
  type RunPolicyDraft,
  type SessionCommand,
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
const RUNTIME: ActorContext = {
  kind: "system",
  userId: "runtime-worker",
  displayName: "Runtime Worker",
};
const unconfigured = { kind: "unconfigured" } as const;
const EFFECT_ENFORCER_SET_DIGEST = "b".repeat(64);

describe("Team Session Agent Runs", () => {
  let directory: string;
  let filename: string;
  let sessions: TeamSessions;
  let runtimeJournal: RuntimeLifecycleJournal;
  let now: number;
  let sequence: number;
  let generated: number;
  let runtimeAuthorizationGenerationOffset: number;

  beforeEach(async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-agent-runs-"));
    filename = path.join(directory, "team-sessions.sqlite");
    now = 2_000_000_000_000;
    sequence = 0;
    generated = 0;
    runtimeAuthorizationGenerationOffset = 0;
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
          generation: runtimeAuthorizationGeneration + runtimeAuthorizationGenerationOffset,
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
      name: "Checkout latency",
      tmuxName: "checkout-latency",
      steeringPolicy: "shared",
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
      idempotency: { scope: "vitest:agent-runs", key: `command-${sequence}` },
      occurredAtMs: now,
    } as SessionCommand;
  }

  async function dispatch(input: Record<string, unknown>, actor = ALICE) {
    return sessions.dispatch(command(input, actor));
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
    if (!delivery) throw new Error("Expected Runtime delivery");
    await sessions.markRuntimeOutboxDispatch({
      outboxId: delivery.outboxId,
      workerId: RUNTIME.userId,
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
    });
    await dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: delivery.outboxId,
        workerId: RUNTIME.userId,
        expectedAttempt: delivery.attempts,
        expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      },
      RUNTIME
    );
    return delivery;
  }

  function policy(overrides: Partial<RunPolicyDraft> = {}): RunPolicyDraft {
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
      ...overrides,
    };
  }

  function commit(runPolicy = policy()) {
    return {
      policy: runPolicy,
      policyDigest: digestRunPolicyDraft(runPolicy),
      expectedProjectCeilingRevision: "local-tmux-ceiling:v1",
      expectedRuntimeAssignmentGeneration: 1,
      expectedSandboxGeneration: 1,
      expectedRuntimeAuthorizationGeneration: 1,
    };
  }

  function startInput(runPolicy = policy()): AgentRunCommandPayload {
    return {
      type: "run.start",
      sessionId: SESSION_ID,
      expectedSessionRevision: 1,
      initialGoals: [
        {
          goalId: "goal:diagnose",
          position: 1,
          title: "Find the bottleneck",
          acceptanceCriteria: ["A trace identifies the slow span"],
          dependencyGoalIds: [],
        },
      ],
      commit: commit(runPolicy),
    };
  }

  async function startRun(runPolicy = policy()) {
    await enforceNextRuntime("runtime.session.ensure");
    const started = await dispatch(startInput(runPolicy) as unknown as Record<string, unknown>);
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

  async function runState() {
    return sessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.run-state",
      sessionId: SESSION_ID,
    });
  }

  async function publicRunState(actor = ALICE) {
    return sessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      type: "session.public-run-state",
      sessionId: SESSION_ID,
    });
  }

  it("keeps lifecycle activation closed unless every trusted security seam is configured", () => {
    expect(() =>
      createTeamSessionKernel({
        runtimeCommandAuthorityIssuer: createTestRuntimeCommandAuthorityIssuer(),
      })
    ).toThrow(/configured together/);
  });

  it("exposes compensation workers only when the complete platform-security trust group is configured", () => {
    const lifecycleSecurity = {
      runtimeCommandAuthorityIssuer: createTestRuntimeCommandAuthorityIssuer(),
      runtimeAuthorizationSnapshotSource: {
        resolve: ({
          runtimeAuthorizationGeneration,
        }: {
          runtimeAuthorizationGeneration: number;
        }) => ({
          generation: runtimeAuthorizationGeneration,
          networkPolicyRef: "test-network-policy:v1",
          networkPolicyDigest: "c".repeat(64),
          credentialPolicyRef: "test-credential-policy:v1",
          credentialPolicyDigest: "d".repeat(64),
          effectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
        }),
      },
      runtimeEnforcementProofVerifier: () => true,
    };
    const compensationSecurity = {
      runtimeCompensationAuthorityIssuer: {
        issue: () => {
          throw new Error("No incident should be signed during composition");
        },
      },
      runtimeCompensationAuthorityVerifier: () => true,
      runtimeCompensationPolicySource: { resolve: () => undefined },
      runtimeCompensationEnforcementProofVerifier: () => true,
    };

    expect(() =>
      createTeamSessionKernel({
        filename: path.join(directory, "partial-compensation.sqlite"),
        ...lifecycleSecurity,
        runtimeCompensationAuthorityVerifier:
          compensationSecurity.runtimeCompensationAuthorityVerifier,
      })
    ).toThrow(/compensation.*configured together/i);
    expect(() =>
      createTeamSessionKernel({
        filename: path.join(directory, "compensation-without-lifecycle.sqlite"),
        ...compensationSecurity,
      })
    ).toThrow(/requires the complete Runtime lifecycle/i);

    const composed = createTeamSessionKernel({
      filename: path.join(directory, "complete-compensation.sqlite"),
      ...lifecycleSecurity,
      ...compensationSecurity,
    });
    try {
      expect(composed.runtimeAssignmentKernel).toBe(composed.teamSessions);
      expect(composed.runtimeCompensationJournal).toBeDefined();
      expect(composed.runtimeCompensationMaterializer).toBeDefined();
      expect(Object.isFrozen(composed)).toBe(true);
    } finally {
      composed.teamSessions.close();
    }
  });

  it("rejects an authorization epoch whose trusted snapshot generation mismatches its binding", async () => {
    runtimeAuthorizationGenerationOffset = 1;
    await enforceNextRuntime("runtime.session.ensure");
    await expect(
      dispatch(startInput() as unknown as Record<string, unknown>)
    ).rejects.toMatchObject({ code: "conflict" } satisfies Partial<TeamSessionError>);

    const db = new Database(filename, { readonly: true });
    const epochCount = db
      .prepare(`SELECT COUNT(*) AS count FROM runtime_authorization_epochs`)
      .get() as { count: number };
    db.close();
    expect(epochCount.count).toBe(0);
  });

  it("waits for Runtime enforcement, starts one durable Run, and projects its goals", async () => {
    await expect(
      dispatch(startInput() as unknown as Record<string, unknown>)
    ).rejects.toMatchObject({
      code: "conflict",
    } satisfies Partial<TeamSessionError>);

    const started = await startRun();
    expect(started.data).toMatchObject({
      lifecycle: "starting",
      stateVersion: 1,
      runPolicyRevision: 1,
      goalSetRevision: 1,
      runStateRevision: 2,
    });
    expect(started.events).toHaveLength(1);
    expect(started.events[0]?.type).toBe("run.runtime-command.requested");

    const db = new Database(filename, { readonly: true });
    const trustedDigests = db
      .prepare(
        `SELECT epoch.effect_enforcer_set_digest AS epoch_digest,
                policy.required_effect_enforcer_set_digest AS policy_digest,
                command.required_effect_enforcer_set_digest AS command_digest,
                json_extract(
                  command.command_json, '$.requiredEffectEnforcerSetDigest'
                ) AS signed_command_digest,
                json_extract(
                  command.command_json, '$.policy.requiredEffectEnforcerSetDigest'
                ) AS signed_policy_digest
         FROM agent_runs run
         JOIN runtime_authorization_epochs epoch
           ON epoch.session_id = run.session_id
          AND epoch.generation = run.runtime_authorization_generation
         JOIN run_policy_revisions policy
           ON policy.agent_run_id = run.id AND policy.revision = run.current_policy_revision
         JOIN runtime_run_commands command ON command.id = run.start_command_id
         WHERE run.id = ?`
      )
      .get(started.data.agentRunId) as Record<string, string>;
    db.close();
    expect(Object.values(trustedDigests)).toEqual(
      Array.from({ length: 5 }, () => EFFECT_ENFORCER_SET_DIGEST)
    );

    const state = await runState();
    expect(state).toMatchObject({
      lifecycle: "active",
      stateVersion: 2,
      pendingLifecycleOperation: null,
      mode: "autonomous",
      completionPolicy: "continue-until-all-goals-achieved",
      goals: [
        {
          goalId: "goal:diagnose",
          position: 1,
          version: 1,
          status: "pending",
          evidence: [],
        },
      ],
    });

    await expect(
      dispatch({ ...startInput(), expectedSessionRevision: 2 } as unknown as Record<
        string,
        unknown
      >)
    ).rejects.toMatchObject({ code: "stale-revision" } satisfies Partial<TeamSessionError>);
  });

  it("atomically projects only an authorized actor's mutable Run ahead of same-clock terminal history", async () => {
    const started = await startRun();
    const agentRunId = started.data.agentRunId as string;
    const db = new Database(filename);
    const terminalRunId = "zzzz-same-clock-terminal-run";
    const terminalGoalSetId = "zzzz-same-clock-terminal-goal-set";
    db.transaction(() => {
      db.prepare(
        `INSERT INTO agent_runs
           (id, session_id, team_id, project_id, runtime_assignment_id, lifecycle,
            state_version, current_policy_revision, current_goal_set_revision,
            runtime_authorization_generation, final_review_version,
            created_by_user_id, created_at_ms, updated_at_ms, terminal_at_ms)
         SELECT ?, session_id, team_id, project_id,
                runtime_assignment_id, 'stopped', 1, current_policy_revision,
                current_goal_set_revision, runtime_authorization_generation, 1,
                created_by_user_id, created_at_ms, created_at_ms, created_at_ms
         FROM agent_runs WHERE id = ?`
      ).run(terminalRunId, agentRunId);
      db.prepare(
        `INSERT INTO goal_sets
           (goal_set_id, agent_run_id, revision, previous_revision, digest, created_at_ms)
         SELECT ?, ?, revision, previous_revision, digest, created_at_ms
         FROM goal_sets WHERE agent_run_id = ? AND revision = 1`
      ).run(terminalGoalSetId, terminalRunId, agentRunId);
      db.prepare(
        `INSERT INTO goals
           (agent_run_id, goal_set_id, goal_set_revision, goal_id, position, version, title,
            acceptance_criteria_json, dependency_goal_ids_json, status)
         SELECT ?, ?, goal_set_revision, goal_id, position, version, title,
                acceptance_criteria_json, dependency_goal_ids_json, status
         FROM goals WHERE agent_run_id = ? AND goal_set_revision = 1`
      ).run(terminalRunId, terminalGoalSetId, agentRunId);
      db.prepare(
        `INSERT INTO run_policy_revisions
           (agent_run_id, session_id, revision, previous_revision, digest, policy_body_digest,
            mode, completion_policy, scoped_external_policy_ref, scoped_external_rules_json,
            limits_json, initial_goal_set_id, initial_goal_set_revision,
            project_ceiling_revision, project_ceiling_digest, runtime_assignment_id,
            runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, required_effect_enforcer_set_digest,
            yolo_confirmation_ref, created_at_ms)
         SELECT ?, session_id, revision, previous_revision, digest, policy_body_digest,
                mode, completion_policy, scoped_external_policy_ref, scoped_external_rules_json,
                limits_json, ?, initial_goal_set_revision,
                project_ceiling_revision, project_ceiling_digest, runtime_assignment_id,
                runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id,
                runtime_authorization_generation, required_effect_enforcer_set_digest,
                yolo_confirmation_ref, created_at_ms
         FROM run_policy_revisions WHERE agent_run_id = ? AND revision = 1`
      ).run(terminalRunId, terminalGoalSetId, agentRunId);
    })();
    db.close();

    await expect(publicRunState()).resolves.toMatchObject({
      currentRun: { agentRunId, lifecycle: "active" },
    });
    await expect(
      publicRunState({ kind: "human", userId: "mallory", displayName: "Mallory" })
    ).resolves.toBeNull();
  });

  it("keeps YOLO unavailable on LocalTmux and allows only policy tightening without approval", async () => {
    await enforceNextRuntime("runtime.session.ensure");
    const yolo = policy({ mode: "yolo" });
    await expect(dispatch(startInput(yolo) as unknown as Record<string, unknown>)).rejects.toThrow(
      /not eligible/
    );

    const started = await dispatch(startInput() as unknown as Record<string, unknown>);
    await enforceLifecycleCommand("run.start");
    const agentRunId = started.data.agentRunId as string;
    const supervised = policy({
      mode: "supervised",
      completionPolicy: { kind: "stop-after-directed-work" },
    });
    const revised = await dispatch({
      type: "run.policy.revise",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunPolicyRevision: 1,
      commit: commit(supervised),
    });
    expect(revised.data).toMatchObject({ runPolicyRevision: 2, stateVersion: 3 });
    expect(await runState()).toMatchObject({ mode: "supervised", runPolicyRevision: 2 });

    await expect(
      dispatch({
        type: "run.policy.revise",
        sessionId: SESSION_ID,
        agentRunId,
        expectedRunPolicyRevision: 2,
        commit: commit(),
      })
    ).rejects.toThrow(/one-shot approval/);
  });

  it("attributes monotonic Goal changes to ordered Directives", async () => {
    const started = await startRun();
    const agentRunId = started.data.agentRunId as string;
    const added = await dispatch({
      type: "goal.add",
      sessionId: SESSION_ID,
      agentRunId,
      expectedGoalSetRevision: 1,
      goal: {
        goalId: "goal:fix",
        position: 2,
        title: "Apply the bounded fix",
        acceptanceCriteria: ["Focused tests pass"],
        dependencyGoalIds: ["goal:diagnose"],
      },
      directive: { format: "plain-text", body: "Add the bounded fix as the next goal." },
    });
    expect(added.events.map((event) => event.type)).toEqual([
      "directive.queued",
      "goal-set.revised",
    ]);
    expect(added.data).toMatchObject({ goalSetRevision: 2, stateVersion: 3 });

    const strengthened = await dispatch({
      type: "goal.criteria.strengthen",
      sessionId: SESSION_ID,
      agentRunId,
      goalId: "goal:fix",
      expectedGoalSetRevision: 2,
      addedCriteria: ["The regression test fails before the fix"],
      directive: { format: "plain-text", body: "Prove the regression before applying the fix." },
    });
    expect(strengthened.data).toMatchObject({ goalSetRevision: 3, stateVersion: 4 });
    expect(await runState()).toMatchObject({
      goals: [
        { goalId: "goal:diagnose", position: 1 },
        {
          goalId: "goal:fix",
          position: 2,
          version: 2,
          acceptanceCriteria: ["Focused tests pass", "The regression test fails before the fix"],
        },
      ],
    });

    await expect(
      dispatch({
        type: "goal.dependency.add",
        sessionId: SESSION_ID,
        agentRunId,
        goalId: "goal:diagnose",
        dependencyGoalId: "goal:fix",
        expectedGoalSetRevision: 3,
        directive: { format: "plain-text", body: "Make diagnosis depend on the fix." },
      })
    ).rejects.toThrow(/cycle/);
  });

  it("projects evidence only for the exact current Goal Set and Goal version", async () => {
    const started = await startRun();
    const agentRunId = started.data.agentRunId as string;
    const db = new Database(filename);
    const goalSet = db
      .prepare(
        `SELECT goal_set_id FROM goal_sets
         WHERE agent_run_id = ? AND revision = 1`
      )
      .get(agentRunId) as { goal_set_id: string };
    db.prepare(
      `INSERT INTO goal_evidence
         (id, agent_run_id, goal_set_id, goal_set_revision, goal_id, goal_version,
          evidence_ref, evidence_digest, status, created_at_ms, reviewed_at_ms)
       VALUES ('evidence:revision-1', ?, ?, 1, 'goal:diagnose', 1,
               'artifact:evidence-revision-1', ?, 'validated', ?, ?)`
    ).run(agentRunId, goalSet.goal_set_id, "e".repeat(64), now, now);
    db.close();

    await expect(runState()).resolves.toMatchObject({
      goals: [
        { goalId: "goal:diagnose", version: 1, evidence: [{ evidenceId: "evidence:revision-1" }] },
      ],
    });

    await dispatch({
      type: "goal.criteria.strengthen",
      sessionId: SESSION_ID,
      agentRunId,
      goalId: "goal:diagnose",
      expectedGoalSetRevision: 1,
      addedCriteria: ["The regression test proves the exact current result"],
      directive: { format: "plain-text", body: "Strengthen the current Goal criteria." },
    });

    await expect(runState()).resolves.toMatchObject({
      goalSetRevision: 2,
      goals: [{ goalId: "goal:diagnose", version: 2, evidence: [] }],
    });
    await expect(publicRunState()).resolves.toMatchObject({
      currentRun: {
        goalSetRevision: 2,
        goals: [{ goalId: "goal:diagnose", version: 2, evidenceTotalCount: 0, evidence: [] }],
      },
    });
  });

  it("uses fenced lifecycle versions for pause, resume, and stop", async () => {
    const started = await startRun();
    const agentRunId = started.data.agentRunId as string;
    const paused = await dispatch({
      type: "run.pause",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: 2,
      reason: "Review the trace",
    });
    expect(paused.data).toMatchObject({
      lifecycle: "active",
      stateVersion: 2,
      requestedLifecycle: "paused",
    });
    await enforceLifecycleCommand("run.pause");
    await expect(runState()).resolves.toMatchObject({ lifecycle: "paused", stateVersion: 3 });

    await expect(
      dispatch({
        type: "run.resume",
        sessionId: SESSION_ID,
        agentRunId,
        expectedRunStateVersion: 2,
        expectedRunPolicyRevision: 1,
        expectedRuntimeAuthorizationGeneration: 1,
      })
    ).rejects.toMatchObject({ code: "stale-revision" } satisfies Partial<TeamSessionError>);

    const resumed = await dispatch({
      type: "run.resume",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: 3,
      expectedRunPolicyRevision: 1,
      expectedRuntimeAuthorizationGeneration: 1,
    });
    expect(resumed.data).toMatchObject({
      lifecycle: "paused",
      stateVersion: 3,
      requestedLifecycle: "active",
    });
    await enforceLifecycleCommand("run.resume");

    const stopped = await dispatch({
      type: "run.stop",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: 4,
    });
    expect(stopped.data).toMatchObject({
      lifecycle: "active",
      stateVersion: 4,
      requestedLifecycle: "stopped",
    });
    await enforceLifecycleCommand("run.stop");
    await expect(runState()).resolves.toMatchObject({ lifecycle: "stopped", stateVersion: 5 });
  });

  it("quarantines immediately but records emergency-stopped only after Runtime retirement", async () => {
    const started = await startRun();
    const agentRunId = started.data.agentRunId as string;
    const db = new Database(filename, { readonly: true });
    const binding = db
      .prepare(
        `SELECT id, generation, sandbox_id, sandbox_generation
         FROM runtime_assignments WHERE session_id = ?`
      )
      .get(SESSION_ID) as {
      id: string;
      generation: number;
      sandbox_id: string;
      sandbox_generation: number;
    };
    db.close();

    const requested = await dispatch({
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
      reason: "Unexpected production target",
    });
    expect(requested.data).toMatchObject({
      lifecycle: "pausing",
      stateVersion: 3,
      enforcementPending: true,
      runtimeAuthorizationGeneration: 2,
    });
    expect(await runState()).toMatchObject({ lifecycle: "pausing", sandboxState: "quarantined" });
    expect(
      sessions.isCurrentRuntimeBinding({
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 2,
        emergencyStop: {
          agentRunId,
          runtimeAssignmentId: binding.id,
          runtimeAssignmentGeneration: binding.generation,
          sandboxId: binding.sandbox_id,
          sandboxGeneration: binding.sandbox_generation,
        },
      })
    ).toBe(true);

    const [failedRetire] = await sessions.claimRuntimeOutbox({
      workerId: RUNTIME.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    expect(failedRetire?.kind).toBe("runtime.session.retire");
    if (!failedRetire) throw new Error("Expected emergency retirement");
    await sessions.markRuntimeOutboxDispatch({
      outboxId: failedRetire.outboxId,
      workerId: RUNTIME.userId,
      expectedAttempt: failedRetire.attempts,
      expectedLeaseExpiresAtMs: failedRetire.leaseExpiresAtMs,
    });
    await dispatch(
      {
        type: "runtime.outbox.fail",
        outboxId: failedRetire.outboxId,
        workerId: RUNTIME.userId,
        expectedAttempt: failedRetire.attempts,
        expectedLeaseExpiresAtMs: failedRetire.leaseExpiresAtMs,
        retryable: false,
        errorCode: "runtime_invalid_state",
      },
      RUNTIME
    );
    expect(await runState()).toMatchObject({ lifecycle: "pausing" });

    const retried = await dispatch({
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
      reason: "Retry emergency retirement",
    });
    expect(retried.data).toMatchObject({ lifecycle: "pausing", runtimeAuthorizationGeneration: 3 });
    await enforceNextRuntime("runtime.session.retire");
    expect(await runState()).toMatchObject({
      lifecycle: "emergency-stopped",
      stateVersion: 5,
      sandboxState: "retired",
    });
    expect(
      sessions.isCurrentRuntimeBinding({
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 3,
      })
    ).toBe(false);
  });
});
