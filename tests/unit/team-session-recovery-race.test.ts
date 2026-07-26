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

interface Kernel {
  readonly sessions: TeamSessions;
  readonly runtimeJournal: RuntimeLifecycleJournal;
}

describe("Team Session recovery races and crash recovery", () => {
  let directory: string;
  let filename: string;
  let sessions: TeamSessions;
  let runtimeJournal: RuntimeLifecycleJournal;
  let now: number;
  let sequence: number;
  let generated: number;

  function openKernel(): Kernel {
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
          effectEnforcerPolicyDigest: EFFECT_ENFORCER_SET_DIGEST,
        }),
      },
      runtimeEnforcementProofVerifier: () => true,
    });
    return { sessions: kernel.teamSessions, runtimeJournal: kernel.runtimeLifecycleJournal };
  }

  beforeEach(async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-recovery-race-"));
    filename = path.join(directory, "team-sessions.sqlite");
    now = 2_000_000_000_000;
    sequence = 0;
    generated = 0;
    const kernel = openKernel();
    sessions = kernel.sessions;
    runtimeJournal = kernel.runtimeJournal;
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
      idempotency: { scope: "vitest:recovery-race", key: `command-${sequence}` },
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
      commit: {
        policy: runPolicy,
        policyDigest: digestRunPolicyDraft(runPolicy),
        expectedProjectCeilingRevision: "local-tmux-ceiling:v1",
        expectedRuntimeAssignmentGeneration: 1,
        expectedSandboxGeneration: 1,
        expectedRuntimeAuthorizationGeneration: 1,
      },
    };
  }

  async function startRun() {
    await enforceNextRuntime("runtime.session.ensure");
    const started = await dispatch(startInput() as unknown as Record<string, unknown>);
    await enforceLifecycleCommand("run.start");
    return started.data.agentRunId as string;
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
    if (!requiredEffectEnforcerSetDigest) throw new Error("Expected a trusted enforcer digest");
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
    if (renewal.kind !== "renewed") throw new Error("Expected the lifecycle dispatch interlock");
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
  }

  async function runState() {
    return sessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.run-state",
      sessionId: SESSION_ID,
    });
  }

  async function expectFailClosed(
    run: () => Promise<unknown>,
    codes: ReadonlyArray<TeamSessionError["code"]> = ["stale-revision", "conflict"]
  ): Promise<void> {
    let error: unknown;
    try {
      await run();
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(TeamSessionError);
    expect(codes).toContain((error as TeamSessionError).code);
  }

  function seedReadyAssignment(id: string): void {
    const seed = new Database(filename);
    try {
      seed
        .prepare(
          `INSERT INTO runtime_assignments
             (id, session_id, team_id, project_id, generation, runtime_kind, sandbox_id,
              sandbox_generation, runtime_principal_id, runtime_authorization_generation,
              status, created_at_ms, retired_at_ms)
           VALUES (?, ?, ?, ?, 1, 'local-tmux', ?, 1, ?, 1, 'ready', ?, NULL)`
        )
        .run(id, SESSION_ID, TEAM_ID, PROJECT_ID, `sandbox-${id}`, `principal-${id}`, now);
    } finally {
      seed.close();
    }
  }

  it("end loses to a live Run's stop, then a late stop loses to the ended Session", async () => {
    const agentRunId = await startRun();
    const active = await runState();
    expect(active.lifecycle).toBe("active");

    // A live Run makes session.end fail closed: end cannot race a live dispatch.
    await expect(
      dispatch({
        type: "session.end",
        sessionId: SESSION_ID,
        expectedAccessRevision: 1,
        reason: "x",
      })
    ).rejects.toMatchObject({ code: "conflict" } satisfies Partial<TeamSessionError>);

    // run.stop wins and resolves the Run.
    await dispatch({
      type: "run.stop",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: active.stateVersion,
    });
    await enforceLifecycleCommand("run.stop");
    const stopped = await runState();
    expect(stopped.lifecycle).toBe("stopped");

    // Now end wins; the Session becomes the single terminal state.
    const ended = await dispatch({
      type: "session.end",
      sessionId: SESSION_ID,
      expectedAccessRevision: 1,
      reason: "engagement complete",
    });
    expect(ended.data).toMatchObject({ status: "ended" });

    // A late stop against the pre-end Run state fails closed (not silently):
    // the ended Session revokes the manager authority and rejects the mutation.
    await expectFailClosed(
      () =>
        dispatch({
          type: "run.stop",
          sessionId: SESSION_ID,
          agentRunId,
          expectedRunStateVersion: active.stateVersion,
        }),
      ["stale-revision", "conflict", "not-authorized"]
    );

    expect(sessions.verifySessionEventChain(SESSION_ID).ok).toBe(true);
  });

  it("end loses while an emergency-stop is enforcing", async () => {
    const agentRunId = await startRun();
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
    expect(requested.data).toMatchObject({ lifecycle: "pausing" });

    // The Run is mid-retirement (pausing): session.end must fail closed rather
    // than race the emergency-stop to a torn state.
    await expect(
      dispatch({
        type: "session.end",
        sessionId: SESSION_ID,
        expectedAccessRevision: 1,
        reason: "x",
      })
    ).rejects.toMatchObject({ code: "conflict" } satisfies Partial<TeamSessionError>);

    expect(sessions.verifySessionEventChain(SESSION_ID).ok).toBe(true);
  });

  it("end loses to a paused Run's resume", async () => {
    const agentRunId = await startRun();
    const active = await runState();

    await dispatch({
      type: "run.pause",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: active.stateVersion,
      reason: "Review the trace",
    });
    await enforceLifecycleCommand("run.pause");
    const paused = await runState();
    expect(paused.lifecycle).toBe("paused");

    // A paused Run still blocks end.
    await expect(
      dispatch({
        type: "session.end",
        sessionId: SESSION_ID,
        expectedAccessRevision: 1,
        reason: "x",
      })
    ).rejects.toMatchObject({ code: "conflict" } satisfies Partial<TeamSessionError>);

    // resume wins from the paused state.
    const resumed = await dispatch({
      type: "run.resume",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: paused.stateVersion,
      expectedRunPolicyRevision: 1,
      expectedRuntimeAuthorizationGeneration: 1,
    });
    expect(resumed.data).toMatchObject({ requestedLifecycle: "active" });
    await enforceLifecycleCommand("run.resume");

    // A second resume against the now-stale paused version fails closed on the
    // version fence, never silently.
    await expect(
      dispatch({
        type: "run.resume",
        sessionId: SESSION_ID,
        agentRunId,
        expectedRunStateVersion: paused.stateVersion,
        expectedRunPolicyRevision: 1,
        expectedRuntimeAuthorizationGeneration: 1,
      })
    ).rejects.toMatchObject({ code: "stale-revision" } satisfies Partial<TeamSessionError>);
  });

  it("resolves racing session.end commands to one terminal state and fails the losers closed", async () => {
    // Drain the ensure outbox that session.start enqueued so the Session is
    // quiescent and end is not blocked by outstanding Runtime work.
    await enforceNextRuntime("runtime.session.ensure");
    seedReadyAssignment("assign-end-race");

    // Two supervisors observe access_revision 1 and both try to end. The first
    // wins (access_revision -> 2); the losers fail closed on the version fence
    // and on the terminal state, never silently.
    const ended = await dispatch({
      type: "session.end",
      sessionId: SESSION_ID,
      expectedAccessRevision: 1,
      reason: "engagement complete",
      retentionMs: 1_000,
    });
    expect(ended.data).toMatchObject({ status: "ended" });

    // Same stale fence the loser observed -> version conflict.
    await expect(
      dispatch({
        type: "session.end",
        sessionId: SESSION_ID,
        expectedAccessRevision: 1,
        reason: "again",
      })
    ).rejects.toMatchObject({ code: "stale-revision" } satisfies Partial<TeamSessionError>);

    // Even with a refreshed fence, the terminal state rejects a second end.
    await expect(
      dispatch({
        type: "session.end",
        sessionId: SESSION_ID,
        expectedAccessRevision: 2,
        reason: "again",
      })
    ).rejects.toMatchObject({ code: "conflict" } satisfies Partial<TeamSessionError>);

    // A responsibility change (handoff) against the ended Session also fails closed.
    await expect(
      dispatch({
        type: "session.handoff.offer",
        sessionId: SESSION_ID,
        recipientParticipantId: "00000000-0000-4000-8000-000000009999",
        expectedAssigneeRevision: 1,
        expectedRecipientParticipantVersion: 1,
        expectedOffererResponsibilityVersion: 1,
      })
    ).rejects.toMatchObject({ code: "conflict" } satisfies Partial<TeamSessionError>);

    expect(sessions.verifySessionEventChain(SESSION_ID).ok).toBe(true);
  });

  it("resolves racing pre-Run platform-security actions on the generation fence", async () => {
    await enforceNextRuntime("runtime.session.ensure");
    seedReadyAssignment("assign-ps-race");

    // First quarantine wins and advances the authorization generation to 2.
    const quarantined = await dispatch({
      type: "session.platform-security.act",
      sessionId: SESSION_ID,
      runtimeAssignmentId: "assign-ps-race",
      action: "quarantine",
      reason: "seeded canary tripped",
      observedRuntimeAuthorizationGeneration: 1,
      idempotencyKey: "ps-quarantine-A",
    });
    expect(quarantined.data).toMatchObject({
      runtimeAuthorizationGeneration: 2,
      assignmentStatus: "quarantined",
    });

    // A racing action that observed the same stale generation (1) fails closed.
    await expect(
      dispatch({
        type: "session.platform-security.act",
        sessionId: SESSION_ID,
        runtimeAssignmentId: "assign-ps-race",
        action: "retire",
        reason: "racing retire on stale fence",
        observedRuntimeAuthorizationGeneration: 1,
        idempotencyKey: "ps-retire-B",
      })
    ).rejects.toMatchObject({ code: "stale-revision" } satisfies Partial<TeamSessionError>);

    // Reusing the winner's key for a different action is a fail-closed conflict,
    // not a silent replay of the recorded outcome.
    await expect(
      dispatch({
        type: "session.platform-security.act",
        sessionId: SESSION_ID,
        runtimeAssignmentId: "assign-ps-race",
        action: "retire",
        reason: "different action, same key",
        observedRuntimeAuthorizationGeneration: 1,
        idempotencyKey: "ps-quarantine-A",
      })
    ).rejects.toMatchObject({ code: "idempotency-conflict" } satisfies Partial<TeamSessionError>);

    // After the Session is ended, a further platform-security action fails closed.
    await dispatch({
      type: "session.end",
      sessionId: SESSION_ID,
      expectedAccessRevision: 1,
      reason: "contained and closed",
    });
    await expect(
      dispatch({
        type: "session.platform-security.act",
        sessionId: SESSION_ID,
        runtimeAssignmentId: "assign-ps-race",
        action: "retire",
        reason: "too late",
        observedRuntimeAuthorizationGeneration: 2,
        idempotencyKey: "ps-retire-late",
      })
    ).rejects.toMatchObject({ code: "conflict" } satisfies Partial<TeamSessionError>);

    expect(sessions.verifySessionEventChain(SESSION_ID).ok).toBe(true);
  });

  it("recovers a mid-lifecycle Run from a real on-disk reopen with an intact event chain", async () => {
    const agentRunId = await startRun();
    const active = await runState();
    await dispatch({
      type: "run.pause",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: active.stateVersion,
      reason: "Pause before the crash",
    });
    await enforceLifecycleCommand("run.pause");
    const beforeCrash = await runState();
    expect(beforeCrash.lifecycle).toBe("paused");
    const chainBefore = sessions.verifySessionEventChain(SESSION_ID);
    expect(chainBefore.ok).toBe(true);

    // Simulate a crash: drop the process handle and reopen the database from disk.
    sessions.close();
    const reopened = openKernel();
    sessions = reopened.sessions;
    runtimeJournal = reopened.runtimeJournal;

    // The recovered state is consistent with the pre-crash checkpoint...
    const afterCrash = await runState();
    expect(afterCrash.lifecycle).toBe("paused");
    expect(afterCrash.stateVersion).toBe(beforeCrash.stateVersion);
    expect(afterCrash.agentRunId).toBe(agentRunId);

    // ...and the event chain still verifies against its persisted head.
    const chainAfter = sessions.verifySessionEventChain(SESSION_ID);
    expect(chainAfter.ok).toBe(true);
    if (chainAfter.ok && chainBefore.ok) {
      expect(chainAfter.headHash).toBe(chainBefore.headHash);
      expect(chainAfter.headSequence).toBe(chainBefore.headSequence);
    }

    // The recovered kernel can continue the lifecycle: stop the Run and end the
    // Session, and the chain remains verifiable through the terminal transition.
    await dispatch({
      type: "run.stop",
      sessionId: SESSION_ID,
      agentRunId,
      expectedRunStateVersion: afterCrash.stateVersion,
    });
    await enforceLifecycleCommand("run.stop");
    const ended = await dispatch({
      type: "session.end",
      sessionId: SESSION_ID,
      expectedAccessRevision: 1,
      reason: "closed after recovery",
    });
    expect(ended.data).toMatchObject({ status: "ended" });
    expect(sessions.verifySessionEventChain(SESSION_ID).ok).toBe(true);
  });
});
