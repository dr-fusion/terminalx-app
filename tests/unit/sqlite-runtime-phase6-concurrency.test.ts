import { generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  createTeamSessionKernel,
  type ActorContext,
  type CommandResult,
  type CreateTeamSessionsOptions,
  type RunPolicyDraft,
  type SessionCommand,
  type TeamSessionKernel,
  type TeamSessions,
} from "@/lib/team-sessions";
import { digestRunPolicyDraft } from "@/lib/team-sessions/run-policy";
import { createSqliteRuntimeLifecycleJournal } from "@/lib/team-sessions/sqlite-runtime-lifecycle-journal";
import { openTeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import {
  commitRuntimeEffectRef,
  createRuntimeCommandAuthorityIssuer,
  createRuntimeCompensationReceiptObservationIssuer,
  createRuntimeReceiptObservationIssuer,
  digestAggregateEnforcementProof,
  digestRuntimeCommandClaims,
  digestRuntimeCompensationEnforcementSubject,
  digestRuntimeEnforcementSubject,
  type RuntimeCompensationCommand,
  type RuntimeCompensationReceipt,
  type RuntimeLifecycleDelivery,
  type RuntimeReceipt,
} from "@/lib/runtime";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const PEER_SESSION_ID = "44444444-4444-4444-8444-444444444444";
const ALICE: ActorContext = { kind: "human", userId: "alice", displayName: "Alice" };
const RUNTIME: ActorContext = {
  kind: "system",
  userId: "runtime-phase6-worker",
  displayName: "Runtime Phase 6 Worker",
};
const UNCONFIGURED = { kind: "unconfigured" } as const;
const EFFECT_ENFORCER_SET_DIGEST = "b".repeat(64);
const CONTAINMENT_ENFORCER_SET_DIGEST = "c".repeat(64);
const RUNTIME_EFFECT_REF = "provider-private-runtime-effect";
const CONTAINMENT_EFFECT_REF = "provider-private-containment-effect";
const OBSERVATION_KEY_ID = "runtime-observer:phase6-concurrency";
const PLATFORM_SIGNATURE = Buffer.alloc(64, 9).toString("base64url");

describe("Phase 6 SQLite concurrency and crash boundaries", () => {
  let directory: string;
  let filename: string;
  let observationPrivateKeyFile: string;
  let observationPublicKeyPem: string;
  let authorityPrivateKeyFile: string;
  let now: number;
  let generated: number;
  let commandSequence: number;
  let authorityIssuer: ReturnType<typeof createRuntimeCommandAuthorityIssuer>;
  let primary: TeamSessionKernel;
  let sessions: TeamSessions;
  const openSessions = new Set<TeamSessions>();

  beforeEach(async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-phase6-concurrency-"));
    filename = path.join(directory, "team-sessions.sqlite");
    const observationKeys = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    observationPrivateKeyFile = path.join(directory, "runtime-observation-private.pem");
    observationPublicKeyPem = observationKeys.publicKey;
    fs.writeFileSync(observationPrivateKeyFile, observationKeys.privateKey, { mode: 0o600 });
    fs.chmodSync(observationPrivateKeyFile, 0o600);
    const authorityKeys = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    authorityPrivateKeyFile = path.join(directory, "runtime-authority-private.pem");
    fs.writeFileSync(authorityPrivateKeyFile, authorityKeys.privateKey, { mode: 0o600 });
    fs.chmodSync(authorityPrivateKeyFile, 0o600);
    now = 2_000_000_000_000;
    generated = 0;
    commandSequence = 0;
    authorityIssuer = createRuntimeCommandAuthorityIssuer({
      issuer: "team-session",
      issuerKeyId: "team-session:phase6-key",
      trustedConfigurationRoot: directory,
      privateKeyFile: authorityPrivateKeyFile,
      clock: () => now,
    });
    primary = openKernel();
    sessions = primary.teamSessions;

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
      name: "Phase 6 concurrency",
      tmuxName: "phase6-concurrency",
      steeringPolicy: "shared",
    });
    const [ensure] = await sessions.claimRuntimeOutbox({
      workerId: RUNTIME.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    if (!ensure) throw new Error("Expected Runtime ensure delivery");
    await sessions.markRuntimeOutboxDispatch({
      outboxId: ensure.outboxId,
      workerId: RUNTIME.userId,
      expectedAttempt: ensure.attempts,
      expectedLeaseExpiresAtMs: ensure.leaseExpiresAtMs,
    });
    await dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: ensure.outboxId,
        workerId: RUNTIME.userId,
        expectedAttempt: ensure.attempts,
        expectedLeaseExpiresAtMs: ensure.leaseExpiresAtMs,
      },
      RUNTIME
    );
  });

  afterEach(() => {
    for (const active of openSessions) active.close();
    openSessions.clear();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function kernelOptions(): CreateTeamSessionsOptions {
    return {
      filename,
      clock: () => now,
      idGenerator: () => {
        generated += 1;
        return `00000000-0000-4000-8000-${String(generated).padStart(12, "0")}`;
      },
      runtimeCommandAuthorityIssuer: authorityIssuer,
      runtimeAuthorizationSnapshotSource: {
        resolve: ({ runtimeAuthorizationGeneration }) => ({
          generation: runtimeAuthorizationGeneration,
          networkPolicyRef: "test-network-policy:v1",
          networkPolicyDigest: "d".repeat(64),
          credentialPolicyRef: "test-credential-policy:v1",
          credentialPolicyDigest: "e".repeat(64),
          effectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
        }),
      },
      runtimeEnforcementProofVerifier: () => true,
      runtimeCompensationAuthorityIssuer: {
        issue: (claims) => ({
          issuer: "platform-security",
          issuerKeyId: "platform-security:phase6-key",
          audience: "runtime",
          capability: "safety.quarantine",
          claimsDigest: digestRuntimeCommandClaims(claims),
          issuedAtMs: claims.issuedAtMs,
          expiresAtMs: claims.deadlineAtMs,
          signature: PLATFORM_SIGNATURE,
        }),
      },
      runtimeCompensationAuthorityVerifier: ({ command }) =>
        command.authority.signature === PLATFORM_SIGNATURE,
      runtimeCompensationPolicySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:phase6:v1",
          requiredContainmentEnforcerSetDigest: CONTAINMENT_ENFORCER_SET_DIGEST,
        }),
      },
      runtimeCompensationEnforcementProofVerifier: () => true,
    };
  }

  function openKernel(): TeamSessionKernel {
    const kernel = createTeamSessionKernel(kernelOptions());
    openSessions.add(kernel.teamSessions);
    return kernel;
  }

  function closeKernel(kernel: TeamSessionKernel): void {
    if (!openSessions.delete(kernel.teamSessions)) return;
    kernel.teamSessions.close();
  }

  function command(input: Record<string, unknown>, actor = ALICE): SessionCommand {
    commandSequence += 1;
    return {
      ...input,
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      idempotency: {
        scope: "vitest:phase6-concurrency",
        key: `command-${commandSequence}`,
      },
      occurredAtMs: now,
    } as SessionCommand;
  }

  async function dispatch(input: Record<string, unknown>, actor = ALICE): Promise<CommandResult> {
    return sessions.dispatch(command(input, actor));
  }

  function policy(): RunPolicyDraft {
    return {
      mode: "autonomous",
      completionPolicy: { kind: "continue-until-all-goals-achieved" },
      scopedExternalPolicyRef: "project-policy:1",
      limits: {
        wallClock: UNCONFIGURED,
        modelTokens: UNCONFIGURED,
        modelSpend: UNCONFIGURED,
        outboundBytes: UNCONFIGURED,
        actionCounts: {
          local: UNCONFIGURED,
          "scoped-external": UNCONFIGURED,
          protected: UNCONFIGURED,
          forbidden: UNCONFIGURED,
        },
      },
    };
  }

  async function requestStart(): Promise<void> {
    const runPolicy = policy();
    await dispatch({
      type: "run.start",
      sessionId: SESSION_ID,
      expectedSessionRevision: 1,
      initialGoals: [
        {
          goalId: "goal:phase6-concurrency",
          position: 1,
          title: "Prove singular durable effects",
          acceptanceCriteria: ["Every competing worker observes one durable winner"],
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
    });
  }

  function enforcedRuntimeReceipt(delivery: RuntimeLifecycleDelivery): RuntimeReceipt {
    const requiredEffectEnforcerSetDigest = delivery.command.requiredEffectEnforcerSetDigest;
    if (!requiredEffectEnforcerSetDigest) throw new Error("Expected lifecycle enforcer set");
    const enforcementSubjectDigest = digestRuntimeEnforcementSubject({
      version: 1,
      commandId: delivery.command.commandId,
      commandClaimsDigest: delivery.command.authority.claimsDigest,
      binding: delivery.command.binding,
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest,
      effectRefCommitment: commitRuntimeEffectRef(RUNTIME_EFFECT_REF),
      enforcedFence: delivery.command.toRunStateVersion,
    });
    const proof = {
      generation: delivery.command.runtimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest,
      enforcementSubjectDigest,
      acknowledgements: [
        {
          enforcerRef: "phase6-runtime-enforcer",
          enforcerKind: "runtime" as const,
          acknowledgementDigest: "f".repeat(64),
        },
      ],
    };
    return {
      commandId: delivery.command.commandId,
      binding: delivery.command.binding,
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
      outcome: "enforced",
      effectRef: RUNTIME_EFFECT_REF,
      enforcedFence: delivery.command.toRunStateVersion,
      aggregateEnforcementProof: {
        ...proof,
        aggregateProofDigest: digestAggregateEnforcementProof(proof),
      },
    };
  }

  function enforcedCompensationReceipt(
    commandValue: RuntimeCompensationCommand
  ): RuntimeCompensationReceipt {
    const containment = {
      terminalWritesRevoked: true as const,
      processExecutionStopped: true as const,
      runtimeQuarantined: true as const,
    };
    const subject = {
      version: 1 as const,
      purpose: "stale-lifecycle-effect-containment" as const,
      compensationId: commandValue.compensationId,
      commandId: commandValue.commandId,
      commandClaimsDigest: commandValue.authority.claimsDigest,
      binding: commandValue.binding,
      observedRuntimeAuthorizationGeneration: commandValue.observedRuntimeAuthorizationGeneration,
      safetyFence: commandValue.safetyFence,
      enforcedSafetyFence: commandValue.safetyFence,
      sourceReceiptDigest: commandValue.source.lifecycleReceiptDigest,
      sourceEnforcementSubjectDigest: commandValue.source.lifecycleEnforcementSubjectDigest,
      sourceAggregateProofDigest: commandValue.source.lifecycleAggregateProofDigest,
      requiredContainmentEnforcerSetDigest: commandValue.requiredContainmentEnforcerSetDigest,
      effectRefCommitment: commitRuntimeEffectRef(CONTAINMENT_EFFECT_REF),
      containment,
    };
    const proof = {
      generation: commandValue.observedRuntimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest: commandValue.requiredContainmentEnforcerSetDigest,
      enforcementSubjectDigest: digestRuntimeCompensationEnforcementSubject(subject),
      acknowledgements: [
        {
          enforcerRef: "phase6-containment-enforcer",
          enforcerKind: "runtime" as const,
          acknowledgementDigest: "a".repeat(64),
        },
      ],
    };
    return {
      receiptKind: "runtime.compensation",
      compensationId: commandValue.compensationId,
      commandId: commandValue.commandId,
      binding: commandValue.binding,
      observedRuntimeAuthorizationGeneration: commandValue.observedRuntimeAuthorizationGeneration,
      outcome: "enforced",
      effectRef: CONTAINMENT_EFFECT_REF,
      enforcedSafetyFence: commandValue.safetyFence,
      containment,
      aggregateEnforcementProof: {
        ...proof,
        aggregateProofDigest: digestAggregateEnforcementProof(proof),
      },
    };
  }

  function advanceRuntimeAuthorizationGeneration(
    delivery: RuntimeLifecycleDelivery,
    generation: number
  ): void {
    const binding = delivery.command.binding;
    const db = new Database(filename);
    try {
      db.pragma("foreign_keys = ON");
      db.transaction(() => {
        db.prepare(
          `INSERT INTO runtime_authorization_epochs
             (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
              sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
              effect_enforcer_set_digest)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          binding.sessionId,
          generation,
          binding.runtimeAssignmentId,
          binding.runtimeAssignmentGeneration,
          binding.sandboxId,
          binding.sandboxGeneration,
          binding.runtimePrincipalId,
          now,
          EFFECT_ENFORCER_SET_DIGEST
        );
        const assignment = db
          .prepare(
            `UPDATE runtime_assignments
             SET runtime_authorization_generation = ?
             WHERE id = ? AND session_id = ? AND generation = ?
               AND sandbox_id = ? AND sandbox_generation = ? AND runtime_principal_id = ?
               AND runtime_authorization_generation = ?`
          )
          .run(
            generation,
            binding.runtimeAssignmentId,
            binding.sessionId,
            binding.runtimeAssignmentGeneration,
            binding.sandboxId,
            binding.sandboxGeneration,
            binding.runtimePrincipalId,
            delivery.command.runtimeAuthorizationGeneration
          );
        const session = db
          .prepare(
            `UPDATE sessions
             SET runtime_authorization_generation = ?, runtime_authorization_state = 'pending'
             WHERE id = ? AND runtime_authorization_generation = ?`
          )
          .run(generation, binding.sessionId, delivery.command.runtimeAuthorizationGeneration);
        if (assignment.changes !== 1 || session.changes !== 1) {
          throw new Error("Could not advance the exact Runtime authorization fixture");
        }
      })();
    } finally {
      db.close();
    }
  }

  function readOne<T>(sql: string, ...parameters: Array<string | number>): T {
    const db = new Database(filename, { readonly: true });
    try {
      return db.prepare(sql).get(...parameters) as T;
    } finally {
      db.close();
    }
  }

  it("keeps lifecycle, follow, compensation, and late settlement singular across restarts", async () => {
    await requestStart();
    const lifecyclePeer = openKernel();
    const lifecycleClaims = await Promise.all([
      primary.runtimeLifecycleJournal.claim({
        workerId: "lifecycle-worker-a",
        limit: 1,
        leaseDurationMs: 100,
        nowMs: now,
      }),
      lifecyclePeer.runtimeLifecycleJournal.claim({
        workerId: "lifecycle-worker-b",
        limit: 1,
        leaseDurationMs: 100,
        nowMs: now,
      }),
    ]);
    const lifecycleWinners = lifecycleClaims.flat();
    expect(lifecycleWinners).toHaveLength(1);
    const lifecycleDelivery = lifecycleWinners[0];
    if (!lifecycleDelivery) throw new Error("Expected one lifecycle winner");
    const lifecycleOwner =
      lifecycleClaims[0].length === 1
        ? primary.runtimeLifecycleJournal
        : lifecyclePeer.runtimeLifecycleJournal;
    const lifecycleRenewal = await lifecycleOwner.renew({
      commandId: lifecycleDelivery.command.commandId,
      workerId: lifecycleDelivery.leaseOwner,
      expectedAttempt: lifecycleDelivery.attempt,
      expectedLeaseExpiresAtMs: lifecycleDelivery.leaseExpiresAtMs,
      leaseDurationMs: 100,
      nowMs: now,
    });
    if (lifecycleRenewal.kind !== "renewed") {
      throw new Error("Expected lifecycle dispatch interlock");
    }

    closeKernel(primary);
    closeKernel(lifecyclePeer);
    now = lifecycleRenewal.leaseExpiresAtMs;
    const restartedA = openKernel();
    const restartedB = openKernel();
    await restartedA.runtimeLifecycleJournal.reconcile({ nowMs: now });
    expect(
      readOne<{
        status: string;
        attempts: number;
        dispatch_interlock_acquired_at_ms: number | null;
      }>(
        `SELECT status, attempts, dispatch_interlock_acquired_at_ms
         FROM runtime_run_command_dispatch WHERE command_id = ?`,
        lifecycleDelivery.command.commandId
      )
    ).toEqual({
      status: "awaiting-receipt",
      attempts: 1,
      dispatch_interlock_acquired_at_ms: 2_000_000_000_000,
    });
    const postCrashLifecycleClaims = await Promise.all([
      restartedA.runtimeLifecycleJournal.claim({
        workerId: "lifecycle-retry-a",
        limit: 1,
        leaseDurationMs: 100,
        nowMs: now + 1,
      }),
      restartedB.runtimeLifecycleJournal.claim({
        workerId: "lifecycle-retry-b",
        limit: 1,
        leaseDurationMs: 100,
        nowMs: now + 1,
      }),
    ]);
    expect(postCrashLifecycleClaims.flat()).toHaveLength(0);

    restartedA.runtimeReceiptFollowJournal.register({
      binding: lifecycleDelivery.command.binding,
      runtimeAuthorizationGeneration: lifecycleDelivery.command.runtimeAuthorizationGeneration,
      issuerKeyId: OBSERVATION_KEY_ID,
      publicKeySpkiPem: observationPublicKeyPem,
      createdAtMs: now,
    });
    const followClaims = [
      restartedA.runtimeReceiptFollowJournal.claim({
        workerId: "follow-worker-a",
        leaseDurationMs: 1_000,
        nowMs: now,
      }),
      restartedB.runtimeReceiptFollowJournal.claim({
        workerId: "follow-worker-b",
        leaseDurationMs: 1_000,
        nowMs: now,
      }),
    ].filter((claim) => claim !== null);
    expect(followClaims).toHaveLength(1);
    const lifecycleFollowLease = followClaims[0];
    if (!lifecycleFollowLease) throw new Error("Expected one lifecycle follow winner");
    const runtimeReceipt = enforcedRuntimeReceipt(lifecycleDelivery);
    const runtimeObservation = createRuntimeReceiptObservationIssuer({
      issuerKeyId: OBSERVATION_KEY_ID,
      binding: lifecycleDelivery.command.binding,
      trustedConfigurationRoot: directory,
      privateKeyFile: observationPrivateKeyFile,
      clock: () => now,
    }).issue({
      observationId: "observation:phase6:lifecycle",
      cursor: "runtime-cursor:phase6:1",
      previous: lifecycleFollowLease.checkpoint,
      command: lifecycleDelivery.command,
      receipt: runtimeReceipt,
    });
    advanceRuntimeAuthorizationGeneration(lifecycleDelivery, 2);
    restartedA.runtimeReceiptFollowJournal.settle({
      runtimeAssignmentId: lifecycleFollowLease.binding.runtimeAssignmentId,
      runtimeAuthorizationGeneration: lifecycleFollowLease.runtimeAuthorizationGeneration,
      workerId: lifecycleFollowLease.leaseOwner,
      expectedLeaseVersion: lifecycleFollowLease.leaseVersion,
      expectedLeaseExpiresAtMs: lifecycleFollowLease.leaseExpiresAtMs,
      nowMs: now,
      observation: runtimeObservation,
      receivedAtMs: now,
    });
    expect(
      readOne<{
        status: string;
        receipts: number;
        effects: number;
        incidents: number;
      }>(
        `SELECT dispatch.status,
                (SELECT COUNT(*) FROM runtime_run_command_receipts receipt
                  WHERE receipt.command_id = command.id) AS receipts,
                (SELECT COUNT(*) FROM runtime_run_command_effects effect
                  WHERE effect.command_id = command.id) AS effects,
                (SELECT COUNT(*) FROM runtime_compensation_incidents incident
                  WHERE incident.source_command_id = command.id) AS incidents
         FROM runtime_run_commands command
         JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
         WHERE command.id = ?`,
        lifecycleDelivery.command.commandId
      )
    ).toEqual({ status: "compensating", receipts: 1, effects: 0, incidents: 1 });

    const materializer = restartedA.runtimeCompensationMaterializer;
    const compensationA = restartedA.runtimeCompensationJournal;
    const compensationB = restartedB.runtimeCompensationJournal;
    if (!materializer || !compensationA || !compensationB) {
      throw new Error("Expected configured compensation workers");
    }
    await expect(materializer.runOnce()).resolves.toEqual({ found: 1, created: 1 });
    const compensationClaims = await Promise.all([
      compensationA.claim({
        workerId: "compensation-worker-a",
        leaseDurationMs: 100,
        nowMs: now,
      }),
      compensationB.claim({
        workerId: "compensation-worker-b",
        leaseDurationMs: 100,
        nowMs: now,
      }),
    ]);
    const compensationWinners = compensationClaims.filter((claim) => claim !== null);
    expect(compensationWinners).toHaveLength(1);
    const compensationDelivery = compensationWinners[0];
    if (!compensationDelivery) throw new Error("Expected one compensation winner");
    const compensationOwner = compensationClaims[0] ? compensationA : compensationB;
    const compensationRenewal = await compensationOwner.renew({
      commandId: compensationDelivery.command.commandId,
      workerId: compensationDelivery.leaseOwner,
      expectedAttempt: compensationDelivery.attempt,
      expectedLeaseExpiresAtMs: compensationDelivery.leaseExpiresAtMs,
      leaseDurationMs: 100,
      nowMs: now,
    });
    if (compensationRenewal.kind !== "renewed") {
      throw new Error("Expected compensation dispatch interlock");
    }

    closeKernel(restartedA);
    closeKernel(restartedB);
    now = compensationRenewal.leaseExpiresAtMs;
    const settledA = openKernel();
    const settledB = openKernel();
    const restartedCompensationA = settledA.runtimeCompensationJournal;
    const restartedCompensationB = settledB.runtimeCompensationJournal;
    if (!restartedCompensationA || !restartedCompensationB) {
      throw new Error("Expected restarted compensation workers");
    }
    await restartedCompensationA.reconcile({ nowMs: now });
    expect(
      readOne<{ status: string; attempts: number }>(
        `SELECT status, attempts FROM runtime_compensation_dispatch
         WHERE compensation_command_id = ?`,
        compensationDelivery.command.commandId
      )
    ).toEqual({ status: "awaiting-receipt", attempts: 1 });
    const postCrashCompensationClaims = await Promise.all([
      restartedCompensationA.claim({
        workerId: "compensation-retry-a",
        leaseDurationMs: 100,
        nowMs: now + 1,
      }),
      restartedCompensationB.claim({
        workerId: "compensation-retry-b",
        leaseDurationMs: 100,
        nowMs: now + 1,
      }),
    ]);
    expect(postCrashCompensationClaims.filter((claim) => claim !== null)).toHaveLength(0);

    now = Math.max(
      now,
      readOne<{ available_at_ms: number }>(
        `SELECT available_at_ms FROM runtime_receipt_follow_streams
         WHERE runtime_assignment_id = ? AND runtime_authorization_generation = ?`,
        lifecycleDelivery.command.binding.runtimeAssignmentId,
        lifecycleDelivery.command.runtimeAuthorizationGeneration
      ).available_at_ms
    );
    const compensationFollowClaims = [
      settledA.runtimeReceiptFollowJournal.claim({
        workerId: "compensation-follow-worker-a",
        leaseDurationMs: 1_000,
        nowMs: now,
      }),
      settledB.runtimeReceiptFollowJournal.claim({
        workerId: "compensation-follow-worker-b",
        leaseDurationMs: 1_000,
        nowMs: now,
      }),
    ].filter((claim) => claim !== null);
    expect(compensationFollowClaims).toHaveLength(1);
    const compensationFollowLease = compensationFollowClaims[0];
    if (!compensationFollowLease) throw new Error("Expected one compensation follow winner");
    const compensationReceipt = enforcedCompensationReceipt(compensationDelivery.command);
    const compensationObservation = createRuntimeCompensationReceiptObservationIssuer({
      issuerKeyId: OBSERVATION_KEY_ID,
      binding: compensationDelivery.command.binding,
      trustedConfigurationRoot: directory,
      privateKeyFile: observationPrivateKeyFile,
      clock: () => now,
    }).issue({
      observationId: "observation:phase6:compensation",
      cursor: "runtime-cursor:phase6:2",
      previous: compensationFollowLease.checkpoint,
      command: compensationDelivery.command,
      receipt: compensationReceipt,
    });
    const settlement = {
      runtimeAssignmentId: compensationFollowLease.binding.runtimeAssignmentId,
      runtimeAuthorizationGeneration: compensationFollowLease.runtimeAuthorizationGeneration,
      workerId: compensationFollowLease.leaseOwner,
      expectedLeaseVersion: compensationFollowLease.leaseVersion,
      expectedLeaseExpiresAtMs: compensationFollowLease.leaseExpiresAtMs,
      nowMs: now,
      observation: compensationObservation,
      receivedAtMs: now,
    } as const;
    const competingSettlements = await Promise.allSettled([
      Promise.resolve().then(() => settledA.runtimeReceiptFollowJournal.settle(settlement)),
      Promise.resolve().then(() => settledB.runtimeReceiptFollowJournal.settle(settlement)),
    ]);
    expect(competingSettlements.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(competingSettlements.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(
      readOne<{
        status: string;
        receipts: number;
        effects: number;
        events: number;
        cursor: string | null;
        receipt_sequence: number;
      }>(
        `SELECT dispatch.status,
                (SELECT COUNT(*) FROM runtime_compensation_receipts receipt
                  WHERE receipt.compensation_command_id = command.id) AS receipts,
                (SELECT COUNT(*) FROM runtime_compensation_effects effect
                  WHERE effect.compensation_command_id = command.id) AS effects,
                (SELECT COUNT(*) FROM runtime_compensation_follow_events event
                  WHERE event.compensation_command_id = command.id) AS events,
                stream.cursor, stream.receipt_sequence
         FROM runtime_compensation_commands command
         JOIN runtime_compensation_dispatch dispatch
           ON dispatch.compensation_command_id = command.id
         JOIN runtime_receipt_follow_streams stream
           ON stream.runtime_assignment_id = command.runtime_assignment_id
          AND stream.runtime_authorization_generation =
            command.observed_runtime_authorization_generation
         WHERE command.id = ?`,
        compensationDelivery.command.commandId
      )
    ).toEqual({
      status: "enforced",
      receipts: 1,
      effects: 1,
      events: 1,
      cursor: "runtime-cursor:phase6:2",
      receipt_sequence: 2,
    });
  });

  it("samples the Runtime outbox claim clock under the write lock without rejecting a later peer append", async () => {
    const peerDb = (sessions as unknown as { db: Database.Database }).db;
    peerDb.pragma("busy_timeout = 0");
    let probeClaimClock = false;
    let clockSamples = 0;
    let peerWriteLockAcquisitions = 0;
    const peerWriteLockErrors: string[] = [];
    const claimant = createTeamSessionKernel({
      ...kernelOptions(),
      clock: () => {
        if (!probeClaimClock) return now;
        clockSamples += 1;
        let peerTransactionOpen = false;
        try {
          peerDb.exec("BEGIN IMMEDIATE");
          peerTransactionOpen = true;
          peerWriteLockAcquisitions += 1;
        } catch (error) {
          peerWriteLockErrors.push((error as { code?: string }).code ?? "UNKNOWN");
        } finally {
          if (peerTransactionOpen) peerDb.exec("ROLLBACK");
        }
        return now;
      },
    });
    openSessions.add(claimant.teamSessions);
    probeClaimClock = true;

    await expect(
      claimant.teamSessions.claimRuntimeOutbox({
        workerId: "clock-claimant",
        limit: 1,
        leaseDurationMs: 1_000,
      })
    ).resolves.toEqual([]);
    expect({ clockSamples, peerWriteLockAcquisitions, peerWriteLockErrors }).toEqual({
      clockSamples: 1,
      peerWriteLockAcquisitions: 0,
      peerWriteLockErrors: ["SQLITE_BUSY"],
    });

    now += 1;
    await dispatch({
      type: "session.start",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sessionId: PEER_SESSION_ID,
      name: "Runtime outbox clock peer",
      tmuxName: "phase6-clock-peer",
      steeringPolicy: "shared",
    });
    expect(
      peerDb
        .prepare(
          `SELECT status, created_at_ms
           FROM runtime_outbox
           WHERE session_id = ? AND kind = 'runtime.session.ensure'`
        )
        .get(PEER_SESSION_ID)
    ).toEqual({ status: "pending", created_at_ms: now });

    await expect(
      claimant.teamSessions.claimRuntimeOutbox({
        workerId: "clock-claimant",
        limit: 1,
        leaseDurationMs: 1_000,
      })
    ).resolves.toEqual([
      expect.objectContaining({
        sessionId: PEER_SESSION_ID,
        kind: "runtime.session.ensure",
        attempts: 1,
        leaseOwner: "clock-claimant",
        leaseExpiresAtMs: now + 1_000,
        dispatchMode: "apply",
      }),
    ]);
    expect({ clockSamples, peerWriteLockAcquisitions, peerWriteLockErrors }).toEqual({
      clockSamples: 2,
      peerWriteLockAcquisitions: 0,
      peerWriteLockErrors: ["SQLITE_BUSY", "SQLITE_BUSY"],
    });
  });

  it("rolls a zero-timeout SQLITE_BUSY claim back without a partial lease", async () => {
    await requestStart();
    const contenderDatabase = openTeamSessionDatabase({ filename });
    contenderDatabase.db.pragma("busy_timeout = 0");
    const contender = createSqliteRuntimeLifecycleJournal({
      db: contenderDatabase.db,
      idGenerator: () => "phase6-busy-journal-id",
      verifyEnforcementProof: () => true,
    });
    const blocker = new Database(filename);
    blocker.pragma("busy_timeout = 0");
    try {
      blocker.exec("BEGIN IMMEDIATE");
      await expect(
        contender.claim({
          workerId: "busy-contender",
          limit: 1,
          leaseDurationMs: 1_000,
          nowMs: now,
        })
      ).rejects.toMatchObject({ code: "SQLITE_BUSY" });
      expect(
        readOne<{
          status: string;
          attempts: number;
          lease_owner: string | null;
          lease_expires_at_ms: number | null;
        }>(
          `SELECT status, attempts, lease_owner, lease_expires_at_ms
           FROM runtime_run_command_dispatch`
        )
      ).toEqual({
        status: "pending",
        attempts: 0,
        lease_owner: null,
        lease_expires_at_ms: null,
      });
      blocker.exec("ROLLBACK");
      const deliveries = await contender.claim({
        workerId: "busy-contender",
        limit: 1,
        leaseDurationMs: 1_000,
        nowMs: now,
      });
      expect(deliveries).toHaveLength(1);
      expect(
        readOne<{ status: string; attempts: number; lease_owner: string | null }>(
          `SELECT status, attempts, lease_owner FROM runtime_run_command_dispatch`
        )
      ).toEqual({ status: "processing", attempts: 1, lease_owner: "busy-contender" });
    } finally {
      if (blocker.inTransaction) blocker.exec("ROLLBACK");
      blocker.close();
      contenderDatabase.close();
    }
  });
});
