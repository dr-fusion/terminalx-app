import { createHash, generateKeyPairSync, sign as signEd25519 } from "node:crypto";
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
  type RunPolicyDraft,
  type SessionCommand,
  type TeamSessionKernel,
  type TeamSessions,
} from "@/lib/team-sessions";
import { digestRunPolicyDraft } from "@/lib/team-sessions/run-policy";
import { projectPublicSessionEvent } from "@/lib/team-sessions/public-event";
import {
  RUNTIME_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN,
  RUNTIME_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN,
  RUNTIME_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN,
  canonicalRuntimeJson,
  commitRuntimeEffectRef,
  createRuntimeCommandAuthorityIssuer,
  createRuntimeCompensationReceiptObservationIssuer,
  createRuntimeReceiptObservationIssuer,
  digestAggregateEnforcementProof,
  digestRuntimeCommandClaims,
  digestRuntimeCompensationEnforcementSubject,
  digestRuntimeEnforcementSubject,
  digestRuntimeCompensationIncident,
  type RuntimeCompensationCommand,
  type RuntimeCompensationEnforcementProofVerificationInput,
  type RuntimeCompensationReceipt,
  type RuntimeEnforcementProofVerificationInput,
  type RuntimeLifecycleDelivery,
  type RuntimeLifecycleReceiptObservation,
  type RuntimeReceipt,
} from "@/lib/runtime";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ALICE: ActorContext = { kind: "human", userId: "alice", displayName: "Alice" };
const RUNTIME: ActorContext = {
  kind: "system",
  userId: "runtime-follow-worker",
  displayName: "Runtime Follow Worker",
};
const UNCONFIGURED = { kind: "unconfigured" } as const;
const EFFECT_ENFORCER_SET_DIGEST = "b".repeat(64);
const CONTAINMENT_ENFORCER_SET_DIGEST = "f".repeat(64);
const PROVIDER_EFFECT_REF = "provider-private-late-effect-reference";
const PROVIDER_CONTAINMENT_EFFECT_REF = "provider-private-containment-reference";
const OBSERVATION_KEY_ID = "runtime-observer:integration-key";
const PLATFORM_SECURITY_SIGNATURE = Buffer.alloc(64, 7).toString("base64url");
type EnforcedRuntimeReceipt = Extract<RuntimeReceipt, { readonly outcome: "enforced" }>;
type ProofVerifierMode = "accept" | "reject" | "async" | "async-reject";

describe("signed Runtime late-receipt composition", () => {
  let directory: string;
  let filename: string;
  let privateKeyFile: string;
  let publicKeyPem: string;
  let kernel: TeamSessionKernel;
  let sessions: TeamSessions;
  let now: number;
  let commandSequence: number;
  let generated: number;
  let verifiedProofs: number;
  let proofVerifierMode: ProofVerifierMode;
  let compensationProofVerifierMode: "accept" | "reject";
  let verifiedCompensationProofs: number;

  beforeEach(async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-follow-integration-"));
    filename = path.join(directory, "team-sessions.sqlite");
    const keys = generateKeyPairSync("ed25519");
    privateKeyFile = path.join(directory, "runtime-observation-key.pem");
    fs.writeFileSync(privateKeyFile, keys.privateKey.export({ format: "pem", type: "pkcs8" }), {
      mode: 0o600,
    });
    fs.chmodSync(privateKeyFile, 0o600);
    publicKeyPem = keys.publicKey.export({ format: "pem", type: "spki" }).toString();
    const authorityKeys = generateKeyPairSync("ed25519");
    const authorityPrivateKeyFile = path.join(directory, "runtime-authority-key.pem");
    fs.writeFileSync(
      authorityPrivateKeyFile,
      authorityKeys.privateKey.export({ format: "pem", type: "pkcs8" }),
      { mode: 0o600 }
    );
    fs.chmodSync(authorityPrivateKeyFile, 0o600);
    now = 2_000_000_000_000;
    commandSequence = 0;
    generated = 0;
    verifiedProofs = 0;
    proofVerifierMode = "accept";
    compensationProofVerifierMode = "accept";
    verifiedCompensationProofs = 0;

    kernel = createTeamSessionKernel({
      filename,
      clock: () => now,
      idGenerator: () => {
        generated += 1;
        return `00000000-0000-4000-8000-${String(generated).padStart(12, "0")}`;
      },
      runtimeCommandAuthorityIssuer: createRuntimeCommandAuthorityIssuer({
        issuer: "team-session",
        issuerKeyId: "team-session:follow-integration-key",
        trustedConfigurationRoot: directory,
        privateKeyFile: authorityPrivateKeyFile,
        clock: () => now,
      }),
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
      runtimeEnforcementProofVerifier: verifyExactTestProof,
      runtimeCompensationAuthorityIssuer: {
        issue: (claims) => ({
          issuer: "platform-security",
          issuerKeyId: "platform-security:follow-integration-key",
          audience: "runtime",
          capability: "safety.quarantine",
          claimsDigest: digestRuntimeCommandClaims(claims),
          issuedAtMs: claims.issuedAtMs,
          expiresAtMs: claims.deadlineAtMs,
          signature: PLATFORM_SECURITY_SIGNATURE,
        }),
      },
      runtimeCompensationAuthorityVerifier: ({ command }) =>
        command.authority.signature === PLATFORM_SECURITY_SIGNATURE,
      runtimeCompensationPolicySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:follow-integration:v1",
          requiredContainmentEnforcerSetDigest: CONTAINMENT_ENFORCER_SET_DIGEST,
        }),
      },
      runtimeCompensationEnforcementProofVerifier: verifyExactCompensationProof,
    });
    sessions = kernel.teamSessions;

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
      name: "Signed late receipt",
      tmuxName: "signed-late-receipt",
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
    sessions.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function verifyExactTestProof(input: RuntimeEnforcementProofVerificationInput): boolean {
    const acknowledgement = input.proof.acknowledgements[0];
    const valid =
      input.subjectDigest === input.proof.enforcementSubjectDigest &&
      input.subject.requiredEffectEnforcerSetDigest === EFFECT_ENFORCER_SET_DIGEST &&
      input.subject.effectRefCommitment === commitRuntimeEffectRef(PROVIDER_EFFECT_REF) &&
      input.proof.requiredEffectEnforcerSetDigest === EFFECT_ENFORCER_SET_DIGEST &&
      input.proof.acknowledgements.length === 1 &&
      acknowledgement?.enforcerRef === "test-runtime-enforcer" &&
      acknowledgement.enforcerKind === "runtime" &&
      acknowledgement.acknowledgementDigest === "e".repeat(64);
    if (!valid || proofVerifierMode === "reject") return false;
    verifiedProofs += 1;
    // Deliberately violate the synchronous TypeScript contract to exercise the
    // journal's runtime fail-closed defense against misconfigured JavaScript.
    if (proofVerifierMode === "async") return Promise.resolve(true) as unknown as boolean;
    if (proofVerifierMode === "async-reject") {
      return Promise.reject(
        new Error("provider-sensitive async verifier failure")
      ) as unknown as boolean;
    }
    return true;
  }

  function verifyExactCompensationProof(
    input: RuntimeCompensationEnforcementProofVerificationInput
  ): boolean {
    const acknowledgement = input.proof.acknowledgements[0];
    const valid =
      input.subjectDigest === input.proof.enforcementSubjectDigest &&
      input.subject.requiredContainmentEnforcerSetDigest === CONTAINMENT_ENFORCER_SET_DIGEST &&
      input.subject.effectRefCommitment ===
        commitRuntimeEffectRef(PROVIDER_CONTAINMENT_EFFECT_REF) &&
      input.proof.requiredEffectEnforcerSetDigest === CONTAINMENT_ENFORCER_SET_DIGEST &&
      input.proof.acknowledgements.length === 1 &&
      acknowledgement?.enforcerRef === "test-containment-enforcer" &&
      acknowledgement.enforcerKind === "runtime" &&
      acknowledgement.acknowledgementDigest === "a".repeat(64);
    if (!valid || compensationProofVerifierMode === "reject") return false;
    verifiedCompensationProofs += 1;
    return true;
  }

  function command(input: Record<string, unknown>, actor = ALICE): SessionCommand {
    commandSequence += 1;
    return {
      ...input,
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      idempotency: { scope: "vitest:follow-integration", key: `command-${commandSequence}` },
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
          goalId: "goal:late-receipt",
          position: 1,
          title: "Settle a signed late receipt",
          acceptanceCriteria: ["Lifecycle and cursor advance atomically"],
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

  async function claimStart(): Promise<RuntimeLifecycleDelivery> {
    const [delivery] = await kernel.runtimeLifecycleJournal.claim({
      workerId: RUNTIME.userId,
      limit: 1,
      leaseDurationMs: 30_000,
      nowMs: now,
    });
    if (!delivery) throw new Error("Expected run.start delivery");
    return delivery;
  }

  async function acquireDispatchInterlock(
    delivery: RuntimeLifecycleDelivery
  ): Promise<RuntimeLifecycleDelivery> {
    const renewal = await kernel.runtimeLifecycleJournal.renew({
      commandId: delivery.command.commandId,
      workerId: RUNTIME.userId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      leaseDurationMs: 30_000,
      nowMs: now,
    });
    if (renewal.kind !== "renewed") {
      throw new Error("Expected the Runtime lifecycle dispatch interlock");
    }
    return { ...delivery, leaseExpiresAtMs: renewal.leaseExpiresAtMs };
  }

  function enforcedReceipt(delivery: RuntimeLifecycleDelivery): EnforcedRuntimeReceipt {
    const requiredEffectEnforcerSetDigest = delivery.command.requiredEffectEnforcerSetDigest;
    if (!requiredEffectEnforcerSetDigest) throw new Error("Expected trusted enforcer-set digest");
    const enforcementSubjectDigest = digestRuntimeEnforcementSubject({
      version: 1,
      commandId: delivery.command.commandId,
      commandClaimsDigest: delivery.command.authority.claimsDigest,
      binding: delivery.command.binding,
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest,
      effectRefCommitment: commitRuntimeEffectRef(PROVIDER_EFFECT_REF),
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
    return {
      commandId: delivery.command.commandId,
      binding: delivery.command.binding,
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
      outcome: "enforced",
      effectRef: PROVIDER_EFFECT_REF,
      enforcedFence: delivery.command.toRunStateVersion,
      aggregateEnforcementProof: {
        ...proofPayload,
        aggregateProofDigest: digestAggregateEnforcementProof(proofPayload),
      },
    };
  }

  function execute(sql: string): void {
    const db = new Database(filename);
    try {
      db.pragma("foreign_keys = ON");
      db.pragma("busy_timeout = 5000");
      db.exec(sql);
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

  function readAll<T>(sql: string, ...parameters: Array<string | number>): T[] {
    const db = new Database(filename, { readonly: true });
    try {
      return db.prepare(sql).all(...parameters) as T[];
    } finally {
      db.close();
    }
  }

  async function prepareLateSettlement() {
    await requestStart();
    const delivery = await acquireDispatchInterlock(await claimStart());
    await kernel.runtimeLifecycleJournal.complete({
      commandId: delivery.command.commandId,
      workerId: RUNTIME.userId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      observedAtMs: now,
      outcome: {
        kind: "receipt",
        receipt: {
          commandId: delivery.command.commandId,
          binding: delivery.command.binding,
          runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
          outcome: "accepted",
          effectRef: PROVIDER_EFFECT_REF,
        },
      },
    });

    kernel.runtimeReceiptFollowJournal.register({
      binding: delivery.command.binding,
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
      issuerKeyId: OBSERVATION_KEY_ID,
      publicKeySpkiPem: publicKeyPem,
      createdAtMs: now,
    });
    const followLease = kernel.runtimeReceiptFollowJournal.claim({
      workerId: RUNTIME.userId,
      leaseDurationMs: 30_000,
      nowMs: now,
    });
    if (!followLease) throw new Error("Expected signed receipt follow lease");
    const receipt = enforcedReceipt(delivery);
    const observation = createRuntimeReceiptObservationIssuer({
      issuerKeyId: OBSERVATION_KEY_ID,
      binding: delivery.command.binding,
      trustedConfigurationRoot: directory,
      privateKeyFile,
      clock: () => now,
    }).issue({
      observationId: "observation:late-enforced:1",
      cursor: "runtime-cursor:1",
      previous: null,
      command: delivery.command,
      receipt,
    });
    const settlement = {
      runtimeAssignmentId: followLease.binding.runtimeAssignmentId,
      runtimeAuthorizationGeneration: followLease.runtimeAuthorizationGeneration,
      workerId: followLease.leaseOwner,
      expectedLeaseVersion: followLease.leaseVersion,
      expectedLeaseExpiresAtMs: followLease.leaseExpiresAtMs,
      nowMs: now,
      observation,
      receivedAtMs: now,
    } as const;
    return { delivery, receipt, observation, settlement } as const;
  }

  function compensationReceiptBase(command: RuntimeCompensationCommand) {
    return {
      receiptKind: "runtime.compensation" as const,
      compensationId: command.compensationId,
      commandId: command.commandId,
      binding: command.binding,
      observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
    };
  }

  function enforcedCompensationReceipt(
    command: RuntimeCompensationCommand
  ): RuntimeCompensationReceipt {
    const containment = {
      terminalWritesRevoked: true as const,
      processExecutionStopped: true as const,
      runtimeQuarantined: true as const,
    };
    const subject = {
      version: 1 as const,
      purpose: "stale-lifecycle-effect-containment" as const,
      compensationId: command.compensationId,
      commandId: command.commandId,
      commandClaimsDigest: command.authority.claimsDigest,
      binding: command.binding,
      observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
      safetyFence: command.safetyFence,
      enforcedSafetyFence: command.safetyFence,
      sourceReceiptDigest: command.source.lifecycleReceiptDigest,
      sourceEnforcementSubjectDigest: command.source.lifecycleEnforcementSubjectDigest,
      sourceAggregateProofDigest: command.source.lifecycleAggregateProofDigest,
      requiredContainmentEnforcerSetDigest: command.requiredContainmentEnforcerSetDigest,
      effectRefCommitment: commitRuntimeEffectRef(PROVIDER_CONTAINMENT_EFFECT_REF),
      containment,
    };
    const proofPayload = {
      generation: command.observedRuntimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest: command.requiredContainmentEnforcerSetDigest,
      enforcementSubjectDigest: digestRuntimeCompensationEnforcementSubject(subject),
      acknowledgements: [
        {
          enforcerRef: "test-containment-enforcer",
          enforcerKind: "runtime" as const,
          acknowledgementDigest: "a".repeat(64),
        },
      ],
    };
    return {
      ...compensationReceiptBase(command),
      outcome: "enforced",
      effectRef: PROVIDER_CONTAINMENT_EFFECT_REF,
      enforcedSafetyFence: command.safetyFence,
      containment,
      aggregateEnforcementProof: {
        ...proofPayload,
        aggregateProofDigest: digestAggregateEnforcementProof(proofPayload),
      },
    };
  }

  function compensationReceipt(
    command: RuntimeCompensationCommand,
    outcome: "accepted" | "enforced" | "rejected"
  ): RuntimeCompensationReceipt {
    if (outcome === "enforced") return enforcedCompensationReceipt(command);
    if (outcome === "accepted") {
      return {
        ...compensationReceiptBase(command),
        outcome,
        effectRef: PROVIDER_CONTAINMENT_EFFECT_REF,
      };
    }
    return {
      ...compensationReceiptBase(command),
      outcome,
      code: "not_ready",
      safeDetail: "Runtime could not finish containment",
    };
  }

  async function prepareLateCompensationSettlement(
    outcome: "accepted" | "enforced" | "rejected" = "enforced"
  ) {
    const lifecycle = await prepareLateSettlement();
    advanceRuntimeAuthorizationGeneration(lifecycle.delivery, 2);
    const lifecycleResult = kernel.runtimeReceiptFollowJournal.settle(lifecycle.settlement);

    now += 1_000;
    const materializer = kernel.runtimeCompensationMaterializer;
    const journal = kernel.runtimeCompensationJournal;
    if (!materializer || !journal) throw new Error("Expected configured compensation workers");
    await expect(materializer.runOnce()).resolves.toEqual({ found: 1, created: 1 });
    const delivery = await journal.claim({
      workerId: RUNTIME.userId,
      leaseDurationMs: 30_000,
      nowMs: now,
    });
    if (!delivery) throw new Error("Expected Runtime compensation delivery");
    const renewal = await journal.renew({
      commandId: delivery.command.commandId,
      workerId: delivery.leaseOwner,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      leaseDurationMs: 30_000,
      nowMs: now,
    });
    if (renewal.kind !== "renewed") throw new Error("Expected compensation dispatch interlock");
    await journal.complete({
      commandId: delivery.command.commandId,
      workerId: delivery.leaseOwner,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: renewal.leaseExpiresAtMs,
      observedAtMs: now,
      outcome: {
        kind: "failure",
        code: "runtime_command_failed",
        dispatchCertainty: "dispatch-uncertain",
      },
    });

    const followLease = kernel.runtimeReceiptFollowJournal.claim({
      workerId: RUNTIME.userId,
      leaseDurationMs: 30_000,
      nowMs: now,
    });
    if (!followLease) throw new Error("Expected historical compensation follow lease");
    const renewedFollowLease = kernel.runtimeReceiptFollowJournal.renew({
      runtimeAssignmentId: followLease.binding.runtimeAssignmentId,
      runtimeAuthorizationGeneration: followLease.runtimeAuthorizationGeneration,
      workerId: followLease.leaseOwner,
      expectedLeaseVersion: followLease.leaseVersion,
      expectedLeaseExpiresAtMs: followLease.leaseExpiresAtMs,
      leaseDurationMs: 60_000,
      nowMs: now,
    });
    const receipt = compensationReceipt(delivery.command, outcome);
    const observation = createRuntimeCompensationReceiptObservationIssuer({
      issuerKeyId: OBSERVATION_KEY_ID,
      binding: delivery.command.binding,
      trustedConfigurationRoot: directory,
      privateKeyFile,
      clock: () => now,
    }).issue({
      observationId: `observation:late-compensation:${outcome}`,
      cursor: "runtime-cursor:2",
      previous: followLease.checkpoint,
      command: delivery.command,
      receipt,
    });
    const settlement = {
      runtimeAssignmentId: followLease.binding.runtimeAssignmentId,
      runtimeAuthorizationGeneration: followLease.runtimeAuthorizationGeneration,
      workerId: followLease.leaseOwner,
      expectedLeaseVersion: followLease.leaseVersion,
      expectedLeaseExpiresAtMs: renewedFollowLease.leaseExpiresAtMs,
      nowMs: now,
      observation,
      receivedAtMs: now,
    } as const;
    return {
      lifecycle,
      lifecycleResult,
      delivery,
      receipt,
      observation,
      settlement,
    } as const;
  }

  function signedObservationWithReceipt(
    template: RuntimeLifecycleReceiptObservation,
    receipt: RuntimeReceipt
  ): RuntimeLifecycleReceiptObservation {
    const receiptDigest = domainDigest(RUNTIME_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN, receipt);
    const claims = {
      version: template.version,
      kind: template.kind,
      observationId: template.observationId,
      cursor: template.cursor,
      previous: template.previous,
      observedAtMs: template.observedAtMs,
      command: template.command,
      receipt,
      receiptDigest,
    } as const;
    const claimsDigest = domainDigest(RUNTIME_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN, claims);
    const statement = {
      version: 1,
      issuer: template.authority.issuer,
      issuerKeyId: template.authority.issuerKeyId,
      audience: template.authority.audience,
      capability: template.authority.capability,
      claimsDigest,
      issuedAtMs: template.authority.issuedAtMs,
      expiresAtMs: template.authority.expiresAtMs,
    } as const;
    const signature = signEd25519(
      null,
      Buffer.concat([
        Buffer.from(RUNTIME_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN, "utf8"),
        Buffer.from(canonicalRuntimeJson(statement), "utf8"),
      ]),
      fs.readFileSync(privateKeyFile)
    ).toString("base64url");
    return {
      ...claims,
      authority: {
        issuer: statement.issuer,
        issuerKeyId: statement.issuerKeyId,
        audience: statement.audience,
        capability: statement.capability,
        claimsDigest,
        issuedAtMs: statement.issuedAtMs,
        expiresAtMs: statement.expiresAtMs,
        signature,
      },
    };
  }

  function domainDigest(domain: string, value: unknown): string {
    return createHash("sha256")
      .update(domain, "utf8")
      .update(canonicalRuntimeJson(value), "utf8")
      .digest("hex");
  }

  function sha256(value: string): string {
    return createHash("sha256").update(value, "utf8").digest("hex");
  }

  function seedMutableGrant(delivery: RuntimeLifecycleDelivery): string {
    const grantId = "grant:proof-containment";
    const manifestId = "manifest:proof-containment";
    const approvalId = "approval:proof-containment";
    const manifestDigest = domainDigest("test:manifest\0", { manifestId });
    const binding = delivery.command.binding;
    const db = new Database(filename);
    try {
      db.pragma("foreign_keys = ON");
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
          delivery.command.agentRunId,
          manifestDigest,
          domainDigest("test:schema\0", { schema: 1 }),
          domainDigest("test:effect\0", { effect: 1 }),
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
              status, expires_at_ms, created_at_ms, resolved_at_ms, resolved_by_actor_ref)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?,
                   'scoped-external', 'github', 'branch.push', 'repo:session-branch',
                   'manifest', ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        const common = [
          approvalId,
          SESSION_ID,
          delivery.command.agentRunId,
          binding.runtimeAssignmentId,
          binding.runtimeAssignmentGeneration,
          binding.sandboxId,
          binding.sandboxGeneration,
          binding.runtimePrincipalId,
          delivery.command.runtimeAuthorizationGeneration,
          manifestId,
          manifestDigest,
          manifestDigest,
        ] as const;
        insertApproval.run(
          common[0],
          1,
          null,
          domainDigest("test:approval\0", { status: "open" }),
          ...common.slice(1),
          "open",
          now + 60_000,
          now,
          null,
          null
        );
        insertApproval.run(
          common[0],
          2,
          1,
          domainDigest("test:approval\0", { status: "approved" }),
          ...common.slice(1),
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
              eligible_run_use, issuer_actor_ref, issuer_approval_authority_revision,
              expires_at_ms, signature, created_at_ms)
           VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 2,
                   'approved', 'manifest', 'scoped-external', 'github', 'branch.push',
                   'repo:session-branch', '{}', 'ledger:proof-containment', 'once', ?, ?,
                   'effect:session-branch', NULL, NULL, NULL,
                   ?, 'session-manager:1', ?, 'test-signature', ?)`
        ).run(
          grantId,
          SESSION_ID,
          delivery.command.agentRunId,
          binding.runtimeAssignmentId,
          binding.runtimeAssignmentGeneration,
          binding.sandboxId,
          binding.sandboxGeneration,
          binding.runtimePrincipalId,
          delivery.command.runtimeAuthorizationGeneration,
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
           VALUES (?, 1, NULL, 'issued', 'issued', ?, ?),
                  (?, 2, 1, 'active', 'enforcement', ?, ?)`
        ).run(grantId, ALICE.userId, now, grantId, ALICE.userId, now);
      })();
    } finally {
      db.close();
    }
    return grantId;
  }

  function latestGrantState(grantId: string) {
    return readOne<{ version: number; status: string; reason: string }>(
      `SELECT version, status, reason FROM action_grant_states
       WHERE grant_id = ? ORDER BY version DESC LIMIT 1`,
      grantId
    );
  }

  function containmentState(commandId: string) {
    return readOne<{
      lifecycle: string;
      state_version: number;
      run_state_revision: number;
      dispatch_status: string;
      dispatch_error: string | null;
      dispatch_terminal_at_ms: number | null;
      dispatch_lease_owner: string | null;
      dispatch_lease_expires_at_ms: number | null;
      receipts: number;
      enforced_receipts: number;
      effects: number;
      follow_events: number;
      follow_status: string;
      follow_error: string;
      cursor: string | null;
      last_observation_digest: string | null;
      receipt_sequence: number;
      assignment_status: string;
      authorization_state: string;
      mutable_grants: number;
      containment_events: number;
    }>(
      `SELECT run.lifecycle, run.state_version, session.run_state_revision,
              dispatch.status AS dispatch_status,
              dispatch.last_safe_error_code AS dispatch_error,
              dispatch.terminal_at_ms AS dispatch_terminal_at_ms,
              dispatch.lease_owner AS dispatch_lease_owner,
              dispatch.lease_expires_at_ms AS dispatch_lease_expires_at_ms,
              (SELECT COUNT(*) FROM runtime_run_command_receipts
                WHERE command_id = command.id) AS receipts,
              (SELECT COUNT(*) FROM runtime_run_command_receipts
                WHERE command_id = command.id AND outcome = 'enforced') AS enforced_receipts,
              (SELECT COUNT(*) FROM runtime_run_command_effects
                WHERE command_id = command.id) AS effects,
              (SELECT COUNT(*) FROM runtime_receipt_follow_events) AS follow_events,
              stream.status AS follow_status, stream.last_safe_error_code AS follow_error,
              stream.cursor, stream.last_observation_digest, stream.receipt_sequence,
              assignment.status AS assignment_status,
              session.runtime_authorization_state AS authorization_state,
              (SELECT COUNT(*)
                 FROM action_grants grant_record
                 JOIN action_grant_states grant_state ON grant_state.grant_id = grant_record.id
                WHERE grant_record.agent_run_id = command.agent_run_id
                  AND grant_state.version = (
                    SELECT MAX(candidate.version) FROM action_grant_states candidate
                    WHERE candidate.grant_id = grant_record.id
                  )
                  AND grant_state.status IN ('issued', 'enforcement-pending', 'active'))
                AS mutable_grants,
              (SELECT COUNT(*) FROM session_events event
                WHERE event.session_id = command.session_id
                  AND event.type = 'session.runtime-authorization.quarantined')
                AS containment_events
       FROM runtime_run_commands command
       JOIN agent_runs run ON run.id = command.agent_run_id
       JOIN sessions session ON session.id = command.session_id
       JOIN runtime_assignments assignment ON assignment.id = command.runtime_assignment_id
       JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
       JOIN runtime_receipt_follow_streams stream
         ON stream.runtime_assignment_id = command.runtime_assignment_id
        AND stream.runtime_authorization_generation = command.runtime_authorization_generation
       WHERE command.id = ?`,
      commandId
    );
  }

  function compensationFollowState(commandId: string) {
    return readOne<{
      compensation_status: string;
      compensation_error: string | null;
      source_status: string;
      compensation_receipts: number;
      compensation_effects: number;
      compensation_follow_events: number;
      lifecycle_follow_events: number;
      follow_status: string;
      follow_error: string | null;
      cursor: string | null;
      receipt_sequence: number;
      assignment_status: string;
      assignment_authorization_generation: number;
      session_authorization_state: string;
      session_authorization_generation: number;
      authorization_quarantine_events: number;
    }>(
      `SELECT compensation_dispatch.status AS compensation_status,
              compensation_dispatch.last_safe_error_code AS compensation_error,
              source_dispatch.status AS source_status,
              (SELECT COUNT(*) FROM runtime_compensation_receipts receipt
                WHERE receipt.compensation_command_id = command.id)
                AS compensation_receipts,
              (SELECT COUNT(*) FROM runtime_compensation_effects effect
                WHERE effect.compensation_command_id = command.id)
                AS compensation_effects,
              (SELECT COUNT(*) FROM runtime_compensation_follow_events event
                WHERE event.compensation_command_id = command.id)
                AS compensation_follow_events,
              (SELECT COUNT(*) FROM runtime_receipt_follow_events event
                WHERE event.runtime_assignment_id = command.runtime_assignment_id
                  AND event.runtime_authorization_generation =
                    command.observed_runtime_authorization_generation)
                AS lifecycle_follow_events,
              stream.status AS follow_status,
              stream.last_safe_error_code AS follow_error,
              stream.cursor, stream.receipt_sequence,
              assignment.status AS assignment_status,
              assignment.runtime_authorization_generation
                AS assignment_authorization_generation,
              session.runtime_authorization_state AS session_authorization_state,
              session.runtime_authorization_generation AS session_authorization_generation,
              (SELECT COUNT(*) FROM session_events event
                WHERE event.session_id = command.session_id
                  AND event.type = 'session.runtime-authorization.quarantined')
                AS authorization_quarantine_events
       FROM runtime_compensation_commands command
       JOIN runtime_compensation_dispatch compensation_dispatch
         ON compensation_dispatch.compensation_command_id = command.id
       JOIN runtime_run_command_dispatch source_dispatch
         ON source_dispatch.command_id = command.source_command_id
       JOIN runtime_receipt_follow_streams stream
         ON stream.runtime_assignment_id = command.runtime_assignment_id
        AND stream.runtime_authorization_generation =
          command.observed_runtime_authorization_generation
       JOIN runtime_assignments assignment ON assignment.id = command.runtime_assignment_id
       JOIN sessions session ON session.id = command.session_id
       WHERE command.id = ?`,
      commandId
    );
  }

  function expectContained(commandId: string, expectedRunStateRevision: number): void {
    expect(containmentState(commandId)).toEqual({
      lifecycle: "starting",
      state_version: 1,
      run_state_revision: expectedRunStateRevision,
      dispatch_status: "awaiting-receipt",
      dispatch_error: "enforcement_proof_verification_failed",
      dispatch_terminal_at_ms: null,
      dispatch_lease_owner: null,
      dispatch_lease_expires_at_ms: null,
      receipts: 1,
      enforced_receipts: 0,
      effects: 0,
      follow_events: 0,
      follow_status: "quarantined",
      follow_error: "enforcement_proof_verification_failed",
      cursor: null,
      last_observation_digest: null,
      receipt_sequence: 0,
      assignment_status: "quarantined",
      authorization_state: "quarantined",
      mutable_grants: 0,
      containment_events: 1,
    });
    expect(
      kernel.runtimeReceiptFollowJournal.claim({
        workerId: "retry-worker",
        leaseDurationMs: 30_000,
        nowMs: now,
      })
    ).toBeNull();
  }

  function runStateRevision(): number {
    return readOne<{ run_state_revision: number }>(
      `SELECT run_state_revision FROM sessions WHERE id = ?`,
      SESSION_ID
    ).run_state_revision;
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

  function authoritativeSafetyHighWater(delivery: RuntimeLifecycleDelivery) {
    const binding = delivery.command.binding;
    return readOne<{
      allocated_fence: number;
      control_epoch: number;
      steering_revision: number;
      runtime_authorization_generation: number;
      maximum_run_state_version: number;
      maximum_issued_lifecycle_fence: number;
      maximum_enforced_lifecycle_fence: number;
      maximum_incident_fence: number;
    }>(
      `SELECT safety.allocated_fence, session.control_epoch, session.steering_revision,
              session.runtime_authorization_generation,
              COALESCE((
                SELECT MAX(run.state_version) FROM agent_runs run
                WHERE run.session_id = safety.session_id
                  AND run.runtime_assignment_id = safety.runtime_assignment_id
              ), 1) AS maximum_run_state_version,
              COALESCE((
                SELECT MAX(candidate.target_run_state_version)
                FROM runtime_run_commands candidate
                WHERE candidate.session_id = safety.session_id
                  AND candidate.runtime_assignment_id = safety.runtime_assignment_id
                  AND candidate.runtime_assignment_generation =
                    safety.runtime_assignment_generation
                  AND candidate.sandbox_id = safety.sandbox_id
                  AND candidate.sandbox_generation = safety.sandbox_generation
                  AND candidate.runtime_principal_id = safety.runtime_principal_id
              ), 1) AS maximum_issued_lifecycle_fence,
              COALESCE((
                SELECT MAX(json_extract(
                  candidate_receipt.receipt_json,
                  CASE WHEN candidate_receipt.outcome = 'duplicate'
                    THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
                ))
                FROM runtime_run_command_receipts candidate_receipt
                JOIN runtime_run_commands candidate_command
                  ON candidate_command.id = candidate_receipt.command_id
                WHERE candidate_command.session_id = safety.session_id
                  AND candidate_command.runtime_assignment_id = safety.runtime_assignment_id
                  AND candidate_command.runtime_assignment_generation =
                    safety.runtime_assignment_generation
                  AND candidate_command.sandbox_id = safety.sandbox_id
                  AND candidate_command.sandbox_generation = safety.sandbox_generation
                  AND candidate_command.runtime_principal_id = safety.runtime_principal_id
                  AND (candidate_receipt.outcome = 'enforced' OR
                    (candidate_receipt.outcome = 'duplicate'
                      AND candidate_receipt.original_outcome = 'enforced'))
              ), 1) AS maximum_enforced_lifecycle_fence,
              COALESCE((
                SELECT MAX(incident.safety_fence)
                FROM runtime_compensation_incidents incident
                WHERE incident.team_id = safety.team_id
                  AND incident.project_id = safety.project_id
                  AND incident.session_id = safety.session_id
                  AND incident.runtime_assignment_id = safety.runtime_assignment_id
                  AND incident.runtime_assignment_generation =
                    safety.runtime_assignment_generation
                  AND incident.sandbox_id = safety.sandbox_id
                  AND incident.sandbox_generation = safety.sandbox_generation
                  AND incident.runtime_principal_id = safety.runtime_principal_id
              ), 1) AS maximum_incident_fence
       FROM runtime_binding_safety_fences safety
       JOIN sessions session ON session.id = safety.session_id
       WHERE safety.team_id = ? AND safety.project_id = ? AND safety.session_id = ?
         AND safety.runtime_assignment_id = ? AND safety.runtime_assignment_generation = ?
         AND safety.sandbox_id = ? AND safety.sandbox_generation = ?
         AND safety.runtime_principal_id = ?`,
      binding.teamId,
      binding.projectId,
      binding.sessionId,
      binding.runtimeAssignmentId,
      binding.runtimeAssignmentGeneration,
      binding.sandboxId,
      binding.sandboxGeneration,
      binding.runtimePrincipalId
    );
  }

  function staleSettlementState(commandId: string) {
    return readOne<{
      lifecycle: string;
      state_version: number;
      run_state_revision: number;
      dispatch_status: string;
      dispatch_error: string | null;
      receipts: number;
      accepted_receipts: number;
      enforced_receipts: number;
      effects: number;
      incidents: number;
      compensation_commands: number;
      compensation_dispatches: number;
      follow_events: number;
      follow_status: string;
      follow_error: string | null;
      cursor: string | null;
      last_observation_digest: string | null;
      receipt_sequence: number;
      lease_owner: string | null;
      lease_expires_at_ms: number | null;
      assignment_status: string;
      assignment_authorization_generation: number;
      session_authorization_state: string;
      session_authorization_generation: number;
      mutable_grants: number;
      invalidated_grants: number;
      session_events: number;
      authorization_quarantine_events: number;
      compensating_events: number;
      allocated_fence: number;
      safety_fence_updated_at_ms: number;
    }>(
      `SELECT run.lifecycle, run.state_version, session.run_state_revision,
              dispatch.status AS dispatch_status,
              dispatch.last_safe_error_code AS dispatch_error,
              (SELECT COUNT(*) FROM runtime_run_command_receipts receipt
                WHERE receipt.command_id = command.id) AS receipts,
              (SELECT COUNT(*) FROM runtime_run_command_receipts receipt
                WHERE receipt.command_id = command.id AND receipt.outcome = 'accepted')
                AS accepted_receipts,
              (SELECT COUNT(*) FROM runtime_run_command_receipts receipt
                WHERE receipt.command_id = command.id AND receipt.outcome = 'enforced')
                AS enforced_receipts,
              (SELECT COUNT(*) FROM runtime_run_command_effects effect
                WHERE effect.command_id = command.id) AS effects,
              (SELECT COUNT(*) FROM runtime_compensation_incidents incident
                WHERE incident.source_command_id = command.id) AS incidents,
              (SELECT COUNT(*) FROM runtime_compensation_commands compensation_command
                WHERE compensation_command.source_command_id = command.id)
                AS compensation_commands,
              (SELECT COUNT(*) FROM runtime_compensation_dispatch compensation_dispatch
                WHERE compensation_dispatch.source_command_id = command.id)
                AS compensation_dispatches,
              (SELECT COUNT(*) FROM runtime_receipt_follow_events event
                WHERE event.command_id = command.id) AS follow_events,
              stream.status AS follow_status,
              stream.last_safe_error_code AS follow_error,
              stream.cursor, stream.last_observation_digest, stream.receipt_sequence,
              stream.lease_owner, stream.lease_expires_at_ms,
              assignment.status AS assignment_status,
              assignment.runtime_authorization_generation
                AS assignment_authorization_generation,
              session.runtime_authorization_state AS session_authorization_state,
              session.runtime_authorization_generation
                AS session_authorization_generation,
              (SELECT COUNT(*)
                 FROM action_grants grant_record
                 JOIN action_grant_states grant_state ON grant_state.grant_id = grant_record.id
                WHERE grant_record.agent_run_id = command.agent_run_id
                  AND grant_state.version = (
                    SELECT MAX(candidate.version) FROM action_grant_states candidate
                    WHERE candidate.grant_id = grant_record.id
                  )
                  AND grant_state.status IN ('issued', 'enforcement-pending', 'active'))
                AS mutable_grants,
              (SELECT COUNT(*)
                 FROM action_grants grant_record
                 JOIN action_grant_states grant_state ON grant_state.grant_id = grant_record.id
                WHERE grant_record.agent_run_id = command.agent_run_id
                  AND grant_state.version = (
                    SELECT MAX(candidate.version) FROM action_grant_states candidate
                    WHERE candidate.grant_id = grant_record.id
                  )
                  AND grant_state.status = 'invalidated') AS invalidated_grants,
              (SELECT COUNT(*) FROM session_events event
                WHERE event.session_id = command.session_id) AS session_events,
              (SELECT COUNT(*) FROM session_events event
                WHERE event.session_id = command.session_id
                  AND event.type = 'session.runtime-authorization.quarantined')
                AS authorization_quarantine_events,
              (SELECT COUNT(*) FROM session_events event
                WHERE event.session_id = command.session_id
                  AND event.type = 'run.runtime-command.compensating') AS compensating_events,
              safety.allocated_fence,
              safety.updated_at_ms AS safety_fence_updated_at_ms
       FROM runtime_run_commands command
       JOIN agent_runs run ON run.id = command.agent_run_id
       JOIN sessions session ON session.id = command.session_id
       JOIN runtime_assignments assignment ON assignment.id = command.runtime_assignment_id
       JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
       JOIN runtime_receipt_follow_streams stream
         ON stream.runtime_assignment_id = command.runtime_assignment_id
        AND stream.runtime_authorization_generation = command.runtime_authorization_generation
       JOIN runtime_binding_safety_fences safety
         ON safety.team_id = assignment.team_id
        AND safety.project_id = assignment.project_id
        AND safety.session_id = command.session_id
        AND safety.runtime_assignment_id = command.runtime_assignment_id
        AND safety.runtime_assignment_generation = command.runtime_assignment_generation
        AND safety.sandbox_id = command.sandbox_id
        AND safety.sandbox_generation = command.sandbox_generation
        AND safety.runtime_principal_id = command.runtime_principal_id
       WHERE command.id = ?`,
      commandId
    );
  }

  it("routes a signed late enforced receipt through real lifecycle truth in one transaction", async () => {
    const { delivery, receipt, settlement } = await prepareLateSettlement();

    execute(`
      CREATE TRIGGER test_abort_follow_event
      BEFORE INSERT ON runtime_receipt_follow_events
      BEGIN
        SELECT RAISE(ABORT, 'simulated follow-event persistence failure');
      END;
    `);
    expect(() => kernel.runtimeReceiptFollowJournal.settle(settlement)).toThrowError(
      expect.objectContaining({ code: "journal_conflict" })
    );
    expect(
      readOne<{
        lifecycle: string;
        state_version: number;
        dispatch_status: string;
        receipts: number;
        effects: number;
        follow_events: number;
        follow_status: string;
        cursor: string | null;
      }>(
        `SELECT run.lifecycle, run.state_version, dispatch.status AS dispatch_status,
                (SELECT COUNT(*) FROM runtime_run_command_receipts
                  WHERE command_id = command.id) AS receipts,
                (SELECT COUNT(*) FROM runtime_run_command_effects
                  WHERE command_id = command.id) AS effects,
                (SELECT COUNT(*) FROM runtime_receipt_follow_events) AS follow_events,
                stream.status AS follow_status, stream.cursor
         FROM runtime_run_commands command
         JOIN agent_runs run ON run.id = command.agent_run_id
         JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
         JOIN runtime_receipt_follow_streams stream
           ON stream.runtime_assignment_id = command.runtime_assignment_id
          AND stream.runtime_authorization_generation = command.runtime_authorization_generation
         WHERE command.id = ?`,
        delivery.command.commandId
      )
    ).toEqual({
      lifecycle: "starting",
      state_version: 1,
      dispatch_status: "awaiting-receipt",
      receipts: 1,
      effects: 0,
      follow_events: 0,
      follow_status: "processing",
      cursor: null,
    });

    execute("DROP TRIGGER test_abort_follow_event");
    const settled = kernel.runtimeReceiptFollowJournal.settle(settlement);
    expect(verifiedProofs).toBe(2);
    expect(settled.receiptId).toBeTruthy();
    expect(
      await sessions.inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        type: "session.run-state",
        sessionId: SESSION_ID,
      })
    ).toMatchObject({ lifecycle: "active", stateVersion: 2, pendingLifecycleOperation: null });

    const committedEffectRef = commitRuntimeEffectRef(PROVIDER_EFFECT_REF);
    const durable = readOne<{
      lifecycle: string;
      state_version: number;
      dispatch_status: string;
      receipt_json: string;
      receipt_digest: string;
      required_effect_enforcer_set_digest: string;
      enforcement_subject_digest: string;
      aggregate_proof_digest: string;
      proof_verified_at_ms: number;
      effects: number;
      follow_events: number;
      follow_status: string;
      cursor: string;
      last_observation_digest: string;
      effective_receipt_digest: string;
    }>(
      `SELECT run.lifecycle, run.state_version, dispatch.status AS dispatch_status,
              receipt.receipt_json, receipt.receipt_digest,
              receipt.required_effect_enforcer_set_digest,
              receipt.enforcement_subject_digest, receipt.aggregate_proof_digest,
              receipt.proof_verified_at_ms,
              (SELECT COUNT(*) FROM runtime_run_command_effects
                WHERE command_id = command.id) AS effects,
              (SELECT COUNT(*) FROM runtime_receipt_follow_events) AS follow_events,
              stream.status AS follow_status, stream.cursor, stream.last_observation_digest,
              event.effective_receipt_digest
       FROM runtime_run_commands command
       JOIN agent_runs run ON run.id = command.agent_run_id
       JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
       JOIN runtime_run_command_receipts receipt ON receipt.command_id = command.id
       JOIN runtime_receipt_follow_streams stream
         ON stream.runtime_assignment_id = command.runtime_assignment_id
        AND stream.runtime_authorization_generation = command.runtime_authorization_generation
       JOIN runtime_receipt_follow_events event ON event.receipt_id = receipt.id
       WHERE command.id = ? AND receipt.outcome = 'enforced'`,
      delivery.command.commandId
    );
    expect(durable).toMatchObject({
      lifecycle: "active",
      state_version: 2,
      dispatch_status: "enforced",
      receipt_digest: settled.effectiveReceiptDigest,
      required_effect_enforcer_set_digest: EFFECT_ENFORCER_SET_DIGEST,
      enforcement_subject_digest: receipt.aggregateEnforcementProof?.enforcementSubjectDigest,
      aggregate_proof_digest: receipt.aggregateEnforcementProof?.aggregateProofDigest,
      proof_verified_at_ms: now,
      effects: 1,
      follow_events: 1,
      follow_status: "pending",
      cursor: "runtime-cursor:1",
      effective_receipt_digest: settled.effectiveReceiptDigest,
    });
    expect(durable.last_observation_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(durable.receipt_json).toContain(committedEffectRef);
    expect(durable.receipt_json).not.toContain(PROVIDER_EFFECT_REF);
  });

  it("atomically records exact verified compensation evidence for a stale enforced receipt", async () => {
    const fixture = await prepareLateSettlement();
    const grantId = seedMutableGrant(fixture.delivery);
    advanceRuntimeAuthorizationGeneration(fixture.delivery, 2);
    const highWater = authoritativeSafetyHighWater(fixture.delivery);
    const before = staleSettlementState(fixture.delivery.command.commandId);

    const settled = kernel.runtimeReceiptFollowJournal.settle(fixture.settlement);

    expect(verifiedProofs).toBe(2);
    const proof = fixture.receipt.aggregateEnforcementProof;
    if (!proof) throw new Error("Expected exact aggregate enforcement proof");
    const committedEffectRef = commitRuntimeEffectRef(PROVIDER_EFFECT_REF);
    const incident = readOne<{
      compensation_id: string;
      incident_digest: string;
      source_command_id: string;
      source_receipt_id: string;
      trust_state: string;
      session_id: string;
      team_id: string;
      project_id: string;
      agent_run_id: string;
      run_policy_revision: number;
      runtime_assignment_id: string;
      runtime_assignment_generation: number;
      sandbox_id: string;
      sandbox_generation: number;
      runtime_principal_id: string;
      runtime_authorization_generation: number;
      source_command_digest: string;
      lifecycle_command_claims_digest: string;
      lifecycle_receipt_digest: string;
      source_enforced_fence: number;
      safety_fence: number;
      source_effect_ref_commitment: string;
      source_required_effect_enforcer_set_digest: string;
      lifecycle_enforcement_subject_digest: string;
      lifecycle_aggregate_proof_digest: string;
      source_proof_verified_at_ms: number;
      created_at_ms: number;
    }>(
      `SELECT compensation_id, incident_digest, source_command_id, source_receipt_id,
              trust_state, session_id, team_id, project_id, agent_run_id,
              run_policy_revision, runtime_assignment_id, runtime_assignment_generation,
              sandbox_id, sandbox_generation, runtime_principal_id,
              runtime_authorization_generation, source_command_digest,
              lifecycle_command_claims_digest, lifecycle_receipt_digest,
              source_enforced_fence, safety_fence, source_effect_ref_commitment,
              source_required_effect_enforcer_set_digest,
              lifecycle_enforcement_subject_digest, lifecycle_aggregate_proof_digest,
              source_proof_verified_at_ms, created_at_ms
       FROM runtime_compensation_incidents WHERE source_command_id = ?`,
      fixture.delivery.command.commandId
    );
    expect(incident.compensation_id).toMatch(/^compensation:[0-9a-f]{64}$/);
    expect(incident).toMatchObject({
      source_command_id: fixture.delivery.command.commandId,
      source_receipt_id: settled.receiptId,
      trust_state: "verified",
      session_id: fixture.delivery.command.binding.sessionId,
      team_id: fixture.delivery.command.binding.teamId,
      project_id: fixture.delivery.command.binding.projectId,
      agent_run_id: fixture.delivery.command.agentRunId,
      run_policy_revision: fixture.delivery.command.runPolicyRevision,
      runtime_assignment_id: fixture.delivery.command.binding.runtimeAssignmentId,
      runtime_assignment_generation: fixture.delivery.command.binding.runtimeAssignmentGeneration,
      sandbox_id: fixture.delivery.command.binding.sandboxId,
      sandbox_generation: fixture.delivery.command.binding.sandboxGeneration,
      runtime_principal_id: fixture.delivery.command.binding.runtimePrincipalId,
      runtime_authorization_generation: fixture.delivery.command.runtimeAuthorizationGeneration,
      source_command_digest: sha256(canonicalRuntimeJson(fixture.delivery.command)),
      lifecycle_command_claims_digest: fixture.delivery.command.authority.claimsDigest,
      lifecycle_receipt_digest: settled.effectiveReceiptDigest,
      source_enforced_fence: fixture.receipt.enforcedFence,
      source_effect_ref_commitment: committedEffectRef,
      source_required_effect_enforcer_set_digest: EFFECT_ENFORCER_SET_DIGEST,
      lifecycle_enforcement_subject_digest: proof.enforcementSubjectDigest,
      lifecycle_aggregate_proof_digest: proof.aggregateProofDigest,
      source_proof_verified_at_ms: now,
      created_at_ms: now,
    });
    expect(incident.incident_digest).toBe(
      digestRuntimeCompensationIncident({
        version: 1,
        compensationId: incident.compensation_id,
        sourceCommandId: fixture.delivery.command.commandId,
        sourceReceiptId: settled.receiptId,
        trustState: "verified",
        binding: fixture.delivery.command.binding,
        observedRuntimeAuthorizationGeneration:
          fixture.delivery.command.runtimeAuthorizationGeneration,
        lifecycleCommandClaimsDigest: fixture.delivery.command.authority.claimsDigest,
        lifecycleReceiptDigest: settled.effectiveReceiptDigest,
        sourceEnforcedFence: fixture.receipt.enforcedFence,
        safetyFence: incident.safety_fence,
        sourceRequiredEffectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
        lifecycleEnforcementSubjectDigest: proof.enforcementSubjectDigest,
        lifecycleAggregateProofDigest: proof.aggregateProofDigest,
        sourceEffectRefCommitment: committedEffectRef,
        createdAtMs: now,
      })
    );
    expect(incident.safety_fence).toBeGreaterThan(fixture.receipt.enforcedFence);
    for (const value of Object.values(highWater)) {
      expect(incident.safety_fence).toBeGreaterThan(value);
    }

    expect(staleSettlementState(fixture.delivery.command.commandId)).toMatchObject({
      lifecycle: "starting",
      state_version: 1,
      run_state_revision: before.run_state_revision + 1,
      dispatch_status: "compensating",
      dispatch_error: "stale_enforced_effect",
      receipts: 2,
      accepted_receipts: 1,
      enforced_receipts: 1,
      effects: 0,
      incidents: 1,
      compensation_commands: 0,
      compensation_dispatches: 0,
      follow_events: 1,
      follow_status: "pending",
      follow_error: null,
      cursor: "runtime-cursor:1",
      receipt_sequence: 1,
      lease_owner: null,
      lease_expires_at_ms: null,
      assignment_status: "ready",
      assignment_authorization_generation: 2,
      session_authorization_state: "pending",
      session_authorization_generation: 2,
      mutable_grants: 0,
      invalidated_grants: 1,
      session_events: before.session_events + 1,
      authorization_quarantine_events: 0,
      compensating_events: 1,
      allocated_fence: incident.safety_fence,
    });
    expect(latestGrantState(grantId)).toEqual({
      version: 3,
      status: "invalidated",
      reason: "runtime-authorization",
    });
  });

  it("rolls stale receipt settlement back when compensation incident persistence aborts", async () => {
    const fixture = await prepareLateSettlement();
    const grantId = seedMutableGrant(fixture.delivery);
    advanceRuntimeAuthorizationGeneration(fixture.delivery, 2);
    const before = staleSettlementState(fixture.delivery.command.commandId);
    expect(before).toMatchObject({
      dispatch_status: "awaiting-receipt",
      dispatch_error: null,
      receipts: 1,
      accepted_receipts: 1,
      enforced_receipts: 0,
      effects: 0,
      incidents: 0,
      compensation_commands: 0,
      compensation_dispatches: 0,
      follow_events: 0,
      follow_status: "processing",
      follow_error: null,
      cursor: null,
      last_observation_digest: null,
      receipt_sequence: 0,
      assignment_status: "ready",
      assignment_authorization_generation: 2,
      session_authorization_state: "pending",
      session_authorization_generation: 2,
      mutable_grants: 1,
      invalidated_grants: 0,
      authorization_quarantine_events: 0,
      compensating_events: 0,
    });
    execute(`
      CREATE TRIGGER test_abort_runtime_compensation_incident
      BEFORE INSERT ON runtime_compensation_incidents
      BEGIN
        SELECT RAISE(ABORT, 'simulated compensation incident persistence failure');
      END;
    `);

    expect(() => kernel.runtimeReceiptFollowJournal.settle(fixture.settlement)).toThrowError(
      expect.objectContaining({ code: "journal_conflict" })
    );

    expect(staleSettlementState(fixture.delivery.command.commandId)).toEqual(before);
    expect(latestGrantState(grantId)).toEqual({
      version: 2,
      status: "active",
      reason: "enforcement",
    });
  });

  it.each([
    {
      outcome: "accepted" as const,
      compensationStatus: "awaiting-receipt",
      compensationError: null,
      sourceStatus: "compensating",
      effects: 0,
      verifiedProofs: 0,
    },
    {
      outcome: "enforced" as const,
      compensationStatus: "enforced",
      compensationError: null,
      sourceStatus: "quarantined",
      effects: 1,
      verifiedProofs: 1,
    },
    {
      outcome: "rejected" as const,
      compensationStatus: "blocked",
      compensationError: "compensation_rejected",
      sourceStatus: "compensating",
      effects: 0,
      verifiedProofs: 0,
    },
  ])(
    "settles a signed late compensation $outcome receipt on the common cursor chain",
    async ({
      outcome,
      compensationStatus,
      compensationError,
      sourceStatus,
      effects,
      verifiedProofs: expectedVerifiedProofs,
    }) => {
      const fixture = await prepareLateCompensationSettlement(outcome);
      const settled = kernel.runtimeReceiptFollowJournal.settle(fixture.settlement);

      expect(settled.receiptId).toBeTruthy();
      expect(compensationFollowState(fixture.delivery.command.commandId)).toEqual({
        compensation_status: compensationStatus,
        compensation_error: compensationError,
        source_status: sourceStatus,
        compensation_receipts: 1,
        compensation_effects: effects,
        compensation_follow_events: 1,
        lifecycle_follow_events: 1,
        follow_status: "pending",
        follow_error: null,
        cursor: "runtime-cursor:2",
        receipt_sequence: 2,
        assignment_status: "ready",
        assignment_authorization_generation: 2,
        session_authorization_state: "pending",
        session_authorization_generation: 2,
        authorization_quarantine_events: 0,
      });
      expect(verifiedCompensationProofs).toBe(expectedVerifiedProofs);

      expect(
        readAll<{
          ledger: string;
          receipt_sequence: number;
          cursor: string;
          previous_cursor: string | null;
        }>(
          `SELECT 'lifecycle' AS ledger, receipt_sequence, cursor, previous_cursor
             FROM runtime_receipt_follow_events
           UNION ALL
           SELECT 'compensation' AS ledger, receipt_sequence, cursor, previous_cursor
             FROM runtime_compensation_follow_events
           ORDER BY receipt_sequence ASC`
        )
      ).toEqual([
        {
          ledger: "lifecycle",
          receipt_sequence: 1,
          cursor: "runtime-cursor:1",
          previous_cursor: null,
        },
        {
          ledger: "compensation",
          receipt_sequence: 2,
          cursor: "runtime-cursor:2",
          previous_cursor: "runtime-cursor:1",
        },
      ]);
      const durable = readOne<{
        receipt_id: string;
        receipt_digest: string;
        receipt_json: string;
        wire_receipt_digest: string;
        effective_receipt_digest: string;
      }>(
        `SELECT receipt.id AS receipt_id, receipt.receipt_digest, receipt.receipt_json,
                event.wire_receipt_digest, event.effective_receipt_digest
         FROM runtime_compensation_receipts receipt
         JOIN runtime_compensation_follow_events event ON event.receipt_id = receipt.id
         WHERE receipt.compensation_command_id = ?`,
        fixture.delivery.command.commandId
      );
      expect(durable).toMatchObject({
        receipt_id: settled.receiptId,
        receipt_digest: settled.effectiveReceiptDigest,
        effective_receipt_digest: settled.effectiveReceiptDigest,
        wire_receipt_digest: fixture.observation.receiptDigest,
      });
      expect(durable.receipt_json).not.toContain(PROVIDER_CONTAINMENT_EFFECT_REF);
    }
  );

  it("contains an invalid late compensation proof without touching replacement authorization", async () => {
    const fixture = await prepareLateCompensationSettlement("enforced");
    compensationProofVerifierMode = "reject";

    let failure: unknown;
    try {
      kernel.runtimeReceiptFollowJournal.settle(fixture.settlement);
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      code: "enforcement_proof_rejected",
      message: "Runtime receipt enforcement proof was rejected",
    });
    expect(String(failure)).not.toContain(PROVIDER_CONTAINMENT_EFFECT_REF);
    expect(verifiedCompensationProofs).toBe(0);
    expect(compensationFollowState(fixture.delivery.command.commandId)).toEqual({
      compensation_status: "awaiting-receipt",
      compensation_error: "enforcement_proof_verification_failed",
      source_status: "compensating",
      compensation_receipts: 0,
      compensation_effects: 0,
      compensation_follow_events: 0,
      lifecycle_follow_events: 1,
      follow_status: "quarantined",
      follow_error: "enforcement_proof_verification_failed",
      cursor: "runtime-cursor:1",
      receipt_sequence: 1,
      assignment_status: "ready",
      assignment_authorization_generation: 2,
      session_authorization_state: "pending",
      session_authorization_generation: 2,
      authorization_quarantine_events: 0,
    });
    expect(
      kernel.runtimeReceiptFollowJournal.claim({
        workerId: "retry-worker",
        leaseDurationMs: 30_000,
        nowMs: now,
      })
    ).toBeNull();
  });

  it.each([
    { fault: "signature" as const, followError: "invalid_observation_signature" },
    { fault: "chain" as const, followError: "invalid_observation_chain" },
  ])("fails closed on a compensation observation $fault fault", async ({ fault, followError }) => {
    const fixture = await prepareLateCompensationSettlement("accepted");
    const observation =
      fault === "signature"
        ? {
            ...fixture.observation,
            authority: {
              ...fixture.observation.authority,
              signature: `${fixture.observation.authority.signature[0] === "A" ? "B" : "A"}${fixture.observation.authority.signature.slice(1)}`,
            },
          }
        : createRuntimeCompensationReceiptObservationIssuer({
            issuerKeyId: OBSERVATION_KEY_ID,
            binding: fixture.delivery.command.binding,
            trustedConfigurationRoot: directory,
            privateKeyFile,
            clock: () => now,
          }).issue({
            observationId: "observation:late-compensation:wrong-chain",
            cursor: "runtime-cursor:2",
            previous: null,
            command: fixture.delivery.command,
            receipt: fixture.receipt,
          });

    expect(() =>
      kernel.runtimeReceiptFollowJournal.settle({ ...fixture.settlement, observation })
    ).toThrowError(
      expect.objectContaining({
        code: "invalid_observation",
        message: "Runtime receipt observation is invalid",
      })
    );
    expect(compensationFollowState(fixture.delivery.command.commandId)).toMatchObject({
      compensation_status: "awaiting-receipt",
      compensation_error: "runtime_command_failed",
      source_status: "compensating",
      compensation_receipts: 0,
      compensation_effects: 0,
      compensation_follow_events: 0,
      lifecycle_follow_events: 1,
      follow_status: "quarantined",
      follow_error: followError,
      cursor: "runtime-cursor:1",
      receipt_sequence: 1,
      assignment_status: "ready",
      assignment_authorization_generation: 2,
      session_authorization_state: "pending",
      session_authorization_generation: 2,
      authorization_quarantine_events: 0,
    });
  });

  it.each(["accessor", "proxy"] as const)(
    "rejects a hostile compensation observation %s without invoking value getters or leaking errors",
    async (kind) => {
      const fixture = await prepareLateCompensationSettlement("accepted");
      let valueGetterInvoked = false;
      let hostile: unknown;
      if (kind === "accessor") {
        hostile = Object.create(null) as Record<string, unknown>;
        Object.defineProperties(hostile, {
          kind: {
            enumerable: true,
            get: () => {
              valueGetterInvoked = true;
              throw new Error("provider-secret-accessor-error");
            },
          },
          command: {
            enumerable: true,
            value: { commandId: fixture.delivery.command.commandId },
          },
        });
      } else {
        hostile = new Proxy(
          {
            kind: "runtime.compensation-receipt-observed",
            command: { commandId: fixture.delivery.command.commandId },
          },
          {
            get: () => {
              valueGetterInvoked = true;
              throw new Error("provider-secret-proxy-get-error");
            },
            getOwnPropertyDescriptor: () => {
              throw new Error("provider-secret-proxy-descriptor-error");
            },
          }
        );
      }

      let failure: unknown;
      try {
        kernel.runtimeReceiptFollowJournal.settle({
          ...fixture.settlement,
          observation: hostile,
        });
      } catch (error) {
        failure = error;
      }
      expect(failure).toMatchObject({
        code: "invalid_observation",
        message: "Runtime receipt observation is invalid",
      });
      expect(String(failure)).not.toContain("provider-secret");
      expect(valueGetterInvoked).toBe(false);
      expect(compensationFollowState(fixture.delivery.command.commandId)).toMatchObject({
        compensation_status: "awaiting-receipt",
        compensation_receipts: 0,
        compensation_effects: 0,
        compensation_follow_events: 0,
        lifecycle_follow_events: 1,
        follow_status: "quarantined",
        follow_error: "invalid_observation",
        cursor: "runtime-cursor:1",
        receipt_sequence: 1,
        assignment_status: "ready",
        assignment_authorization_generation: 2,
        session_authorization_state: "pending",
        session_authorization_generation: 2,
        authorization_quarantine_events: 0,
      });
    }
  );

  it("invalidates mutable grants when a direct quarantined lifecycle receipt contains the Run", async () => {
    await requestStart();
    const delivery = await acquireDispatchInterlock(await claimStart());
    const grantId = seedMutableGrant(delivery);

    await kernel.runtimeLifecycleJournal.complete({
      commandId: delivery.command.commandId,
      workerId: RUNTIME.userId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      observedAtMs: now,
      outcome: {
        kind: "receipt",
        receipt: {
          commandId: delivery.command.commandId,
          binding: delivery.command.binding,
          runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
          outcome: "quarantined",
          reason: "effect_enforcer_set_mismatch",
          effectRef: PROVIDER_EFFECT_REF,
        },
      },
    });

    expect(latestGrantState(grantId)).toEqual({
      version: 3,
      status: "invalidated",
      reason: "runtime-authorization",
    });
    expect(
      readOne<{
        lifecycle: string;
        dispatch_status: string;
        assignment_status: string;
        authorization_state: string;
        receipts: number;
      }>(
        `SELECT run.lifecycle, dispatch.status AS dispatch_status,
                assignment.status AS assignment_status,
                session.runtime_authorization_state AS authorization_state,
                (SELECT COUNT(*) FROM runtime_run_command_receipts receipt
                  WHERE receipt.command_id = command.id) AS receipts
         FROM runtime_run_commands command
         JOIN agent_runs run ON run.id = command.agent_run_id
         JOIN sessions session ON session.id = command.session_id
         JOIN runtime_assignments assignment ON assignment.id = command.runtime_assignment_id
         JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
         WHERE command.id = ?`,
        delivery.command.commandId
      )
    ).toEqual({
      lifecycle: "failed",
      dispatch_status: "quarantined",
      assignment_status: "quarantined",
      authorization_state: "quarantined",
      receipts: 1,
    });
  });

  it.each(["missing", "invalid"] as const)(
    "contains a signed enforced observation with a %s aggregate proof",
    async (proofKind) => {
      const fixture = await prepareLateSettlement();
      const revisionBefore = runStateRevision();
      const detailBefore = await sessions.inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        type: "session.detail",
        sessionId: SESSION_ID,
      });
      if (!detailBefore) throw new Error("Expected public Session detail");
      const malformedReceipt: EnforcedRuntimeReceipt =
        proofKind === "missing"
          ? {
              commandId: fixture.receipt.commandId,
              binding: fixture.receipt.binding,
              runtimeAuthorizationGeneration: fixture.receipt.runtimeAuthorizationGeneration,
              outcome: "enforced",
              effectRef: fixture.receipt.effectRef,
              enforcedFence: fixture.receipt.enforcedFence,
            }
          : {
              ...fixture.receipt,
              aggregateEnforcementProof: {
                ...fixture.receipt.aggregateEnforcementProof!,
                aggregateProofDigest: "0".repeat(64),
              },
            };
      const observation = signedObservationWithReceipt(fixture.observation, malformedReceipt);

      expect(() =>
        kernel.runtimeReceiptFollowJournal.settle({ ...fixture.settlement, observation })
      ).toThrowError(expect.objectContaining({ code: "enforcement_proof_rejected" }));
      expectContained(fixture.delivery.command.commandId, revisionBefore + 1);
      const containmentEvents = await sessions.inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        type: "session.events",
        sessionId: SESSION_ID,
        afterSequence: detailBefore.latestSequence,
        limit: 100,
      });
      expect(containmentEvents).toHaveLength(1);
      expect(containmentEvents[0]).toMatchObject({
        sequence: detailBefore.latestSequence + 1,
        type: "session.runtime-authorization.quarantined",
        actor: {
          kind: "system",
          userId: "team-session-kernel",
          displayName: "Team Session Kernel",
        },
        source: {
          scope: "runtime-worker:receipt-follow",
          key: `enforcement-proof-containment:${sha256(
            canonicalRuntimeJson(fixture.delivery.command)
          )}`,
        },
        payload: {
          commandDigest: sha256(canonicalRuntimeJson(fixture.delivery.command)),
          requiredEffectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
          runtimeAuthorizationGeneration: 1,
          safeErrorCode: "enforcement_proof_verification_failed",
        },
      });
      expect(projectPublicSessionEvent(containmentEvents[0]!)).toMatchObject({
        sequence: detailBefore.latestSequence + 1,
        type: "session.runtime-authorization.quarantined",
        actor: {
          kind: "system",
          userId: "session-system",
          displayName: "Session system",
        },
        sourceAdapter: "runtime",
        payload: {},
      });
      const detailAfter = await sessions.inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        type: "session.detail",
        sessionId: SESSION_ID,
      });
      expect(detailAfter).toMatchObject({
        latestSequence: detailBefore.latestSequence + 1,
        runtime: { authorizationState: "quarantined" },
        viewer: {
          basis: {
            runStateRevision: revisionBefore + 1,
            latestSequence: detailBefore.latestSequence + 1,
          },
        },
      });
      const contained = containmentState(fixture.delivery.command.commandId);
      expect(() =>
        kernel.runtimeReceiptFollowJournal.settle({ ...fixture.settlement, observation })
      ).toThrowError(expect.objectContaining({ code: "stale_lease" }));
      expect(containmentState(fixture.delivery.command.commandId)).toEqual(contained);
    }
  );

  it.each(["reject", "async", "async-reject"] as const)(
    "contains a signed enforced observation when the synchronous proof verifier returns %s",
    async (mode) => {
      const fixture = await prepareLateSettlement();
      const revisionBefore = runStateRevision();
      const grantId = seedMutableGrant(fixture.delivery);
      expect(latestGrantState(grantId)).toEqual({
        version: 2,
        status: "active",
        reason: "enforcement",
      });
      proofVerifierMode = mode;

      expect(() => kernel.runtimeReceiptFollowJournal.settle(fixture.settlement)).toThrowError(
        expect.objectContaining({ code: "enforcement_proof_rejected" })
      );
      expectContained(fixture.delivery.command.commandId, revisionBefore + 1);
      expect(latestGrantState(grantId)).toEqual({
        version: 3,
        status: "invalidated",
        reason: "runtime-authorization",
      });
      expect(verifiedProofs).toBe(mode === "reject" ? 0 : 1);
    }
  );

  it("keeps tenant authorization intact for the same malformed proof with a tampered signature", async () => {
    const fixture = await prepareLateSettlement();
    const revisionBefore = runStateRevision();
    const missingProofReceipt: EnforcedRuntimeReceipt = {
      commandId: fixture.receipt.commandId,
      binding: fixture.receipt.binding,
      runtimeAuthorizationGeneration: fixture.receipt.runtimeAuthorizationGeneration,
      outcome: "enforced",
      effectRef: fixture.receipt.effectRef,
      enforcedFence: fixture.receipt.enforcedFence,
    };
    const signed = signedObservationWithReceipt(fixture.observation, missingProofReceipt);
    const observation = {
      ...signed,
      authority: {
        ...signed.authority,
        signature: `${signed.authority.signature[0] === "A" ? "B" : "A"}${signed.authority.signature.slice(1)}`,
      },
    };

    expect(() =>
      kernel.runtimeReceiptFollowJournal.settle({ ...fixture.settlement, observation })
    ).toThrowError(expect.objectContaining({ code: "invalid_observation" }));
    expect(containmentState(fixture.delivery.command.commandId)).toEqual({
      lifecycle: "starting",
      state_version: 1,
      run_state_revision: revisionBefore,
      dispatch_status: "awaiting-receipt",
      dispatch_error: null,
      dispatch_terminal_at_ms: null,
      dispatch_lease_owner: null,
      dispatch_lease_expires_at_ms: null,
      receipts: 1,
      enforced_receipts: 0,
      effects: 0,
      follow_events: 0,
      follow_status: "quarantined",
      follow_error: "invalid_observation_signature",
      cursor: null,
      last_observation_digest: null,
      receipt_sequence: 0,
      assignment_status: "ready",
      authorization_state: "enforced",
      mutable_grants: 0,
      containment_events: 0,
    });
  });

  it("rolls every containment write back on a final stream fault, then contains on exact retry", async () => {
    const fixture = await prepareLateSettlement();
    const revisionBefore = runStateRevision();
    const grantId = seedMutableGrant(fixture.delivery);
    proofVerifierMode = "reject";
    execute(`
      CREATE TRIGGER test_abort_proof_containment
      BEFORE UPDATE OF status ON runtime_receipt_follow_streams
      WHEN NEW.status = 'quarantined'
        AND NEW.last_safe_error_code = 'enforcement_proof_verification_failed'
      BEGIN
        SELECT RAISE(ABORT, 'simulated proof containment persistence failure');
      END;
    `);

    expect(() => kernel.runtimeReceiptFollowJournal.settle(fixture.settlement)).toThrowError(
      expect.objectContaining({ code: "journal_conflict" })
    );
    expect(containmentState(fixture.delivery.command.commandId)).toEqual({
      lifecycle: "starting",
      state_version: 1,
      run_state_revision: revisionBefore,
      dispatch_status: "awaiting-receipt",
      dispatch_error: null,
      dispatch_terminal_at_ms: null,
      dispatch_lease_owner: null,
      dispatch_lease_expires_at_ms: null,
      receipts: 1,
      enforced_receipts: 0,
      effects: 0,
      follow_events: 0,
      follow_status: "processing",
      follow_error: null,
      cursor: null,
      last_observation_digest: null,
      receipt_sequence: 0,
      assignment_status: "ready",
      authorization_state: "enforced",
      mutable_grants: 1,
      containment_events: 0,
    });
    expect(latestGrantState(grantId)).toMatchObject({ version: 2, status: "active" });

    execute("DROP TRIGGER test_abort_proof_containment");
    expect(() => kernel.runtimeReceiptFollowJournal.settle(fixture.settlement)).toThrowError(
      expect.objectContaining({ code: "enforcement_proof_rejected" })
    );
    expectContained(fixture.delivery.command.commandId, revisionBefore + 1);
    expect(latestGrantState(grantId)).toMatchObject({ version: 3, status: "invalidated" });
  });

  it("contains an old authorization stream without quarantining advanced control-plane state", async () => {
    const fixture = await prepareLateSettlement();
    const revisionBefore = runStateRevision();
    proofVerifierMode = "reject";
    execute(`
      BEGIN IMMEDIATE;
      INSERT INTO runtime_authorization_epochs
        (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
         sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
         effect_enforcer_set_digest)
      VALUES
        ('${SESSION_ID}', 2, '${fixture.delivery.command.binding.runtimeAssignmentId}',
         ${fixture.delivery.command.binding.runtimeAssignmentGeneration},
         '${fixture.delivery.command.binding.sandboxId}',
         ${fixture.delivery.command.binding.sandboxGeneration},
         '${fixture.delivery.command.binding.runtimePrincipalId}', ${now},
         '${EFFECT_ENFORCER_SET_DIGEST}');
      UPDATE runtime_assignments
      SET runtime_authorization_generation = 2
      WHERE id = '${fixture.delivery.command.binding.runtimeAssignmentId}';
      UPDATE sessions
      SET runtime_authorization_generation = 2, runtime_authorization_state = 'pending'
      WHERE id = '${SESSION_ID}';
      COMMIT;
    `);

    expect(() => kernel.runtimeReceiptFollowJournal.settle(fixture.settlement)).toThrowError(
      expect.objectContaining({ code: "enforcement_proof_rejected" })
    );
    expect(containmentState(fixture.delivery.command.commandId)).toEqual({
      lifecycle: "starting",
      state_version: 1,
      run_state_revision: revisionBefore,
      dispatch_status: "awaiting-receipt",
      dispatch_error: "enforcement_proof_verification_failed",
      dispatch_terminal_at_ms: null,
      dispatch_lease_owner: null,
      dispatch_lease_expires_at_ms: null,
      receipts: 1,
      enforced_receipts: 0,
      effects: 0,
      follow_events: 0,
      follow_status: "quarantined",
      follow_error: "enforcement_proof_verification_failed",
      cursor: null,
      last_observation_digest: null,
      receipt_sequence: 0,
      assignment_status: "ready",
      authorization_state: "pending",
      mutable_grants: 0,
      containment_events: 0,
    });
    expect(
      readOne<{
        session_generation: number;
        assignment_generation: number;
      }>(
        `SELECT session.runtime_authorization_generation AS session_generation,
                assignment.runtime_authorization_generation AS assignment_generation
         FROM sessions session
         JOIN runtime_assignments assignment ON assignment.session_id = session.id
         WHERE session.id = ?`,
        SESSION_ID
      )
    ).toEqual({ session_generation: 2, assignment_generation: 2 });
  });
});
