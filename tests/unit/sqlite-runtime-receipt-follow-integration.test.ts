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
  createRuntimeReceiptObservationIssuer,
  digestAggregateEnforcementProof,
  digestRuntimeEnforcementSubject,
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
const PROVIDER_EFFECT_REF = "provider-private-late-effect-reference";
const OBSERVATION_KEY_ID = "runtime-observer:integration-key";
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
    await dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: ensure.outboxId,
        workerId: RUNTIME.userId,
        expectedAttempt: ensure.attempts,
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
