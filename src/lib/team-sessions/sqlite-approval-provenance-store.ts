import type { KeyObject } from "node:crypto";
import type Database from "better-sqlite3";
import {
  digestApprovalCapability,
  digestApprovalProvenance,
  signApprovalProvenance,
  verifyApprovalProvenance,
  type ApprovalCapabilityInput,
  type ApprovalProvenancePayload,
  type ApprovalProvenanceProof,
} from "../runtime/approval-provenance";
import type { RuntimeBinding } from "./contracts";

/**
 * Gate 4 (Phase 9) approval-provenance, lineage, and atomic grant consumption.
 *
 * - `recordApprovalProvenance` signs an immutable snapshot of the exact granted
 *   authority (actor, capability, policy, budget, Sandbox, grant state) with the
 *   dedicated approval-provenance key and persists it digest-only.
 * - `appendGrantLineage` records, append-only, that one grant reissues or
 *   supersedes another under a specific authorizing Grant Review version.
 * - `consumeGrant` consumes a grant exactly once, transactionally, together with
 *   the `action_grant_states` transition to `consumed`; concurrent, duplicate, or
 *   crash-retry consumption converges on the first consumption and can never
 *   double-spend.
 * - `invalidateOutstandingGrants` fences off every non-terminal grant for a Run
 *   when its Sandbox / execution boundary changes, so a re-approval is required.
 */

export interface ApprovalProvenanceStoreOptions {
  readonly signingKey: KeyObject;
  readonly signingKeyId: string;
  /** Trusted verification keys by key id, used to authenticate stored provenance. */
  readonly verificationKeys: ReadonlyMap<string, KeyObject>;
}

export interface RecordApprovalProvenanceInput {
  readonly grantId: string;
  readonly approvalRequestId: string;
  readonly approvalRequestVersion: number;
  readonly grantStateVersion: number;
  readonly actorKind: "human" | "system";
  readonly actorRef: string;
  readonly capability: ApprovalCapabilityInput;
  readonly policyDigest: string;
  readonly budgetDigest: string;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly nowMs: number;
}

export interface AppendGrantLineageInput {
  readonly lineageId: string;
  readonly sessionId: string;
  readonly agentRunId: string;
  readonly successorGrantId: string;
  readonly predecessorGrantId: string;
  readonly relation: "reissues" | "supersedes";
  readonly grantReviewId: string;
  readonly grantReviewVersion: number;
  readonly actorRef: string;
  readonly nowMs: number;
}

export interface ConsumeGrantInput {
  readonly grantId: string;
  readonly effectIdempotencyKey: string;
  readonly canonicalEffectInputDigest: string;
  readonly consumptionReceiptDigest: string;
  readonly actorRef: string;
  readonly nowMs: number;
}

export type ConsumeGrantResult =
  | { readonly outcome: "consumed"; readonly grantStateVersion: number }
  | { readonly outcome: "already-consumed"; readonly grantStateVersion: number };

export class ApprovalProvenanceStoreError extends Error {
  readonly code:
    | "grant-consumed"
    | "grant-not-consumable"
    | "conflicting-consumption"
    | "unknown-grant";
  constructor(code: ApprovalProvenanceStoreError["code"], message: string) {
    super(message);
    this.name = "ApprovalProvenanceStoreError";
    this.code = code;
  }
}

export interface InvalidateOutstandingGrantsInput {
  readonly agentRunId: string;
  readonly reason:
    | "runtime-assignment"
    | "sandbox-generation"
    | "runtime-authorization"
    | "policy-revision"
    | "run-terminal";
  readonly actorRef: string;
  readonly nowMs: number;
}

const NON_TERMINAL = ["issued", "enforcement-pending", "active"] as const;

export interface ApprovalProvenanceStore {
  recordApprovalProvenance(input: RecordApprovalProvenanceInput): ApprovalProvenanceProof;
  verifyStoredProvenance(grantId: string): ApprovalProvenancePayload | null;
  appendGrantLineage(input: AppendGrantLineageInput): void;
  consumeGrant(input: ConsumeGrantInput): ConsumeGrantResult;
  invalidateOutstandingGrants(input: InvalidateOutstandingGrantsInput): ReadonlyArray<string>;
}

export function createApprovalProvenanceStore(
  db: Database.Database,
  options: ApprovalProvenanceStoreOptions
): ApprovalProvenanceStore {
  const insertProvenance = db.prepare(
    `INSERT INTO approval_provenance (
       grant_id, signing_key_id, provenance_digest, approval_request_id,
       approval_request_version, grant_state_version, actor_kind, actor_ref,
       action_class, capability_digest, policy_digest, budget_digest,
       runtime_authorization_generation, signature, issued_at_ms, expires_at_ms, created_at_ms
     ) VALUES (
       @grant_id, @signing_key_id, @provenance_digest, @approval_request_id,
       @approval_request_version, @grant_state_version, @actor_kind, @actor_ref,
       @action_class, @capability_digest, @policy_digest, @budget_digest,
       @runtime_authorization_generation, @signature, @issued_at_ms, @expires_at_ms, @created_at_ms
     )`
  );
  const selectProvenance = db.prepare<[string]>(
    "SELECT * FROM approval_provenance WHERE grant_id = ?"
  );
  const insertLineage = db.prepare(
    `INSERT INTO grant_lineage (
       id, session_id, agent_run_id, successor_grant_id, predecessor_grant_id,
       relation, grant_review_id, grant_review_version, actor_ref, created_at_ms
     ) VALUES (
       @id, @session_id, @agent_run_id, @successor_grant_id, @predecessor_grant_id,
       @relation, @grant_review_id, @grant_review_version, @actor_ref, @created_at_ms
     )`
  );
  const selectConsumption = db.prepare<[string]>(
    "SELECT * FROM grant_consumptions WHERE grant_id = ?"
  );
  const insertConsumption = db.prepare(
    `INSERT INTO grant_consumptions (
       grant_id, effect_idempotency_key, canonical_effect_input_digest,
       consumption_receipt_digest, actor_ref, consumed_at_ms
     ) VALUES (
       @grant_id, @effect_idempotency_key, @canonical_effect_input_digest,
       @consumption_receipt_digest, @actor_ref, @consumed_at_ms
     )`
  );
  const latestGrantState = db.prepare<[string]>(
    `SELECT version, status FROM action_grant_states
     WHERE grant_id = ? ORDER BY version DESC LIMIT 1`
  );
  const insertGrantState = db.prepare(
    `INSERT INTO action_grant_states (
       grant_id, version, previous_version, status, reason, actor_ref, created_at_ms
     ) VALUES (
       @grant_id, @version, @previous_version, @status, @reason, @actor_ref, @created_at_ms
     )`
  );
  const grantExists = db.prepare<[string]>("SELECT 1 FROM action_grants WHERE id = ?");
  const runGrants = db.prepare<[string]>(
    "SELECT id FROM action_grants WHERE agent_run_id = ? ORDER BY id ASC"
  );

  function verifyPayload(payload: ApprovalProvenancePayload, signature: string): boolean {
    const key = options.verificationKeys.get(payload.signingKeyId);
    if (!key) return false;
    return verifyApprovalProvenance({ payload, signature }, key) !== null;
  }

  const recordTx = db.transaction(
    (input: RecordApprovalProvenanceInput): ApprovalProvenanceProof => {
      if (!grantExists.get(input.grantId)) {
        throw new ApprovalProvenanceStoreError("unknown-grant", "Unknown Action Grant");
      }
      const payload: ApprovalProvenancePayload = {
        schema: 1,
        kind: "terminalx.approval-provenance",
        signingKeyId: options.signingKeyId,
        grantId: input.grantId,
        approvalRequestId: input.approvalRequestId,
        approvalRequestVersion: input.approvalRequestVersion,
        grantStateVersion: input.grantStateVersion,
        actorKind: input.actorKind,
        actorRef: input.actorRef,
        actionClass: input.capability.actionClass,
        capabilityDigest: digestApprovalCapability(input.capability),
        policyDigest: input.policyDigest,
        budgetDigest: input.budgetDigest,
        binding: input.binding,
        runtimeAuthorizationGeneration: input.runtimeAuthorizationGeneration,
        issuedAtMs: input.issuedAtMs,
        expiresAtMs: input.expiresAtMs,
      };
      const proof = signApprovalProvenance(payload, options.signingKey);
      insertProvenance.run({
        grant_id: proof.payload.grantId,
        signing_key_id: proof.payload.signingKeyId,
        provenance_digest: digestApprovalProvenance(proof.payload),
        approval_request_id: proof.payload.approvalRequestId,
        approval_request_version: proof.payload.approvalRequestVersion,
        grant_state_version: proof.payload.grantStateVersion,
        actor_kind: proof.payload.actorKind,
        actor_ref: proof.payload.actorRef,
        action_class: proof.payload.actionClass,
        capability_digest: proof.payload.capabilityDigest,
        policy_digest: proof.payload.policyDigest,
        budget_digest: proof.payload.budgetDigest,
        runtime_authorization_generation: proof.payload.runtimeAuthorizationGeneration,
        signature: proof.signature,
        issued_at_ms: proof.payload.issuedAtMs,
        expires_at_ms: proof.payload.expiresAtMs,
        created_at_ms: input.nowMs,
      });
      return proof;
    }
  );

  const consumeTx = db.transaction((input: ConsumeGrantInput): ConsumeGrantResult => {
    const existing = selectConsumption.get(input.grantId) as
      | { canonical_effect_input_digest: string; consumption_receipt_digest: string }
      | undefined;
    if (existing) {
      // A grant is consumed exactly once. A retry with the same effect converges;
      // a different effect on an already-consumed grant fails closed.
      if (
        existing.consumption_receipt_digest !== input.consumptionReceiptDigest ||
        existing.canonical_effect_input_digest !== input.canonicalEffectInputDigest
      ) {
        throw new ApprovalProvenanceStoreError(
          "conflicting-consumption",
          "Grant already consumed by a different effect"
        );
      }
      const latest = latestGrantState.get(input.grantId) as { version: number } | undefined;
      return { outcome: "already-consumed", grantStateVersion: latest?.version ?? 0 };
    }
    const latest = latestGrantState.get(input.grantId) as
      | { version: number; status: string }
      | undefined;
    if (!latest) {
      throw new ApprovalProvenanceStoreError("unknown-grant", "Unknown Action Grant state");
    }
    if (!(NON_TERMINAL as readonly string[]).includes(latest.status)) {
      throw new ApprovalProvenanceStoreError(
        "grant-not-consumable",
        `Grant in state ${latest.status} cannot be consumed`
      );
    }
    // Effect and state transition commit together; the UNIQUE grant_id primary
    // key makes a concurrent second consumption abort the whole transaction.
    insertConsumption.run({
      grant_id: input.grantId,
      effect_idempotency_key: input.effectIdempotencyKey,
      canonical_effect_input_digest: input.canonicalEffectInputDigest,
      consumption_receipt_digest: input.consumptionReceiptDigest,
      actor_ref: input.actorRef,
      consumed_at_ms: input.nowMs,
    });
    const nextVersion = latest.version + 1;
    insertGrantState.run({
      grant_id: input.grantId,
      version: nextVersion,
      previous_version: latest.version,
      status: "consumed",
      reason: "consumed",
      actor_ref: input.actorRef,
      created_at_ms: input.nowMs,
    });
    return { outcome: "consumed", grantStateVersion: nextVersion };
  });

  const invalidateTx = db.transaction(
    (input: {
      agentRunId: string;
      reason:
        | "runtime-assignment"
        | "sandbox-generation"
        | "runtime-authorization"
        | "policy-revision"
        | "run-terminal";
      actorRef: string;
      nowMs: number;
    }): ReadonlyArray<string> => {
      const invalidated: string[] = [];
      for (const row of runGrants.all(input.agentRunId) as Array<{ id: string }>) {
        const latest = latestGrantState.get(row.id) as
          | { version: number; status: string }
          | undefined;
        if (!latest || !(NON_TERMINAL as readonly string[]).includes(latest.status)) continue;
        insertGrantState.run({
          grant_id: row.id,
          version: latest.version + 1,
          previous_version: latest.version,
          status: "invalidated",
          reason: input.reason,
          actor_ref: input.actorRef,
          created_at_ms: input.nowMs,
        });
        invalidated.push(row.id);
      }
      return Object.freeze(invalidated);
    }
  );

  return Object.freeze({
    recordApprovalProvenance(input: RecordApprovalProvenanceInput): ApprovalProvenanceProof {
      return recordTx.immediate(input);
    },
    verifyStoredProvenance(grantId: string): ApprovalProvenancePayload | null {
      const row = selectProvenance.get(grantId) as Record<string, unknown> | undefined;
      if (!row) return null;
      const payload: ApprovalProvenancePayload = {
        schema: 1,
        kind: "terminalx.approval-provenance",
        signingKeyId: row.signing_key_id as string,
        grantId: row.grant_id as string,
        approvalRequestId: row.approval_request_id as string,
        approvalRequestVersion: row.approval_request_version as number,
        grantStateVersion: row.grant_state_version as number,
        actorKind: row.actor_kind as "human" | "system",
        actorRef: row.actor_ref as string,
        actionClass: row.action_class as "scoped-external" | "protected",
        capabilityDigest: row.capability_digest as string,
        policyDigest: row.policy_digest as string,
        budgetDigest: row.budget_digest as string,
        binding: readBinding(db, row.grant_id as string),
        runtimeAuthorizationGeneration: row.runtime_authorization_generation as number,
        issuedAtMs: row.issued_at_ms as number,
        expiresAtMs: row.expires_at_ms as number,
      };
      return verifyPayload(payload, row.signature as string) ? payload : null;
    },
    appendGrantLineage(input: AppendGrantLineageInput): void {
      insertLineage.run({
        id: input.lineageId,
        session_id: input.sessionId,
        agent_run_id: input.agentRunId,
        successor_grant_id: input.successorGrantId,
        predecessor_grant_id: input.predecessorGrantId,
        relation: input.relation,
        grant_review_id: input.grantReviewId,
        grant_review_version: input.grantReviewVersion,
        actor_ref: input.actorRef,
        created_at_ms: input.nowMs,
      });
    },
    consumeGrant(input: ConsumeGrantInput): ConsumeGrantResult {
      return consumeTx.immediate(input);
    },
    invalidateOutstandingGrants(input: InvalidateOutstandingGrantsInput) {
      return invalidateTx.immediate(input);
    },
  });
}

function readBinding(db: Database.Database, grantId: string): RuntimeBinding {
  const row = db
    .prepare<[string]>(
      `SELECT ag.runtime_assignment_id, ag.runtime_assignment_generation, ag.sandbox_id,
              ag.sandbox_generation, ag.runtime_principal_id, ag.session_id, s.team_id, s.project_id
       FROM action_grants ag JOIN sessions s ON s.id = ag.session_id
       WHERE ag.id = ?`
    )
    .get(grantId) as Record<string, unknown> | undefined;
  if (!row) throw new ApprovalProvenanceStoreError("unknown-grant", "Unknown Action Grant binding");
  return Object.freeze({
    teamId: row.team_id as string,
    projectId: row.project_id as string,
    sessionId: row.session_id as string,
    runtimeAssignmentId: row.runtime_assignment_id as string,
    runtimeAssignmentGeneration: row.runtime_assignment_generation as number,
    sandboxId: row.sandbox_id as string,
    sandboxGeneration: row.sandbox_generation as number,
    runtimePrincipalId: row.runtime_principal_id as string,
  });
}
