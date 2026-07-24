import { createHash, timingSafeEqual } from "node:crypto";
import type Database from "better-sqlite3";
import type {
  NonDuplicateRuntimeCompensationReceipt,
  RuntimeCompensationCommand,
  RuntimeCompensationReceipt,
} from "../runtime/contracts";
import { assertRuntimeCommandAuthorityBinding } from "../runtime/runtime-authority";
import {
  canonicalRuntimeJson,
  digestRuntimeCommandClaims,
} from "../runtime/runtime-command-canonical";
import {
  RUNTIME_COMPENSATION_RECEIPT_DIGEST_DOMAIN,
  digestNonDuplicateRuntimeCompensationReceipt,
  snapshotRuntimeCompensationReceiptForCommand,
  verifyRuntimeCompensationReceiptEnforcementProofSynchronously,
} from "../runtime/runtime-compensation-execution";
import type { SynchronousRuntimeCompensationEnforcementProofVerifier } from "../runtime/runtime-compensation-enforcement-proof";
import {
  digestRuntimeCompensationIncident,
  snapshotRuntimeCompensationIncident,
  type RuntimeCompensationIncident,
} from "../runtime/runtime-compensation-incident";
import {
  digestRuntimeCompensationReceiptForObservation,
  isVerifiedRuntimeCompensationReceiptObservation,
  type VerifiedRuntimeCompensationReceiptObservation,
} from "../runtime/runtime-compensation-receipt-observation";
import type {
  RuntimeCompensationCommandAuthorityVerifier,
  RuntimeCompensationMaterializationCandidate,
  RuntimeCompensationMaterializationInput,
  RuntimeCompensationMaterializationJournal,
  RuntimeCompensationMaterializationResult,
} from "../runtime/runtime-compensation-materializer";
import type {
  RuntimeCompensationClaimOptions,
  RuntimeCompensationCompletion,
  RuntimeCompensationDelivery,
  RuntimeCompensationJournal,
  RuntimeCompensationReconcileOptions,
  RuntimeCompensationRenewal,
  RuntimeCompensationRenewalOptions,
} from "../runtime/runtime-compensation-supervisor";
import {
  commitRuntimeEffectRef,
  snapshotAggregateEnforcementProof,
} from "../runtime/runtime-enforcement-proof";

type SqlValue = string | number | null;
type SqlRow = Record<string, SqlValue>;

const MAX_IDENTIFIER_LENGTH = 300;
const MAX_WORKER_ID_LENGTH = 128;
const MAX_SAFE_ERROR_CODE_LENGTH = 200;
const DEFAULT_RETRY_DELAY_MS = 1_000;
const MAX_RETRY_DELAY_MS = 60_000;
const SHA256_DIGEST = /^[0-9a-f]{64}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/;
const COMMAND_FIELDS = [
  "kind",
  "commandId",
  "compensationId",
  "binding",
  "observedRuntimeAuthorizationGeneration",
  "source",
  "platformSecurityPolicyRevision",
  "requiredContainmentEnforcerSetDigest",
  "containment",
  "safetyFence",
  "exactBindingOnly",
  "advanceBeyondCurrentFences",
  "reasonRef",
  "causationId",
  "actor",
  "issuedAtMs",
  "deadlineAtMs",
  "authority",
] as const;
const BINDING_FIELDS = [
  "teamId",
  "projectId",
  "sessionId",
  "runtimeAssignmentId",
  "runtimeAssignmentGeneration",
  "sandboxId",
  "sandboxGeneration",
  "runtimePrincipalId",
] as const;
const SOURCE_FIELDS = [
  "lifecycleCommandId",
  "lifecycleCommandClaimsDigest",
  "lifecycleReceiptDigest",
  "lifecycleEnforcementSubjectDigest",
  "lifecycleAggregateProofDigest",
  "sourceRequiredEffectEnforcerSetDigest",
] as const;

const FAILURE_DISPATCH_CERTAINTY = Object.freeze({
  invalid_input: "not-dispatched",
  invalid_authority: "not-dispatched",
  authority_verification_failed: "not-dispatched",
  binding_mismatch: "not-dispatched",
  deadline_expired: "not-dispatched",
  runtime_handle_unavailable: "not-dispatched",
  lease_expired_before_dispatch: "not-dispatched",
  runtime_command_failed: "dispatch-uncertain",
  invalid_receipt: "dispatch-uncertain",
  enforcement_proof_verification_failed: "dispatch-uncertain",
  runtime_internal: "dispatch-uncertain",
} as const);

export type RuntimeCompensationJournalErrorCode =
  | "invalid_input"
  | "invalid_command"
  | "stale_completion"
  | "journal_conflict";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeCompensationJournalErrorCode, string>> = {
  invalid_input: "Runtime compensation journal input is invalid",
  invalid_command: "Runtime compensation command is invalid",
  stale_completion: "Runtime compensation completion lease is stale",
  journal_conflict: "Runtime compensation journal state conflicts",
};

/** Safe internal boundary: provider, signer, and verifier details are never attached. */
export class RuntimeCompensationJournalError extends Error {
  constructor(readonly code: RuntimeCompensationJournalErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeCompensationJournalError";
  }
}

export type RuntimeCompensationReceiptFollowSettlementRejectionCode =
  "enforcement_proof_verification_failed";

/**
 * Narrow trusted-seam rejection used by the follow journal to quarantine a
 * signed observation without accepting its cursor or claimed Runtime effect.
 */
export class RuntimeCompensationReceiptFollowSettlementRejection extends Error {
  constructor(readonly code: RuntimeCompensationReceiptFollowSettlementRejectionCode) {
    super("Runtime compensation receipt enforcement proof could not be verified");
    this.name = "RuntimeCompensationReceiptFollowSettlementRejection";
  }
}

export interface RuntimeCompensationReceiptFollowSettlementInput {
  /** Private-branded result from the binding-pinned observation verifier. */
  readonly observation: VerifiedRuntimeCompensationReceiptObservation;
  readonly command: RuntimeCompensationCommand;
  readonly receivedAtMs: number;
  readonly actorRef: string;
}

export interface RuntimeCompensationReceiptFollowSettlementResult {
  readonly receiptId: string;
  /** Exact digest stored in runtime_compensation_receipts.receipt_digest. */
  readonly effectiveReceiptDigest: string;
}

export interface CreateSqliteRuntimeCompensationJournalOptions {
  readonly db: Database.Database;
  readonly idGenerator: () => string;
  /** Pinned local platform-security key verification. Must settle synchronously. */
  readonly verifyAuthority: RuntimeCompensationCommandAuthorityVerifier;
  /** Pinned local containment-proof verification. Must settle synchronously. */
  readonly verifyEnforcementProof: SynchronousRuntimeCompensationEnforcementProofVerifier;
  readonly retryDelayMs?: number;
}

interface CommandRow extends SqlRow {
  id: string;
  compensation_id: string;
  source_command_id: string;
  command_sequence: number;
  previous_command_sequence: number | null;
  operation: string;
  session_id: string;
  team_id: string;
  project_id: string;
  agent_run_id: string;
  runtime_assignment_id: string;
  runtime_assignment_generation: number;
  sandbox_id: string;
  sandbox_generation: number;
  runtime_principal_id: string;
  observed_runtime_authorization_generation: number;
  source_required_effect_enforcer_set_digest: string;
  lifecycle_command_claims_digest: string;
  lifecycle_receipt_digest: string;
  lifecycle_enforcement_subject_digest: string;
  lifecycle_aggregate_proof_digest: string;
  platform_security_policy_revision: string;
  required_containment_enforcer_set_digest: string;
  safety_fence: number;
  reason_ref: string;
  causation_id: string;
  command_json: string;
  command_digest: string;
  authority_digest: string;
  created_at_ms: number;
  authority_verified_at_ms: number;
  deadline_at_ms: number;
}

interface CompletionRow extends CommandRow {
  dispatch_status: string;
  attempts: number;
  available_at_ms: number;
  lease_owner: string | null;
  lease_expires_at_ms: number | null;
  dispatch_interlock_acquired_at_ms: number | null;
  last_safe_error_code: string | null;
  terminal_at_ms: number | null;
}

type ReceiptSettlementContext =
  | {
      readonly kind: "dispatch";
      readonly actorRef: string;
      readonly observedAtMs: number;
      readonly expectedAttempt: number;
      readonly expectedLeaseExpiresAtMs: number;
    }
  | {
      readonly kind: "follow";
      readonly actorRef: string;
      readonly observedAtMs: number;
    };

class ContainmentSettlementRejection extends Error {
  constructor() {
    super("Runtime compensation containment result is not sufficient");
    this.name = "ContainmentSettlementRejection";
  }
}

/**
 * One SQLite kernel for both unsigned-incident materialization and singular
 * compensation dispatch. No current Session, Run, Assignment status, policy,
 * or goal fence is consulted before dispatch: only immutable historical
 * evidence, exact binding, durable safety fence, and pinned authority matter.
 */
export class SqliteRuntimeCompensationJournal
  implements RuntimeCompensationMaterializationJournal, RuntimeCompensationJournal
{
  private readonly db: Database.Database;
  private readonly idGenerator: () => string;
  private readonly verifyAuthority: RuntimeCompensationCommandAuthorityVerifier;
  private readonly verifyEnforcementProof: SynchronousRuntimeCompensationEnforcementProofVerifier;
  private readonly retryDelayMs: number;

  constructor(options: CreateSqliteRuntimeCompensationJournalOptions) {
    if (
      !options?.db ||
      typeof options.db.prepare !== "function" ||
      typeof options.idGenerator !== "function" ||
      typeof options.verifyAuthority !== "function" ||
      typeof options.verifyEnforcementProof !== "function"
    ) {
      fail("invalid_input");
    }
    this.db = options.db;
    this.idGenerator = options.idGenerator;
    this.verifyAuthority = options.verifyAuthority;
    this.verifyEnforcementProof = options.verifyEnforcementProof;
    this.retryDelayMs = boundedInteger(
      options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS,
      1,
      MAX_RETRY_DELAY_MS
    );
  }

  async findMaterializable(options: {
    readonly nowMs: number;
  }): Promise<RuntimeCompensationMaterializationCandidate | null> {
    const nowMs = nonNegativeInteger(options?.nowMs);
    const read = this.db.transaction(() => {
      const row = this.db
        .prepare(
          `SELECT incident.*
           FROM runtime_compensation_incidents incident
           JOIN runtime_run_command_dispatch source_dispatch
             ON source_dispatch.command_id = incident.source_command_id
           WHERE incident.trust_state = 'verified'
             AND incident.created_at_ms <= @nowMs
             AND source_dispatch.status = 'compensating'
             AND NOT EXISTS (
               SELECT 1 FROM runtime_compensation_effects effect
               WHERE effect.compensation_id = incident.compensation_id
             )
             AND NOT EXISTS (
               SELECT 1
               FROM runtime_compensation_commands command
               JOIN runtime_compensation_dispatch dispatch
                 ON dispatch.compensation_command_id = command.id
               WHERE command.compensation_id = incident.compensation_id
                 AND dispatch.status <> 'expired-before-dispatch'
             )
             AND (
               NOT EXISTS (
                 SELECT 1 FROM runtime_compensation_commands command
                 WHERE command.compensation_id = incident.compensation_id
               ) OR EXISTS (
                 SELECT 1
                 FROM runtime_compensation_commands command
                 JOIN runtime_compensation_dispatch dispatch
                   ON dispatch.compensation_command_id = command.id
                 WHERE command.compensation_id = incident.compensation_id
                   AND dispatch.status = 'expired-before-dispatch'
                   AND command.command_sequence = (
                     SELECT MAX(latest.command_sequence)
                     FROM runtime_compensation_commands latest
                     WHERE latest.compensation_id = incident.compensation_id
                   )
               )
             )
           ORDER BY incident.created_at_ms ASC, incident.compensation_id ASC
           LIMIT 1`
        )
        .get({ nowMs }) as SqlRow | undefined;
      if (!row) return null;
      return candidateFromIncident(this.verifiedIncident(row));
    });
    return read.immediate();
  }

  async materialize(
    unsafeInput: RuntimeCompensationMaterializationInput
  ): Promise<RuntimeCompensationMaterializationResult> {
    const input = snapshotMaterializationInput(unsafeInput);
    const commandJson = canonicalCommandJson(input.command);
    const commandDigest = sha256(commandJson);

    const materialize = this.db.transaction((): RuntimeCompensationMaterializationResult => {
      const incidentRow = this.incidentRow(input.compensationId);
      if (!incidentRow) fail("journal_conflict");
      const incident = this.verifiedIncident(incidentRow);
      if (!sameDigest(input.incidentDigest, incidentRow.incident_digest as string)) {
        fail("journal_conflict");
      }
      assertCommandMatchesIncident(input.command, incident, incidentRow);
      if (
        input.command.issuedAtMs < incident.createdAtMs ||
        input.authorityVerifiedAtMs < incident.createdAtMs ||
        input.materializedAtMs < incident.createdAtMs
      ) {
        fail("invalid_input");
      }
      requireSynchronousAuthority(this.verifyAuthority, input.command, input.authorityVerifiedAtMs);
      // Signing and the first verification deliberately happen outside this
      // transaction. Verify again at the actual durable materialization time;
      // a signature expiring between those instants must never become work.
      requireSynchronousAuthority(this.verifyAuthority, input.command, input.materializedAtMs);

      const existingById = this.commandRow(input.command.commandId);
      if (existingById) {
        const persisted = parsePersistedCommand(existingById);
        if (
          canonicalCommandJson(persisted) === commandJson &&
          existingById.compensation_id === input.compensationId &&
          existingById.command_digest === commandDigest &&
          existingById.authority_verified_at_ms === input.materializedAtMs
        ) {
          return "already-materialized";
        }
        fail("journal_conflict");
      }

      const active = this.db
        .prepare(
          `SELECT command.id
           FROM runtime_compensation_commands command
           JOIN runtime_compensation_dispatch dispatch
             ON dispatch.compensation_command_id = command.id
           WHERE command.compensation_id = ?
             AND dispatch.status <> 'expired-before-dispatch'
           LIMIT 1`
        )
        .get(input.compensationId);
      // Concurrent signers are harmless: the first durable command wins.
      if (active) return "already-materialized";

      const previous = this.db
        .prepare(
          `SELECT command.command_sequence, dispatch.status
           FROM runtime_compensation_commands command
           JOIN runtime_compensation_dispatch dispatch
             ON dispatch.compensation_command_id = command.id
           WHERE command.compensation_id = ?
           ORDER BY command.command_sequence DESC LIMIT 1`
        )
        .get(input.compensationId) as SqlRow | undefined;
      if (previous && previous.status !== "expired-before-dispatch") fail("journal_conflict");
      const commandSequence = previous ? positiveInteger(previous.command_sequence) + 1 : 1;
      if (!Number.isSafeInteger(commandSequence)) fail("journal_conflict");
      const previousCommandSequence = commandSequence === 1 ? null : commandSequence - 1;

      try {
        this.db
          .prepare(
            `INSERT INTO runtime_compensation_commands (
               id, compensation_id, source_command_id,
               command_sequence, previous_command_sequence, operation,
               session_id, team_id, project_id, agent_run_id,
               runtime_assignment_id, runtime_assignment_generation,
               sandbox_id, sandbox_generation, runtime_principal_id,
               observed_runtime_authorization_generation,
               source_required_effect_enforcer_set_digest,
               lifecycle_command_claims_digest, lifecycle_receipt_digest,
               lifecycle_enforcement_subject_digest, lifecycle_aggregate_proof_digest,
               platform_security_policy_revision, required_containment_enforcer_set_digest,
               safety_fence, reason_ref, causation_id, command_json,
               command_digest, authority_digest, created_at_ms,
               authority_verified_at_ms, deadline_at_ms
             ) VALUES (
               ?, ?, ?, ?, ?, 'safety.quarantine',
               ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
             )`
          )
          .run(
            input.command.commandId,
            incident.compensationId,
            incident.sourceCommandId,
            commandSequence,
            previousCommandSequence,
            incident.binding.sessionId,
            incident.binding.teamId,
            incident.binding.projectId,
            incidentRow.agent_run_id,
            incident.binding.runtimeAssignmentId,
            incident.binding.runtimeAssignmentGeneration,
            incident.binding.sandboxId,
            incident.binding.sandboxGeneration,
            incident.binding.runtimePrincipalId,
            incident.observedRuntimeAuthorizationGeneration,
            incident.sourceRequiredEffectEnforcerSetDigest,
            incident.lifecycleCommandClaimsDigest,
            incident.lifecycleReceiptDigest,
            incident.lifecycleEnforcementSubjectDigest,
            incident.lifecycleAggregateProofDigest,
            input.command.platformSecurityPolicyRevision,
            input.command.requiredContainmentEnforcerSetDigest,
            incident.safetyFence,
            incidentRow.incident_digest,
            incident.sourceCommandId,
            commandJson,
            commandDigest,
            input.command.authority.claimsDigest,
            input.command.issuedAtMs,
            input.materializedAtMs,
            input.command.deadlineAtMs
          );
        this.db
          .prepare(
            `INSERT INTO runtime_compensation_dispatch (
               compensation_command_id, compensation_id, source_command_id,
               status, attempts, available_at_ms, lease_owner, lease_expires_at_ms,
               dispatch_interlock_acquired_at_ms, last_safe_error_code,
               created_at_ms, updated_at_ms, terminal_at_ms
             ) VALUES (?, ?, ?, 'pending', 0, ?, NULL, NULL, NULL, NULL, ?, ?, NULL)`
          )
          .run(
            input.command.commandId,
            incident.compensationId,
            incident.sourceCommandId,
            input.materializedAtMs,
            input.materializedAtMs,
            input.materializedAtMs
          );
      } catch (error) {
        if (error instanceof RuntimeCompensationJournalError) throw error;
        fail("journal_conflict");
      }
      return "created";
    });
    return materialize.immediate();
  }

  async reconcile(options: RuntimeCompensationReconcileOptions): Promise<void> {
    const nowMs = nonNegativeInteger(options?.nowMs);
    const retryAtMs = safeAdd(nowMs, this.retryDelayMs);
    const reconcile = this.db.transaction(() => {
      try {
        this.db
          .prepare(
            `UPDATE runtime_compensation_dispatch AS dispatch
             SET status = 'expired-before-dispatch', lease_owner = NULL,
                 lease_expires_at_ms = NULL, last_safe_error_code = 'deadline_expired',
                 updated_at_ms = @nowMs, terminal_at_ms = @nowMs
             WHERE status = 'pending' AND EXISTS (
               SELECT 1 FROM runtime_compensation_commands command
               WHERE command.id = dispatch.compensation_command_id
                 AND (command.deadline_at_ms <= @nowMs OR
                   COALESCE(json_extract(command.command_json, '$.authority.expiresAtMs'), 0)
                     <= @nowMs)
             )`
          )
          .run({ nowMs });
        this.db
          .prepare(
            `UPDATE runtime_compensation_dispatch AS dispatch
             SET status = 'expired-before-dispatch', lease_owner = NULL,
                 lease_expires_at_ms = NULL, last_safe_error_code = 'deadline_expired',
                 updated_at_ms = @nowMs, terminal_at_ms = @nowMs
             WHERE status = 'processing' AND lease_expires_at_ms <= @nowMs
               AND dispatch_interlock_acquired_at_ms IS NULL
               AND EXISTS (
                 SELECT 1 FROM runtime_compensation_commands command
                 WHERE command.id = dispatch.compensation_command_id
                   AND (command.deadline_at_ms <= @nowMs OR
                     COALESCE(json_extract(command.command_json, '$.authority.expiresAtMs'), 0)
                       <= @nowMs)
               )`
          )
          .run({ nowMs });
        this.db
          .prepare(
            `UPDATE runtime_compensation_dispatch AS dispatch
             SET status = 'pending', available_at_ms = MAX(available_at_ms, @retryAtMs),
                 lease_owner = NULL, lease_expires_at_ms = NULL,
                 last_safe_error_code = 'lease_expired_before_dispatch',
                 updated_at_ms = @nowMs
             WHERE status = 'processing' AND lease_expires_at_ms <= @nowMs
               AND dispatch_interlock_acquired_at_ms IS NULL
               AND EXISTS (
                 SELECT 1 FROM runtime_compensation_commands command
                 WHERE command.id = dispatch.compensation_command_id
                   AND command.deadline_at_ms > @nowMs
                   AND COALESCE(
                     json_extract(command.command_json, '$.authority.expiresAtMs') > @nowMs,
                     0
                   )
               )`
          )
          .run({ nowMs, retryAtMs });
        this.db
          .prepare(
            `UPDATE runtime_compensation_dispatch
             SET status = 'awaiting-receipt',
                 available_at_ms = MAX(available_at_ms, @nowMs),
                 lease_owner = NULL, lease_expires_at_ms = NULL,
                 last_safe_error_code = 'lease_expired_dispatch_uncertain',
                 updated_at_ms = @nowMs
             WHERE status = 'processing' AND lease_expires_at_ms <= @nowMs
               AND dispatch_interlock_acquired_at_ms IS NOT NULL`
          )
          .run({ nowMs });
      } catch {
        fail("journal_conflict");
      }
    });
    reconcile.immediate();
  }

  async claim(
    options: RuntimeCompensationClaimOptions
  ): Promise<RuntimeCompensationDelivery | null> {
    const workerId = safeIdentifier(options?.workerId, MAX_WORKER_ID_LENGTH);
    const leaseDurationMs = boundedInteger(options?.leaseDurationMs, 1, 300_000);
    const nowMs = nonNegativeInteger(options?.nowMs);
    const leaseExpiresAtMs = safeAdd(nowMs, leaseDurationMs);

    const claim = this.db.transaction((): RuntimeCompensationDelivery | null => {
      const row = this.db
        .prepare(
          `SELECT command.*
           FROM runtime_compensation_commands command
           JOIN runtime_compensation_dispatch dispatch
             ON dispatch.compensation_command_id = command.id
           JOIN runtime_compensation_incidents incident
             ON incident.compensation_id = command.compensation_id
           JOIN runtime_run_command_dispatch source_dispatch
             ON source_dispatch.command_id = incident.source_command_id
           WHERE dispatch.status = 'pending' AND dispatch.available_at_ms <= @nowMs
             AND command.deadline_at_ms > @nowMs
             AND COALESCE(
               json_extract(command.command_json, '$.authority.expiresAtMs') > @nowMs,
               0
             )
             AND incident.trust_state = 'verified'
             AND source_dispatch.status = 'compensating'
             AND NOT EXISTS (
               SELECT 1 FROM runtime_compensation_receipts receipt
               WHERE receipt.compensation_command_id = command.id
             )
             AND NOT EXISTS (
               SELECT 1 FROM runtime_compensation_effects effect
               WHERE effect.compensation_id = incident.compensation_id
             )
           ORDER BY dispatch.available_at_ms ASC, command.created_at_ms ASC, command.id ASC
           LIMIT 1`
        )
        .get({ nowMs }) as CommandRow | undefined;
      if (!row) return null;
      const command = this.attestedCommand(row, nowMs);
      const updated = this.db
        .prepare(
          `UPDATE runtime_compensation_dispatch
           SET status = 'processing', attempts = attempts + 1,
               lease_owner = ?, lease_expires_at_ms = ?, updated_at_ms = ?,
               last_safe_error_code = NULL, dispatch_interlock_acquired_at_ms = NULL
           WHERE compensation_command_id = ? AND status = 'pending'
             AND available_at_ms <= ?
           RETURNING attempts`
        )
        .get(workerId, leaseExpiresAtMs, nowMs, command.commandId, nowMs) as SqlRow | undefined;
      if (!updated) return null;
      return Object.freeze({
        command,
        attempt: positiveInteger(updated.attempts),
        leaseOwner: workerId,
        leaseExpiresAtMs,
        priorDispatchCertainty: "not-dispatched" as const,
      });
    });
    return claim.immediate();
  }

  async renew(options: RuntimeCompensationRenewalOptions): Promise<RuntimeCompensationRenewal> {
    const commandId = safeIdentifier(options?.commandId, MAX_IDENTIFIER_LENGTH);
    const workerId = safeIdentifier(options?.workerId, MAX_WORKER_ID_LENGTH);
    const expectedAttempt = positiveInteger(options?.expectedAttempt);
    const expectedLeaseExpiresAtMs = nonNegativeInteger(options?.expectedLeaseExpiresAtMs);
    const leaseDurationMs = boundedInteger(options?.leaseDurationMs, 1, 300_000);
    const nowMs = nonNegativeInteger(options?.nowMs);

    const renew = this.db.transaction((): RuntimeCompensationRenewal => {
      const row = this.completionRow(commandId);
      if (
        row &&
        row.dispatch_status === "processing" &&
        row.attempts === expectedAttempt &&
        row.lease_owner === workerId &&
        row.lease_expires_at_ms === expectedLeaseExpiresAtMs &&
        row.dispatch_interlock_acquired_at_ms === null &&
        nowMs >= expectedLeaseExpiresAtMs
      ) {
        const updated = this.db
          .prepare(
            `UPDATE runtime_compensation_dispatch
             SET status = 'expired-before-dispatch', lease_owner = NULL,
                 lease_expires_at_ms = NULL,
                 last_safe_error_code = 'lease_expired_before_dispatch',
                 updated_at_ms = ?, terminal_at_ms = ?
             WHERE compensation_command_id = ? AND status = 'processing'
               AND attempts = ? AND lease_owner = ? AND lease_expires_at_ms = ?
               AND dispatch_interlock_acquired_at_ms IS NULL`
          )
          .run(nowMs, nowMs, commandId, expectedAttempt, workerId, expectedLeaseExpiresAtMs);
        if (updated.changes !== 1) fail("stale_completion");
        return Object.freeze({ kind: "expired-before-dispatch" as const });
      }
      if (!row || !this.hasLease(row, workerId, expectedAttempt, expectedLeaseExpiresAtMs, nowMs)) {
        fail("stale_completion");
      }
      if (row.dispatch_interlock_acquired_at_ms !== null) fail("stale_completion");

      const persistedCommand = parsePersistedCommand(row);
      if (
        persistedCommand.deadlineAtMs <= nowMs ||
        persistedCommand.authority.expiresAtMs <= nowMs
      ) {
        const updated = this.db
          .prepare(
            `UPDATE runtime_compensation_dispatch
             SET status = 'expired-before-dispatch', lease_owner = NULL,
                 lease_expires_at_ms = NULL, last_safe_error_code = 'deadline_expired',
                 updated_at_ms = ?, terminal_at_ms = ?
             WHERE compensation_command_id = ? AND status = 'processing'
               AND attempts = ? AND lease_owner = ? AND lease_expires_at_ms = ?
               AND dispatch_interlock_acquired_at_ms IS NULL`
          )
          .run(nowMs, nowMs, commandId, expectedAttempt, workerId, expectedLeaseExpiresAtMs);
        if (updated.changes !== 1) fail("stale_completion");
        return Object.freeze({ kind: "expired-before-dispatch" as const });
      }
      this.attestedCommand(row, nowMs);

      const requestedExpiry = safeAdd(nowMs, leaseDurationMs);
      const leaseExpiresAtMs = Math.max(expectedLeaseExpiresAtMs, requestedExpiry);
      const updated = this.db
        .prepare(
          `UPDATE runtime_compensation_dispatch
           SET lease_expires_at_ms = ?, updated_at_ms = ?,
               dispatch_interlock_acquired_at_ms = ?
           WHERE compensation_command_id = ? AND status = 'processing'
             AND attempts = ? AND lease_owner = ? AND lease_expires_at_ms = ?
             AND lease_expires_at_ms > ?
             AND dispatch_interlock_acquired_at_ms IS NULL
             AND NOT EXISTS (
               SELECT 1 FROM runtime_compensation_receipts receipt
               WHERE receipt.compensation_command_id = runtime_compensation_dispatch.compensation_command_id
             )`
        )
        .run(
          leaseExpiresAtMs,
          nowMs,
          nowMs,
          commandId,
          expectedAttempt,
          workerId,
          expectedLeaseExpiresAtMs,
          nowMs
        );
      if (updated.changes !== 1) fail("stale_completion");
      return Object.freeze({ kind: "renewed" as const, leaseExpiresAtMs });
    });
    return renew.immediate();
  }

  async complete(unsafeCompletion: RuntimeCompensationCompletion): Promise<void> {
    let completion = validateCompletion(unsafeCompletion);
    if (completion.outcome.kind === "receipt") {
      const row = this.completionRow(completion.commandId);
      if (!row) fail("stale_completion");
      const command = parsePersistedCommand(row);
      let receipt: RuntimeCompensationReceipt;
      try {
        receipt = snapshotRuntimeCompensationReceiptForCommand(completion.outcome.receipt, command);
      } catch {
        fail("invalid_input");
      }
      completion = Object.freeze({
        ...completion,
        outcome: Object.freeze({ kind: "receipt" as const, receipt }),
      });
    }

    const settle = this.db.transaction(() => {
      const row = this.completionRow(completion.commandId);
      if (!row) fail("stale_completion");

      if (!this.hasCompletionLease(row, completion)) {
        if (
          completion.outcome.kind === "receipt" &&
          this.hasExactSettledReceipt(row, completion.outcome.receipt)
        ) {
          return;
        }
        fail("stale_completion");
      }

      if (completion.outcome.kind === "failure") {
        this.completeFailure(row, completion);
        return;
      }

      const command = this.attestedCommand(row, row.authority_verified_at_ms);
      let receipt: RuntimeCompensationReceipt;
      try {
        receipt = snapshotRuntimeCompensationReceiptForCommand(completion.outcome.receipt, command);
        verifyRuntimeCompensationReceiptEnforcementProofSynchronously(
          command,
          receipt,
          this.verifyEnforcementProof
        );
      } catch {
        fail("invalid_input");
      }
      try {
        this.settleReceipt(
          row,
          Object.freeze({
            kind: "dispatch" as const,
            actorRef: completion.workerId,
            observedAtMs: completion.observedAtMs,
            expectedAttempt: completion.expectedAttempt,
            expectedLeaseExpiresAtMs: completion.expectedLeaseExpiresAtMs,
          }),
          receipt
        );
      } catch (error) {
        if (error instanceof ContainmentSettlementRejection) fail("invalid_input");
        throw error;
      }
    });
    settle.immediate();
  }

  /**
   * Settle one receipt authenticated by the private compensation follow
   * channel. The caller must already own the follow journal's IMMEDIATE
   * transaction so receipt truth, the cursor event, and stream advancement
   * can commit or roll back together.
   */
  settleVerifiedReceiptInTransaction(
    unsafeInput: RuntimeCompensationReceiptFollowSettlementInput
  ): RuntimeCompensationReceiptFollowSettlementResult {
    if (!this.db.inTransaction) fail("journal_conflict");
    const input = exactDataRecord(unsafeInput, [
      "observation",
      "command",
      "receivedAtMs",
      "actorRef",
    ]);
    const observation = dataField(input, "observation");
    if (!isVerifiedRuntimeCompensationReceiptObservation(observation)) fail("invalid_input");
    const command = snapshotCompensationCommand(dataField(input, "command"));
    const receivedAtMs = nonNegativeInteger(dataField(input, "receivedAtMs"));
    const actorRef = safeIdentifier(dataField(input, "actorRef"), MAX_WORKER_ID_LENGTH);
    if (receivedAtMs < observation.observedAtMs) fail("invalid_input");

    const row = this.completionRow(command.commandId);
    if (!row || row.dispatch_status !== "awaiting-receipt") fail("stale_completion");
    const persistedCommand = this.attestedCommand(row, row.authority_verified_at_ms);
    if (
      canonicalCommandJson(command) !== canonicalCommandJson(persistedCommand) ||
      digestRuntimeCommandClaims(command) !== command.authority.claimsDigest
    ) {
      fail("invalid_command");
    }
    assertObservationMatchesCommand(observation, persistedCommand);

    let receipt: RuntimeCompensationReceipt;
    try {
      receipt = snapshotRuntimeCompensationReceiptForCommand(observation.receipt, persistedCommand);
      if (
        !sameDigest(
          observation.receiptDigest,
          digestRuntimeCompensationReceiptForObservation(receipt, persistedCommand)
        )
      ) {
        throw new TypeError("Invalid observation receipt digest");
      }
      verifyRuntimeCompensationReceiptEnforcementProofSynchronously(
        persistedCommand,
        receipt,
        this.verifyEnforcementProof
      );
    } catch {
      throw new RuntimeCompensationReceiptFollowSettlementRejection(
        "enforcement_proof_verification_failed"
      );
    }

    try {
      return this.settleReceipt(
        row,
        Object.freeze({
          kind: "follow" as const,
          actorRef,
          observedAtMs: receivedAtMs,
        }),
        receipt
      );
    } catch (error) {
      if (error instanceof ContainmentSettlementRejection) {
        throw new RuntimeCompensationReceiptFollowSettlementRejection(
          "enforcement_proof_verification_failed"
        );
      }
      throw error;
    }
  }

  private completeFailure(
    row: CompletionRow,
    completion: ReturnType<typeof validateCompletion>
  ): void {
    if (completion.outcome.kind !== "failure") fail("invalid_input");
    const markerAcquired = row.dispatch_interlock_acquired_at_ms !== null;
    if (markerAcquired) {
      // The durable marker dominates an in-process certainty label. Once set,
      // a crash can make any local "not dispatched" conclusion unrecoverable.
      const updated = this.db
        .prepare(
          `UPDATE runtime_compensation_dispatch
           SET status = 'awaiting-receipt', available_at_ms = MAX(available_at_ms, ?),
               lease_owner = NULL, lease_expires_at_ms = NULL,
               last_safe_error_code = ?, updated_at_ms = ?
           WHERE compensation_command_id = ? AND status = 'processing'
             AND attempts = ? AND lease_owner = ? AND lease_expires_at_ms = ?
             AND dispatch_interlock_acquired_at_ms IS NOT NULL`
        )
        .run(
          completion.observedAtMs,
          safeErrorCode(completion.outcome.code),
          completion.observedAtMs,
          row.id,
          completion.expectedAttempt,
          completion.workerId,
          completion.expectedLeaseExpiresAtMs
        );
      if (updated.changes !== 1) fail("stale_completion");
      return;
    }
    if (completion.outcome.dispatchCertainty !== "not-dispatched") fail("invalid_input");

    if (
      completion.outcome.code === "deadline_expired" ||
      completion.outcome.code === "lease_expired_before_dispatch"
    ) {
      const updated = this.db
        .prepare(
          `UPDATE runtime_compensation_dispatch
           SET status = 'expired-before-dispatch', lease_owner = NULL,
               lease_expires_at_ms = NULL, last_safe_error_code = ?,
               updated_at_ms = ?, terminal_at_ms = ?
           WHERE compensation_command_id = ? AND status = 'processing'
             AND attempts = ? AND lease_owner = ? AND lease_expires_at_ms = ?
             AND dispatch_interlock_acquired_at_ms IS NULL`
        )
        .run(
          completion.outcome.code,
          completion.observedAtMs,
          completion.observedAtMs,
          row.id,
          completion.expectedAttempt,
          completion.workerId,
          completion.expectedLeaseExpiresAtMs
        );
      if (updated.changes !== 1) fail("stale_completion");
      return;
    }

    const availableAtMs = safeAdd(completion.observedAtMs, this.retryDelayMs);
    const updated = this.db
      .prepare(
        `UPDATE runtime_compensation_dispatch
         SET status = 'pending', available_at_ms = ?, lease_owner = NULL,
             lease_expires_at_ms = NULL, last_safe_error_code = ?, updated_at_ms = ?
         WHERE compensation_command_id = ? AND status = 'processing'
           AND attempts = ? AND lease_owner = ? AND lease_expires_at_ms = ?
           AND dispatch_interlock_acquired_at_ms IS NULL`
      )
      .run(
        availableAtMs,
        safeErrorCode(completion.outcome.code),
        completion.observedAtMs,
        row.id,
        completion.expectedAttempt,
        completion.workerId,
        completion.expectedLeaseExpiresAtMs
      );
    if (updated.changes !== 1) fail("stale_completion");
  }

  private settleReceipt(
    row: CompletionRow,
    settlement: ReceiptSettlementContext,
    rawReceipt: RuntimeCompensationReceipt
  ): RuntimeCompensationReceiptFollowSettlementResult {
    const persisted = sanitizeReceiptForPersistence(rawReceipt);
    const receiptDigest = digestCompensationReceipt(persisted);
    const effective = effectiveReceipt(persisted);
    // Reject insufficient containment before any receipt/event/effect write.
    // The outer follow transaction may catch this narrow rejection in order to
    // quarantine its stream without accepting the observation cursor.
    if (effective.outcome === "enforced") {
      this.assertAndAdvanceSafetyFence(row, effective.enforcedSafetyFence, settlement.observedAtMs);
    }
    const receiptId = this.insertReceipt(row, persisted, receiptDigest, settlement.observedAtMs);

    if (effective.outcome === "accepted") {
      this.parkAcceptedDispatch(row, settlement);
      return Object.freeze({ receiptId, effectiveReceiptDigest: receiptDigest });
    }

    if (effective.outcome === "enforced") {
      this.applyEnforcedReceipt(row, settlement, persisted, receiptId, receiptDigest, effective);
      return Object.freeze({ receiptId, effectiveReceiptDigest: receiptDigest });
    }

    const safeCode =
      effective.outcome === "rejected" ? "compensation_rejected" : "compensation_quarantined";
    this.blockDispatch(row, settlement, safeCode);
    return Object.freeze({ receiptId, effectiveReceiptDigest: receiptDigest });
  }

  private parkAcceptedDispatch(row: CompletionRow, settlement: ReceiptSettlementContext): void {
    const baseSql = `UPDATE runtime_compensation_dispatch
      SET status = 'awaiting-receipt', available_at_ms = MAX(available_at_ms, ?),
          lease_owner = NULL, lease_expires_at_ms = NULL,
          last_safe_error_code = NULL, updated_at_ms = ?
      WHERE compensation_command_id = ?`;
    const updated =
      settlement.kind === "dispatch"
        ? this.db
            .prepare(
              `${baseSql} AND status = 'processing' AND attempts = ?
                 AND lease_owner = ? AND lease_expires_at_ms = ?
                 AND dispatch_interlock_acquired_at_ms IS NOT NULL`
            )
            .run(
              settlement.observedAtMs,
              settlement.observedAtMs,
              row.id,
              settlement.expectedAttempt,
              settlement.actorRef,
              settlement.expectedLeaseExpiresAtMs
            )
        : this.db
            .prepare(
              `${baseSql} AND status = 'awaiting-receipt'
                 AND lease_owner IS NULL AND lease_expires_at_ms IS NULL`
            )
            .run(settlement.observedAtMs, settlement.observedAtMs, row.id);
    if (updated.changes !== 1) {
      fail(settlement.kind === "dispatch" ? "stale_completion" : "journal_conflict");
    }
  }

  private blockDispatch(
    row: CompletionRow,
    settlement: ReceiptSettlementContext,
    safeCode: "compensation_rejected" | "compensation_quarantined"
  ): void {
    const baseSql = `UPDATE runtime_compensation_dispatch
      SET status = 'blocked', lease_owner = NULL, lease_expires_at_ms = NULL,
          last_safe_error_code = ?, updated_at_ms = ?, terminal_at_ms = ?
      WHERE compensation_command_id = ?`;
    const updated =
      settlement.kind === "dispatch"
        ? this.db
            .prepare(
              `${baseSql} AND status = 'processing' AND attempts = ?
                 AND lease_owner = ? AND lease_expires_at_ms = ?
                 AND dispatch_interlock_acquired_at_ms IS NOT NULL`
            )
            .run(
              safeCode,
              settlement.observedAtMs,
              settlement.observedAtMs,
              row.id,
              settlement.expectedAttempt,
              settlement.actorRef,
              settlement.expectedLeaseExpiresAtMs
            )
        : this.db
            .prepare(
              `${baseSql} AND status = 'awaiting-receipt'
                 AND lease_owner IS NULL AND lease_expires_at_ms IS NULL`
            )
            .run(safeCode, settlement.observedAtMs, settlement.observedAtMs, row.id);
    if (updated.changes !== 1) {
      fail(settlement.kind === "dispatch" ? "stale_completion" : "journal_conflict");
    }
  }

  private applyEnforcedReceipt(
    row: CompletionRow,
    settlement: ReceiptSettlementContext,
    receipt: RuntimeCompensationReceipt,
    receiptId: string,
    receiptDigest: string,
    effective: Extract<NonDuplicateRuntimeCompensationReceipt, { outcome: "enforced" }>
  ): void {
    const sequence = this.nextSessionSequence(row.session_id);
    const effectDigest = sha256(
      canonicalRuntimeJson({
        compensationId: row.compensation_id,
        sourceCommandId: row.source_command_id,
        compensationCommandId: row.id,
        commandDigest: row.command_digest,
        receiptDigest,
        receiptId,
        enforcedSafetyFence: effective.enforcedSafetyFence,
        appliedSessionSequence: sequence,
      })
    );
    const payload = {
      compensationId: row.compensation_id,
      sourceCommandId: row.source_command_id,
      compensationCommandId: row.id,
      receiptId,
      effectDigest,
      agentRunId: row.agent_run_id,
      enforcedSafetyFence: effective.enforcedSafetyFence,
    };
    this.db
      .prepare(
        `INSERT INTO session_events (
           session_id, sequence, event_id, type, occurred_at_ms,
           actor_kind, actor_user_id, actor_display_name,
           source_scope, source_key, payload_json
         ) VALUES (?, ?, ?, 'run.runtime-command.compensated', ?,
           'system', ?, 'Runtime Compensation Supervisor',
           'runtime-compensation', ?, ?)`
      )
      .run(
        row.session_id,
        sequence,
        this.nextId(),
        settlement.observedAtMs,
        settlement.actorRef,
        safeIdentifier(`receipt:${row.id}:${receiptDigest}`, 1_000),
        canonicalRuntimeJson(payload)
      );
    this.db
      .prepare(
        `INSERT INTO runtime_compensation_effects (
           compensation_id, source_command_id, compensation_command_id,
           receipt_id, receipt_outcome, session_id, agent_run_id,
           applied_session_sequence, effect_digest, applied_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        row.compensation_id,
        row.source_command_id,
        row.id,
        receiptId,
        receipt.outcome,
        row.session_id,
        row.agent_run_id,
        sequence,
        effectDigest,
        settlement.observedAtMs
      );
    this.enforceDispatch(row, settlement);

    const sourceUpdated = this.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'quarantined', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = 'stale_enforced_effect_compensated',
             updated_at_ms = ?, terminal_at_ms = ?
         WHERE command_id = ? AND status = 'compensating'`
      )
      .run(settlement.observedAtMs, settlement.observedAtMs, row.source_command_id);
    if (sourceUpdated.changes !== 1) fail("journal_conflict");
  }

  private enforceDispatch(row: CompletionRow, settlement: ReceiptSettlementContext): void {
    const baseSql = `UPDATE runtime_compensation_dispatch
      SET status = 'enforced', lease_owner = NULL, lease_expires_at_ms = NULL,
          last_safe_error_code = NULL, updated_at_ms = ?, terminal_at_ms = ?
      WHERE compensation_command_id = ?`;
    const updated =
      settlement.kind === "dispatch"
        ? this.db
            .prepare(
              `${baseSql} AND status = 'processing' AND attempts = ?
                 AND lease_owner = ? AND lease_expires_at_ms = ?
                 AND dispatch_interlock_acquired_at_ms IS NOT NULL`
            )
            .run(
              settlement.observedAtMs,
              settlement.observedAtMs,
              row.id,
              settlement.expectedAttempt,
              settlement.actorRef,
              settlement.expectedLeaseExpiresAtMs
            )
        : this.db
            .prepare(
              `${baseSql} AND status = 'awaiting-receipt'
                 AND lease_owner IS NULL AND lease_expires_at_ms IS NULL`
            )
            .run(settlement.observedAtMs, settlement.observedAtMs, row.id);
    if (updated.changes !== 1) {
      fail(settlement.kind === "dispatch" ? "stale_completion" : "journal_conflict");
    }
  }

  private insertReceipt(
    row: CompletionRow,
    receipt: RuntimeCompensationReceipt,
    receiptDigest: string,
    observedAtMs: number
  ): string {
    const exact = this.db
      .prepare(
        `SELECT id FROM runtime_compensation_receipts
         WHERE compensation_command_id = ? AND receipt_digest = ?`
      )
      .get(row.id, receiptDigest) as SqlRow | undefined;
    if (exact) return safeIdentifier(exact.id, MAX_IDENTIFIER_LENGTH);

    const latest = this.db
      .prepare(
        `SELECT version FROM runtime_compensation_receipts
         WHERE compensation_command_id = ? ORDER BY version DESC LIMIT 1`
      )
      .get(row.id) as SqlRow | undefined;
    const version = latest ? positiveInteger(latest.version) + 1 : 1;
    if (!Number.isSafeInteger(version)) fail("journal_conflict");
    const previousVersion = version === 1 ? null : version - 1;
    const receiptId = this.nextId();
    const effective = effectiveReceipt(receipt);
    const proof =
      effective.outcome === "enforced" ? effective.aggregateEnforcementProof : undefined;
    if (effective.outcome === "enforced" && !proof) fail("invalid_input");
    const originalOutcome =
      receipt.outcome === "duplicate" ? receipt.originalReceipt.outcome : null;
    const originalReceiptDigest =
      receipt.outcome === "duplicate" ? receipt.originalReceiptDigest : null;
    const effectRefCommitment =
      effective.outcome === "accepted" ||
      effective.outcome === "enforced" ||
      effective.outcome === "quarantined"
        ? effective.effectRef
        : null;

    try {
      this.db
        .prepare(
          `INSERT INTO runtime_compensation_receipts (
             id, compensation_command_id, compensation_id, source_command_id,
             version, previous_version, session_id, team_id, project_id, agent_run_id,
             runtime_assignment_id, runtime_assignment_generation,
             sandbox_id, sandbox_generation, runtime_principal_id,
             observed_runtime_authorization_generation, command_digest,
             enforced_safety_fence, outcome, original_outcome, original_receipt_digest,
             receipt_json, receipt_digest, required_containment_enforcer_set_digest,
             effect_ref_commitment, enforcement_subject_digest, aggregate_proof_digest,
             proof_verified_at_ms, received_at_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          receiptId,
          row.id,
          row.compensation_id,
          row.source_command_id,
          version,
          previousVersion,
          row.session_id,
          row.team_id,
          row.project_id,
          row.agent_run_id,
          row.runtime_assignment_id,
          row.runtime_assignment_generation,
          row.sandbox_id,
          row.sandbox_generation,
          row.runtime_principal_id,
          row.observed_runtime_authorization_generation,
          row.command_digest,
          effective.outcome === "enforced" ? effective.enforcedSafetyFence : null,
          receipt.outcome,
          originalOutcome,
          originalReceiptDigest,
          canonicalRuntimeJson(receipt),
          receiptDigest,
          proof?.requiredEffectEnforcerSetDigest ?? null,
          effectRefCommitment,
          proof?.enforcementSubjectDigest ?? null,
          proof?.aggregateProofDigest ?? null,
          proof ? observedAtMs : null,
          observedAtMs
        );
    } catch (error) {
      if (error instanceof RuntimeCompensationJournalError) throw error;
      fail("journal_conflict");
    }
    return receiptId;
  }

  private hasExactSettledReceipt(
    row: CompletionRow,
    rawReceipt: RuntimeCompensationReceipt
  ): boolean {
    try {
      const receipt = sanitizeReceiptForPersistence(rawReceipt);
      const digest = digestCompensationReceipt(receipt);
      const exact = this.db
        .prepare(
          `SELECT 1 FROM runtime_compensation_receipts
           WHERE compensation_command_id = ? AND receipt_digest = ?`
        )
        .get(row.id, digest);
      if (!exact) return false;
      const effective = effectiveReceipt(receipt);
      if (effective.outcome === "accepted") {
        return (
          row.dispatch_status === "awaiting-receipt" ||
          row.dispatch_status === "enforced" ||
          row.dispatch_status === "blocked"
        );
      }
      if (effective.outcome === "enforced") {
        return (
          row.dispatch_status === "enforced" &&
          Boolean(
            this.db
              .prepare(
                `SELECT 1 FROM runtime_compensation_effects
                 WHERE compensation_command_id = ? AND compensation_id = ?`
              )
              .get(row.id, row.compensation_id)
          )
        );
      }
      return row.dispatch_status === "blocked";
    } catch {
      return false;
    }
  }

  private nextSessionSequence(sessionId: string): number {
    const session = this.db
      .prepare(`SELECT next_sequence FROM sessions WHERE id = ?`)
      .get(sessionId) as SqlRow | undefined;
    if (!session) fail("journal_conflict");
    const sequence = positiveInteger(session.next_sequence);
    const updated = this.db
      .prepare(
        `UPDATE sessions
         SET next_sequence = next_sequence + 1,
             run_state_revision = run_state_revision + 1
         WHERE id = ? AND next_sequence = ?`
      )
      .run(sessionId, sequence);
    if (updated.changes !== 1) fail("journal_conflict");
    return sequence;
  }

  private assertAndAdvanceSafetyFence(row: CommandRow, enforcedFence: number, nowMs: number): void {
    const safety = this.db
      .prepare(
        `SELECT allocated_fence FROM runtime_binding_safety_fences
         WHERE team_id = ? AND project_id = ? AND session_id = ?
           AND runtime_assignment_id = ? AND runtime_assignment_generation = ?
           AND sandbox_id = ? AND sandbox_generation = ? AND runtime_principal_id = ?`
      )
      .get(...bindingSqlValues(row)) as SqlRow | undefined;
    if (!safety) fail("journal_conflict");
    const allocatedFence = positiveInteger(safety.allocated_fence);

    // Current values do not decide whether the historical command dispatches,
    // but the proof-backed *result* must contain every authority fence that
    // advanced while it ran. Never invent a local fence higher than Runtime's
    // authenticated result.
    const high = this.db
      .prepare(
        `SELECT session.control_epoch, session.steering_revision,
                session.runtime_authorization_generation,
                COALESCE((SELECT MAX(run.state_version) FROM agent_runs run
                  WHERE run.session_id = @sessionId
                    AND run.runtime_assignment_id = @assignmentId), 0) AS run_state_fence,
                COALESCE((SELECT MAX(command.target_run_state_version)
                  FROM runtime_run_commands command
                  WHERE command.session_id = @sessionId
                    AND command.runtime_assignment_id = @assignmentId
                    AND command.runtime_assignment_generation = @assignmentGeneration
                    AND command.sandbox_id = @sandboxId
                    AND command.sandbox_generation = @sandboxGeneration
                    AND command.runtime_principal_id = @principalId), 0) AS command_fence,
                COALESCE((SELECT MAX(json_extract(
                  receipt.receipt_json,
                  CASE WHEN receipt.outcome = 'duplicate'
                    THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
                ))
                  FROM runtime_run_command_receipts receipt
                  JOIN runtime_run_commands command ON command.id = receipt.command_id
                  WHERE command.session_id = @sessionId
                    AND command.runtime_assignment_id = @assignmentId
                    AND command.runtime_assignment_generation = @assignmentGeneration
                    AND command.sandbox_id = @sandboxId
                    AND command.sandbox_generation = @sandboxGeneration
                    AND command.runtime_principal_id = @principalId
                    AND (receipt.outcome = 'enforced' OR
                      (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced'))
                ), 0) AS lifecycle_receipt_fence,
                COALESCE((SELECT MAX(receipt.enforced_safety_fence)
                  FROM runtime_compensation_effects effect
                  JOIN runtime_compensation_receipts receipt
                    ON receipt.id = effect.receipt_id
                  JOIN runtime_compensation_commands compensation_command
                    ON compensation_command.id = effect.compensation_command_id
                  WHERE compensation_command.session_id = @sessionId
                    AND compensation_command.runtime_assignment_id = @assignmentId
                    AND compensation_command.runtime_assignment_generation = @assignmentGeneration
                    AND compensation_command.sandbox_id = @sandboxId
                    AND compensation_command.sandbox_generation = @sandboxGeneration
                    AND compensation_command.runtime_principal_id = @principalId
                ), 0) AS prior_compensation_fence
         FROM sessions session WHERE session.id = @sessionId`
      )
      .get({
        sessionId: row.session_id,
        assignmentId: row.runtime_assignment_id,
        assignmentGeneration: row.runtime_assignment_generation,
        sandboxId: row.sandbox_id,
        sandboxGeneration: row.sandbox_generation,
        principalId: row.runtime_principal_id,
      }) as SqlRow | undefined;
    if (!high) fail("journal_conflict");
    const durableAuthorityHighWater = Math.max(
      nonNegativeInteger(high.control_epoch),
      nonNegativeInteger(high.steering_revision),
      nonNegativeInteger(high.runtime_authorization_generation),
      nonNegativeInteger(high.run_state_fence),
      nonNegativeInteger(high.command_fence),
      nonNegativeInteger(high.lifecycle_receipt_fence),
      nonNegativeInteger(high.prior_compensation_fence)
    );
    if (enforcedFence < allocatedFence || enforcedFence <= durableAuthorityHighWater) {
      throw new ContainmentSettlementRejection();
    }
    if (enforcedFence === allocatedFence) return;
    const updated = this.db
      .prepare(
        `UPDATE runtime_binding_safety_fences
         SET allocated_fence = ?, updated_at_ms = ?
         WHERE team_id = ? AND project_id = ? AND session_id = ?
           AND runtime_assignment_id = ? AND runtime_assignment_generation = ?
           AND sandbox_id = ? AND sandbox_generation = ? AND runtime_principal_id = ?
           AND allocated_fence = ?`
      )
      .run(enforcedFence, nowMs, ...bindingSqlValues(row), allocatedFence);
    if (updated.changes !== 1) fail("journal_conflict");
  }

  private attestedCommand(row: CommandRow, nowMs: number): RuntimeCompensationCommand {
    const command = parsePersistedCommand(row);
    const incidentRow = this.incidentRow(row.compensation_id);
    if (!incidentRow) fail("invalid_command");
    const incident = this.verifiedIncident(incidentRow);
    assertCommandMatchesIncident(command, incident, incidentRow);
    if (
      row.authority_verified_at_ms < command.issuedAtMs ||
      row.authority_verified_at_ms >= command.deadlineAtMs ||
      row.authority_verified_at_ms < command.authority.issuedAtMs ||
      row.authority_verified_at_ms >= command.authority.expiresAtMs
    ) {
      fail("invalid_command");
    }
    const source = this.db
      .prepare(
        `SELECT dispatch.status,
                EXISTS(SELECT 1 FROM runtime_compensation_effects effect
                  WHERE effect.compensation_id = ?) AS has_effect
         FROM runtime_run_command_dispatch dispatch WHERE dispatch.command_id = ?`
      )
      .get(row.compensation_id, row.source_command_id) as SqlRow | undefined;
    if (!source || source.status !== "compensating" || source.has_effect !== 0) {
      fail("invalid_command");
    }
    requireSynchronousAuthority(this.verifyAuthority, command, nowMs);
    return command;
  }

  private hasLease(
    row: CompletionRow,
    workerId: string,
    expectedAttempt: number,
    expectedLeaseExpiresAtMs: number,
    nowMs: number
  ): boolean {
    return (
      row.dispatch_status === "processing" &&
      row.attempts === expectedAttempt &&
      row.lease_owner === workerId &&
      row.lease_expires_at_ms === expectedLeaseExpiresAtMs &&
      nowMs < expectedLeaseExpiresAtMs
    );
  }

  private hasCompletionLease(
    row: CompletionRow,
    completion: ReturnType<typeof validateCompletion>
  ): boolean {
    if (
      !this.hasLease(
        row,
        completion.workerId,
        completion.expectedAttempt,
        completion.expectedLeaseExpiresAtMs,
        completion.observedAtMs
      )
    ) {
      return false;
    }
    if (completion.outcome.kind === "receipt") {
      return row.dispatch_interlock_acquired_at_ms !== null;
    }
    if (row.dispatch_interlock_acquired_at_ms !== null) return true;
    return completion.outcome.dispatchCertainty === "not-dispatched";
  }

  private commandRow(commandId: string): CommandRow | undefined {
    return this.db
      .prepare(`SELECT * FROM runtime_compensation_commands WHERE id = ?`)
      .get(commandId) as CommandRow | undefined;
  }

  private completionRow(commandId: string): CompletionRow | undefined {
    return this.db
      .prepare(
        `SELECT command.*, dispatch.status AS dispatch_status, dispatch.attempts,
                dispatch.available_at_ms, dispatch.lease_owner,
                dispatch.lease_expires_at_ms,
                dispatch.dispatch_interlock_acquired_at_ms,
                dispatch.last_safe_error_code, dispatch.terminal_at_ms
         FROM runtime_compensation_commands command
         JOIN runtime_compensation_dispatch dispatch
           ON dispatch.compensation_command_id = command.id
         WHERE command.id = ?`
      )
      .get(commandId) as CompletionRow | undefined;
  }

  private incidentRow(compensationId: string): SqlRow | undefined {
    return this.db
      .prepare(`SELECT * FROM runtime_compensation_incidents WHERE compensation_id = ?`)
      .get(compensationId) as SqlRow | undefined;
  }

  private verifiedIncident(
    row: SqlRow
  ): Extract<RuntimeCompensationIncident, { trustState: "verified" }> {
    let incident: RuntimeCompensationIncident;
    try {
      incident = snapshotRuntimeCompensationIncident({
        version: 1,
        compensationId: row.compensation_id,
        sourceCommandId: row.source_command_id,
        sourceReceiptId: row.source_receipt_id,
        trustState: row.trust_state,
        binding: {
          teamId: row.team_id,
          projectId: row.project_id,
          sessionId: row.session_id,
          runtimeAssignmentId: row.runtime_assignment_id,
          runtimeAssignmentGeneration: row.runtime_assignment_generation,
          sandboxId: row.sandbox_id,
          sandboxGeneration: row.sandbox_generation,
          runtimePrincipalId: row.runtime_principal_id,
        },
        observedRuntimeAuthorizationGeneration: row.runtime_authorization_generation,
        lifecycleCommandClaimsDigest: row.lifecycle_command_claims_digest,
        lifecycleReceiptDigest: row.lifecycle_receipt_digest,
        sourceEnforcedFence: row.source_enforced_fence,
        safetyFence: row.safety_fence,
        sourceRequiredEffectEnforcerSetDigest: row.source_required_effect_enforcer_set_digest,
        lifecycleEnforcementSubjectDigest: row.lifecycle_enforcement_subject_digest,
        lifecycleAggregateProofDigest: row.lifecycle_aggregate_proof_digest,
        sourceEffectRefCommitment: row.source_effect_ref_commitment,
        createdAtMs: row.created_at_ms,
      });
    } catch {
      fail("invalid_command");
    }
    if (
      incident.trustState !== "verified" ||
      typeof row.incident_digest !== "string" ||
      !sameDigest(digestRuntimeCompensationIncident(incident), row.incident_digest)
    ) {
      fail("invalid_command");
    }
    return incident;
  }

  private nextId(): string {
    let value: unknown;
    try {
      value = this.idGenerator();
    } catch {
      fail("journal_conflict");
    }
    return safeIdentifier(value, MAX_IDENTIFIER_LENGTH);
  }
}

export function createSqliteRuntimeCompensationJournal(
  options: CreateSqliteRuntimeCompensationJournalOptions
): SqliteRuntimeCompensationJournal {
  return new SqliteRuntimeCompensationJournal(options);
}

function snapshotMaterializationInput(value: RuntimeCompensationMaterializationInput) {
  const record = exactDataRecord(value, [
    "compensationId",
    "incidentDigest",
    "command",
    "authorityVerifiedAtMs",
    "materializedAtMs",
  ]);
  const compensationId = safeIdentifier(dataField(record, "compensationId"), MAX_IDENTIFIER_LENGTH);
  const incidentDigest = sha256Digest(dataField(record, "incidentDigest"));
  const command = snapshotCompensationCommand(dataField(record, "command"));
  const authorityVerifiedAtMs = nonNegativeInteger(dataField(record, "authorityVerifiedAtMs"));
  const materializedAtMs = nonNegativeInteger(dataField(record, "materializedAtMs"));
  if (
    command.compensationId !== compensationId ||
    authorityVerifiedAtMs < command.issuedAtMs ||
    authorityVerifiedAtMs >= command.deadlineAtMs ||
    authorityVerifiedAtMs < command.authority.issuedAtMs ||
    authorityVerifiedAtMs >= command.authority.expiresAtMs ||
    materializedAtMs < authorityVerifiedAtMs ||
    materializedAtMs >= command.deadlineAtMs ||
    materializedAtMs >= command.authority.expiresAtMs
  ) {
    fail("invalid_input");
  }
  return Object.freeze({
    compensationId,
    incidentDigest,
    command,
    authorityVerifiedAtMs,
    materializedAtMs,
  });
}

function snapshotCompensationCommand(value: unknown): RuntimeCompensationCommand {
  let command: RuntimeCompensationCommand;
  try {
    command = JSON.parse(canonicalRuntimeJson(value)) as RuntimeCompensationCommand;
    exactDataRecord(command, COMMAND_FIELDS);
    assertRuntimeCommandAuthorityBinding(command);
  } catch {
    fail("invalid_command");
  }
  if (command.kind !== "safety.quarantine") fail("invalid_command");
  safeReference(command.commandId);
  safeReference(command.compensationId);
  validateBinding(command.binding);
  positiveInteger(command.observedRuntimeAuthorizationGeneration);
  const source = exactDataRecord(command.source, SOURCE_FIELDS);
  safeReference(dataField(source, "lifecycleCommandId"));
  for (const field of SOURCE_FIELDS.slice(1)) sha256Digest(dataField(source, field));
  safeReference(command.platformSecurityPolicyRevision);
  sha256Digest(command.requiredContainmentEnforcerSetDigest);
  exactDataRecord(command.containment, [
    "revokeTerminalWrites",
    "stopProcessExecution",
    "quarantineRuntime",
  ]);
  if (
    command.containment.revokeTerminalWrites !== true ||
    command.containment.stopProcessExecution !== true ||
    command.containment.quarantineRuntime !== true ||
    command.exactBindingOnly !== true ||
    command.advanceBeyondCurrentFences !== true
  ) {
    fail("invalid_command");
  }
  positiveInteger(command.safetyFence);
  safeReference(command.reasonRef);
  if (safeReference(command.causationId) !== command.source.lifecycleCommandId) {
    fail("invalid_command");
  }
  exactDataRecord(command.actor, ["kind", "actorRef"]);
  if (command.actor.kind !== "system" || command.actor.actorRef !== "platform-security") {
    fail("invalid_command");
  }
  const issuedAtMs = nonNegativeInteger(command.issuedAtMs);
  const deadlineAtMs = nonNegativeInteger(command.deadlineAtMs);
  if (deadlineAtMs <= issuedAtMs) fail("invalid_command");
  if (
    command.authority.issuer !== "platform-security" ||
    command.authority.capability !== "safety.quarantine" ||
    command.authority.audience !== "runtime" ||
    command.authority.issuedAtMs !== issuedAtMs ||
    command.authority.expiresAtMs > deadlineAtMs ||
    digestRuntimeCommandClaims(command) !== command.authority.claimsDigest
  ) {
    fail("invalid_command");
  }
  return deepFreeze(command);
}

function parsePersistedCommand(row: CommandRow): RuntimeCompensationCommand {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.command_json);
  } catch {
    fail("invalid_command");
  }
  const command = snapshotCompensationCommand(parsed);
  const canonical = canonicalCommandJson(command);
  if (
    canonical !== row.command_json ||
    sha256(canonical) !== row.command_digest ||
    row.authority_digest !== command.authority.claimsDigest ||
    row.operation !== "safety.quarantine" ||
    row.id !== command.commandId ||
    row.compensation_id !== command.compensationId ||
    row.source_command_id !== command.source.lifecycleCommandId ||
    row.session_id !== command.binding.sessionId ||
    row.team_id !== command.binding.teamId ||
    row.project_id !== command.binding.projectId ||
    row.runtime_assignment_id !== command.binding.runtimeAssignmentId ||
    row.runtime_assignment_generation !== command.binding.runtimeAssignmentGeneration ||
    row.sandbox_id !== command.binding.sandboxId ||
    row.sandbox_generation !== command.binding.sandboxGeneration ||
    row.runtime_principal_id !== command.binding.runtimePrincipalId ||
    row.observed_runtime_authorization_generation !==
      command.observedRuntimeAuthorizationGeneration ||
    row.source_required_effect_enforcer_set_digest !==
      command.source.sourceRequiredEffectEnforcerSetDigest ||
    row.lifecycle_command_claims_digest !== command.source.lifecycleCommandClaimsDigest ||
    row.lifecycle_receipt_digest !== command.source.lifecycleReceiptDigest ||
    row.lifecycle_enforcement_subject_digest !== command.source.lifecycleEnforcementSubjectDigest ||
    row.lifecycle_aggregate_proof_digest !== command.source.lifecycleAggregateProofDigest ||
    row.platform_security_policy_revision !== command.platformSecurityPolicyRevision ||
    row.required_containment_enforcer_set_digest !== command.requiredContainmentEnforcerSetDigest ||
    row.safety_fence !== command.safetyFence ||
    row.reason_ref !== command.reasonRef ||
    row.causation_id !== command.causationId ||
    row.created_at_ms !== command.issuedAtMs ||
    row.deadline_at_ms !== command.deadlineAtMs
  ) {
    fail("invalid_command");
  }
  return command;
}

function assertCommandMatchesIncident(
  command: RuntimeCompensationCommand,
  incident: Extract<RuntimeCompensationIncident, { trustState: "verified" }>,
  row: SqlRow
): void {
  if (
    command.compensationId !== incident.compensationId ||
    command.source.lifecycleCommandId !== incident.sourceCommandId ||
    command.source.lifecycleCommandClaimsDigest !== incident.lifecycleCommandClaimsDigest ||
    command.source.lifecycleReceiptDigest !== incident.lifecycleReceiptDigest ||
    command.source.lifecycleEnforcementSubjectDigest !==
      incident.lifecycleEnforcementSubjectDigest ||
    command.source.lifecycleAggregateProofDigest !== incident.lifecycleAggregateProofDigest ||
    command.source.sourceRequiredEffectEnforcerSetDigest !==
      incident.sourceRequiredEffectEnforcerSetDigest ||
    command.observedRuntimeAuthorizationGeneration !==
      incident.observedRuntimeAuthorizationGeneration ||
    command.safetyFence !== incident.safetyFence ||
    command.reasonRef !== row.incident_digest ||
    command.causationId !== incident.sourceCommandId ||
    !sameBinding(command.binding, incident.binding)
  ) {
    fail("invalid_command");
  }
}

function assertObservationMatchesCommand(
  observation: VerifiedRuntimeCompensationReceiptObservation,
  command: RuntimeCompensationCommand
): void {
  const reference = observation.command;
  if (
    reference.kind !== "safety.quarantine" ||
    reference.commandId !== command.commandId ||
    reference.compensationId !== command.compensationId ||
    !sameDigest(reference.claimsDigest, command.authority.claimsDigest) ||
    !sameBinding(reference.binding, command.binding) ||
    reference.observedRuntimeAuthorizationGeneration !==
      command.observedRuntimeAuthorizationGeneration ||
    reference.safetyFence !== command.safetyFence ||
    reference.source.lifecycleCommandId !== command.source.lifecycleCommandId ||
    !sameDigest(
      reference.source.lifecycleCommandClaimsDigest,
      command.source.lifecycleCommandClaimsDigest
    ) ||
    !sameDigest(reference.source.lifecycleReceiptDigest, command.source.lifecycleReceiptDigest) ||
    !sameDigest(
      reference.source.lifecycleEnforcementSubjectDigest,
      command.source.lifecycleEnforcementSubjectDigest
    ) ||
    !sameDigest(
      reference.source.lifecycleAggregateProofDigest,
      command.source.lifecycleAggregateProofDigest
    ) ||
    !sameDigest(
      reference.source.sourceRequiredEffectEnforcerSetDigest,
      command.source.sourceRequiredEffectEnforcerSetDigest
    ) ||
    !sameDigest(
      reference.requiredContainmentEnforcerSetDigest,
      command.requiredContainmentEnforcerSetDigest
    )
  ) {
    fail("invalid_input");
  }
}

function candidateFromIncident(
  incident: Extract<RuntimeCompensationIncident, { trustState: "verified" }>
): RuntimeCompensationMaterializationCandidate {
  return deepFreeze({
    compensationId: incident.compensationId,
    // Recomputed immediately before returning; the caller never trusts a
    // separately mutable digest projection.
    incidentDigest: digestRuntimeCompensationIncident(incident),
    binding: { ...incident.binding },
    observedRuntimeAuthorizationGeneration: incident.observedRuntimeAuthorizationGeneration,
    safetyFence: incident.safetyFence,
    source: {
      lifecycleCommandId: incident.sourceCommandId,
      lifecycleCommandClaimsDigest: incident.lifecycleCommandClaimsDigest,
      lifecycleReceiptDigest: incident.lifecycleReceiptDigest,
      lifecycleEnforcementSubjectDigest: incident.lifecycleEnforcementSubjectDigest,
      lifecycleAggregateProofDigest: incident.lifecycleAggregateProofDigest,
      sourceRequiredEffectEnforcerSetDigest: incident.sourceRequiredEffectEnforcerSetDigest,
    },
  });
}

function validateCompletion(completion: RuntimeCompensationCompletion) {
  const record = exactDataRecord(completion, [
    "commandId",
    "workerId",
    "expectedAttempt",
    "expectedLeaseExpiresAtMs",
    "observedAtMs",
    "outcome",
  ]);
  const commandId = safeIdentifier(dataField(record, "commandId"), MAX_IDENTIFIER_LENGTH);
  const workerId = safeIdentifier(dataField(record, "workerId"), MAX_WORKER_ID_LENGTH);
  const expectedAttempt = positiveInteger(dataField(record, "expectedAttempt"));
  const expectedLeaseExpiresAtMs = nonNegativeInteger(
    dataField(record, "expectedLeaseExpiresAtMs")
  );
  const observedAtMs = nonNegativeInteger(dataField(record, "observedAtMs"));
  const outcome = dataField(record, "outcome") as RuntimeCompensationCompletion["outcome"];
  if (!outcome || typeof outcome !== "object") fail("invalid_input");
  if (outcome.kind === "failure") {
    exactDataRecord(outcome, ["kind", "code", "dispatchCertainty"]);
    const code = safeErrorCode(outcome.code);
    if (
      !Object.hasOwn(FAILURE_DISPATCH_CERTAINTY, code) ||
      FAILURE_DISPATCH_CERTAINTY[code as keyof typeof FAILURE_DISPATCH_CERTAINTY] !==
        outcome.dispatchCertainty
    ) {
      fail("invalid_input");
    }
  } else if (outcome.kind === "receipt") {
    exactDataRecord(outcome, ["kind", "receipt"]);
  } else {
    fail("invalid_input");
  }
  return Object.freeze({
    commandId,
    workerId,
    expectedAttempt,
    expectedLeaseExpiresAtMs,
    observedAtMs,
    outcome,
  });
}

function sanitizeReceiptForPersistence(
  receipt: RuntimeCompensationReceipt
): RuntimeCompensationReceipt {
  const sanitizeNonDuplicate = (
    value: NonDuplicateRuntimeCompensationReceipt
  ): NonDuplicateRuntimeCompensationReceipt => {
    const base = {
      receiptKind: "runtime.compensation" as const,
      compensationId: value.compensationId,
      commandId: value.commandId,
      binding: { ...value.binding },
      observedRuntimeAuthorizationGeneration: value.observedRuntimeAuthorizationGeneration,
    };
    switch (value.outcome) {
      case "accepted":
        return deepFreeze({
          ...base,
          outcome: "accepted",
          effectRef: commitRuntimeEffectRef(value.effectRef),
        });
      case "enforced":
        if (!value.aggregateEnforcementProof) fail("invalid_input");
        return deepFreeze({
          ...base,
          outcome: "enforced",
          effectRef: commitRuntimeEffectRef(value.effectRef),
          enforcedSafetyFence: value.enforcedSafetyFence,
          containment: {
            terminalWritesRevoked: true,
            processExecutionStopped: true,
            runtimeQuarantined: true,
          },
          aggregateEnforcementProof: snapshotAggregateEnforcementProof(
            value.aggregateEnforcementProof
          ),
        });
      case "rejected":
        return deepFreeze({
          ...base,
          outcome: "rejected",
          code: value.code,
          safeDetail: "Runtime rejected the containment command",
        });
      case "quarantined":
        return deepFreeze({
          ...base,
          outcome: "quarantined",
          reason: value.reason,
          effectRef: commitRuntimeEffectRef(value.effectRef),
        });
    }
  };
  if (receipt.outcome !== "duplicate") return sanitizeNonDuplicate(receipt);
  const originalReceipt = sanitizeNonDuplicate(receipt.originalReceipt);
  return deepFreeze({
    receiptKind: "runtime.compensation",
    compensationId: receipt.compensationId,
    commandId: receipt.commandId,
    binding: { ...receipt.binding },
    observedRuntimeAuthorizationGeneration: receipt.observedRuntimeAuthorizationGeneration,
    outcome: "duplicate",
    originalReceipt,
    originalReceiptDigest: digestNonDuplicateRuntimeCompensationReceipt(originalReceipt),
  });
}

function effectiveReceipt(
  receipt: RuntimeCompensationReceipt
): NonDuplicateRuntimeCompensationReceipt {
  return receipt.outcome === "duplicate" ? receipt.originalReceipt : receipt;
}

function digestCompensationReceipt(receipt: RuntimeCompensationReceipt): string {
  try {
    return createHash("sha256")
      .update(RUNTIME_COMPENSATION_RECEIPT_DIGEST_DOMAIN, "utf8")
      .update(canonicalRuntimeJson(receipt), "utf8")
      .digest("hex");
  } catch {
    fail("invalid_input");
  }
}

function requireSynchronousAuthority(
  verifier: RuntimeCompensationCommandAuthorityVerifier,
  command: RuntimeCompensationCommand,
  nowMs: number
): void {
  if (
    nowMs < command.issuedAtMs ||
    nowMs >= command.deadlineAtMs ||
    nowMs < command.authority.issuedAtMs ||
    nowMs >= command.authority.expiresAtMs
  ) {
    fail("invalid_command");
  }
  let verified: unknown;
  try {
    verified = verifier(Object.freeze({ command, nowMs }));
  } catch {
    fail("invalid_command");
  }
  if (verified !== true) {
    void Promise.resolve(verified).catch(() => undefined);
    fail("invalid_command");
  }
}

function validateBinding(binding: RuntimeCompensationCommand["binding"]): void {
  exactDataRecord(binding, BINDING_FIELDS);
  safeReference(binding.teamId);
  safeReference(binding.projectId);
  safeReference(binding.sessionId);
  safeReference(binding.runtimeAssignmentId);
  positiveInteger(binding.runtimeAssignmentGeneration);
  safeReference(binding.sandboxId);
  positiveInteger(binding.sandboxGeneration);
  safeReference(binding.runtimePrincipalId);
}

function sameBinding(
  left: RuntimeCompensationCommand["binding"],
  right: RuntimeCompensationCommand["binding"]
): boolean {
  return BINDING_FIELDS.every((field) => left[field] === right[field]);
}

function bindingSqlValues(row: CommandRow): readonly SqlValue[] {
  return [
    row.team_id,
    row.project_id,
    row.session_id,
    row.runtime_assignment_id,
    row.runtime_assignment_generation,
    row.sandbox_id,
    row.sandbox_generation,
    row.runtime_principal_id,
  ];
}

function canonicalCommandJson(command: RuntimeCompensationCommand): string {
  try {
    return canonicalRuntimeJson(command);
  } catch {
    fail("invalid_command");
  }
}

function exactDataRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid_input");
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch {
    fail("invalid_input");
  }
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    fail("invalid_input");
  }
  for (const field of fields) dataField(value as Record<string, unknown>, field);
  return value as Record<string, unknown>;
}

function dataField(record: Record<string, unknown>, field: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail("invalid_input");
  return descriptor.value;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function safeIdentifier(value: unknown, maximumLength: number): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximumLength ||
    /[\0\r\n\t]/.test(value)
  ) {
    fail("invalid_input");
  }
  return value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) fail("invalid_command");
  return value;
}

function safeErrorCode(value: unknown): string {
  return safeIdentifier(value, MAX_SAFE_ERROR_CODE_LENGTH);
}

function sha256Digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) fail("invalid_input");
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail("invalid_input");
  return value as number;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) fail("invalid_input");
  return value as number;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail("invalid_input");
  }
  return value as number;
}

function safeAdd(left: number, right: number): number {
  const value = left + right;
  if (!Number.isSafeInteger(value)) fail("invalid_input");
  return value;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sameDigest(left: string, right: string): boolean {
  if (!SHA256_DIGEST.test(left) || !SHA256_DIGEST.test(right)) return false;
  try {
    return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
  } catch {
    return false;
  }
}

function fail(code: RuntimeCompensationJournalErrorCode): never {
  throw new RuntimeCompensationJournalError(code);
}
