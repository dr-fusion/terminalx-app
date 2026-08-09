import { createHash, createPublicKey } from "node:crypto";
import type Database from "better-sqlite3";
import type { RuntimeCompensationCommand, RuntimeLifecycleCommand } from "../runtime/contracts";
import {
  canonicalRuntimeJson,
  digestRuntimeCommandClaims,
} from "../runtime/runtime-command-canonical";
import {
  RuntimeReceiptObservationError,
  createRuntimeReceiptObservationVerifier,
  type RuntimeReceiptObservationCheckpoint,
  type VerifiedRuntimeLifecycleReceiptObservation,
} from "../runtime/runtime-receipt-observation";
import {
  RuntimeCompensationReceiptObservationError,
  createRuntimeCompensationReceiptObservationVerifier,
  type VerifiedRuntimeCompensationReceiptObservation,
} from "../runtime/runtime-compensation-receipt-observation";
import {
  RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS,
  runtimeReceiptObservationCursorCodePoints,
} from "../runtime/runtime-receipt-observation-contract";
import type { RuntimeBinding } from "./contracts";
import {
  RuntimeCompensationReceiptFollowSettlementRejection,
  type RuntimeCompensationReceiptFollowSettlementInput,
  type RuntimeCompensationReceiptFollowSettlementResult,
} from "./sqlite-runtime-compensation-journal";

type SqlValue = string | number | null;
type SqlRow = Record<string, SqlValue>;

const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_WORKER_ID_LENGTH = 128;
const MAX_IDENTIFIER_LENGTH = 300;
const MAX_PUBLIC_KEY_BYTES = 4_000;
const DEFAULT_RETRY_DELAY_MS = 1_000;
const MAX_RETRY_DELAY_MS = 60_000;
const MAX_LEASE_DURATION_MS = 300_000;
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

export type RuntimeReceiptFollowJournalErrorCode =
  | "invalid_input"
  | "invalid_public_key"
  | "binding_unavailable"
  | "stale_lease"
  | "invalid_observation"
  | "enforcement_proof_rejected"
  | "journal_conflict";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeReceiptFollowJournalErrorCode, string>> = {
  invalid_input: "Runtime receipt follow journal input is invalid",
  invalid_public_key: "Runtime receipt observation public key is invalid",
  binding_unavailable: "Runtime receipt follow binding is unavailable",
  stale_lease: "Runtime receipt follow lease is stale",
  invalid_observation: "Runtime receipt observation is invalid",
  enforcement_proof_rejected: "Runtime receipt enforcement proof was rejected",
  journal_conflict: "Runtime receipt follow journal state conflicts",
};

/** Safe internal failure surface; SQLite, key, and provider values are never attached. */
export class RuntimeReceiptFollowJournalError extends Error {
  constructor(readonly code: RuntimeReceiptFollowJournalErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeReceiptFollowJournalError";
  }
}

export type RuntimeReceiptFollowSettlementRejectionCode = "enforcement_proof_verification_failed";

/**
 * Narrow trusted-seam rejection. Lifecycle truth may throw only this safe code
 * after a verified observation cannot prove its claimed enforced effect.
 */
export class RuntimeReceiptFollowSettlementRejection extends Error {
  constructor(readonly code: RuntimeReceiptFollowSettlementRejectionCode) {
    super("Runtime receipt enforcement proof could not be verified");
    this.name = "RuntimeReceiptFollowSettlementRejection";
  }
}

export interface RuntimeReceiptFollowRegistration {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly issuerKeyId: string;
  readonly publicKeySpkiPem: string;
  readonly createdAtMs: number;
}

export interface RuntimeReceiptFollowRegistrationRecord {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly issuerKeyId: string;
  /** SHA-256 of canonical Ed25519 SubjectPublicKeyInfo DER. */
  readonly publicKeySpkiDigest: string;
}

export interface RuntimeReceiptFollowClaimOptions {
  readonly workerId: string;
  readonly leaseDurationMs: number;
  readonly nowMs: number;
}

export interface RuntimeReceiptFollowLease {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly issuerKeyId: string;
  readonly publicKeySpkiDigest: string;
  readonly checkpoint: RuntimeReceiptObservationCheckpoint | null;
  readonly attempt: number;
  readonly leaseOwner: string;
  readonly leaseVersion: number;
  readonly leaseExpiresAtMs: number;
}

interface ExactRuntimeReceiptFollowLease {
  readonly runtimeAssignmentId: string;
  readonly runtimeAuthorizationGeneration: number;
  readonly workerId: string;
  readonly expectedLeaseVersion: number;
  readonly expectedLeaseExpiresAtMs: number;
  readonly nowMs: number;
}

export interface RuntimeReceiptFollowRenewalOptions extends ExactRuntimeReceiptFollowLease {
  readonly leaseDurationMs: number;
}

export interface RuntimeReceiptFollowReleaseOptions extends ExactRuntimeReceiptFollowLease {
  readonly reason: "no-event" | "transport-unavailable";
}

export interface RuntimeReceiptFollowQuarantineOptions extends ExactRuntimeReceiptFollowLease {
  readonly reason:
    | "invalid-observation"
    | "invalid-observation-chain"
    | "invalid-observation-signature";
}

export interface RuntimeReceiptFollowSettlementOptions extends ExactRuntimeReceiptFollowLease {
  readonly observation: unknown;
  readonly receivedAtMs: number;
}

export interface RuntimeReceiptFollowSettlementInput {
  /** Private-branded value created by the persisted-key verifier in this module. */
  readonly observation: VerifiedRuntimeLifecycleReceiptObservation;
  readonly command: RuntimeLifecycleCommand;
  readonly receivedAtMs: number;
  readonly actorRef: string;
}

export interface RuntimeReceiptFollowSettlementResult {
  readonly receiptId: string;
  /** Digest stored in runtime_run_command_receipts.receipt_digest. */
  readonly effectiveReceiptDigest: string;
}

interface RuntimeReceiptFollowContainmentResult {
  readonly kind: "contained";
  readonly code: RuntimeReceiptFollowSettlementRejectionCode;
}

interface RuntimeReceiptFollowCommitResult {
  readonly kind: "settled";
  readonly result: RuntimeReceiptFollowSettlementResult;
}

/**
 * Must synchronously persist the receipt and apply its lifecycle effect while
 * `db.inTransaction` is true. Returning before those writes are durable is a
 * configuration error; the follow-event trigger independently checks the
 * returned receipt identity and digest. A Runtime observation signature is not
 * an effect-enforcement proof: for an effective `enforced` receipt this seam
 * must also authenticate the aggregate proof against the trusted enforcer set
 * before inserting the receipt or effect.
 */
export type SettleVerifiedRuntimeReceiptInTransaction = (
  input: RuntimeReceiptFollowSettlementInput
) => RuntimeReceiptFollowSettlementResult;

/** Optional private seam used only when the compensation trust group is configured. */
export type SettleVerifiedRuntimeCompensationReceiptInTransaction = (
  input: RuntimeCompensationReceiptFollowSettlementInput
) => RuntimeCompensationReceiptFollowSettlementResult;

export interface CreateSqliteRuntimeReceiptFollowJournalOptions {
  readonly db: Database.Database;
  /** Kernel-owned identity source for canonical Session events. */
  readonly idGenerator: () => string;
  readonly settleVerifiedReceiptInTransaction: SettleVerifiedRuntimeReceiptInTransaction;
  readonly settleVerifiedCompensationReceiptInTransaction?: SettleVerifiedRuntimeCompensationReceiptInTransaction;
  readonly retryDelayMs?: number;
}

interface FollowStreamRow extends SqlRow {
  runtime_assignment_id: string;
  session_id: string;
  runtime_assignment_generation: number;
  sandbox_id: string;
  sandbox_generation: number;
  runtime_principal_id: string;
  runtime_authorization_generation: number;
  issuer_key_id: string;
  public_key_spki_digest: string;
  public_key_spki_pem: string;
  team_id: string;
  project_id: string;
  status: "pending" | "processing" | "quarantined";
  attempts: number;
  lease_version: number;
  available_at_ms: number;
  lease_owner: string | null;
  lease_expires_at_ms: number | null;
  cursor: string | null;
  last_observation_digest: string | null;
  receipt_sequence: number;
}

interface CommandRow extends SqlRow {
  id: string;
  session_id: string;
  agent_run_id: string;
  runtime_assignment_id: string;
  runtime_assignment_generation: number;
  sandbox_id: string;
  sandbox_generation: number;
  runtime_principal_id: string;
  runtime_authorization_generation: number;
  command_json: string;
  command_digest: string;
  authority_digest: string;
  required_effect_enforcer_set_digest: string | null;
  operation: RuntimeLifecycleCommand["kind"];
}

interface CompensationCommandRow extends SqlRow {
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

/**
 * Durable, private Runtime follow-channel journal.
 *
 * This module owns observation-key pinning, one-at-a-time follow leases, and
 * the signed cursor chain. Lifecycle truth remains owned by the lifecycle
 * journal through the injected synchronous settlement seam.
 */
export class SqliteRuntimeReceiptFollowJournal {
  private readonly db: Database.Database;
  private readonly idGenerator: () => string;
  private readonly settleVerifiedReceiptInTransaction: SettleVerifiedRuntimeReceiptInTransaction;
  private readonly settleVerifiedCompensationReceiptInTransaction?: SettleVerifiedRuntimeCompensationReceiptInTransaction;
  private readonly retryDelayMs: number;

  constructor(options: CreateSqliteRuntimeReceiptFollowJournalOptions) {
    if (
      !options?.db ||
      typeof options.db.prepare !== "function" ||
      typeof options.idGenerator !== "function" ||
      typeof options.settleVerifiedReceiptInTransaction !== "function" ||
      (options.settleVerifiedCompensationReceiptInTransaction !== undefined &&
        typeof options.settleVerifiedCompensationReceiptInTransaction !== "function")
    ) {
      fail("invalid_input");
    }
    this.db = options.db;
    this.idGenerator = options.idGenerator;
    this.settleVerifiedReceiptInTransaction = options.settleVerifiedReceiptInTransaction;
    this.settleVerifiedCompensationReceiptInTransaction =
      options.settleVerifiedCompensationReceiptInTransaction;
    this.retryDelayMs = boundedInteger(
      options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS,
      1,
      MAX_RETRY_DELAY_MS
    );
  }

  /** Pin one immutable Ed25519 observation key and create its empty stream atomically. */
  register(
    unsafeRegistration: RuntimeReceiptFollowRegistration
  ): RuntimeReceiptFollowRegistrationRecord {
    const registration = snapshotRegistration(unsafeRegistration);
    const publicKey = canonicalEd25519PublicKey(registration.publicKeySpkiPem);
    const record = Object.freeze({
      binding: registration.binding,
      runtimeAuthorizationGeneration: registration.runtimeAuthorizationGeneration,
      issuerKeyId: registration.issuerKeyId,
      publicKeySpkiDigest: publicKey.digest,
    });

    const register = this.db.transaction(() => {
      if (
        !this.bindingIsCurrent(
          registration.binding,
          registration.runtimeAuthorizationGeneration,
          registration.createdAtMs
        )
      ) {
        fail("binding_unavailable");
      }
      const existing = this.db
        .prepare(
          `SELECT key.session_id, key.runtime_assignment_generation, key.sandbox_id,
                  key.sandbox_generation, key.runtime_principal_id, key.issuer_key_id,
                  key.public_key_spki_pem, key.public_key_spki_digest,
                  EXISTS(
                    SELECT 1 FROM runtime_receipt_follow_streams stream
                    WHERE stream.runtime_assignment_id = key.runtime_assignment_id
                      AND stream.runtime_authorization_generation = key.runtime_authorization_generation
                      AND stream.issuer_key_id = key.issuer_key_id
                      AND stream.public_key_spki_digest = key.public_key_spki_digest
                  ) AS has_stream
           FROM runtime_principal_observation_keys key
           WHERE key.runtime_assignment_id = ?
             AND key.runtime_authorization_generation = ?`
        )
        .get(
          registration.binding.runtimeAssignmentId,
          registration.runtimeAuthorizationGeneration
        ) as SqlRow | undefined;
      if (existing) {
        if (
          existing.session_id !== registration.binding.sessionId ||
          existing.runtime_assignment_generation !==
            registration.binding.runtimeAssignmentGeneration ||
          existing.sandbox_id !== registration.binding.sandboxId ||
          existing.sandbox_generation !== registration.binding.sandboxGeneration ||
          existing.runtime_principal_id !== registration.binding.runtimePrincipalId ||
          existing.issuer_key_id !== registration.issuerKeyId ||
          existing.public_key_spki_pem !== publicKey.pem ||
          existing.public_key_spki_digest !== publicKey.digest ||
          existing.has_stream !== 1
        ) {
          fail("journal_conflict");
        }
        return;
      }

      this.db
        .prepare(
          `INSERT INTO runtime_principal_observation_keys
             (runtime_assignment_id, session_id, runtime_assignment_generation,
              sandbox_id, sandbox_generation, runtime_principal_id,
              runtime_authorization_generation, issuer_key_id,
              public_key_spki_pem, public_key_spki_digest, created_at_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          registration.binding.runtimeAssignmentId,
          registration.binding.sessionId,
          registration.binding.runtimeAssignmentGeneration,
          registration.binding.sandboxId,
          registration.binding.sandboxGeneration,
          registration.binding.runtimePrincipalId,
          registration.runtimeAuthorizationGeneration,
          registration.issuerKeyId,
          publicKey.pem,
          publicKey.digest,
          registration.createdAtMs
        );
      this.db
        .prepare(
          `INSERT INTO runtime_receipt_follow_streams
             (runtime_assignment_id, session_id, runtime_assignment_generation,
              sandbox_id, sandbox_generation, runtime_principal_id,
              runtime_authorization_generation, issuer_key_id, public_key_spki_digest,
              status, attempts, lease_version, available_at_ms, lease_owner,
              lease_expires_at_ms, cursor, last_observation_digest, receipt_sequence,
              last_safe_error_code, created_at_ms, updated_at_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, 0, ?, NULL,
                   NULL, NULL, NULL, 0, NULL, ?, ?)`
        )
        .run(
          registration.binding.runtimeAssignmentId,
          registration.binding.sessionId,
          registration.binding.runtimeAssignmentGeneration,
          registration.binding.sandboxId,
          registration.binding.sandboxGeneration,
          registration.binding.runtimePrincipalId,
          registration.runtimeAuthorizationGeneration,
          registration.issuerKeyId,
          publicKey.digest,
          registration.createdAtMs,
          registration.createdAtMs,
          registration.createdAtMs
        );
    });
    runImmediate(register);
    return record;
  }

  /** Claim at most one stream which has durable awaiting-receipt work. */
  claim(unsafeOptions: RuntimeReceiptFollowClaimOptions): RuntimeReceiptFollowLease | null {
    const options = snapshotClaimOptions(unsafeOptions);
    const leaseExpiresAtMs = safeAdd(options.nowMs, options.leaseDurationMs);
    const claim = this.db.transaction(() => {
      const row = this.db
        .prepare(
          `${FOLLOW_STREAM_SELECT}
           WHERE stream.status = 'pending' AND stream.available_at_ms <= ?
             AND (${this.awaitingReceiptPredicate()})
           ORDER BY stream.available_at_ms ASC, stream.created_at_ms ASC,
                    stream.runtime_assignment_id ASC
           LIMIT 1`
        )
        .get(options.nowMs) as FollowStreamRow | undefined;
      if (!row) return null;

      const updated = this.db
        .prepare(
          `UPDATE runtime_receipt_follow_streams
           SET status = 'processing', attempts = attempts + 1,
               lease_version = lease_version + 1, lease_owner = ?,
               lease_expires_at_ms = ?, last_safe_error_code = NULL,
               updated_at_ms = ?
           WHERE runtime_assignment_id = ? AND runtime_authorization_generation = ?
             AND status = 'pending' AND available_at_ms <= ?
           RETURNING attempts, lease_version`
        )
        .get(
          options.workerId,
          leaseExpiresAtMs,
          options.nowMs,
          row.runtime_assignment_id,
          row.runtime_authorization_generation,
          options.nowMs
        ) as SqlRow | undefined;
      if (!updated) return null;
      return leaseFor(row, {
        attempt: positiveInteger(updated.attempts),
        leaseVersion: positiveInteger(updated.lease_version),
        leaseOwner: options.workerId,
        leaseExpiresAtMs,
      });
    });
    return runImmediate(claim);
  }

  /** Renew only the exact live owner/version/expiry tuple. */
  renew(unsafeOptions: RuntimeReceiptFollowRenewalOptions): { leaseExpiresAtMs: number } {
    const options = snapshotRenewalOptions(unsafeOptions);
    if (options.nowMs >= options.expectedLeaseExpiresAtMs) fail("stale_lease");
    const leaseExpiresAtMs = Math.max(
      options.expectedLeaseExpiresAtMs,
      safeAdd(options.nowMs, options.leaseDurationMs)
    );
    const renew = this.db.transaction(() => {
      const updated = this.db
        .prepare(
          `UPDATE runtime_receipt_follow_streams AS stream
           SET lease_expires_at_ms = ?, updated_at_ms = ?
           WHERE runtime_assignment_id = ? AND runtime_authorization_generation = ?
             AND status = 'processing' AND lease_owner = ? AND lease_version = ?
             AND lease_expires_at_ms = ? AND lease_expires_at_ms > ?
             AND (${this.awaitingReceiptPredicate()})`
        )
        .run(
          leaseExpiresAtMs,
          options.nowMs,
          options.runtimeAssignmentId,
          options.runtimeAuthorizationGeneration,
          options.workerId,
          options.expectedLeaseVersion,
          options.expectedLeaseExpiresAtMs,
          options.nowMs
        );
      if (updated.changes !== 1) fail("stale_lease");
    });
    runImmediate(renew);
    return Object.freeze({ leaseExpiresAtMs });
  }

  /** Return expired work to the pending queue without changing its signed cursor checkpoint. */
  reconcile(nowMsValue: number): number {
    const nowMs = nonNegativeInteger(nowMsValue);
    const reconcile = this.db.transaction(() => {
      const result = this.db
        .prepare(
          `UPDATE runtime_receipt_follow_streams
           SET status = 'pending', available_at_ms = MAX(available_at_ms, ?),
               lease_owner = NULL, lease_expires_at_ms = NULL,
               last_safe_error_code = 'follow_lease_expired', updated_at_ms = ?
           WHERE status = 'processing' AND lease_expires_at_ms <= ?`
        )
        .run(nowMs, nowMs, nowMs);
      return result.changes;
    });
    return runImmediate(reconcile);
  }

  /** Release a live lease after a safe empty poll or transport failure. */
  release(unsafeOptions: RuntimeReceiptFollowReleaseOptions): void {
    const options = snapshotReleaseOptions(unsafeOptions);
    const availableAtMs = safeAdd(options.nowMs, this.retryDelayMs);
    const safeCode =
      options.reason === "no-event" ? "follow_no_event" : "follow_transport_unavailable";
    this.releaseExactLease(options, availableAtMs, safeCode);
  }

  /** Permanently stop consuming a stream whose signed integrity chain is invalid. */
  quarantine(unsafeOptions: RuntimeReceiptFollowQuarantineOptions): void {
    const options = snapshotQuarantineOptions(unsafeOptions);
    this.quarantineExactLease(options, safeQuarantineCode(options.reason));
  }

  /**
   * Verify with the exact persisted binding-scoped key, then atomically settle
   * receipt/lifecycle truth, append the follow event, and advance the cursor.
   */
  settle(
    unsafeOptions: RuntimeReceiptFollowSettlementOptions
  ): RuntimeReceiptFollowSettlementResult {
    const options = snapshotSettlementOptions(unsafeOptions);
    let outcome: RuntimeReceiptFollowCommitResult | RuntimeReceiptFollowContainmentResult;
    try {
      const settle = this.db.transaction(() => this.settleInTransaction(options));
      outcome = runImmediate(settle);
    } catch (error) {
      if (
        error instanceof RuntimeReceiptObservationError ||
        error instanceof RuntimeCompensationReceiptObservationError
      ) {
        this.containRejectedObservation(options, error.code);
        fail("invalid_observation");
      }
      if (
        error instanceof RuntimeReceiptFollowJournalError &&
        error.code === "invalid_observation"
      ) {
        this.containRejectedObservation(options, "invalid_observation");
      }
      throw error;
    }
    if (outcome.kind === "contained") {
      fail("enforcement_proof_rejected");
    }
    return outcome.result;
  }

  private settleInTransaction(
    options: ReturnType<typeof snapshotSettlementOptions>
  ): RuntimeReceiptFollowCommitResult | RuntimeReceiptFollowContainmentResult {
    if (!this.db.inTransaction) fail("journal_conflict");
    const stream = this.exactLeasedStream(options);
    const reference = observationReference(options.observation);
    return reference.kind === "lifecycle"
      ? this.settleLifecycleObservationInTransaction(stream, reference.commandId, options)
      : this.settleCompensationObservationInTransaction(stream, reference.commandId, options);
  }

  private settleLifecycleObservationInTransaction(
    stream: FollowStreamRow,
    commandId: string,
    options: ReturnType<typeof snapshotSettlementOptions>
  ): RuntimeReceiptFollowCommitResult | RuntimeReceiptFollowContainmentResult {
    const commandRow = this.db
      .prepare(
        `SELECT command.*
         FROM runtime_run_commands command
         JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
         WHERE command.id = ? AND dispatch.status = 'awaiting-receipt'
           AND command.session_id = ?
           AND command.runtime_assignment_id = ?
           AND command.runtime_assignment_generation = ?
           AND command.sandbox_id = ? AND command.sandbox_generation = ?
           AND command.runtime_principal_id = ?
           AND command.runtime_authorization_generation = ?`
      )
      .get(
        commandId,
        stream.session_id,
        stream.runtime_assignment_id,
        stream.runtime_assignment_generation,
        stream.sandbox_id,
        stream.sandbox_generation,
        stream.runtime_principal_id,
        stream.runtime_authorization_generation
      ) as CommandRow | undefined;
    if (!commandRow) fail("invalid_observation");
    const command = parsePersistedCommand(commandRow, bindingFor(stream));
    const checkpoint = checkpointFor(stream);
    const verifier = createRuntimeReceiptObservationVerifier({
      pinnedPublicKeys: [
        {
          issuerKeyId: stream.issuer_key_id,
          binding: bindingFor(stream),
          publicKeyPem: stream.public_key_spki_pem,
        },
      ],
    });
    let observation: VerifiedRuntimeLifecycleReceiptObservation;
    try {
      observation = verifier.verify({
        observation: options.observation,
        command,
        expectedPrevious: checkpoint,
        nowMs: options.receivedAtMs,
      });
    } catch (error) {
      if (error instanceof RuntimeReceiptObservationError && error.code === "invalid_receipt") {
        return this.containEnforcementProofFailureInTransaction(
          stream,
          commandRow,
          options,
          "enforcement_proof_verification_failed"
        );
      }
      throw error;
    }
    if (
      runtimeReceiptObservationCursorCodePoints(observation.cursor) >
      RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS
    ) {
      fail("invalid_observation");
    }

    let settlement: RuntimeReceiptFollowSettlementResult;
    try {
      settlement = snapshotSettlementResult(
        this.settleVerifiedReceiptInTransaction(
          Object.freeze({
            observation,
            command,
            receivedAtMs: options.receivedAtMs,
            actorRef: options.workerId,
          })
        )
      );
    } catch (error) {
      if (error instanceof RuntimeReceiptFollowSettlementRejection) {
        return this.containEnforcementProofFailureInTransaction(
          stream,
          commandRow,
          options,
          error.code
        );
      }
      if (
        error instanceof RuntimeReceiptObservationError ||
        error instanceof RuntimeReceiptFollowJournalError
      ) {
        throw error;
      }
      fail("journal_conflict");
    }
    if (!this.db.inTransaction) fail("journal_conflict");
    const durableReceipt = this.db
      .prepare(
        `SELECT 1 FROM runtime_run_command_receipts
         WHERE id = ? AND command_id = ? AND receipt_digest = ?`
      )
      .get(settlement.receiptId, command.commandId, settlement.effectiveReceiptDigest);
    if (!durableReceipt) fail("journal_conflict");

    const receiptSequence = safeAdd(stream.receipt_sequence, 1);
    this.db
      .prepare(
        `INSERT INTO runtime_receipt_follow_events
           (id, runtime_assignment_id, session_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, issuer_key_id, public_key_spki_digest,
            receipt_sequence, cursor, previous_cursor, previous_observation_digest,
            observation_digest, command_id, command_digest, receipt_id,
            wire_receipt_digest, effective_receipt_digest, signature,
            lease_owner, lease_version, observed_at_ms, received_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        observation.observationId,
        stream.runtime_assignment_id,
        stream.session_id,
        stream.runtime_assignment_generation,
        stream.sandbox_id,
        stream.sandbox_generation,
        stream.runtime_principal_id,
        stream.runtime_authorization_generation,
        stream.issuer_key_id,
        stream.public_key_spki_digest,
        receiptSequence,
        observation.cursor,
        observation.previous?.cursor ?? null,
        observation.previous?.observationDigest ?? null,
        observation.observationDigest,
        command.commandId,
        commandRow.command_digest,
        settlement.receiptId,
        observation.receiptDigest,
        settlement.effectiveReceiptDigest,
        observation.authority.signature,
        options.workerId,
        options.expectedLeaseVersion,
        observation.observedAtMs,
        options.receivedAtMs
      );
    this.advanceFollowStream(observation, receiptSequence, options);
    return Object.freeze({ kind: "settled", result: settlement });
  }

  private settleCompensationObservationInTransaction(
    stream: FollowStreamRow,
    commandId: string,
    options: ReturnType<typeof snapshotSettlementOptions>
  ): RuntimeReceiptFollowCommitResult | RuntimeReceiptFollowContainmentResult {
    const commandRow = this.db
      .prepare(
        `SELECT command.*
         FROM runtime_compensation_commands command
         JOIN runtime_compensation_dispatch dispatch
           ON dispatch.compensation_command_id = command.id
         JOIN runtime_compensation_incidents incident
           ON incident.compensation_id = command.compensation_id
          AND incident.source_command_id = command.source_command_id
         JOIN runtime_run_command_dispatch source_dispatch
           ON source_dispatch.command_id = command.source_command_id
         WHERE command.id = ? AND dispatch.status = 'awaiting-receipt'
           AND incident.trust_state = 'verified'
           AND source_dispatch.status = 'compensating'
           AND command.session_id = ?
           AND command.team_id = ? AND command.project_id = ?
           AND command.runtime_assignment_id = ?
           AND command.runtime_assignment_generation = ?
           AND command.sandbox_id = ? AND command.sandbox_generation = ?
           AND command.runtime_principal_id = ?
           AND command.observed_runtime_authorization_generation = ?`
      )
      .get(
        commandId,
        stream.session_id,
        stream.team_id,
        stream.project_id,
        stream.runtime_assignment_id,
        stream.runtime_assignment_generation,
        stream.sandbox_id,
        stream.sandbox_generation,
        stream.runtime_principal_id,
        stream.runtime_authorization_generation
      ) as CompensationCommandRow | undefined;
    if (!commandRow || !this.settleVerifiedCompensationReceiptInTransaction) {
      fail("invalid_observation");
    }
    const command = parsePersistedCompensationCommand(commandRow, bindingFor(stream));
    const verifier = createRuntimeCompensationReceiptObservationVerifier({
      pinnedPublicKeys: [
        {
          issuerKeyId: stream.issuer_key_id,
          binding: bindingFor(stream),
          publicKeyPem: stream.public_key_spki_pem,
        },
      ],
    });
    let observation: VerifiedRuntimeCompensationReceiptObservation;
    try {
      observation = verifier.verify({
        observation: options.observation,
        command,
        expectedPrevious: checkpointFor(stream),
        nowMs: options.receivedAtMs,
      });
    } catch (error) {
      if (
        error instanceof RuntimeCompensationReceiptObservationError &&
        error.code === "invalid_receipt"
      ) {
        return this.containCompensationEnforcementProofFailureInTransaction(
          stream,
          commandRow,
          options,
          "enforcement_proof_verification_failed"
        );
      }
      throw error;
    }
    if (
      runtimeReceiptObservationCursorCodePoints(observation.cursor) >
      RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS
    ) {
      fail("invalid_observation");
    }

    let settlement: RuntimeReceiptFollowSettlementResult;
    try {
      settlement = snapshotSettlementResult(
        this.settleVerifiedCompensationReceiptInTransaction(
          Object.freeze({
            observation,
            command,
            receivedAtMs: options.receivedAtMs,
            actorRef: options.workerId,
          })
        )
      );
    } catch (error) {
      if (error instanceof RuntimeCompensationReceiptFollowSettlementRejection) {
        return this.containCompensationEnforcementProofFailureInTransaction(
          stream,
          commandRow,
          options,
          error.code
        );
      }
      if (
        error instanceof RuntimeCompensationReceiptObservationError ||
        error instanceof RuntimeReceiptFollowJournalError
      ) {
        throw error;
      }
      fail("journal_conflict");
    }
    if (!this.db.inTransaction) fail("journal_conflict");
    const durableReceipt = this.db
      .prepare(
        `SELECT 1 FROM runtime_compensation_receipts
         WHERE id = ? AND compensation_command_id = ?
           AND compensation_id = ? AND source_command_id = ? AND receipt_digest = ?`
      )
      .get(
        settlement.receiptId,
        command.commandId,
        command.compensationId,
        command.source.lifecycleCommandId,
        settlement.effectiveReceiptDigest
      );
    if (!durableReceipt) fail("journal_conflict");

    const receiptSequence = safeAdd(stream.receipt_sequence, 1);
    this.db
      .prepare(
        `INSERT INTO runtime_compensation_follow_events
           (id, runtime_assignment_id, session_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, issuer_key_id, public_key_spki_digest,
            receipt_sequence, cursor, previous_cursor, previous_observation_digest,
            observation_digest, compensation_command_id, compensation_id,
            source_command_id, command_digest, receipt_id, wire_receipt_digest,
            effective_receipt_digest, signature, lease_owner, lease_version,
            observed_at_ms, received_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        observation.observationId,
        stream.runtime_assignment_id,
        stream.session_id,
        stream.runtime_assignment_generation,
        stream.sandbox_id,
        stream.sandbox_generation,
        stream.runtime_principal_id,
        stream.runtime_authorization_generation,
        stream.issuer_key_id,
        stream.public_key_spki_digest,
        receiptSequence,
        observation.cursor,
        observation.previous?.cursor ?? null,
        observation.previous?.observationDigest ?? null,
        observation.observationDigest,
        command.commandId,
        command.compensationId,
        command.source.lifecycleCommandId,
        commandRow.command_digest,
        settlement.receiptId,
        observation.receiptDigest,
        settlement.effectiveReceiptDigest,
        observation.authority.signature,
        options.workerId,
        options.expectedLeaseVersion,
        observation.observedAtMs,
        options.receivedAtMs
      );
    this.advanceFollowStream(observation, receiptSequence, options);
    return Object.freeze({ kind: "settled", result: settlement });
  }

  private advanceFollowStream(
    observation:
      | VerifiedRuntimeLifecycleReceiptObservation
      | VerifiedRuntimeCompensationReceiptObservation,
    receiptSequence: number,
    options: ReturnType<typeof snapshotSettlementOptions>
  ): void {
    const availableAtMs = safeAdd(options.receivedAtMs, this.retryDelayMs);
    const advanced = this.db
      .prepare(
        `UPDATE runtime_receipt_follow_streams
         SET status = 'pending', available_at_ms = ?, lease_owner = NULL,
             lease_expires_at_ms = NULL, cursor = ?, last_observation_digest = ?,
             receipt_sequence = ?, last_safe_error_code = NULL, updated_at_ms = ?
         WHERE runtime_assignment_id = ? AND runtime_authorization_generation = ?
           AND status = 'processing' AND lease_owner = ? AND lease_version = ?
           AND lease_expires_at_ms = ? AND lease_expires_at_ms > ?`
      )
      .run(
        availableAtMs,
        observation.cursor,
        observation.observationDigest,
        receiptSequence,
        options.receivedAtMs,
        options.runtimeAssignmentId,
        options.runtimeAuthorizationGeneration,
        options.workerId,
        options.expectedLeaseVersion,
        options.expectedLeaseExpiresAtMs,
        options.receivedAtMs
      );
    if (advanced.changes !== 1) fail("stale_lease");
  }

  private exactLeasedStream(
    options: ReturnType<typeof snapshotSettlementOptions>
  ): FollowStreamRow {
    const row = this.db
      .prepare(
        `${FOLLOW_STREAM_SELECT}
         WHERE stream.runtime_assignment_id = ?
           AND stream.runtime_authorization_generation = ?
           AND stream.status = 'processing' AND stream.lease_owner = ?
           AND stream.lease_version = ? AND stream.lease_expires_at_ms = ?
           AND stream.lease_expires_at_ms > ?`
      )
      .get(
        options.runtimeAssignmentId,
        options.runtimeAuthorizationGeneration,
        options.workerId,
        options.expectedLeaseVersion,
        options.expectedLeaseExpiresAtMs,
        options.receivedAtMs
      ) as FollowStreamRow | undefined;
    if (!row) fail("stale_lease");
    return row;
  }

  /**
   * Contain an authenticated claim that cannot prove its enforced effect. The
   * ordinary command remains uncertain and eligible only for later trusted
   * reconciliation; no receipt, effect, follow event, or cursor is accepted.
   */
  private containEnforcementProofFailureInTransaction(
    stream: FollowStreamRow,
    command: CommandRow,
    options: ReturnType<typeof snapshotSettlementOptions>,
    safeCode: RuntimeReceiptFollowSettlementRejectionCode
  ): RuntimeReceiptFollowContainmentResult {
    if (!this.db.inTransaction) fail("journal_conflict");
    try {
      return this.applyEnforcementProofContainment(stream, command, options, safeCode);
    } catch (error) {
      if (error instanceof RuntimeReceiptFollowJournalError) throw error;
      fail("journal_conflict");
    }
  }

  /**
   * Historical compensation containment is deliberately stream-local. The
   * exact compensation work remains awaiting a later trusted receipt, while
   * replacement assignment and Session authorization state are untouched.
   */
  private containCompensationEnforcementProofFailureInTransaction(
    stream: FollowStreamRow,
    command: CompensationCommandRow,
    options: ReturnType<typeof snapshotSettlementOptions>,
    safeCode: RuntimeReceiptFollowSettlementRejectionCode
  ): RuntimeReceiptFollowContainmentResult {
    if (!this.db.inTransaction) fail("journal_conflict");
    try {
      const dispatch = this.db
        .prepare(
          `UPDATE runtime_compensation_dispatch AS dispatch
           SET status = 'awaiting-receipt', available_at_ms = MAX(available_at_ms, ?),
               lease_owner = NULL, lease_expires_at_ms = NULL,
               last_safe_error_code = ?, updated_at_ms = ?
           WHERE compensation_command_id = ? AND compensation_id = ?
             AND source_command_id = ? AND status = 'awaiting-receipt'
             AND lease_owner IS NULL AND lease_expires_at_ms IS NULL
             AND EXISTS (
               SELECT 1
               FROM runtime_compensation_incidents incident
               JOIN runtime_run_command_dispatch source_dispatch
                 ON source_dispatch.command_id = incident.source_command_id
               WHERE incident.compensation_id = dispatch.compensation_id
                 AND incident.source_command_id = dispatch.source_command_id
                 AND incident.trust_state = 'verified'
                 AND source_dispatch.status = 'compensating'
             )`
        )
        .run(
          options.receivedAtMs,
          safeCode,
          options.receivedAtMs,
          command.id,
          command.compensation_id,
          command.source_command_id
        );
      if (dispatch.changes !== 1) fail("journal_conflict");

      const follow = this.db
        .prepare(
          `UPDATE runtime_receipt_follow_streams
           SET status = 'quarantined', lease_owner = NULL, lease_expires_at_ms = NULL,
               last_safe_error_code = ?, updated_at_ms = ?
           WHERE runtime_assignment_id = ? AND runtime_authorization_generation = ?
             AND session_id = ? AND runtime_assignment_generation = ?
             AND sandbox_id = ? AND sandbox_generation = ? AND runtime_principal_id = ?
             AND status = 'processing' AND lease_owner = ? AND lease_version = ?
             AND lease_expires_at_ms = ? AND lease_expires_at_ms > ?`
        )
        .run(
          safeCode,
          options.receivedAtMs,
          stream.runtime_assignment_id,
          stream.runtime_authorization_generation,
          stream.session_id,
          stream.runtime_assignment_generation,
          stream.sandbox_id,
          stream.sandbox_generation,
          stream.runtime_principal_id,
          options.workerId,
          options.expectedLeaseVersion,
          options.expectedLeaseExpiresAtMs,
          options.receivedAtMs
        );
      if (follow.changes !== 1) fail("stale_lease");
      return Object.freeze({ kind: "contained", code: safeCode });
    } catch (error) {
      if (error instanceof RuntimeReceiptFollowJournalError) throw error;
      fail("journal_conflict");
    }
  }

  private applyEnforcementProofContainment(
    stream: FollowStreamRow,
    command: CommandRow,
    options: ReturnType<typeof snapshotSettlementOptions>,
    safeCode: RuntimeReceiptFollowSettlementRejectionCode
  ): RuntimeReceiptFollowContainmentResult {
    const dispatch = this.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'awaiting-receipt', available_at_ms = MAX(available_at_ms, ?),
             lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = ?, updated_at_ms = ?
         WHERE command_id = ? AND agent_run_id = ? AND status = 'awaiting-receipt'
           AND lease_owner IS NULL AND lease_expires_at_ms IS NULL`
      )
      .run(options.receivedAtMs, safeCode, options.receivedAtMs, command.id, command.agent_run_id);
    if (dispatch.changes !== 1) fail("journal_conflict");

    this.invalidateMutableRunGrants(command.agent_run_id, options.receivedAtMs);

    this.db
      .prepare(
        `UPDATE runtime_assignments SET status = 'quarantined'
         WHERE id = ? AND session_id = ? AND team_id = ? AND project_id = ?
           AND generation = ? AND sandbox_id = ? AND sandbox_generation = ?
           AND runtime_principal_id = ? AND runtime_authorization_generation = ?
           AND status IN (
             'provisioning', 'ready', 'checkpointing', 'recovering', 'quarantined'
           )`
      )
      .run(
        stream.runtime_assignment_id,
        stream.session_id,
        stream.team_id,
        stream.project_id,
        stream.runtime_assignment_generation,
        stream.sandbox_id,
        stream.sandbox_generation,
        stream.runtime_principal_id,
        stream.runtime_authorization_generation
      );

    const quarantinedSession = this.db
      .prepare(
        `UPDATE sessions
         SET runtime_authorization_state = 'quarantined',
             run_state_revision = run_state_revision + 1,
             next_sequence = next_sequence + 1
         WHERE id = ? AND team_id = ? AND project_id = ?
           AND runtime_authorization_generation = ?
           AND runtime_authorization_state = 'enforced'
           AND EXISTS (
             SELECT 1 FROM runtime_assignments assignment
             WHERE assignment.id = ? AND assignment.session_id = sessions.id
               AND assignment.team_id = sessions.team_id
               AND assignment.project_id = sessions.project_id
               AND assignment.generation = ? AND assignment.sandbox_id = ?
               AND assignment.sandbox_generation = ?
               AND assignment.runtime_principal_id = ?
               AND assignment.runtime_authorization_generation = ?
           )
         RETURNING run_state_revision, next_sequence - 1 AS event_sequence`
      )
      .get(
        stream.session_id,
        stream.team_id,
        stream.project_id,
        stream.runtime_authorization_generation,
        stream.runtime_assignment_id,
        stream.runtime_assignment_generation,
        stream.sandbox_id,
        stream.sandbox_generation,
        stream.runtime_principal_id,
        stream.runtime_authorization_generation
      ) as SqlRow | undefined;

    if (quarantinedSession) {
      const eventSequence = positiveInteger(quarantinedSession.event_sequence);
      this.db
        .prepare(
          `INSERT INTO session_events
             (session_id, sequence, event_id, type, occurred_at_ms,
              actor_kind, actor_user_id, actor_display_name,
              source_scope, source_key, payload_json)
           VALUES (?, ?, ?, 'session.runtime-authorization.quarantined', ?,
                   'system', 'team-session-kernel', 'Team Session Kernel',
                   'runtime-worker:receipt-follow', ?, ?)`
        )
        .run(
          stream.session_id,
          eventSequence,
          this.nextId(),
          options.receivedAtMs,
          `enforcement-proof-containment:${command.command_digest}`,
          JSON.stringify({
            commandDigest: command.command_digest,
            requiredEffectEnforcerSetDigest: command.required_effect_enforcer_set_digest,
            runtimeAuthorizationGeneration: stream.runtime_authorization_generation,
            safeErrorCode: safeCode,
          })
        );
    }

    const follow = this.db
      .prepare(
        `UPDATE runtime_receipt_follow_streams
         SET status = 'quarantined', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = ?, updated_at_ms = ?
         WHERE runtime_assignment_id = ? AND runtime_authorization_generation = ?
           AND session_id = ? AND runtime_assignment_generation = ?
           AND sandbox_id = ? AND sandbox_generation = ? AND runtime_principal_id = ?
           AND status = 'processing' AND lease_owner = ? AND lease_version = ?
           AND lease_expires_at_ms = ? AND lease_expires_at_ms > ?`
      )
      .run(
        safeCode,
        options.receivedAtMs,
        stream.runtime_assignment_id,
        stream.runtime_authorization_generation,
        stream.session_id,
        stream.runtime_assignment_generation,
        stream.sandbox_id,
        stream.sandbox_generation,
        stream.runtime_principal_id,
        options.workerId,
        options.expectedLeaseVersion,
        options.expectedLeaseExpiresAtMs,
        options.receivedAtMs
      );
    if (follow.changes !== 1) fail("stale_lease");

    return Object.freeze({ kind: "contained", code: safeCode });
  }

  private invalidateMutableRunGrants(agentRunId: string, nowMs: number): void {
    const grants = this.db
      .prepare(
        `SELECT grant.id, state.version
         FROM action_grants grant
         JOIN action_grant_states state ON state.grant_id = grant.id
         WHERE grant.agent_run_id = ?
           AND state.version = (
             SELECT MAX(candidate.version) FROM action_grant_states candidate
             WHERE candidate.grant_id = grant.id
           )
           AND state.status IN ('issued', 'enforcement-pending', 'active')
         ORDER BY grant.id ASC`
      )
      .all(agentRunId) as SqlRow[];
    const insert = this.db.prepare(
      `INSERT INTO action_grant_states
         (grant_id, version, previous_version, status, reason, actor_ref, created_at_ms)
       VALUES (?, ?, ?, 'invalidated', 'runtime-authorization', 'team-session-kernel', ?)`
    );
    for (const grant of grants) {
      const grantId = safeIdentifier(grant.id, MAX_IDENTIFIER_LENGTH, "journal_conflict");
      const version = positiveInteger(grant.version);
      insert.run(grantId, version + 1, version, nowMs);
    }
  }

  private containRejectedObservation(
    options: ReturnType<typeof snapshotSettlementOptions>,
    code: string
  ): void {
    try {
      if (code === "expired") {
        this.releaseExactLease(
          { ...options, nowMs: options.receivedAtMs },
          safeAdd(options.receivedAtMs, this.retryDelayMs),
          "follow_observation_expired"
        );
        return;
      }
      const reason =
        code === "chain_mismatch"
          ? "invalid_observation_chain"
          : code === "invalid_signature" || code === "untrusted_issuer"
            ? "invalid_observation_signature"
            : "invalid_observation";
      this.quarantineExactLease({ ...options, nowMs: options.receivedAtMs }, reason);
    } catch {
      // Preserve the safe verification error. A concurrent lease loss is not
      // evidence that an untrusted observation should be accepted.
    }
  }

  private releaseExactLease(
    options: ExactRuntimeReceiptFollowLease,
    availableAtMs: number,
    safeCode: string
  ): void {
    if (options.nowMs >= options.expectedLeaseExpiresAtMs) fail("stale_lease");
    const release = this.db.transaction(() => {
      const updated = this.db
        .prepare(
          `UPDATE runtime_receipt_follow_streams
           SET status = 'pending', available_at_ms = ?, lease_owner = NULL,
               lease_expires_at_ms = NULL, last_safe_error_code = ?, updated_at_ms = ?
           WHERE runtime_assignment_id = ? AND runtime_authorization_generation = ?
             AND status = 'processing' AND lease_owner = ? AND lease_version = ?
             AND lease_expires_at_ms = ? AND lease_expires_at_ms > ?`
        )
        .run(
          availableAtMs,
          safeCode,
          options.nowMs,
          options.runtimeAssignmentId,
          options.runtimeAuthorizationGeneration,
          options.workerId,
          options.expectedLeaseVersion,
          options.expectedLeaseExpiresAtMs,
          options.nowMs
        );
      if (updated.changes !== 1) fail("stale_lease");
    });
    runImmediate(release);
  }

  private quarantineExactLease(options: ExactRuntimeReceiptFollowLease, safeCode: string): void {
    const quarantine = this.db.transaction(() => {
      const updated = this.db
        .prepare(
          `UPDATE runtime_receipt_follow_streams
           SET status = 'quarantined', lease_owner = NULL, lease_expires_at_ms = NULL,
               last_safe_error_code = ?, updated_at_ms = ?
           WHERE runtime_assignment_id = ? AND runtime_authorization_generation = ?
             AND status = 'processing' AND lease_owner = ? AND lease_version = ?
             AND lease_expires_at_ms = ? AND lease_expires_at_ms > ?`
        )
        .run(
          safeCode,
          options.nowMs,
          options.runtimeAssignmentId,
          options.runtimeAuthorizationGeneration,
          options.workerId,
          options.expectedLeaseVersion,
          options.expectedLeaseExpiresAtMs,
          options.nowMs
        );
      if (updated.changes !== 1) fail("stale_lease");
    });
    runImmediate(quarantine);
  }

  private bindingIsCurrent(
    binding: RuntimeBinding,
    authorizationGeneration: number,
    createdAtMs: number
  ): boolean {
    return Boolean(
      this.db
        .prepare(
          `SELECT 1
           FROM runtime_assignments assignment
           JOIN sessions session ON session.id = assignment.session_id
           JOIN runtime_authorization_epochs epoch
             ON epoch.session_id = assignment.session_id
            AND epoch.generation = ?
            AND epoch.runtime_assignment_id = assignment.id
            AND epoch.runtime_assignment_generation = assignment.generation
            AND epoch.sandbox_id = assignment.sandbox_id
            AND epoch.sandbox_generation = assignment.sandbox_generation
            AND epoch.runtime_principal_id = assignment.runtime_principal_id
           WHERE assignment.id = ? AND assignment.team_id = ? AND assignment.project_id = ?
             AND assignment.session_id = ? AND assignment.generation = ?
             AND assignment.sandbox_id = ? AND assignment.sandbox_generation = ?
             AND assignment.runtime_principal_id = ?
             AND assignment.runtime_authorization_generation = ?
             AND (
               (assignment.status = 'provisioning' AND
                session.runtime_authorization_state = 'pending') OR
               (assignment.status IN ('ready', 'checkpointing', 'recovering', 'quarantined') AND
                session.runtime_authorization_state IN ('enforced', 'pending', 'quarantined'))
             )
             AND session.runtime_authorization_generation = ?
             AND session.status <> 'ended'
             AND epoch.effect_enforcer_policy_digest IS NOT NULL
             AND epoch.created_at_ms <= ?
             AND assignment.created_at_ms <= ?
             AND session.created_at_ms <= ?`
        )
        .get(
          authorizationGeneration,
          binding.runtimeAssignmentId,
          binding.teamId,
          binding.projectId,
          binding.sessionId,
          binding.runtimeAssignmentGeneration,
          binding.sandboxId,
          binding.sandboxGeneration,
          binding.runtimePrincipalId,
          authorizationGeneration,
          authorizationGeneration,
          createdAtMs,
          createdAtMs,
          createdAtMs
        )
    );
  }

  private awaitingReceiptPredicate(): string {
    return this.settleVerifiedCompensationReceiptInTransaction === undefined
      ? FOLLOW_STREAM_HAS_CURRENT_LIFECYCLE_RECEIPT
      : FOLLOW_STREAM_HAS_AWAITING_RECEIPT;
  }

  private nextId(): string {
    return safeIdentifier(this.idGenerator(), MAX_IDENTIFIER_LENGTH, "journal_conflict");
  }
}

const FOLLOW_STREAM_HAS_CURRENT_LIFECYCLE_RECEIPT = `EXISTS (
  SELECT 1
  FROM runtime_assignments current_assignment
  JOIN sessions current_session ON current_session.id = current_assignment.session_id
  JOIN runtime_run_commands command
    ON command.session_id = current_assignment.session_id
   AND command.runtime_assignment_id = current_assignment.id
   AND command.runtime_assignment_generation = current_assignment.generation
   AND command.sandbox_id = current_assignment.sandbox_id
   AND command.sandbox_generation = current_assignment.sandbox_generation
   AND command.runtime_principal_id = current_assignment.runtime_principal_id
  JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
  JOIN runtime_authorization_epochs epoch
    ON epoch.session_id = command.session_id
   AND epoch.generation = command.runtime_authorization_generation
   AND epoch.runtime_assignment_id = command.runtime_assignment_id
   AND epoch.runtime_assignment_generation = command.runtime_assignment_generation
   AND epoch.sandbox_id = command.sandbox_id
   AND epoch.sandbox_generation = command.sandbox_generation
   AND epoch.runtime_principal_id = command.runtime_principal_id
  JOIN runtime_effect_enforcer_set_activations activation
    ON activation.session_id = epoch.session_id
   AND activation.generation = epoch.generation
   AND activation.runtime_assignment_id = epoch.runtime_assignment_id
   AND activation.runtime_assignment_generation = epoch.runtime_assignment_generation
   AND activation.sandbox_id = epoch.sandbox_id
   AND activation.sandbox_generation = epoch.sandbox_generation
   AND activation.runtime_principal_id = epoch.runtime_principal_id
   AND activation.effect_enforcer_policy_digest = epoch.effect_enforcer_policy_digest
  WHERE current_assignment.id = stream.runtime_assignment_id
    AND current_assignment.session_id = stream.session_id
    AND current_assignment.generation = stream.runtime_assignment_generation
    AND current_assignment.sandbox_id = stream.sandbox_id
    AND current_assignment.sandbox_generation = stream.sandbox_generation
    AND current_assignment.runtime_principal_id = stream.runtime_principal_id
    AND current_assignment.runtime_authorization_generation =
      stream.runtime_authorization_generation
    AND current_assignment.status = 'ready'
    AND current_session.status <> 'ended'
    AND current_session.runtime_authorization_generation =
      stream.runtime_authorization_generation
    AND current_session.runtime_authorization_state = 'enforced'
    AND command.runtime_authorization_generation = stream.runtime_authorization_generation
    AND command.required_effect_enforcer_set_digest IS NOT NULL
    AND command.required_effect_enforcer_set_digest = activation.effect_enforcer_set_digest
    AND dispatch.status = 'awaiting-receipt'
)`;

const FOLLOW_STREAM_HAS_HISTORICAL_COMPENSATION_RECEIPT = `EXISTS (
  SELECT 1
  FROM runtime_assignments historical_assignment
  JOIN runtime_compensation_commands command
    ON command.session_id = historical_assignment.session_id
   AND command.team_id = historical_assignment.team_id
   AND command.project_id = historical_assignment.project_id
   AND command.runtime_assignment_id = historical_assignment.id
   AND command.runtime_assignment_generation = historical_assignment.generation
   AND command.sandbox_id = historical_assignment.sandbox_id
   AND command.sandbox_generation = historical_assignment.sandbox_generation
   AND command.runtime_principal_id = historical_assignment.runtime_principal_id
  JOIN runtime_compensation_dispatch dispatch
    ON dispatch.compensation_command_id = command.id
  JOIN runtime_compensation_incidents incident
    ON incident.compensation_id = command.compensation_id
   AND incident.source_command_id = command.source_command_id
  JOIN runtime_run_command_dispatch source_dispatch
    ON source_dispatch.command_id = command.source_command_id
  WHERE historical_assignment.id = stream.runtime_assignment_id
    AND historical_assignment.session_id = stream.session_id
    AND historical_assignment.generation = stream.runtime_assignment_generation
    AND historical_assignment.sandbox_id = stream.sandbox_id
    AND historical_assignment.sandbox_generation = stream.sandbox_generation
    AND historical_assignment.runtime_principal_id = stream.runtime_principal_id
    AND command.observed_runtime_authorization_generation =
      stream.runtime_authorization_generation
    AND incident.trust_state = 'verified'
    AND incident.session_id = stream.session_id
    AND incident.team_id = historical_assignment.team_id
    AND incident.project_id = historical_assignment.project_id
    AND incident.runtime_assignment_id = stream.runtime_assignment_id
    AND incident.runtime_assignment_generation = stream.runtime_assignment_generation
    AND incident.sandbox_id = stream.sandbox_id
    AND incident.sandbox_generation = stream.sandbox_generation
    AND incident.runtime_principal_id = stream.runtime_principal_id
    AND incident.runtime_authorization_generation = stream.runtime_authorization_generation
    AND dispatch.status = 'awaiting-receipt'
    AND source_dispatch.status = 'compensating'
)`;

const FOLLOW_STREAM_HAS_AWAITING_RECEIPT = `
  (${FOLLOW_STREAM_HAS_CURRENT_LIFECYCLE_RECEIPT}) OR
  (${FOLLOW_STREAM_HAS_HISTORICAL_COMPENSATION_RECEIPT})
`;

const FOLLOW_STREAM_SELECT = `
  SELECT stream.*, key.public_key_spki_pem,
         assignment.team_id, assignment.project_id
  FROM runtime_receipt_follow_streams stream
  JOIN runtime_principal_observation_keys key
    ON key.runtime_assignment_id = stream.runtime_assignment_id
   AND key.runtime_authorization_generation = stream.runtime_authorization_generation
   AND key.issuer_key_id = stream.issuer_key_id
   AND key.public_key_spki_digest = stream.public_key_spki_digest
  JOIN runtime_assignments assignment
    ON assignment.id = stream.runtime_assignment_id
   AND assignment.session_id = stream.session_id
   AND assignment.generation = stream.runtime_assignment_generation
   AND assignment.sandbox_id = stream.sandbox_id
   AND assignment.sandbox_generation = stream.sandbox_generation
   AND assignment.runtime_principal_id = stream.runtime_principal_id`;

export function createSqliteRuntimeReceiptFollowJournal(
  options: CreateSqliteRuntimeReceiptFollowJournalOptions
): SqliteRuntimeReceiptFollowJournal {
  return new SqliteRuntimeReceiptFollowJournal(options);
}

function snapshotRegistration(value: RuntimeReceiptFollowRegistration) {
  const input = plainRecord(value, "invalid_input");
  exactFields(
    input,
    ["binding", "runtimeAuthorizationGeneration", "issuerKeyId", "publicKeySpkiPem", "createdAtMs"],
    "invalid_input"
  );
  const publicKeySpkiPem = dataField(input, "publicKeySpkiPem", "invalid_public_key");
  if (
    typeof publicKeySpkiPem !== "string" ||
    Buffer.byteLength(publicKeySpkiPem, "utf8") > MAX_PUBLIC_KEY_BYTES
  ) {
    fail("invalid_public_key");
  }
  return Object.freeze({
    binding: snapshotBinding(dataField(input, "binding", "invalid_input")),
    runtimeAuthorizationGeneration: positiveInteger(
      dataField(input, "runtimeAuthorizationGeneration", "invalid_input")
    ),
    issuerKeyId: keyId(dataField(input, "issuerKeyId", "invalid_input")),
    publicKeySpkiPem,
    createdAtMs: nonNegativeInteger(dataField(input, "createdAtMs", "invalid_input")),
  });
}

function snapshotClaimOptions(value: RuntimeReceiptFollowClaimOptions) {
  const input = plainRecord(value, "invalid_input");
  exactFields(input, ["workerId", "leaseDurationMs", "nowMs"], "invalid_input");
  return Object.freeze({
    workerId: safeIdentifier(dataField(input, "workerId", "invalid_input"), MAX_WORKER_ID_LENGTH),
    leaseDurationMs: boundedInteger(
      dataField(input, "leaseDurationMs", "invalid_input"),
      1,
      MAX_LEASE_DURATION_MS
    ),
    nowMs: nonNegativeInteger(dataField(input, "nowMs", "invalid_input")),
  });
}

function snapshotExactLease(value: ExactRuntimeReceiptFollowLease) {
  const input = plainRecord(value, "invalid_input");
  return {
    input,
    result: {
      runtimeAssignmentId: safeIdentifier(
        dataField(input, "runtimeAssignmentId", "invalid_input"),
        MAX_IDENTIFIER_LENGTH
      ),
      runtimeAuthorizationGeneration: positiveInteger(
        dataField(input, "runtimeAuthorizationGeneration", "invalid_input")
      ),
      workerId: safeIdentifier(dataField(input, "workerId", "invalid_input"), MAX_WORKER_ID_LENGTH),
      expectedLeaseVersion: positiveInteger(
        dataField(input, "expectedLeaseVersion", "invalid_input")
      ),
      expectedLeaseExpiresAtMs: positiveInteger(
        dataField(input, "expectedLeaseExpiresAtMs", "invalid_input")
      ),
      nowMs: nonNegativeInteger(dataField(input, "nowMs", "invalid_input")),
    },
  } as const;
}

function snapshotRenewalOptions(value: RuntimeReceiptFollowRenewalOptions) {
  const { input, result } = snapshotExactLease(value);
  exactFields(
    input,
    [
      "runtimeAssignmentId",
      "runtimeAuthorizationGeneration",
      "workerId",
      "expectedLeaseVersion",
      "expectedLeaseExpiresAtMs",
      "nowMs",
      "leaseDurationMs",
    ],
    "invalid_input"
  );
  return Object.freeze({
    ...result,
    leaseDurationMs: boundedInteger(
      dataField(input, "leaseDurationMs", "invalid_input"),
      1,
      MAX_LEASE_DURATION_MS
    ),
  });
}

function snapshotReleaseOptions(value: RuntimeReceiptFollowReleaseOptions) {
  const { input, result } = snapshotExactLease(value);
  exactFields(
    input,
    [
      "runtimeAssignmentId",
      "runtimeAuthorizationGeneration",
      "workerId",
      "expectedLeaseVersion",
      "expectedLeaseExpiresAtMs",
      "nowMs",
      "reason",
    ],
    "invalid_input"
  );
  const reason = dataField(input, "reason", "invalid_input");
  if (reason !== "no-event" && reason !== "transport-unavailable") fail("invalid_input");
  return Object.freeze({ ...result, reason });
}

function snapshotQuarantineOptions(value: RuntimeReceiptFollowQuarantineOptions) {
  const { input, result } = snapshotExactLease(value);
  exactFields(
    input,
    [
      "runtimeAssignmentId",
      "runtimeAuthorizationGeneration",
      "workerId",
      "expectedLeaseVersion",
      "expectedLeaseExpiresAtMs",
      "nowMs",
      "reason",
    ],
    "invalid_input"
  );
  const reason = dataField(input, "reason", "invalid_input");
  if (
    reason !== "invalid-observation" &&
    reason !== "invalid-observation-chain" &&
    reason !== "invalid-observation-signature"
  ) {
    fail("invalid_input");
  }
  return Object.freeze({ ...result, reason });
}

function snapshotSettlementOptions(value: RuntimeReceiptFollowSettlementOptions) {
  const { input, result } = snapshotExactLease(value);
  exactFields(
    input,
    [
      "runtimeAssignmentId",
      "runtimeAuthorizationGeneration",
      "workerId",
      "expectedLeaseVersion",
      "expectedLeaseExpiresAtMs",
      "nowMs",
      "observation",
      "receivedAtMs",
    ],
    "invalid_input"
  );
  const receivedAtMs = nonNegativeInteger(dataField(input, "receivedAtMs", "invalid_input"));
  if (receivedAtMs !== result.nowMs) fail("invalid_input");
  return Object.freeze({
    ...result,
    observation: dataField(input, "observation", "invalid_input"),
    receivedAtMs,
  });
}

function snapshotSettlementResult(value: RuntimeReceiptFollowSettlementResult) {
  const result = plainRecord(value, "journal_conflict");
  exactFields(result, ["receiptId", "effectiveReceiptDigest"], "journal_conflict");
  return Object.freeze({
    receiptId: safeIdentifier(
      dataField(result, "receiptId", "journal_conflict"),
      MAX_IDENTIFIER_LENGTH,
      "journal_conflict"
    ),
    effectiveReceiptDigest: digest(
      dataField(result, "effectiveReceiptDigest", "journal_conflict"),
      "journal_conflict"
    ),
  });
}

function parsePersistedCommand(row: CommandRow, expectedBinding: RuntimeBinding) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.command_json);
  } catch {
    fail("invalid_observation");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    fail("invalid_observation");
  }
  const command = parsed as RuntimeLifecycleCommand;
  let canonicalDigest: string;
  let claimsDigest: string;
  try {
    canonicalDigest = sha256(canonicalRuntimeJson(command));
    claimsDigest = digestRuntimeCommandClaims(command);
  } catch {
    fail("invalid_observation");
  }
  if (
    command.commandId !== row.id ||
    command.kind !== row.operation ||
    command.binding === undefined ||
    !sameBinding(command.binding, expectedBinding) ||
    command.runtimeAuthorizationGeneration !== row.runtime_authorization_generation ||
    command.authority?.claimsDigest !== row.authority_digest ||
    claimsDigest !== row.authority_digest ||
    canonicalDigest !== row.command_digest ||
    !SHA256.test(command.requiredEffectEnforcerSetDigest ?? "") ||
    command.requiredEffectEnforcerSetDigest !== row.required_effect_enforcer_set_digest
  ) {
    fail("invalid_observation");
  }
  return deepFreeze(command);
}

function parsePersistedCompensationCommand(
  row: CompensationCommandRow,
  expectedBinding: RuntimeBinding
): RuntimeCompensationCommand {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.command_json);
  } catch {
    fail("invalid_observation");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    fail("invalid_observation");
  }
  const command = parsed as RuntimeCompensationCommand;
  let canonical: string;
  let claimsDigest: string;
  try {
    canonical = canonicalRuntimeJson(command);
    claimsDigest = digestRuntimeCommandClaims(command);
  } catch {
    fail("invalid_observation");
  }
  if (
    canonical !== row.command_json ||
    sha256(canonical) !== row.command_digest ||
    command.kind !== "safety.quarantine" ||
    row.operation !== command.kind ||
    command.commandId !== row.id ||
    command.compensationId !== row.compensation_id ||
    command.source?.lifecycleCommandId !== row.source_command_id ||
    command.binding === undefined ||
    !sameBinding(command.binding, expectedBinding) ||
    command.binding.teamId !== row.team_id ||
    command.binding.projectId !== row.project_id ||
    command.binding.sessionId !== row.session_id ||
    command.binding.runtimeAssignmentId !== row.runtime_assignment_id ||
    command.binding.runtimeAssignmentGeneration !== row.runtime_assignment_generation ||
    command.binding.sandboxId !== row.sandbox_id ||
    command.binding.sandboxGeneration !== row.sandbox_generation ||
    command.binding.runtimePrincipalId !== row.runtime_principal_id ||
    command.observedRuntimeAuthorizationGeneration !==
      row.observed_runtime_authorization_generation ||
    command.source.sourceRequiredEffectEnforcerSetDigest !==
      row.source_required_effect_enforcer_set_digest ||
    command.source.lifecycleCommandClaimsDigest !== row.lifecycle_command_claims_digest ||
    command.source.lifecycleReceiptDigest !== row.lifecycle_receipt_digest ||
    command.source.lifecycleEnforcementSubjectDigest !== row.lifecycle_enforcement_subject_digest ||
    command.source.lifecycleAggregateProofDigest !== row.lifecycle_aggregate_proof_digest ||
    command.platformSecurityPolicyRevision !== row.platform_security_policy_revision ||
    command.requiredContainmentEnforcerSetDigest !== row.required_containment_enforcer_set_digest ||
    command.safetyFence !== row.safety_fence ||
    command.reasonRef !== row.reason_ref ||
    command.causationId !== row.causation_id ||
    command.issuedAtMs !== row.created_at_ms ||
    command.deadlineAtMs !== row.deadline_at_ms ||
    command.authority?.claimsDigest !== row.authority_digest ||
    claimsDigest !== row.authority_digest ||
    row.authority_verified_at_ms < command.issuedAtMs ||
    row.authority_verified_at_ms >= command.deadlineAtMs ||
    row.authority_verified_at_ms < command.authority.issuedAtMs ||
    row.authority_verified_at_ms >= command.authority.expiresAtMs
  ) {
    fail("invalid_observation");
  }
  return deepFreeze(command);
}

function observationReference(value: unknown): {
  readonly kind: "lifecycle" | "compensation";
  readonly commandId: string;
} {
  const observation = plainRecord(value, "invalid_observation");
  const unsafeKind = dataField(observation, "kind", "invalid_observation");
  const kind =
    unsafeKind === "runtime.lifecycle-receipt-observed"
      ? "lifecycle"
      : unsafeKind === "runtime.compensation-receipt-observed"
        ? "compensation"
        : fail("invalid_observation");
  const command = plainRecord(
    dataField(observation, "command", "invalid_observation"),
    "invalid_observation"
  );
  return Object.freeze({
    kind,
    commandId: safeIdentifier(
      dataField(command, "commandId", "invalid_observation"),
      MAX_IDENTIFIER_LENGTH,
      "invalid_observation"
    ),
  });
}

function canonicalEd25519PublicKey(pem: string): { pem: string; digest: string } {
  if (
    !pem.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
    !pem.endsWith("-----END PUBLIC KEY-----\n") ||
    pem.includes("PRIVATE KEY")
  ) {
    fail("invalid_public_key");
  }
  try {
    const key = createPublicKey(pem);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      fail("invalid_public_key");
    }
    const canonicalPem = key.export({ format: "pem", type: "spki" }).toString();
    if (canonicalPem !== pem) fail("invalid_public_key");
    const der = key.export({ format: "der", type: "spki" });
    return Object.freeze({ pem: canonicalPem, digest: sha256(der) });
  } catch (error) {
    if (error instanceof RuntimeReceiptFollowJournalError) throw error;
    fail("invalid_public_key");
  }
}

function leaseFor(
  row: FollowStreamRow,
  lease: {
    attempt: number;
    leaseVersion: number;
    leaseOwner: string;
    leaseExpiresAtMs: number;
  }
): RuntimeReceiptFollowLease {
  return deepFreeze({
    binding: bindingFor(row),
    runtimeAuthorizationGeneration: row.runtime_authorization_generation,
    issuerKeyId: row.issuer_key_id,
    publicKeySpkiDigest: row.public_key_spki_digest,
    checkpoint: checkpointFor(row),
    attempt: lease.attempt,
    leaseOwner: lease.leaseOwner,
    leaseVersion: lease.leaseVersion,
    leaseExpiresAtMs: lease.leaseExpiresAtMs,
  });
}

function bindingFor(row: FollowStreamRow): RuntimeBinding {
  return Object.freeze({
    teamId: row.team_id,
    projectId: row.project_id,
    sessionId: row.session_id,
    runtimeAssignmentId: row.runtime_assignment_id,
    runtimeAssignmentGeneration: row.runtime_assignment_generation,
    sandboxId: row.sandbox_id,
    sandboxGeneration: row.sandbox_generation,
    runtimePrincipalId: row.runtime_principal_id,
  });
}

function checkpointFor(row: FollowStreamRow): RuntimeReceiptObservationCheckpoint | null {
  if (row.cursor === null || row.last_observation_digest === null) {
    if (row.cursor !== null || row.last_observation_digest !== null || row.receipt_sequence !== 0) {
      fail("journal_conflict");
    }
    return null;
  }
  if (row.receipt_sequence < 1 || !SHA256.test(row.last_observation_digest)) {
    fail("journal_conflict");
  }
  return Object.freeze({ cursor: row.cursor, observationDigest: row.last_observation_digest });
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const binding = plainRecord(value, "invalid_input");
  exactFields(binding, BINDING_FIELDS, "invalid_input");
  const result = {
    teamId: safeIdentifier(dataField(binding, "teamId", "invalid_input"), MAX_IDENTIFIER_LENGTH),
    projectId: safeIdentifier(
      dataField(binding, "projectId", "invalid_input"),
      MAX_IDENTIFIER_LENGTH
    ),
    sessionId: safeIdentifier(
      dataField(binding, "sessionId", "invalid_input"),
      MAX_IDENTIFIER_LENGTH
    ),
    runtimeAssignmentId: safeIdentifier(
      dataField(binding, "runtimeAssignmentId", "invalid_input"),
      MAX_IDENTIFIER_LENGTH
    ),
    runtimeAssignmentGeneration: positiveInteger(
      dataField(binding, "runtimeAssignmentGeneration", "invalid_input")
    ),
    sandboxId: safeIdentifier(
      dataField(binding, "sandboxId", "invalid_input"),
      MAX_IDENTIFIER_LENGTH
    ),
    sandboxGeneration: positiveInteger(dataField(binding, "sandboxGeneration", "invalid_input")),
    runtimePrincipalId: safeIdentifier(
      dataField(binding, "runtimePrincipalId", "invalid_input"),
      MAX_IDENTIFIER_LENGTH
    ),
  };
  return Object.freeze(result);
}

function sameBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
  return BINDING_FIELDS.every((field) => left[field] === right[field]);
}

function safeQuarantineCode(reason: RuntimeReceiptFollowQuarantineOptions["reason"]): string {
  switch (reason) {
    case "invalid-observation":
      return "invalid_observation";
    case "invalid-observation-chain":
      return "invalid_observation_chain";
    case "invalid-observation-signature":
      return "invalid_observation_signature";
  }
}

function plainRecord(
  value: unknown,
  code: RuntimeReceiptFollowJournalErrorCode
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(code);
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    fail(code);
  }
  if (prototype !== Object.prototype && prototype !== null) fail(code);
  return value as Record<string, unknown>;
}

function exactFields(
  value: Record<string, unknown>,
  expected: readonly string[],
  code: RuntimeReceiptFollowJournalErrorCode
): void {
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    fail(code);
  }
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    fail(code);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  }
}

function dataField(
  value: Record<string, unknown>,
  key: string,
  code: RuntimeReceiptFollowJournalErrorCode
): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, key);
  } catch {
    fail(code);
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  return descriptor.value;
}

function keyId(value: unknown): string {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) fail("invalid_input");
  return value;
}

function safeIdentifier(
  value: unknown,
  maximumLength: number,
  code: RuntimeReceiptFollowJournalErrorCode = "invalid_input"
): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximumLength ||
    value.trim() !== value ||
    /[\0\r\n\t]/.test(value)
  ) {
    fail(code);
  }
  return value;
}

function digest(value: unknown, code: RuntimeReceiptFollowJournalErrorCode): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(code);
  return value;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) {
    fail("invalid_input");
  }
  return value as number;
}

function positiveInteger(value: unknown): number {
  const result = nonNegativeInteger(value);
  if (result < 1) fail("invalid_input");
  return result;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail("invalid_input");
  }
  return value as number;
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result) || result < left) fail("invalid_input");
  return result;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function runImmediate<T>(transaction: { immediate(): T }): T {
  try {
    return transaction.immediate();
  } catch (error) {
    if (
      error instanceof RuntimeReceiptFollowJournalError ||
      error instanceof RuntimeReceiptObservationError ||
      error instanceof RuntimeCompensationReceiptObservationError
    ) {
      throw error;
    }
    fail("journal_conflict");
  }
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor) deepFreeze(descriptor.value);
  }
  return Object.freeze(value);
}

function fail(code: RuntimeReceiptFollowJournalErrorCode): never {
  throw new RuntimeReceiptFollowJournalError(code);
}
