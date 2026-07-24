import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import type {
  NonDuplicateRuntimeReceipt,
  RuntimeLifecycleCommand,
  RuntimeReceipt,
} from "../runtime/contracts";
import {
  canonicalRuntimeJson,
  digestRuntimeCommandClaims,
} from "../runtime/runtime-command-canonical";
import {
  RuntimeCommandExecutionError,
  snapshotRuntimeReceiptForCommand,
  verifyRuntimeReceiptEnforcementProofSynchronously,
} from "../runtime/runtime-command-execution";
import {
  commitRuntimeEffectRef,
  type SynchronousRuntimeEnforcementProofVerifier,
} from "../runtime/runtime-enforcement-proof";
import type {
  RuntimeLifecycleClaimOptions,
  RuntimeLifecycleCompletion,
  RuntimeLifecycleDelivery,
  RuntimeLifecycleJournal,
  RuntimeLifecycleReconcileOptions,
  RuntimeLifecycleRenewal,
  RuntimeLifecycleRenewalOptions,
} from "../runtime/runtime-lifecycle-supervisor";
import {
  RuntimeReceiptFollowSettlementRejection,
  type RuntimeReceiptFollowSettlementInput,
  type RuntimeReceiptFollowSettlementResult,
} from "./sqlite-runtime-receipt-follow-journal";
import { isVerifiedRuntimeLifecycleReceiptObservation } from "../runtime/runtime-receipt-observation";

type SqlValue = string | number | null;
type SqlRow = Record<string, SqlValue>;

const MAX_WORKER_ID_LENGTH = 128;
const MAX_IDENTIFIER_LENGTH = 300;
const MAX_SAFE_ERROR_CODE_LENGTH = 200;
const SHA256_DIGEST = /^[0-9a-f]{64}$/;
const DEFAULT_RETRY_DELAY_MS = 1_000;
const MAX_RETRY_DELAY_MS = 60_000;

/**
 * Complete persisted trust fence for a lifecycle command immediately before
 * dispatch. Keep this one predicate shared by reconciliation, claim, and
 * renewal so a new authority input cannot be checked at only one stage.
 * Callers must bind the named `nowMs` parameter.
 */
const CURRENT_RUNTIME_LIFECYCLE_DISPATCH_FENCE_SQL = `
  command.deadline_at_ms > @nowMs
  AND COALESCE(
    json_extract(command.command_json, '$.authority.expiresAtMs') > @nowMs,
    0
  )
  AND NOT EXISTS (
    SELECT 1 FROM runtime_run_command_receipts receipt
    WHERE receipt.command_id = command.id
  )
  AND EXISTS (
    SELECT 1
    FROM agent_runs run
    JOIN sessions session
      ON session.id = run.session_id
    JOIN runtime_assignments assignment
      ON assignment.id = run.runtime_assignment_id
     AND assignment.session_id = run.session_id
    JOIN run_policy_revisions policy
      ON policy.agent_run_id = run.id
     AND policy.session_id = run.session_id
     AND policy.revision = run.current_policy_revision
    JOIN goal_sets goal_set
      ON goal_set.agent_run_id = run.id
     AND goal_set.revision = run.current_goal_set_revision
    JOIN runtime_authorization_epochs epoch
      ON epoch.session_id = session.id
     AND epoch.generation = session.runtime_authorization_generation
    WHERE run.id = command.agent_run_id
      AND run.session_id = command.session_id
      AND run.team_id = session.team_id
      AND run.project_id = session.project_id
      AND session.status = 'active'
      AND json_extract(command.command_json, '$.binding.teamId') = session.team_id
      AND json_extract(command.command_json, '$.binding.projectId') = session.project_id
      AND run.state_version = command.expected_run_state_version
      AND run.current_policy_revision = command.run_policy_revision
      AND run.current_goal_set_revision = command.goal_set_revision
      AND goal_set.goal_set_id = command.goal_set_id
      AND run.runtime_assignment_id = command.runtime_assignment_id
      AND run.runtime_authorization_generation = command.runtime_authorization_generation
      AND session.runtime_authorization_generation = command.runtime_authorization_generation
      AND session.runtime_authorization_state = 'enforced'
      AND assignment.team_id = session.team_id
      AND assignment.project_id = session.project_id
      AND assignment.id = command.runtime_assignment_id
      AND assignment.generation = command.runtime_assignment_generation
      AND assignment.sandbox_id = command.sandbox_id
      AND assignment.sandbox_generation = command.sandbox_generation
      AND assignment.runtime_principal_id = command.runtime_principal_id
      AND assignment.runtime_authorization_generation =
        command.runtime_authorization_generation
      AND assignment.status = 'ready'
      AND policy.runtime_assignment_id = command.runtime_assignment_id
      AND policy.runtime_assignment_generation = command.runtime_assignment_generation
      AND policy.sandbox_id = command.sandbox_id
      AND policy.sandbox_generation = command.sandbox_generation
      AND policy.runtime_principal_id = command.runtime_principal_id
      AND policy.runtime_authorization_generation = command.runtime_authorization_generation
      AND policy.project_ceiling_revision =
        json_extract(command.command_json, '$.projectCeilingRevision')
      AND command.required_effect_enforcer_set_digest IS NOT NULL
      AND policy.required_effect_enforcer_set_digest =
        command.required_effect_enforcer_set_digest
      AND epoch.runtime_assignment_id = command.runtime_assignment_id
      AND epoch.runtime_assignment_generation = command.runtime_assignment_generation
      AND epoch.sandbox_id = command.sandbox_id
      AND epoch.sandbox_generation = command.sandbox_generation
      AND epoch.runtime_principal_id = command.runtime_principal_id
      AND epoch.effect_enforcer_set_digest = command.required_effect_enforcer_set_digest
      AND (command.operation <> 'run.start' OR run.start_command_id = command.id)
      AND (
        (command.operation = 'run.start' AND run.lifecycle = 'starting') OR
        (command.operation = 'run.pause' AND run.lifecycle = 'active') OR
        (command.operation = 'run.resume'
          AND run.lifecycle IN ('paused', 'agent-work-finished')) OR
        (command.operation = 'run.stop'
          AND run.lifecycle IN ('active', 'paused', 'agent-work-finished'))
      )
  )`;

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

export type RuntimeLifecycleJournalErrorCode =
  | "invalid_input"
  | "invalid_command"
  | "stale_completion"
  | "journal_conflict";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeLifecycleJournalErrorCode, string>> = {
  invalid_input: "Runtime lifecycle journal input is invalid",
  invalid_command: "Runtime lifecycle command is invalid",
  stale_completion: "Runtime lifecycle completion lease is stale",
  journal_conflict: "Runtime lifecycle journal state conflicts",
};

/** Safe internal error surface: provider values and persisted payloads are never interpolated. */
export class RuntimeLifecycleJournalError extends Error {
  constructor(readonly code: RuntimeLifecycleJournalErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeLifecycleJournalError";
  }
}

export interface CreateSqliteRuntimeLifecycleJournalOptions {
  readonly db: Database.Database;
  readonly idGenerator: () => string;
  readonly retryDelayMs?: number;
  /** Required synchronously to settle enforced receipts; absence always fails closed. */
  readonly verifyEnforcementProof?: SynchronousRuntimeEnforcementProofVerifier;
}

export interface RuntimeLifecycleIntent {
  readonly command: RuntimeLifecycleCommand;
  readonly sourceSessionSequence: number;
}

export interface RuntimeLifecycleIntentRecord {
  readonly commandId: string;
  readonly commandSequence: number;
  readonly commandDigest: string;
  readonly targetLifecycle: "active" | "paused" | "stopped";
}

interface CommandJournalRow extends SqlRow {
  id: string;
  session_id: string;
  agent_run_id: string;
  command_sequence: number;
  operation: RuntimeLifecycleCommand["kind"];
  target_lifecycle: "active" | "paused" | "stopped";
  expected_run_state_version: number;
  target_run_state_version: number;
  run_policy_revision: number;
  goal_set_id: string;
  goal_set_revision: number;
  runtime_assignment_id: string;
  runtime_assignment_generation: number;
  sandbox_id: string;
  sandbox_generation: number;
  runtime_principal_id: string;
  runtime_authorization_generation: number;
  required_effect_enforcer_set_digest: string;
  source_session_sequence: number;
  command_json: string;
  command_digest: string;
  created_at_ms: number;
  deadline_at_ms: number;
}

interface DispatchJournalRow extends SqlRow {
  command_id: string;
  agent_run_id: string;
  status:
    | "pending"
    | "processing"
    | "awaiting-receipt"
    | "compensating"
    | "enforced"
    | "rejected"
    | "quarantined"
    | "superseded"
    | "failed";
  attempts: number;
  available_at_ms: number;
  lease_owner: string | null;
  lease_expires_at_ms: number | null;
  last_safe_error_code: string | null;
  created_at_ms: number;
  updated_at_ms: number;
  terminal_at_ms: number | null;
}

interface CompletionRow extends CommandJournalRow {
  dispatch_status: DispatchJournalRow["status"];
  attempts: number;
  available_at_ms: number;
  lease_owner: string | null;
  lease_expires_at_ms: number | null;
  dispatch_interlock_acquired_at_ms: number | null;
  run_lifecycle: string;
  run_state_version: number;
  session_run_state_revision: number;
}

type ReceiptSettlementFence =
  | {
      readonly kind: "dispatch";
      readonly expectedAttempt: number;
      readonly expectedLeaseExpiresAtMs: number;
    }
  | { readonly kind: "follow" };

interface ReceiptSettlementContext {
  readonly actorRef: string;
  readonly observedAtMs: number;
  readonly fence: ReceiptSettlementFence;
}

/**
 * SQLite implementation of the durable Runtime lifecycle journal seam.
 *
 * Intent insertion is synchronous so it can participate in the Team Session
 * command transaction. Delivery and settlement each take an immediate write
 * lock and keep receipt, event, effect, Run state, and dispatch state atomic.
 */
export class SqliteRuntimeLifecycleJournal implements RuntimeLifecycleJournal {
  private readonly db: Database.Database;
  private readonly idGenerator: () => string;
  private readonly retryDelayMs: number;
  private readonly verifyEnforcementProof?: SynchronousRuntimeEnforcementProofVerifier;

  constructor(options: CreateSqliteRuntimeLifecycleJournalOptions) {
    if (
      !options?.db ||
      typeof options.db.prepare !== "function" ||
      typeof options.idGenerator !== "function"
    ) {
      fail("invalid_input");
    }
    this.db = options.db;
    this.idGenerator = options.idGenerator;
    if (
      options.verifyEnforcementProof !== undefined &&
      typeof options.verifyEnforcementProof !== "function"
    ) {
      fail("invalid_input");
    }
    this.verifyEnforcementProof = options.verifyEnforcementProof;
    this.retryDelayMs = boundedInteger(
      options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS,
      1,
      MAX_RETRY_DELAY_MS
    );
  }

  /** Record one signed immutable command and its initially-pending delivery. */
  enqueue(intent: RuntimeLifecycleIntent): RuntimeLifecycleIntentRecord {
    if (!this.db.inTransaction) fail("journal_conflict");
    const command = validateLifecycleCommand(intent?.command);
    const sourceSessionSequence = positiveInteger(intent?.sourceSessionSequence);
    const canonicalCommand = canonicalCommandJson(command);
    const commandDigest = sha256(canonicalCommand);
    if (digestRuntimeCommandClaims(command) !== command.authority.claimsDigest) {
      fail("invalid_command");
    }

    const run = this.db
      .prepare(
        `SELECT run.current_goal_set_revision, goal_set.goal_set_id
         FROM agent_runs run
         JOIN goal_sets goal_set
           ON goal_set.agent_run_id = run.id
          AND goal_set.revision = run.current_goal_set_revision
         WHERE run.id = ? AND run.session_id = ?`
      )
      .get(command.agentRunId, command.binding.sessionId) as SqlRow | undefined;
    if (!run) fail("journal_conflict");

    const sequence = this.db
      .prepare(
        `SELECT COALESCE(MAX(command_sequence), 0) + 1 AS next_sequence
         FROM runtime_run_commands WHERE agent_run_id = ?`
      )
      .get(command.agentRunId) as SqlRow;
    const commandSequence = positiveInteger(sequence.next_sequence);
    const previousCommandSequence = commandSequence === 1 ? null : commandSequence - 1;
    const targetLifecycle = targetLifecycleFor(command.kind);

    try {
      this.db
        .prepare(
          `INSERT INTO runtime_run_commands
             (id, session_id, agent_run_id, command_sequence, previous_command_sequence,
              operation, target_lifecycle, expected_run_state_version,
              target_run_state_version, run_policy_revision, goal_set_id,
              goal_set_revision, runtime_assignment_id, runtime_assignment_generation,
              sandbox_id, sandbox_generation, runtime_principal_id,
              runtime_authorization_generation, required_effect_enforcer_set_digest,
              source_session_sequence, command_json, command_digest, authority_digest,
              created_at_ms, deadline_at_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          command.commandId,
          command.binding.sessionId,
          command.agentRunId,
          commandSequence,
          previousCommandSequence,
          command.kind,
          targetLifecycle,
          command.fromRunStateVersion,
          command.toRunStateVersion,
          command.runPolicyRevision,
          run.goal_set_id,
          run.current_goal_set_revision,
          command.binding.runtimeAssignmentId,
          command.binding.runtimeAssignmentGeneration,
          command.binding.sandboxId,
          command.binding.sandboxGeneration,
          command.binding.runtimePrincipalId,
          command.runtimeAuthorizationGeneration,
          command.requiredEffectEnforcerSetDigest,
          sourceSessionSequence,
          JSON.stringify(command),
          commandDigest,
          command.authority.claimsDigest,
          command.issuedAtMs,
          command.deadlineAtMs
        );
      this.db
        .prepare(
          `INSERT INTO runtime_run_command_dispatch
             (command_id, agent_run_id, status, attempts, available_at_ms,
              lease_owner, lease_expires_at_ms, last_safe_error_code,
              created_at_ms, updated_at_ms, terminal_at_ms)
           VALUES (?, ?, 'pending', 0, ?, NULL, NULL, NULL, ?, ?, NULL)`
        )
        .run(
          command.commandId,
          command.agentRunId,
          command.issuedAtMs,
          command.issuedAtMs,
          command.issuedAtMs
        );
    } catch {
      fail("journal_conflict");
    }

    return Object.freeze({
      commandId: command.commandId,
      commandSequence,
      commandDigest,
      targetLifecycle,
    });
  }

  async reconcile(options: RuntimeLifecycleReconcileOptions): Promise<void> {
    const nowMs = nonNegativeInteger(options?.nowMs);
    const reconcile = this.db.transaction(() => {
      const expiredPredispatchLeases = this.db
        .prepare(
          `SELECT command.*
           FROM runtime_run_commands command
           JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
           WHERE dispatch.status = 'processing' AND dispatch.lease_expires_at_ms <= ?
             AND dispatch.dispatch_interlock_acquired_at_ms IS NULL
           ORDER BY dispatch.created_at_ms ASC, command.id ASC`
        )
        .all(nowMs) as CommandJournalRow[];
      for (const row of expiredPredispatchLeases) {
        const safeCode =
          row.deadline_at_ms <= nowMs ? "deadline_expired" : "lease_expired_before_dispatch";
        const updated = this.db
          .prepare(
            `UPDATE runtime_run_command_dispatch
             SET status = 'pending', lease_owner = NULL, lease_expires_at_ms = NULL,
                 last_safe_error_code = ?,
                 available_at_ms = MAX(available_at_ms, ?), updated_at_ms = ?
             WHERE command_id = ? AND status = 'processing'
               AND lease_expires_at_ms <= ?
               AND dispatch_interlock_acquired_at_ms IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM runtime_run_command_receipts receipt
                 WHERE receipt.command_id = runtime_run_command_dispatch.command_id
               )`
          )
          .run(safeCode, nowMs, nowMs, row.id, nowMs);
        if (updated.changes > 1) fail("journal_conflict");
      }

      const expiredDispatchedLeases = this.db
        .prepare(
          `SELECT command.*
           FROM runtime_run_commands command
           JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
           WHERE dispatch.status = 'processing' AND dispatch.lease_expires_at_ms <= ?
             AND dispatch.dispatch_interlock_acquired_at_ms IS NOT NULL
           ORDER BY dispatch.created_at_ms ASC, command.id ASC`
        )
        .all(nowMs) as CommandJournalRow[];
      for (const row of expiredDispatchedLeases) {
        const updated = this.db
          .prepare(
            `UPDATE runtime_run_command_dispatch
             SET status = 'awaiting-receipt', lease_owner = NULL,
                 lease_expires_at_ms = NULL,
                 last_safe_error_code = 'lease_expired_dispatch_uncertain',
                 available_at_ms = MAX(available_at_ms, ?), updated_at_ms = ?
             WHERE command_id = ? AND status = 'processing'
               AND lease_expires_at_ms <= ?
               AND dispatch_interlock_acquired_at_ms IS NOT NULL`
          )
          .run(nowMs, nowMs, row.id, nowMs);
        if (updated.changes === 1) {
          this.recordJournalEvent(
            row,
            nowMs,
            "runtime-lifecycle-reconciler",
            "run.runtime-command.outcome-uncertain",
            {
              commandId: row.id,
              agentRunId: row.agent_run_id,
              operation: row.operation,
              safeErrorCode: "lease_expired_dispatch_uncertain",
              stateVersion: row.expected_run_state_version,
            }
          );
        }
      }

      const expiredPending = this.db
        .prepare(
          `SELECT command.*
           FROM runtime_run_commands command
           JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
           WHERE dispatch.status = 'pending' AND command.deadline_at_ms <= ?
           ORDER BY command.created_at_ms ASC, command.id ASC`
        )
        .all(nowMs) as CommandJournalRow[];
      for (const command of expiredPending) {
        this.failUndispatchedCommand(
          command,
          nowMs,
          "deadline_expired",
          "runtime-lifecycle-reconciler"
        );
      }

      const stalePending = this.db
        .prepare(
          `SELECT command.*
           FROM runtime_run_commands command
           JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
           WHERE dispatch.status = 'pending'
             AND NOT (${CURRENT_RUNTIME_LIFECYCLE_DISPATCH_FENCE_SQL})
           ORDER BY command.created_at_ms ASC, command.id ASC`
        )
        .all({ nowMs }) as CommandJournalRow[];
      for (const command of stalePending) {
        this.supersedeUndispatchedCommand(command, nowMs, "runtime-lifecycle-reconciler");
      }
    });
    reconcile.immediate();
  }

  async claim(
    options: RuntimeLifecycleClaimOptions
  ): Promise<ReadonlyArray<RuntimeLifecycleDelivery>> {
    const workerId = safeIdentifier(options?.workerId, MAX_WORKER_ID_LENGTH);
    const limit = boundedInteger(options?.limit, 1, 100);
    const leaseDurationMs = boundedInteger(options?.leaseDurationMs, 1, 300_000);
    const nowMs = nonNegativeInteger(options?.nowMs);
    const leaseExpiresAtMs = safeAdd(nowMs, leaseDurationMs);

    const claim = this.db.transaction(() => {
      const rows = this.db
        .prepare(
          `SELECT command.*
           FROM runtime_run_commands command
           JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
           WHERE dispatch.status = 'pending' AND dispatch.available_at_ms <= @nowMs
             AND ${CURRENT_RUNTIME_LIFECYCLE_DISPATCH_FENCE_SQL}
           ORDER BY dispatch.available_at_ms ASC, command.created_at_ms ASC, command.id ASC
           LIMIT @limit`
        )
        .all({ nowMs, limit }) as CommandJournalRow[];
      const deliveries: RuntimeLifecycleDelivery[] = [];
      for (const row of rows) {
        let command: RuntimeLifecycleCommand;
        try {
          command = parsePersistedCommand(row);
        } catch {
          this.failUndispatchedCommand(row, nowMs, "invalid_input", workerId);
          continue;
        }
        const updated = this.db
          .prepare(
            `UPDATE runtime_run_command_dispatch
             SET status = 'processing', attempts = attempts + 1,
                 lease_owner = ?, lease_expires_at_ms = ?, updated_at_ms = ?,
                 last_safe_error_code = NULL, dispatch_interlock_acquired_at_ms = NULL
             WHERE command_id = ? AND status = 'pending' AND available_at_ms <= ?
             RETURNING attempts`
          )
          .get(workerId, leaseExpiresAtMs, nowMs, row.id, nowMs) as SqlRow | undefined;
        if (!updated) continue;
        deliveries.push(
          Object.freeze({
            command,
            attempt: positiveInteger(updated.attempts),
            leaseOwner: workerId,
            leaseExpiresAtMs,
            priorDispatchCertainty: "not-dispatched" as const,
          })
        );
      }
      return deliveries;
    });
    return Object.freeze(claim.immediate());
  }

  async renew(options: RuntimeLifecycleRenewalOptions): Promise<RuntimeLifecycleRenewal> {
    const commandId = safeIdentifier(options?.commandId, MAX_IDENTIFIER_LENGTH);
    const workerId = safeIdentifier(options?.workerId, MAX_WORKER_ID_LENGTH);
    const expectedAttempt = positiveInteger(options?.expectedAttempt);
    const expectedLeaseExpiresAtMs = nonNegativeInteger(options?.expectedLeaseExpiresAtMs);
    const leaseDurationMs = boundedInteger(options?.leaseDurationMs, 1, 300_000);
    const nowMs = nonNegativeInteger(options?.nowMs);
    if (nowMs >= expectedLeaseExpiresAtMs) fail("stale_completion");
    const requestedExpiry = safeAdd(nowMs, leaseDurationMs);
    const leaseExpiresAtMs = Math.max(expectedLeaseExpiresAtMs, requestedExpiry);
    const renew = this.db.transaction((): RuntimeLifecycleRenewal => {
      const row = this.db
        .prepare(
          `SELECT command.*
           FROM runtime_run_commands command
           JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
           WHERE command.id = @commandId
             AND dispatch.status = 'processing' AND dispatch.attempts = @expectedAttempt
             AND dispatch.lease_owner = @workerId
             AND dispatch.lease_expires_at_ms = @expectedLeaseExpiresAtMs
             AND dispatch.lease_expires_at_ms > @nowMs
             AND dispatch.dispatch_interlock_acquired_at_ms IS NULL
             AND NOT EXISTS (
               SELECT 1 FROM runtime_run_command_receipts receipt
               WHERE receipt.command_id = command.id
             )`
        )
        .get({
          commandId,
          expectedAttempt,
          workerId,
          expectedLeaseExpiresAtMs,
          nowMs,
        }) as CommandJournalRow | undefined;
      if (!row) fail("stale_completion");

      const current = this.db
        .prepare(
          `SELECT 1 FROM runtime_run_commands command
           WHERE command.id = @commandId
             AND ${CURRENT_RUNTIME_LIFECYCLE_DISPATCH_FENCE_SQL}`
        )
        .get({ commandId, nowMs });
      if (!current) {
        this.supersedeClaimedUndispatchedCommand(row, {
          workerId,
          expectedAttempt,
          expectedLeaseExpiresAtMs,
          nowMs,
        });
        return Object.freeze({ kind: "superseded" as const });
      }

      const updated = this.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET lease_expires_at_ms = ?, updated_at_ms = ?,
               dispatch_interlock_acquired_at_ms = ?
           WHERE command_id = ? AND status = 'processing' AND attempts = ?
             AND lease_owner = ? AND lease_expires_at_ms = ?
             AND lease_expires_at_ms > ?
             AND dispatch_interlock_acquired_at_ms IS NULL
             AND NOT EXISTS (
               SELECT 1 FROM runtime_run_command_receipts receipt
               WHERE receipt.command_id = runtime_run_command_dispatch.command_id
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

  async complete(completion: RuntimeLifecycleCompletion): Promise<void> {
    let input = validateCompletion(completion);
    if (input.outcome.kind === "receipt") {
      const row = this.completionRow(input.commandId);
      if (!row) fail("stale_completion");
      const command = parsePersistedCommand(row);
      const receipt = validateReceiptForCommand(input.outcome.receipt, row);
      try {
        verifyRuntimeReceiptEnforcementProofSynchronously(
          command,
          receipt,
          this.verifyEnforcementProof
        );
      } catch {
        fail("invalid_input");
      }
      input = Object.freeze({
        ...input,
        outcome: Object.freeze({ kind: "receipt" as const, receipt }),
      });
    }
    const settle = this.db.transaction(() => {
      const row = this.completionRow(input.commandId);
      if (!row) fail("stale_completion");

      if (!this.hasCompletionLease(row, input)) {
        if (
          input.outcome.kind === "receipt" &&
          this.hasExactReceipt(input.commandId, input.outcome.receipt)
        ) {
          if (this.hasSettledReceiptPostcondition(input.commandId, input.outcome.receipt)) return;
          fail("journal_conflict");
        }
        fail("stale_completion");
      }

      if (input.outcome.kind === "failure") {
        this.completeFailure(row, input);
        return;
      }
      this.completeReceipt(row, input, input.outcome.receipt);
    });
    settle.immediate();
  }

  /**
   * Settle one receipt that was authenticated by the private Runtime follow
   * channel. The caller must already hold the follow journal's IMMEDIATE
   * transaction so receipt evidence, lifecycle truth, cursor advancement, and
   * the follow event either commit together or all roll back.
   */
  settleVerifiedReceiptInTransaction(
    unsafeInput: RuntimeReceiptFollowSettlementInput
  ): RuntimeReceiptFollowSettlementResult {
    if (!this.db.inTransaction) fail("journal_conflict");
    if (!unsafeInput || typeof unsafeInput !== "object") fail("invalid_input");

    let actorRef: string;
    let receivedAtMs: number;
    let command: RuntimeLifecycleCommand;
    let observation: RuntimeReceiptFollowSettlementInput["observation"];
    try {
      actorRef = safeIdentifier(unsafeInput.actorRef, MAX_WORKER_ID_LENGTH);
      receivedAtMs = nonNegativeInteger(unsafeInput.receivedAtMs);
      command = validateLifecycleCommand(unsafeInput.command);
      observation = unsafeInput.observation;
    } catch {
      fail("invalid_input");
    }
    if (!isVerifiedRuntimeLifecycleReceiptObservation(observation)) fail("invalid_input");

    const row = this.completionRow(command.commandId);
    if (!row || row.dispatch_status !== "awaiting-receipt") fail("stale_completion");
    const persistedCommand = parsePersistedCommand(row);
    if (
      canonicalCommandJson(command) !== canonicalCommandJson(persistedCommand) ||
      digestRuntimeCommandClaims(command) !== command.authority.claimsDigest
    ) {
      fail("invalid_command");
    }

    let receipt: RuntimeReceipt;
    try {
      receipt = validateReceiptForCommand(observation.receipt, row);
    } catch {
      throw new RuntimeReceiptFollowSettlementRejection("enforcement_proof_verification_failed");
    }
    try {
      verifyRuntimeReceiptEnforcementProofSynchronously(
        persistedCommand,
        receipt,
        this.verifyEnforcementProof
      );
    } catch (error) {
      if (
        error instanceof RuntimeCommandExecutionError &&
        (error.code === "invalid_receipt" || error.code === "enforcement_proof_verification_failed")
      ) {
        throw new RuntimeReceiptFollowSettlementRejection("enforcement_proof_verification_failed");
      }
      fail("invalid_input");
    }

    return this.settleReceipt(
      row,
      Object.freeze({
        actorRef,
        observedAtMs: receivedAtMs,
        fence: Object.freeze({ kind: "follow" as const }),
      }),
      receipt
    );
  }

  private completionRow(commandId: string): CompletionRow | undefined {
    return this.db
      .prepare(
        `SELECT command.*, dispatch.status AS dispatch_status, dispatch.attempts,
                dispatch.available_at_ms, dispatch.lease_owner, dispatch.lease_expires_at_ms,
                dispatch.dispatch_interlock_acquired_at_ms,
                run.lifecycle AS run_lifecycle, run.state_version AS run_state_version,
                session.run_state_revision AS session_run_state_revision
         FROM runtime_run_commands command
         JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
         JOIN agent_runs run ON run.id = command.agent_run_id
         JOIN sessions session ON session.id = command.session_id
         WHERE command.id = ?`
      )
      .get(commandId) as CompletionRow | undefined;
  }

  private hasCompletionLease(
    row: CompletionRow,
    completion: ReturnType<typeof validateCompletion>
  ): boolean {
    const requiresDispatchInterlock =
      completion.outcome.kind === "receipt" ||
      completion.outcome.dispatchCertainty === "dispatch-uncertain";
    return (
      row.dispatch_status === "processing" &&
      row.attempts === completion.expectedAttempt &&
      row.lease_owner === completion.workerId &&
      row.lease_expires_at_ms === completion.expectedLeaseExpiresAtMs &&
      completion.observedAtMs < completion.expectedLeaseExpiresAtMs &&
      (!requiresDispatchInterlock || row.dispatch_interlock_acquired_at_ms !== null)
    );
  }

  private completeFailure(
    row: CompletionRow,
    completion: ReturnType<typeof validateCompletion>
  ): void {
    if (completion.outcome.kind !== "failure") fail("invalid_input");
    const { code, dispatchCertainty } = completion.outcome;
    if (dispatchCertainty === "dispatch-uncertain") {
      this.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'awaiting-receipt', available_at_ms = MAX(available_at_ms, ?),
               lease_owner = NULL, lease_expires_at_ms = NULL,
               last_safe_error_code = ?, updated_at_ms = ?
           WHERE command_id = ? AND status = 'processing' AND attempts = ?
             AND lease_owner = ? AND lease_expires_at_ms = ?`
        )
        .run(
          completion.observedAtMs,
          code,
          completion.observedAtMs,
          row.id,
          completion.expectedAttempt,
          completion.workerId,
          completion.expectedLeaseExpiresAtMs
        );
      this.recordJournalEvent(
        row,
        completion.observedAtMs,
        completion.workerId,
        "run.runtime-command.outcome-uncertain",
        {
          commandId: row.id,
          agentRunId: row.agent_run_id,
          operation: row.operation,
          safeErrorCode: code,
          stateVersion: row.run_state_version,
        }
      );
      return;
    }

    if (code === "runtime_handle_unavailable") {
      const availableAtMs = safeAdd(completion.observedAtMs, this.retryDelayMs);
      this.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'pending', available_at_ms = ?, lease_owner = NULL,
               lease_expires_at_ms = NULL, last_safe_error_code = ?, updated_at_ms = ?
           WHERE command_id = ? AND status = 'processing' AND attempts = ?
             AND lease_owner = ? AND lease_expires_at_ms = ?`
        )
        .run(
          availableAtMs,
          code,
          completion.observedAtMs,
          row.id,
          completion.expectedAttempt,
          completion.workerId,
          completion.expectedLeaseExpiresAtMs
        );
      return;
    }

    this.failUndispatchedCommand(row, completion.observedAtMs, code, completion.workerId);
  }

  private completeReceipt(
    row: CompletionRow,
    completion: ReturnType<typeof validateCompletion>,
    receipt: RuntimeReceipt
  ): RuntimeReceiptFollowSettlementResult {
    return this.settleReceipt(
      row,
      {
        actorRef: completion.workerId,
        observedAtMs: completion.observedAtMs,
        fence: {
          kind: "dispatch",
          expectedAttempt: completion.expectedAttempt,
          expectedLeaseExpiresAtMs: completion.expectedLeaseExpiresAtMs,
        },
      },
      receipt
    );
  }

  private settleReceipt(
    row: CompletionRow,
    settlement: ReceiptSettlementContext,
    receipt: RuntimeReceipt
  ): RuntimeReceiptFollowSettlementResult {
    const persisted = validateReceiptForCommand(receipt, row);
    const receiptId = this.insertReceipt(row, persisted, settlement.observedAtMs);
    const effectiveReceiptDigest = digestReceipt(persisted);
    const effective = persisted.outcome === "duplicate" ? persisted.originalReceipt : persisted;

    if (effective.outcome === "accepted") {
      this.recordJournalEvent(
        row,
        settlement.observedAtMs,
        settlement.actorRef,
        "run.runtime-command.accepted",
        {
          commandId: row.id,
          agentRunId: row.agent_run_id,
          operation: row.operation,
          stateVersion: row.run_state_version,
        }
      );
      this.parkAcceptedDispatch(row, settlement);
      return Object.freeze({ receiptId, effectiveReceiptDigest });
    }

    if (effective.outcome === "enforced") {
      this.applyEnforcedReceipt(row, settlement, persisted, receiptId);
      return Object.freeze({ receiptId, effectiveReceiptDigest });
    }
    if (effective.outcome === "rejected") {
      this.applyRejectedReceipt(row, settlement, persisted, effective);
      return Object.freeze({ receiptId, effectiveReceiptDigest });
    }
    this.applyQuarantinedReceipt(row, settlement, persisted, effective);
    return Object.freeze({ receiptId, effectiveReceiptDigest });
  }

  private parkAcceptedDispatch(row: CompletionRow, settlement: ReceiptSettlementContext): void {
    const baseSql = `UPDATE runtime_run_command_dispatch
      SET status = 'awaiting-receipt', available_at_ms = MAX(available_at_ms, ?),
          lease_owner = NULL, lease_expires_at_ms = NULL,
          last_safe_error_code = NULL, updated_at_ms = ?
      WHERE command_id = ?`;
    const updated =
      settlement.fence.kind === "dispatch"
        ? this.db
            .prepare(
              `${baseSql} AND status = 'processing' AND attempts = ?
                 AND lease_owner = ? AND lease_expires_at_ms = ?`
            )
            .run(
              settlement.observedAtMs,
              settlement.observedAtMs,
              row.id,
              settlement.fence.expectedAttempt,
              settlement.actorRef,
              settlement.fence.expectedLeaseExpiresAtMs
            )
        : this.db
            .prepare(
              `${baseSql} AND status = 'awaiting-receipt'
                 AND lease_owner IS NULL AND lease_expires_at_ms IS NULL`
            )
            .run(settlement.observedAtMs, settlement.observedAtMs, row.id);
    if (updated.changes !== 1) {
      fail(settlement.fence.kind === "dispatch" ? "stale_completion" : "journal_conflict");
    }
  }

  private insertReceipt(row: CompletionRow, receipt: RuntimeReceipt, observedAtMs: number): string {
    const persistedReceipt = sanitizeReceiptForPersistence(receipt);
    const receiptDigest = digestReceipt(receipt);
    const exact = this.db
      .prepare(
        `SELECT id FROM runtime_run_command_receipts
         WHERE command_id = ? AND receipt_digest = ?`
      )
      .get(row.id, receiptDigest) as SqlRow | undefined;
    if (exact) return safeIdentifier(exact.id, MAX_IDENTIFIER_LENGTH);

    const latest = this.db
      .prepare(
        `SELECT version FROM runtime_run_command_receipts
         WHERE command_id = ? ORDER BY version DESC LIMIT 1`
      )
      .get(row.id) as SqlRow | undefined;
    const version = latest ? positiveInteger(latest.version) + 1 : 1;
    const previousVersion = version === 1 ? null : version - 1;
    const receiptId = this.nextId();
    const originalOutcome =
      persistedReceipt.outcome === "duplicate" ? persistedReceipt.originalReceipt.outcome : null;
    const originalReceiptDigest =
      persistedReceipt.outcome === "duplicate" ? persistedReceipt.originalReceiptDigest : null;
    const effectiveReceipt =
      persistedReceipt.outcome === "duplicate"
        ? persistedReceipt.originalReceipt
        : persistedReceipt;
    const aggregateProof =
      effectiveReceipt.outcome === "enforced"
        ? effectiveReceipt.aggregateEnforcementProof
        : undefined;
    if (effectiveReceipt.outcome === "enforced" && !aggregateProof) fail("invalid_input");

    try {
      this.db
        .prepare(
          `INSERT INTO runtime_run_command_receipts
             (id, command_id, version, previous_version, session_id, agent_run_id,
              command_sequence, run_policy_revision, goal_set_id, goal_set_revision,
              runtime_assignment_id, runtime_assignment_generation, sandbox_id,
              sandbox_generation, runtime_principal_id, runtime_authorization_generation,
              expected_run_state_version, target_run_state_version, source_session_sequence,
              command_digest, outcome, original_outcome, original_receipt_digest,
              receipt_json, receipt_digest, received_at_ms,
              required_effect_enforcer_set_digest, enforcement_subject_digest,
              aggregate_proof_digest, proof_verified_at_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          receiptId,
          row.id,
          version,
          previousVersion,
          row.session_id,
          row.agent_run_id,
          row.command_sequence,
          row.run_policy_revision,
          row.goal_set_id,
          row.goal_set_revision,
          row.runtime_assignment_id,
          row.runtime_assignment_generation,
          row.sandbox_id,
          row.sandbox_generation,
          row.runtime_principal_id,
          row.runtime_authorization_generation,
          row.expected_run_state_version,
          row.target_run_state_version,
          row.source_session_sequence,
          row.command_digest,
          persistedReceipt.outcome,
          originalOutcome,
          originalReceiptDigest,
          JSON.stringify(persistedReceipt),
          receiptDigest,
          observedAtMs,
          aggregateProof?.requiredEffectEnforcerSetDigest ?? null,
          aggregateProof?.enforcementSubjectDigest ?? null,
          aggregateProof?.aggregateProofDigest ?? null,
          aggregateProof ? observedAtMs : null
        );
    } catch {
      fail("journal_conflict");
    }
    return receiptId;
  }

  private applyEnforcedReceipt(
    row: CompletionRow,
    settlement: ReceiptSettlementContext,
    receipt: RuntimeReceipt,
    receiptId: string
  ): void {
    if (!this.commandStillCurrent(row)) {
      this.invalidateRunGrants(row.agent_run_id, settlement.observedAtMs, "runtime-authorization");
      this.db
        .prepare(
          `UPDATE runtime_assignments SET status = 'quarantined'
           WHERE id = ? AND session_id = ?
             AND status IN ('provisioning', 'ready', 'checkpointing', 'recovering')`
        )
        .run(row.runtime_assignment_id, row.session_id);
      this.db
        .prepare(
          `UPDATE sessions SET runtime_authorization_state = 'quarantined'
           WHERE id = ? AND runtime_authorization_generation = ?`
        )
        .run(row.session_id, row.runtime_authorization_generation);
      this.recordJournalEvent(
        row,
        settlement.observedAtMs,
        settlement.actorRef,
        "run.runtime-command.compensating",
        {
          commandId: row.id,
          agentRunId: row.agent_run_id,
          operation: row.operation,
          observedOutcome: "enforced",
          stateVersion: row.run_state_version,
        }
      );
      this.markDispatchCompensating(row, settlement);
      return;
    }

    const nextRunStateRevision = row.session_run_state_revision + 1;
    const invalidatedGrantCount =
      row.operation === "run.stop"
        ? this.invalidateRunGrants(row.agent_run_id, settlement.observedAtMs, "run-terminal")
        : 0;
    const appliedSequence = this.appendSystemEvent(
      row.session_id,
      settlement.observedAtMs,
      settlement.actorRef,
      eventTypeFor(row.operation),
      {
        commandId: row.id,
        agentRunId: row.agent_run_id,
        lifecycle: row.target_lifecycle,
        fromRunStateVersion: row.expected_run_state_version,
        toRunStateVersion: row.target_run_state_version,
        stateVersion: row.target_run_state_version,
        runPolicyRevision: row.run_policy_revision,
        goalSetRevision: row.goal_set_revision,
        invalidatedGrantCount,
        runStateRevision: nextRunStateRevision,
      },
      `receipt:${row.id}:${digestReceipt(receipt)}`
    );
    const effectDigest = sha256(
      canonicalRuntimeJson({
        commandDigest: row.command_digest,
        receiptDigest: digestReceipt(receipt),
        appliedSessionSequence: appliedSequence,
        targetRunStateVersion: row.target_run_state_version,
      })
    );
    this.db
      .prepare(
        `INSERT INTO runtime_run_command_effects
           (command_id, receipt_id, receipt_outcome, session_id, agent_run_id,
            command_sequence, expected_run_state_version, target_run_state_version,
            source_session_sequence, applied_session_sequence, effect_digest, applied_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        row.id,
        receiptId,
        receipt.outcome,
        row.session_id,
        row.agent_run_id,
        row.command_sequence,
        row.expected_run_state_version,
        row.target_run_state_version,
        row.source_session_sequence,
        appliedSequence,
        effectDigest,
        settlement.observedAtMs
      );
    const updated = this.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = ?, state_version = ?, updated_at_ms = ?,
             terminal_at_ms = CASE WHEN ? = 'stopped' THEN ? ELSE NULL END
         WHERE id = ? AND session_id = ? AND state_version = ?
           AND lifecycle = ?`
      )
      .run(
        row.target_lifecycle,
        row.target_run_state_version,
        settlement.observedAtMs,
        row.target_lifecycle,
        settlement.observedAtMs,
        row.agent_run_id,
        row.session_id,
        row.expected_run_state_version,
        sourceLifecycleFor(row.operation, row.run_lifecycle)
      );
    if (updated.changes !== 1) fail("journal_conflict");
    this.advanceRunStateRevision(row.session_id, row.session_run_state_revision);
    this.terminalizeDispatch(row, settlement, "enforced", null);
  }

  private applyRejectedReceipt(
    row: CompletionRow,
    settlement: ReceiptSettlementContext,
    receipt: RuntimeReceipt,
    effective: Extract<NonDuplicateRuntimeReceipt, { outcome: "rejected" }>
  ): void {
    this.recordJournalEvent(
      row,
      settlement.observedAtMs,
      settlement.actorRef,
      "run.runtime-command.rejected",
      {
        commandId: row.id,
        agentRunId: row.agent_run_id,
        operation: row.operation,
        code: effective.code,
        safeDetail: "Runtime rejected the lifecycle command",
        stateVersion: row.run_state_version,
      },
      digestReceipt(receipt)
    );
    this.terminalizeDispatch(row, settlement, "rejected", effective.code);
    if (row.operation === "run.start" && this.startStillPending(row)) {
      this.failStartingRun(row, settlement.observedAtMs);
    }
  }

  private applyQuarantinedReceipt(
    row: CompletionRow,
    settlement: ReceiptSettlementContext,
    receipt: RuntimeReceipt,
    effective: Extract<NonDuplicateRuntimeReceipt, { outcome: "quarantined" }>
  ): void {
    this.recordJournalEvent(
      row,
      settlement.observedAtMs,
      settlement.actorRef,
      "run.runtime-command.quarantined",
      {
        commandId: row.id,
        agentRunId: row.agent_run_id,
        operation: row.operation,
        reason: effective.reason,
        stateVersion: row.run_state_version,
      },
      digestReceipt(receipt)
    );
    this.terminalizeDispatch(row, settlement, "quarantined", effective.reason);
    this.invalidateRunGrants(row.agent_run_id, settlement.observedAtMs, "runtime-authorization");
    this.db
      .prepare(
        `UPDATE runtime_assignments SET status = 'quarantined'
         WHERE id = ? AND session_id = ?
           AND status IN ('provisioning', 'ready', 'checkpointing', 'recovering')`
      )
      .run(row.runtime_assignment_id, row.session_id);
    this.db
      .prepare(
        `UPDATE sessions SET runtime_authorization_state = 'quarantined'
         WHERE id = ? AND runtime_authorization_generation = ?`
      )
      .run(row.session_id, row.runtime_authorization_generation);
    if (row.operation === "run.start" && this.startStillPending(row)) {
      this.failStartingRun(row, settlement.observedAtMs);
      return;
    }
    if (
      row.run_lifecycle === "active" &&
      row.run_state_version === row.expected_run_state_version
    ) {
      this.db
        .prepare(
          `UPDATE agent_runs SET lifecycle = 'pausing', state_version = state_version + 1,
             updated_at_ms = ?
           WHERE id = ? AND session_id = ? AND lifecycle = 'active' AND state_version = ?`
        )
        .run(
          settlement.observedAtMs,
          row.agent_run_id,
          row.session_id,
          row.expected_run_state_version
        );
    }
  }

  private terminalizeDispatch(
    row: CompletionRow,
    settlement: ReceiptSettlementContext,
    status: "enforced" | "rejected" | "quarantined" | "superseded",
    safeCode: string | null
  ): void {
    const baseSql = `UPDATE runtime_run_command_dispatch
      SET status = ?, lease_owner = NULL, lease_expires_at_ms = NULL,
          last_safe_error_code = ?, updated_at_ms = ?, terminal_at_ms = ?
      WHERE command_id = ?`;
    const updated =
      settlement.fence.kind === "dispatch"
        ? this.db
            .prepare(
              `${baseSql} AND status = 'processing' AND attempts = ?
                 AND lease_owner = ? AND lease_expires_at_ms = ?`
            )
            .run(
              status,
              safeCode,
              settlement.observedAtMs,
              settlement.observedAtMs,
              row.id,
              settlement.fence.expectedAttempt,
              settlement.actorRef,
              settlement.fence.expectedLeaseExpiresAtMs
            )
        : this.db
            .prepare(
              `${baseSql} AND status = 'awaiting-receipt'
                 AND lease_owner IS NULL AND lease_expires_at_ms IS NULL`
            )
            .run(status, safeCode, settlement.observedAtMs, settlement.observedAtMs, row.id);
    if (updated.changes !== 1) {
      fail(settlement.fence.kind === "dispatch" ? "stale_completion" : "journal_conflict");
    }
  }

  private markDispatchCompensating(row: CompletionRow, settlement: ReceiptSettlementContext): void {
    const baseSql = `UPDATE runtime_run_command_dispatch
      SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
          last_safe_error_code = 'stale_enforced_effect', updated_at_ms = ?,
          terminal_at_ms = NULL
      WHERE command_id = ?`;
    const updated =
      settlement.fence.kind === "dispatch"
        ? this.db
            .prepare(
              `${baseSql} AND status = 'processing' AND attempts = ?
                 AND lease_owner = ? AND lease_expires_at_ms = ?`
            )
            .run(
              settlement.observedAtMs,
              row.id,
              settlement.fence.expectedAttempt,
              settlement.actorRef,
              settlement.fence.expectedLeaseExpiresAtMs
            )
        : this.db
            .prepare(
              `${baseSql} AND status = 'awaiting-receipt'
                 AND lease_owner IS NULL AND lease_expires_at_ms IS NULL`
            )
            .run(settlement.observedAtMs, row.id);
    if (updated.changes !== 1) {
      fail(settlement.fence.kind === "dispatch" ? "stale_completion" : "journal_conflict");
    }
  }

  private failUndispatchedCommand(
    row: CommandJournalRow,
    nowMs: number,
    safeCode: string,
    actorRef: string
  ): void {
    const processing = this.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'pending', available_at_ms = MAX(available_at_ms, ?),
             lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = ?, updated_at_ms = ?
         WHERE command_id = ? AND status = 'processing' AND lease_expires_at_ms > ?`
      )
      .run(nowMs, safeErrorCode(safeCode), nowMs, row.id, nowMs);
    if (processing.changes > 1) fail("journal_conflict");
    const updated = this.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'failed', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = ?, updated_at_ms = ?, terminal_at_ms = ?
         WHERE command_id = ? AND status = 'pending'`
      )
      .run(safeErrorCode(safeCode), nowMs, nowMs, row.id);
    if (updated.changes !== 1) fail("journal_conflict");
    this.recordJournalEvent(row, nowMs, actorRef, "run.runtime-command.failed", {
      commandId: row.id,
      agentRunId: row.agent_run_id,
      operation: row.operation,
      safeErrorCode: safeCode,
      stateVersion: row.expected_run_state_version,
    });
    if (row.operation === "run.start") this.failStartingRun(row, nowMs);
  }

  private supersedeUndispatchedCommand(
    row: CommandJournalRow,
    nowMs: number,
    actorRef: string
  ): void {
    const updated = this.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'superseded', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = 'state_fence_superseded', updated_at_ms = ?, terminal_at_ms = ?
         WHERE command_id = ? AND status = 'pending'`
      )
      .run(nowMs, nowMs, row.id);
    if (updated.changes !== 1) fail("journal_conflict");
    this.recordJournalEvent(row, nowMs, actorRef, "run.runtime-command.superseded", {
      commandId: row.id,
      agentRunId: row.agent_run_id,
      operation: row.operation,
      observedOutcome: "not-dispatched",
      stateVersion: row.expected_run_state_version,
    });
  }

  private supersedeClaimedUndispatchedCommand(
    row: CommandJournalRow,
    fence: {
      readonly workerId: string;
      readonly expectedAttempt: number;
      readonly expectedLeaseExpiresAtMs: number;
      readonly nowMs: number;
    }
  ): void {
    const updated = this.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'superseded', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = 'state_fence_superseded', updated_at_ms = ?, terminal_at_ms = ?
         WHERE command_id = ? AND status = 'processing' AND attempts = ?
           AND lease_owner = ? AND lease_expires_at_ms = ?
           AND lease_expires_at_ms > ?
           AND dispatch_interlock_acquired_at_ms IS NULL
           AND NOT EXISTS (
             SELECT 1 FROM runtime_run_command_receipts receipt
             WHERE receipt.command_id = runtime_run_command_dispatch.command_id
           )`
      )
      .run(
        fence.nowMs,
        fence.nowMs,
        row.id,
        fence.expectedAttempt,
        fence.workerId,
        fence.expectedLeaseExpiresAtMs,
        fence.nowMs
      );
    if (updated.changes !== 1) fail("stale_completion");
    this.recordJournalEvent(row, fence.nowMs, fence.workerId, "run.runtime-command.superseded", {
      commandId: row.id,
      agentRunId: row.agent_run_id,
      operation: row.operation,
      observedOutcome: "not-dispatched",
      stateVersion: row.expected_run_state_version,
    });
  }

  private recordJournalEvent(
    row: Pick<CommandJournalRow, "session_id" | "id"> & Partial<CompletionRow>,
    nowMs: number,
    actorRef: string,
    type: string,
    payload: Record<string, unknown>,
    receiptDigest?: string
  ): void {
    this.appendSystemEvent(
      row.session_id,
      nowMs,
      actorRef,
      type,
      payload,
      receiptDigest === undefined
        ? `command:${row.id}:${type}`
        : `receipt:${row.id}:${receiptDigest}`
    );
    const session = this.db
      .prepare(`SELECT run_state_revision FROM sessions WHERE id = ?`)
      .get(row.session_id) as SqlRow | undefined;
    if (!session) fail("journal_conflict");
    this.advanceRunStateRevision(row.session_id, positiveInteger(session.run_state_revision));
  }

  private appendSystemEvent(
    sessionId: string,
    occurredAtMs: number,
    actorRef: string,
    type: string,
    payload: Record<string, unknown>,
    sourceKey: string
  ): number {
    const session = this.db
      .prepare(`SELECT next_sequence FROM sessions WHERE id = ?`)
      .get(sessionId) as SqlRow | undefined;
    if (!session) fail("journal_conflict");
    const sequence = positiveInteger(session.next_sequence);
    const advanced = this.db
      .prepare(
        `UPDATE sessions SET next_sequence = next_sequence + 1
         WHERE id = ? AND next_sequence = ?`
      )
      .run(sessionId, sequence);
    if (advanced.changes !== 1) fail("journal_conflict");
    this.db
      .prepare(
        `INSERT INTO session_events
           (session_id, sequence, event_id, type, occurred_at_ms,
            actor_kind, actor_user_id, actor_display_name,
            source_scope, source_key, payload_json)
         VALUES (?, ?, ?, ?, ?, 'system', ?, 'Runtime Lifecycle Supervisor',
                 'runtime-lifecycle', ?, ?)`
      )
      .run(
        sessionId,
        sequence,
        this.nextId(),
        type,
        occurredAtMs,
        safeIdentifier(actorRef, MAX_WORKER_ID_LENGTH),
        safeIdentifier(sourceKey, 1_000),
        JSON.stringify(payload)
      );
    return sequence;
  }

  private advanceRunStateRevision(sessionId: string, expectedRevision: number): number {
    const updated = this.db
      .prepare(
        `UPDATE sessions SET run_state_revision = run_state_revision + 1
         WHERE id = ? AND run_state_revision = ? RETURNING run_state_revision`
      )
      .get(sessionId, expectedRevision) as SqlRow | undefined;
    if (!updated) fail("journal_conflict");
    return positiveInteger(updated.run_state_revision);
  }

  private commandStillCurrent(row: CompletionRow): boolean {
    return Boolean(
      this.db
        .prepare(
          `SELECT 1
           FROM agent_runs run
           JOIN sessions session ON session.id = run.session_id
           JOIN runtime_assignments assignment ON assignment.id = run.runtime_assignment_id
           WHERE run.id = ? AND run.session_id = ? AND run.state_version = ?
             AND run.current_policy_revision = ? AND run.current_goal_set_revision = ?
             AND run.runtime_assignment_id = ?
             AND run.runtime_authorization_generation = ?
             AND session.runtime_authorization_generation = ?
             AND session.runtime_authorization_state = 'enforced'
             AND assignment.generation = ? AND assignment.sandbox_id = ?
             AND assignment.sandbox_generation = ? AND assignment.runtime_principal_id = ?
             AND assignment.runtime_authorization_generation = ? AND assignment.status = 'ready'
             AND run.lifecycle = ?`
        )
        .get(
          row.agent_run_id,
          row.session_id,
          row.expected_run_state_version,
          row.run_policy_revision,
          row.goal_set_revision,
          row.runtime_assignment_id,
          row.runtime_authorization_generation,
          row.runtime_authorization_generation,
          row.runtime_assignment_generation,
          row.sandbox_id,
          row.sandbox_generation,
          row.runtime_principal_id,
          row.runtime_authorization_generation,
          sourceLifecycleFor(row.operation, row.run_lifecycle)
        )
    );
  }

  private startStillPending(
    row: Pick<
      CommandJournalRow,
      "agent_run_id" | "session_id" | "id" | "expected_run_state_version"
    >
  ): boolean {
    return Boolean(
      this.db
        .prepare(
          `SELECT 1 FROM agent_runs
           WHERE id = ? AND session_id = ? AND start_command_id = ?
             AND lifecycle = 'starting' AND state_version = ?`
        )
        .get(row.agent_run_id, row.session_id, row.id, row.expected_run_state_version)
    );
  }

  private failStartingRun(
    row: Pick<
      CommandJournalRow,
      | "agent_run_id"
      | "session_id"
      | "id"
      | "expected_run_state_version"
      | "target_run_state_version"
    >,
    nowMs: number
  ): void {
    this.invalidateRunGrants(row.agent_run_id, nowMs, "run-terminal");
    const updated = this.db
      .prepare(
        `UPDATE agent_runs SET lifecycle = 'failed', state_version = ?,
             updated_at_ms = ?, terminal_at_ms = ?
         WHERE id = ? AND session_id = ? AND start_command_id = ?
           AND lifecycle = 'starting' AND state_version = ?`
      )
      .run(
        row.target_run_state_version,
        nowMs,
        nowMs,
        row.agent_run_id,
        row.session_id,
        row.id,
        row.expected_run_state_version
      );
    if (updated.changes !== 1) fail("journal_conflict");
  }

  private invalidateRunGrants(
    agentRunId: string,
    nowMs: number,
    reason: "run-terminal" | "runtime-authorization"
  ): number {
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
       VALUES (?, ?, ?, 'invalidated', ?, 'team-session-kernel', ?)`
    );
    for (const grant of grants) {
      const version = positiveInteger(grant.version);
      insert.run(grant.id, version + 1, version, reason, nowMs);
    }
    return grants.length;
  }

  private hasExactReceipt(commandId: string, receipt: RuntimeReceipt): boolean {
    try {
      const digest = digestReceipt(receipt);
      return Boolean(
        this.db
          .prepare(
            `SELECT 1 FROM runtime_run_command_receipts
             WHERE command_id = ? AND receipt_digest = ?`
          )
          .get(commandId, digest)
      );
    } catch {
      return false;
    }
  }

  private hasSettledReceiptPostcondition(commandId: string, receipt: RuntimeReceipt): boolean {
    const effective = receipt.outcome === "duplicate" ? receipt.originalReceipt : receipt;
    const row = this.db
      .prepare(
        `SELECT command.operation, dispatch.status,
                EXISTS(
                  SELECT 1 FROM runtime_run_command_effects effect
                  WHERE effect.command_id = command.id
                ) AS has_effect,
                EXISTS(
                  SELECT 1 FROM runtime_run_command_receipts successor
                  WHERE successor.command_id = command.id
                    AND (
                      successor.outcome IN ('enforced', 'rejected', 'quarantined') OR
                      (successor.outcome = 'duplicate'
                        AND successor.original_outcome IN ('enforced', 'rejected', 'quarantined'))
                    )
                ) AS has_terminal_receipt
         FROM runtime_run_commands command
         JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
         WHERE command.id = ?`
      )
      .get(commandId) as SqlRow | undefined;
    if (!row) return false;
    switch (effective.outcome) {
      case "accepted":
        return row.status === "awaiting-receipt" || row.has_terminal_receipt === 1;
      case "enforced":
        return row.status === "compensating" || (row.status === "enforced" && row.has_effect === 1);
      case "rejected":
        return row.status === "rejected";
      case "quarantined":
        return row.status === "quarantined";
    }
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

export function createSqliteRuntimeLifecycleJournal(
  options: CreateSqliteRuntimeLifecycleJournalOptions
): SqliteRuntimeLifecycleJournal {
  return new SqliteRuntimeLifecycleJournal(options);
}

function parsePersistedCommand(row: CommandJournalRow): RuntimeLifecycleCommand {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.command_json);
  } catch {
    fail("invalid_command");
  }
  const command = validateLifecycleCommand(parsed);
  if (
    command.commandId !== row.id ||
    command.kind !== row.operation ||
    command.agentRunId !== row.agent_run_id ||
    sha256(canonicalCommandJson(command)) !== row.command_digest ||
    digestRuntimeCommandClaims(command) !== command.authority.claimsDigest
  ) {
    fail("invalid_command");
  }
  return Object.freeze(command);
}

function validateLifecycleCommand(value: unknown): RuntimeLifecycleCommand {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("invalid_command");
  const command = value as Partial<RuntimeLifecycleCommand>;
  if (
    command.kind !== "run.start" &&
    command.kind !== "run.pause" &&
    command.kind !== "run.resume" &&
    command.kind !== "run.stop"
  ) {
    fail("invalid_command");
  }
  safeIdentifier(command.commandId, MAX_IDENTIFIER_LENGTH);
  safeIdentifier(command.agentRunId, MAX_IDENTIFIER_LENGTH);
  positiveInteger(command.runPolicyRevision);
  const fromRunStateVersion = positiveInteger(command.fromRunStateVersion);
  if (positiveInteger(command.toRunStateVersion) !== fromRunStateVersion + 1) {
    fail("invalid_command");
  }
  const issuedAtMs = nonNegativeInteger(command.issuedAtMs);
  if (nonNegativeInteger(command.deadlineAtMs) <= issuedAtMs) fail("invalid_command");
  if (!command.binding || typeof command.binding !== "object") fail("invalid_command");
  for (const field of [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "sandboxId",
    "runtimePrincipalId",
  ] as const) {
    safeIdentifier(command.binding[field], MAX_IDENTIFIER_LENGTH);
  }
  positiveInteger(command.binding.runtimeAssignmentGeneration);
  positiveInteger(command.binding.sandboxGeneration);
  positiveInteger(command.runtimeAuthorizationGeneration);
  sha256Digest(command.requiredEffectEnforcerSetDigest);
  if (!command.authority || typeof command.authority !== "object") fail("invalid_command");
  safeIdentifier(command.authority.claimsDigest, 64);
  return command as RuntimeLifecycleCommand;
}

function validateCompletion(completion: RuntimeLifecycleCompletion) {
  if (!completion || typeof completion !== "object") fail("invalid_input");
  const commandId = safeIdentifier(completion.commandId, MAX_IDENTIFIER_LENGTH);
  const workerId = safeIdentifier(completion.workerId, MAX_WORKER_ID_LENGTH);
  const expectedAttempt = positiveInteger(completion.expectedAttempt);
  const expectedLeaseExpiresAtMs = nonNegativeInteger(completion.expectedLeaseExpiresAtMs);
  const observedAtMs = nonNegativeInteger(completion.observedAtMs);
  const outcome = completion.outcome;
  if (!outcome || typeof outcome !== "object") fail("invalid_input");
  if (outcome.kind === "failure") {
    const code = safeErrorCode(outcome.code);
    if (
      !Object.hasOwn(FAILURE_DISPATCH_CERTAINTY, code) ||
      FAILURE_DISPATCH_CERTAINTY[code as keyof typeof FAILURE_DISPATCH_CERTAINTY] !==
        outcome.dispatchCertainty
    ) {
      fail("invalid_input");
    }
  } else if (outcome.kind !== "receipt") {
    fail("invalid_input");
  }
  return {
    commandId,
    workerId,
    expectedAttempt,
    expectedLeaseExpiresAtMs,
    observedAtMs,
    outcome,
  } as const;
}

function validateReceiptForCommand(
  receipt: RuntimeReceipt,
  row: CommandJournalRow
): RuntimeReceipt {
  try {
    return snapshotRuntimeReceiptForCommand(receipt, parsePersistedCommand(row));
  } catch {
    fail("invalid_input");
  }
}

function canonicalCommandJson(command: RuntimeLifecycleCommand): string {
  try {
    return canonicalRuntimeJson(command);
  } catch {
    fail("invalid_command");
  }
}

function digestReceipt(receipt: RuntimeReceipt): string {
  try {
    return sha256(canonicalRuntimeJson(sanitizeReceiptForPersistence(receipt)));
  } catch {
    fail("invalid_input");
  }
}

/**
 * Runtime/provider text is untrusted even when its contract labels it safe.
 * Persist only exact bindings, closed enums, hashes, and kernel-owned text.
 */
function sanitizeReceiptForPersistence(receipt: RuntimeReceipt): RuntimeReceipt {
  const sanitizeNonDuplicate = (value: NonDuplicateRuntimeReceipt): NonDuplicateRuntimeReceipt => {
    const base = {
      commandId: value.commandId,
      binding: { ...value.binding },
      runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
    };
    switch (value.outcome) {
      case "accepted":
        return {
          ...base,
          outcome: "accepted",
          effectRef: commitRuntimeEffectRef(value.effectRef),
        };
      case "enforced":
        if (!value.aggregateEnforcementProof) fail("invalid_input");
        return {
          ...base,
          outcome: "enforced",
          effectRef: commitRuntimeEffectRef(value.effectRef),
          enforcedFence: value.enforcedFence,
          aggregateEnforcementProof: {
            generation: value.aggregateEnforcementProof.generation,
            requiredEffectEnforcerSetDigest:
              value.aggregateEnforcementProof.requiredEffectEnforcerSetDigest,
            enforcementSubjectDigest: value.aggregateEnforcementProof.enforcementSubjectDigest,
            acknowledgements: value.aggregateEnforcementProof.acknowledgements.map(
              (acknowledgement) => ({ ...acknowledgement })
            ),
            aggregateProofDigest: value.aggregateEnforcementProof.aggregateProofDigest,
          },
        };
      case "rejected":
        return {
          ...base,
          outcome: "rejected",
          code: value.code,
          safeDetail: "Runtime rejected the lifecycle command",
        };
      case "quarantined":
        return {
          ...base,
          outcome: "quarantined",
          reason: value.reason,
          effectRef: commitRuntimeEffectRef(value.effectRef),
        };
    }
  };
  if (receipt.outcome !== "duplicate") return sanitizeNonDuplicate(receipt);
  const originalReceipt = sanitizeNonDuplicate(receipt.originalReceipt);
  return {
    commandId: receipt.commandId,
    binding: { ...receipt.binding },
    runtimeAuthorizationGeneration: receipt.runtimeAuthorizationGeneration,
    outcome: "duplicate",
    originalReceipt,
    originalReceiptDigest: sha256(canonicalRuntimeJson(originalReceipt)),
  };
}

function eventTypeFor(kind: RuntimeLifecycleCommand["kind"]): string {
  switch (kind) {
    case "run.start":
      return "run.started";
    case "run.pause":
      return "run.paused";
    case "run.resume":
      return "run.resumed";
    case "run.stop":
      return "run.stopped";
  }
}

function targetLifecycleFor(
  kind: RuntimeLifecycleCommand["kind"]
): "active" | "paused" | "stopped" {
  switch (kind) {
    case "run.start":
    case "run.resume":
      return "active";
    case "run.pause":
      return "paused";
    case "run.stop":
      return "stopped";
  }
}

function sourceLifecycleFor(kind: RuntimeLifecycleCommand["kind"], observed: string): string {
  switch (kind) {
    case "run.start":
      return "starting";
    case "run.pause":
      return "active";
    case "run.resume":
      return observed === "agent-work-finished" ? observed : "paused";
    case "run.stop":
      return observed;
  }
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

function safeErrorCode(value: unknown): string {
  return safeIdentifier(value, MAX_SAFE_ERROR_CODE_LENGTH);
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) fail("invalid_input");
  return value as number;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail("invalid_input");
  return value as number;
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

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sha256Digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) fail("invalid_command");
  return value;
}

function fail(code: RuntimeLifecycleJournalErrorCode): never {
  throw new RuntimeLifecycleJournalError(code);
}
