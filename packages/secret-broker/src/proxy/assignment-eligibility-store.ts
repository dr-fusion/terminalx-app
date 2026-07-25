import { chmodSync } from "node:fs";
import Database from "better-sqlite3";
import { SecretBrokerProtocolError } from "../protocol";

/**
 * Slice 8F Runtime-Assignment-scoped credential eligibility.
 *
 * A hosted Run exercises a Credential Handle only under the exact Runtime
 * Assignment identity (assignment id + generation + Sandbox identity digest from
 * the Phase 7 trust chain). This broker-private, durable store records which
 * assignment a handle is currently pinned to and enforces the same
 * generation-fence discipline used elsewhere: a mismatched assignment or a stale
 * (superseded) generation is denied, and observing a newer generation advances
 * the fence — which revokes in-flight eligibility for the superseded generation.
 *
 * Local non-hosted callers (the 8E HTTP flows) are human-session-fenced, not
 * assignment-fenced, and never reach this store.
 */
export type AssignmentEligibilityOutcome =
  | "eligible"
  | "denied-mismatch"
  | "denied-stale"
  | "denied-revoked";

export interface AssignmentEligibilityInput {
  readonly handleId: string;
  readonly runtimeAssignmentId: string;
  readonly runtimeAssignmentGeneration: number;
  readonly sandboxIdentityDigest: string;
}

export interface AssignmentEligibilityRow {
  readonly handleId: string;
  readonly runtimeAssignmentId: string;
  readonly runtimeAssignmentGeneration: number;
  readonly sandboxIdentityDigest: string;
  readonly revoked: boolean;
}

export interface AssignmentEligibilityStore {
  /**
   * Evaluate (and, on first use or a newer generation, durably record) the
   * eligibility of `input.handleId` under the given Runtime Assignment identity.
   */
  evaluate(input: AssignmentEligibilityInput, nowMs: number): AssignmentEligibilityOutcome;
  /** Irreversibly revoke a handle's assignment eligibility (e.g. handle revoked). */
  revoke(handleId: string, nowMs: number): void;
  /**
   * Advance the fence for a handle to a newer assignment generation without a
   * send, revoking in-flight eligibility for the superseded generation.
   */
  supersede(
    handleId: string,
    runtimeAssignmentId: string,
    runtimeAssignmentGeneration: number,
    sandboxIdentityDigest: string,
    nowMs: number
  ): void;
  get(handleId: string): AssignmentEligibilityRow | null;
  close(): void;
}

interface RawRow {
  handle_id: string;
  runtime_assignment_id: string;
  runtime_assignment_generation: number;
  sandbox_identity_digest: string;
  revoked: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS handle_assignment_eligibility (
  handle_id TEXT PRIMARY KEY,
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL,
  sandbox_identity_digest TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
  bound_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
`;

const SHA256 = /^[0-9a-f]{64}$/;

export interface OpenAssignmentEligibilityStoreOptions {
  readonly databasePath: string;
}

export function openAssignmentEligibilityStore(
  options: OpenAssignmentEligibilityStoreOptions
): AssignmentEligibilityStore {
  if (typeof options !== "object" || options === null) throw new TypeError();
  const db = new Database(options.databasePath);
  if (options.databasePath !== ":memory:") restrictDatabaseFiles(options.databasePath);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  db.exec(SCHEMA);
  if (options.databasePath !== ":memory:") restrictDatabaseFiles(options.databasePath);

  const selectByHandle = db.prepare<[string]>(
    "SELECT * FROM handle_assignment_eligibility WHERE handle_id = ?"
  );

  const evaluate = db.transaction(
    (input: AssignmentEligibilityInput, nowMs: number): AssignmentEligibilityOutcome => {
      const existing = selectByHandle.get(input.handleId) as RawRow | undefined;
      if (!existing) {
        db.prepare(
          `INSERT INTO handle_assignment_eligibility (
             handle_id, runtime_assignment_id, runtime_assignment_generation,
             sandbox_identity_digest, revoked, bound_at_ms, updated_at_ms
           ) VALUES (?, ?, ?, ?, 0, ?, ?)`
        ).run(
          input.handleId,
          input.runtimeAssignmentId,
          input.runtimeAssignmentGeneration,
          input.sandboxIdentityDigest,
          nowMs,
          nowMs
        );
        return "eligible";
      }
      if (existing.revoked === 1) return "denied-revoked";
      if (existing.runtime_assignment_id !== input.runtimeAssignmentId) return "denied-mismatch";
      if (input.runtimeAssignmentGeneration < existing.runtime_assignment_generation) {
        return "denied-stale";
      }
      if (input.runtimeAssignmentGeneration === existing.runtime_assignment_generation) {
        // The same generation must be exercised only by the same Sandbox
        // identity; a different Sandbox claiming the generation is a mismatch.
        return existing.sandbox_identity_digest === input.sandboxIdentityDigest
          ? "eligible"
          : "denied-mismatch";
      }
      // A newer generation supersedes: advance the fence, revoking in-flight
      // eligibility for the older generation.
      db.prepare(
        `UPDATE handle_assignment_eligibility
           SET runtime_assignment_generation = ?, sandbox_identity_digest = ?, updated_at_ms = ?
         WHERE handle_id = ?`
      ).run(input.runtimeAssignmentGeneration, input.sandboxIdentityDigest, nowMs, input.handleId);
      return "eligible";
    }
  );

  return Object.freeze({
    evaluate(input: AssignmentEligibilityInput, nowMs: number): AssignmentEligibilityOutcome {
      validateInput(input);
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new TypeError();
      return evaluate(input, nowMs);
    },
    revoke(handleId: string, nowMs: number): void {
      if (typeof handleId !== "string" || handleId.length < 1) throw new TypeError();
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new TypeError();
      db.prepare(
        `UPDATE handle_assignment_eligibility SET revoked = 1, updated_at_ms = ? WHERE handle_id = ?`
      ).run(nowMs, handleId);
    },
    supersede(
      handleId: string,
      runtimeAssignmentId: string,
      runtimeAssignmentGeneration: number,
      sandboxIdentityDigest: string,
      nowMs: number
    ): void {
      validateInput({
        handleId,
        runtimeAssignmentId,
        runtimeAssignmentGeneration,
        sandboxIdentityDigest,
      });
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new TypeError();
      db.prepare(
        `INSERT INTO handle_assignment_eligibility (
           handle_id, runtime_assignment_id, runtime_assignment_generation,
           sandbox_identity_digest, revoked, bound_at_ms, updated_at_ms
         ) VALUES (?, ?, ?, ?, 0, ?, ?)
         ON CONFLICT(handle_id) DO UPDATE SET
           runtime_assignment_id = excluded.runtime_assignment_id,
           runtime_assignment_generation = MAX(
             handle_assignment_eligibility.runtime_assignment_generation,
             excluded.runtime_assignment_generation
           ),
           sandbox_identity_digest = excluded.sandbox_identity_digest,
           updated_at_ms = excluded.updated_at_ms`
      ).run(
        handleId,
        runtimeAssignmentId,
        runtimeAssignmentGeneration,
        sandboxIdentityDigest,
        nowMs,
        nowMs
      );
    },
    get(handleId: string): AssignmentEligibilityRow | null {
      const row = selectByHandle.get(handleId) as RawRow | undefined;
      return row ? toRow(row) : null;
    },
    close(): void {
      db.close();
    },
  });
}

function validateInput(input: AssignmentEligibilityInput): void {
  if (
    typeof input !== "object" ||
    input === null ||
    typeof input.handleId !== "string" ||
    input.handleId.length < 1 ||
    typeof input.runtimeAssignmentId !== "string" ||
    input.runtimeAssignmentId.length < 1 ||
    !Number.isSafeInteger(input.runtimeAssignmentGeneration) ||
    input.runtimeAssignmentGeneration < 1 ||
    typeof input.sandboxIdentityDigest !== "string" ||
    !SHA256.test(input.sandboxIdentityDigest)
  ) {
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

function toRow(row: RawRow): AssignmentEligibilityRow {
  return Object.freeze({
    handleId: row.handle_id,
    runtimeAssignmentId: row.runtime_assignment_id,
    runtimeAssignmentGeneration: row.runtime_assignment_generation,
    sandboxIdentityDigest: row.sandbox_identity_digest,
    revoked: row.revoked === 1,
  });
}

function restrictDatabaseFiles(databasePath: string): void {
  for (const suffix of ["", "-wal", "-shm", "-journal"]) {
    try {
      chmodSync(`${databasePath}${suffix}`, 0o600);
    } catch {
      // sidecars may not exist yet
    }
  }
}
