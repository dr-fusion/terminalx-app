import { chmodSync } from "node:fs";
import Database from "better-sqlite3";
import { SecretBrokerProtocolError } from "./protocol";

export type RegistrationStatus = "pending" | "active" | "revoked" | "aborted";

export interface RegistrationRow {
  readonly operationId: string;
  readonly handleId: string;
  readonly receiptId: string;
  readonly provider: string;
  readonly brokerKind: string;
  readonly usage: string;
  readonly expectationDigest: string;
  readonly status: RegistrationStatus;
  readonly replacesHandleId: string | null;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly hasSecretMaterial: boolean;
}

export interface PreparedRegistrationInput {
  readonly operationId: string;
  readonly handleId: string;
  readonly receiptId: string;
  readonly provider: string;
  readonly brokerKind: string;
  readonly usage: string;
  readonly expectationDigest: string;
  readonly replacesHandleId: string | null;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  /** Adapter-opaque bytes (sealed OAuth envelope or external reference). */
  readonly secretMaterial: Buffer;
}

/**
 * The broker-private SQLite store. Every mutation is idempotent by
 * operationId/handleId/receiptId so a duplicate protocol message, retry, or
 * crash recovery converges on one state. Secret material is nulled the instant a
 * registration reaches a terminal aborted/revoked state.
 */
export interface SecretBrokerStateStore {
  prepare(input: PreparedRegistrationInput): RegistrationRow;
  getByOperationId(operationId: string): RegistrationRow | null;
  getByHandleId(handleId: string): RegistrationRow | null;
  getByReceiptId(receiptId: string): RegistrationRow | null;
  /**
   * Broker-private credential-use seam for the Credential Proxy (Slice 8D).
   * Returns the stored adapter-opaque secret material for an `active` handle so
   * the proxy — running inside this same non-exporting process — can resolve it
   * for a single approved outbound request. Returns `null` for any non-active
   * handle. This value never crosses the protocol boundary; the closed-response
   * guard makes returning it over the wire impossible.
   */
  getActiveSecretMaterial(handleId: string): Buffer | null;
  finalize(handleId: string, receiptId: string): RegistrationRow;
  finalizeRotation(handleId: string, receiptId: string): RegistrationRow;
  abort(receiptId: string): RegistrationRow;
  revoke(handleId: string): RegistrationRow;
  reapExpiredPending(now: number): readonly RegistrationRow[];
  countPending(): number;
  close(): void;
}

interface RawRow {
  operation_id: string;
  handle_id: string;
  receipt_id: string;
  provider: string;
  broker_kind: string;
  usage: string;
  expectation_digest: string;
  status: RegistrationStatus;
  replaces_handle_id: string | null;
  issued_at_ms: number;
  expires_at_ms: number;
  secret_material: Buffer | null;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS registrations (
  operation_id TEXT PRIMARY KEY,
  handle_id TEXT NOT NULL UNIQUE,
  receipt_id TEXT NOT NULL UNIQUE,
  provider TEXT NOT NULL,
  broker_kind TEXT NOT NULL,
  usage TEXT NOT NULL,
  expectation_digest TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked', 'aborted')),
  replaces_handle_id TEXT,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  secret_material BLOB,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS registrations_pending
  ON registrations(status, expires_at_ms);
`;

export interface OpenSecretBrokerStateStoreOptions {
  readonly databasePath: string;
  readonly clock?: () => number;
}

export function openSecretBrokerStateStore(
  options: OpenSecretBrokerStateStoreOptions
): SecretBrokerStateStore {
  if (typeof options !== "object" || options === null) throw new TypeError();
  const clock = options.clock ?? Date.now;
  const db = new Database(options.databasePath);
  if (options.databasePath !== ":memory:") restrictDatabaseFiles(options.databasePath);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  if (options.databasePath !== ":memory:") restrictDatabaseFiles(options.databasePath);

  const now = (): number => {
    const value = clock();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new SecretBrokerProtocolError("internal");
    }
    return value;
  };

  const selectByOperation = db.prepare<[string]>(
    "SELECT * FROM registrations WHERE operation_id = ?"
  );
  const selectByHandle = db.prepare<[string]>("SELECT * FROM registrations WHERE handle_id = ?");
  const selectByReceipt = db.prepare<[string]>("SELECT * FROM registrations WHERE receipt_id = ?");

  return Object.freeze({
    prepare(input: PreparedRegistrationInput): RegistrationRow {
      const insert = db.transaction((): RawRow => {
        const existing = selectByOperation.get(input.operationId) as RawRow | undefined;
        if (existing) {
          if (
            existing.handle_id !== input.handleId ||
            existing.receipt_id !== input.receiptId ||
            existing.expectation_digest !== input.expectationDigest
          ) {
            throw new SecretBrokerProtocolError("conflict");
          }
          return existing;
        }
        const timestamp = now();
        db.prepare(
          `INSERT INTO registrations (
             operation_id, handle_id, receipt_id, provider, broker_kind, usage,
             expectation_digest, status, replaces_handle_id, issued_at_ms,
             expires_at_ms, secret_material, created_at_ms, updated_at_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)`
        ).run(
          input.operationId,
          input.handleId,
          input.receiptId,
          input.provider,
          input.brokerKind,
          input.usage,
          input.expectationDigest,
          input.replacesHandleId,
          input.issuedAtMs,
          input.expiresAtMs,
          input.secretMaterial,
          timestamp,
          timestamp
        );
        return selectByOperation.get(input.operationId) as RawRow;
      });
      let row: RawRow;
      try {
        row = insert();
      } catch (error) {
        if (error instanceof SecretBrokerProtocolError) throw error;
        throw new SecretBrokerProtocolError("conflict");
      } finally {
        input.secretMaterial.fill(0);
      }
      return toRow(row);
    },

    getByOperationId(operationId: string): RegistrationRow | null {
      const row = selectByOperation.get(operationId) as RawRow | undefined;
      return row ? toRow(row) : null;
    },
    getByHandleId(handleId: string): RegistrationRow | null {
      const row = selectByHandle.get(handleId) as RawRow | undefined;
      return row ? toRow(row) : null;
    },
    getByReceiptId(receiptId: string): RegistrationRow | null {
      const row = selectByReceipt.get(receiptId) as RawRow | undefined;
      return row ? toRow(row) : null;
    },
    getActiveSecretMaterial(handleId: string): Buffer | null {
      const row = selectByHandle.get(handleId) as RawRow | undefined;
      if (!row || row.status !== "active" || row.secret_material === null) return null;
      // Return a copy so the caller can zero it without touching the driver's buffer.
      return Buffer.from(row.secret_material);
    },

    finalize(handleId: string, receiptId: string): RegistrationRow {
      return db.transaction((): RegistrationRow => {
        const row = requireByHandle(selectByHandle, handleId);
        if (row.receipt_id !== receiptId) throw new SecretBrokerProtocolError("conflict");
        if (row.status === "active") return toRow(row);
        if (row.status !== "pending") throw new SecretBrokerProtocolError("conflict");
        setStatus(db, handleId, "active", now(), false);
        return toRow(requireByHandle(selectByHandle, handleId));
      })();
    },

    finalizeRotation(handleId: string, receiptId: string): RegistrationRow {
      return db.transaction((): RegistrationRow => {
        const row = requireByHandle(selectByHandle, handleId);
        if (row.receipt_id !== receiptId || row.replaces_handle_id === null) {
          throw new SecretBrokerProtocolError("conflict");
        }
        const replaced = requireByHandle(selectByHandle, row.replaces_handle_id);
        const timestamp = now();
        if (row.status === "pending") {
          setStatus(db, handleId, "active", timestamp, false);
        } else if (row.status !== "active") {
          throw new SecretBrokerProtocolError("conflict");
        }
        if (replaced.status === "active") {
          setStatus(db, replaced.handle_id, "revoked", timestamp, true);
        } else if (replaced.status !== "revoked") {
          throw new SecretBrokerProtocolError("conflict");
        }
        return toRow(requireByHandle(selectByHandle, handleId));
      })();
    },

    abort(receiptId: string): RegistrationRow {
      return db.transaction((): RegistrationRow => {
        const row = requireByReceipt(selectByReceipt, receiptId);
        if (row.status === "aborted") return toRow(row);
        if (row.status !== "pending") throw new SecretBrokerProtocolError("conflict");
        setStatus(db, row.handle_id, "aborted", now(), true);
        return toRow(requireByReceipt(selectByReceipt, receiptId));
      })();
    },

    revoke(handleId: string): RegistrationRow {
      return db.transaction((): RegistrationRow => {
        const row = requireByHandle(selectByHandle, handleId);
        if (row.status === "revoked") return toRow(row);
        if (row.status !== "active") throw new SecretBrokerProtocolError("conflict");
        setStatus(db, handleId, "revoked", now(), true);
        return toRow(requireByHandle(selectByHandle, handleId));
      })();
    },

    reapExpiredPending(nowMs: number): readonly RegistrationRow[] {
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new TypeError();
      const reap = db.transaction((): RegistrationRow[] => {
        const expired = db
          .prepare<
            [number]
          >("SELECT * FROM registrations WHERE status = 'pending' AND expires_at_ms <= ?")
          .all(nowMs) as RawRow[];
        const reaped: RegistrationRow[] = [];
        for (const row of expired) {
          setStatus(db, row.handle_id, "aborted", nowMs, true);
          reaped.push(toRow({ ...row, status: "aborted", secret_material: null }));
        }
        return reaped;
      });
      return Object.freeze(reap());
    },

    countPending(): number {
      const row = db
        .prepare("SELECT COUNT(*) AS count FROM registrations WHERE status = 'pending'")
        .get() as {
        count: number;
      };
      return row.count;
    },

    close(): void {
      db.close();
    },
  });
}

function requireByHandle(statement: Database.Statement, handleId: string): RawRow {
  const row = statement.get(handleId) as RawRow | undefined;
  if (!row) throw new SecretBrokerProtocolError("not-found");
  return row;
}

function requireByReceipt(statement: Database.Statement, receiptId: string): RawRow {
  const row = statement.get(receiptId) as RawRow | undefined;
  if (!row) throw new SecretBrokerProtocolError("not-found");
  return row;
}

function setStatus(
  db: Database.Database,
  handleId: string,
  status: RegistrationStatus,
  timestamp: number,
  clearSecret: boolean
): void {
  db.prepare(
    `UPDATE registrations
       SET status = ?, updated_at_ms = ?${clearSecret ? ", secret_material = NULL" : ""}
     WHERE handle_id = ?`
  ).run(status, timestamp, handleId);
}

function toRow(row: RawRow): RegistrationRow {
  return Object.freeze({
    operationId: row.operation_id,
    handleId: row.handle_id,
    receiptId: row.receipt_id,
    provider: row.provider,
    brokerKind: row.broker_kind,
    usage: row.usage,
    expectationDigest: row.expectation_digest,
    status: row.status,
    replacesHandleId: row.replaces_handle_id,
    issuedAtMs: row.issued_at_ms,
    expiresAtMs: row.expires_at_ms,
    hasSecretMaterial: row.secret_material !== null,
  });
}

function restrictDatabaseFiles(databasePath: string): void {
  for (const suffix of ["", "-wal", "-shm", "-journal"]) {
    try {
      chmodSync(`${databasePath}${suffix}`, 0o600);
    } catch {
      // The WAL/SHM sidecars may not exist yet; they are re-restricted on the
      // next call after journal-mode initialization.
    }
  }
}
