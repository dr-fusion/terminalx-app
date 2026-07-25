import { chmodSync } from "node:fs";
import Database from "better-sqlite3";
import { SecretBrokerProtocolError } from "../protocol";
import type { ProxyErrorCode, ProxyResultClass } from "./proxy-protocol";

/**
 * The broker-side, append-only outbound accounting log. It is the receipt source
 * Gate 5 (Phase 9) will consume, so every row is immutable and monotonically
 * ordered by an autoincrement rowid. Database triggers reject any UPDATE or
 * DELETE. This slice deliberately records only the accounting facts — it does
 * not perform Gate 5 reservation math.
 */
export interface ProxyAccountingInput {
  readonly operationId: string;
  readonly provider: string;
  readonly operation: string;
  readonly destinationHost: string;
  readonly resultClass: ProxyResultClass;
  readonly ambiguous: boolean;
  readonly errorCode: ProxyErrorCode | null;
  readonly requestBytes: number;
  readonly responseBytes: number;
  readonly handleId: string;
  readonly handleGeneration: number;
  readonly installationRevision: number;
  readonly bindingRevision: number | null;
  readonly authoritySnapshotDigest: string;
  readonly startedAtMs: number;
  readonly completedAtMs: number;
}

export interface ProxyAccountingRow extends ProxyAccountingInput {
  /** Monotonic, gap-tolerant ordering key. */
  readonly rowId: number;
}

export interface ProxyAccountingStore {
  record(input: ProxyAccountingInput): ProxyAccountingRow;
  getByOperationId(operationId: string): ProxyAccountingRow | null;
  list(): readonly ProxyAccountingRow[];
  close(): void;
}

interface RawRow {
  row_id: number;
  operation_id: string;
  provider: string;
  operation: string;
  destination_host: string;
  result_class: ProxyResultClass;
  ambiguous: number;
  error_code: string | null;
  request_bytes: number;
  response_bytes: number;
  handle_id: string;
  handle_generation: number;
  installation_revision: number;
  binding_revision: number | null;
  authority_snapshot_digest: string;
  started_at_ms: number;
  completed_at_ms: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS proxy_accounting (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id TEXT NOT NULL UNIQUE,
  provider TEXT NOT NULL,
  operation TEXT NOT NULL,
  destination_host TEXT NOT NULL,
  result_class TEXT NOT NULL,
  ambiguous INTEGER NOT NULL CHECK (ambiguous IN (0, 1)),
  error_code TEXT,
  request_bytes INTEGER NOT NULL CHECK (request_bytes >= 0),
  response_bytes INTEGER NOT NULL CHECK (response_bytes >= 0),
  handle_id TEXT NOT NULL,
  handle_generation INTEGER NOT NULL,
  installation_revision INTEGER NOT NULL,
  binding_revision INTEGER,
  authority_snapshot_digest TEXT NOT NULL,
  started_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS proxy_accounting_no_update
  BEFORE UPDATE ON proxy_accounting
  BEGIN SELECT RAISE(ABORT, 'proxy accounting is append-only'); END;
CREATE TRIGGER IF NOT EXISTS proxy_accounting_no_delete
  BEFORE DELETE ON proxy_accounting
  BEGIN SELECT RAISE(ABORT, 'proxy accounting is append-only'); END;
`;

export interface OpenProxyAccountingStoreOptions {
  readonly databasePath: string;
}

export function openProxyAccountingStore(
  options: OpenProxyAccountingStoreOptions
): ProxyAccountingStore {
  if (typeof options !== "object" || options === null) throw new TypeError();
  const db = new Database(options.databasePath);
  if (options.databasePath !== ":memory:") restrictDatabaseFiles(options.databasePath);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  db.exec(SCHEMA);
  if (options.databasePath !== ":memory:") restrictDatabaseFiles(options.databasePath);

  const insert = db.prepare(
    `INSERT INTO proxy_accounting (
       operation_id, provider, operation, destination_host, result_class, ambiguous,
       error_code, request_bytes, response_bytes, handle_id, handle_generation,
       installation_revision, binding_revision, authority_snapshot_digest,
       started_at_ms, completed_at_ms
     ) VALUES (
       @operationId, @provider, @operation, @destinationHost, @resultClass, @ambiguous,
       @errorCode, @requestBytes, @responseBytes, @handleId, @handleGeneration,
       @installationRevision, @bindingRevision, @authoritySnapshotDigest,
       @startedAtMs, @completedAtMs
     )`
  );
  const selectByOperation = db.prepare<[string]>(
    "SELECT * FROM proxy_accounting WHERE operation_id = ?"
  );
  const selectAll = db.prepare("SELECT * FROM proxy_accounting ORDER BY row_id ASC");

  return Object.freeze({
    record(input: ProxyAccountingInput): ProxyAccountingRow {
      let info: Database.RunResult;
      try {
        info = insert.run({
          operationId: input.operationId,
          provider: input.provider,
          operation: input.operation,
          destinationHost: input.destinationHost,
          resultClass: input.resultClass,
          ambiguous: input.ambiguous ? 1 : 0,
          errorCode: input.errorCode,
          requestBytes: input.requestBytes,
          responseBytes: input.responseBytes,
          handleId: input.handleId,
          handleGeneration: input.handleGeneration,
          installationRevision: input.installationRevision,
          bindingRevision: input.bindingRevision,
          authoritySnapshotDigest: input.authoritySnapshotDigest,
          startedAtMs: input.startedAtMs,
          completedAtMs: input.completedAtMs,
        });
      } catch {
        // A duplicate operationId (idempotent retry) converges on the stored row.
        const existing = selectByOperation.get(input.operationId) as RawRow | undefined;
        if (existing) return toRow(existing);
        throw new SecretBrokerProtocolError("internal");
      }
      const row = selectByOperation.get(input.operationId) as RawRow | undefined;
      if (!row || row.row_id !== Number(info.lastInsertRowid)) {
        throw new SecretBrokerProtocolError("internal");
      }
      return toRow(row);
    },
    getByOperationId(operationId: string): ProxyAccountingRow | null {
      const row = selectByOperation.get(operationId) as RawRow | undefined;
      return row ? toRow(row) : null;
    },
    list(): readonly ProxyAccountingRow[] {
      return Object.freeze((selectAll.all() as RawRow[]).map(toRow));
    },
    close(): void {
      db.close();
    },
  });
}

function toRow(row: RawRow): ProxyAccountingRow {
  return Object.freeze({
    rowId: row.row_id,
    operationId: row.operation_id,
    provider: row.provider,
    operation: row.operation,
    destinationHost: row.destination_host,
    resultClass: row.result_class,
    ambiguous: row.ambiguous === 1,
    errorCode: (row.error_code as ProxyErrorCode | null) ?? null,
    requestBytes: row.request_bytes,
    responseBytes: row.response_bytes,
    handleId: row.handle_id,
    handleGeneration: row.handle_generation,
    installationRevision: row.installation_revision,
    bindingRevision: row.binding_revision,
    authoritySnapshotDigest: row.authority_snapshot_digest,
    startedAtMs: row.started_at_ms,
    completedAtMs: row.completed_at_ms,
  });
}

function restrictDatabaseFiles(databasePath: string): void {
  for (const suffix of ["", "-wal", "-shm", "-journal"]) {
    try {
      chmodSync(`${databasePath}${suffix}`, 0o600);
    } catch {
      // Sidecars may not exist yet; re-restricted on the next call.
    }
  }
}
