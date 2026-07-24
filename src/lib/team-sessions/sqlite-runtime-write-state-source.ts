import type Database from "better-sqlite3";
import type { RuntimeWriteStateUpdate } from "../runtime/local-tmux-runtime";

type SqlValue = string | number | null;
type SqlRow = Record<string, SqlValue>;

export type RuntimeWriteStateSnapshotErrorCode = "invalid_configuration" | "journal_conflict";

const SAFE_MESSAGES: Readonly<Record<RuntimeWriteStateSnapshotErrorCode, string>> = {
  invalid_configuration: "Runtime write-state snapshot source configuration is invalid",
  journal_conflict: "Runtime write-state snapshot conflicts with durable state",
};

export class RuntimeWriteStateSnapshotError extends Error {
  constructor(readonly code: RuntimeWriteStateSnapshotErrorCode) {
    super(SAFE_MESSAGES[code]);
    this.name = "RuntimeWriteStateSnapshotError";
  }
}

export interface RuntimeWriteStateSnapshotSource {
  /** One transactionally consistent row per durable Session. */
  read(): ReadonlyArray<RuntimeWriteStateUpdate>;
}

export interface CreateSqliteRuntimeWriteStateSnapshotSourceOptions {
  readonly db: Database.Database;
}

interface WriteStateRow extends SqlRow {
  session_id: string;
  session_status: string;
  session_authorization_generation: number;
  session_authorization_state: string;
  assignment_status: string | null;
  assignment_authorization_generation: number | null;
  assignment_authorization_high_water: number | null;
}

/**
 * Reconstruct the process-local terminal/process write fence from canonical
 * SQLite truth before transports begin accepting mutations.
 */
export class SqliteRuntimeWriteStateSnapshotSource implements RuntimeWriteStateSnapshotSource {
  private readonly db: Database.Database;
  private readonly prepare: (...args: unknown[]) => unknown;
  private readonly transaction: (...args: unknown[]) => unknown;

  constructor(options: CreateSqliteRuntimeWriteStateSnapshotSourceOptions) {
    let db: unknown;
    let prepare: (...args: unknown[]) => unknown;
    let transaction: (...args: unknown[]) => unknown;
    try {
      const record = exactDataRecord(options, ["db"]);
      db = dataValue(record, "db");
      prepare = captureDataMethod(db, "prepare");
      transaction = captureDataMethod(db, "transaction");
    } catch {
      fail("invalid_configuration");
    }
    this.db = db as Database.Database;
    this.prepare = prepare;
    this.transaction = transaction;
  }

  read(): ReadonlyArray<RuntimeWriteStateUpdate> {
    try {
      const snapshot = Reflect.apply(this.transaction, this.db, [
        () => {
          const statement = Reflect.apply(this.prepare, this.db, [
            `SELECT session.id AS session_id,
                  session.status AS session_status,
                  session.runtime_authorization_generation AS
                    session_authorization_generation,
                  session.runtime_authorization_state AS session_authorization_state,
                  assignment.status AS assignment_status,
                  assignment.runtime_authorization_generation AS
                    assignment_authorization_generation,
                  (SELECT MAX(history.runtime_authorization_generation)
                     FROM runtime_assignments history
                    WHERE history.session_id = session.id) AS
                    assignment_authorization_high_water
           FROM sessions session
           LEFT JOIN runtime_assignments assignment
             ON assignment.session_id = session.id
            AND assignment.generation = (
              SELECT MAX(candidate.generation)
              FROM runtime_assignments candidate
              WHERE candidate.session_id = session.id
            )
           ORDER BY session.id ASC`,
          ]);
          const all = captureDataMethod(statement, "all");
          return snapshotRows(Reflect.apply(all, statement, []));
        },
      ]) as unknown;
      const immediate = captureDataMethod(snapshot, "immediate");
      return Reflect.apply(immediate, snapshot, []) as ReadonlyArray<RuntimeWriteStateUpdate>;
    } catch (error) {
      if (error instanceof RuntimeWriteStateSnapshotError) throw error;
      fail("journal_conflict");
    }
  }
}

export function createSqliteRuntimeWriteStateSnapshotSource(
  options: CreateSqliteRuntimeWriteStateSnapshotSourceOptions
): SqliteRuntimeWriteStateSnapshotSource {
  return new SqliteRuntimeWriteStateSnapshotSource(options);
}

function snapshotRow(row: WriteStateRow): RuntimeWriteStateUpdate {
  const record = exactDataRecord(row, [
    "session_id",
    "session_status",
    "session_authorization_generation",
    "session_authorization_state",
    "assignment_status",
    "assignment_authorization_generation",
    "assignment_authorization_high_water",
  ]);
  const sessionId = identifier(dataValue(record, "session_id"));
  const sessionGeneration = positiveInteger(dataValue(record, "session_authorization_generation"));
  const unsafeAssignmentGeneration = dataValue(record, "assignment_authorization_generation");
  const assignmentGeneration =
    unsafeAssignmentGeneration === null ? null : positiveInteger(unsafeAssignmentGeneration);
  const unsafeAssignmentHighWater = dataValue(record, "assignment_authorization_high_water");
  const assignmentHighWater =
    unsafeAssignmentHighWater === null ? null : positiveInteger(unsafeAssignmentHighWater);
  const generation = Math.max(sessionGeneration, assignmentHighWater ?? sessionGeneration);
  const sessionStatus = dataValue(record, "session_status");
  const authorizationState = dataValue(record, "session_authorization_state");
  const assignmentStatus = dataValue(record, "assignment_status");
  if (
    (sessionStatus !== "active" &&
      sessionStatus !== "awaiting_assignee" &&
      sessionStatus !== "ended") ||
    (authorizationState !== "enforced" &&
      authorizationState !== "pending" &&
      authorizationState !== "quarantined") ||
    (assignmentStatus !== null &&
      assignmentStatus !== "provisioning" &&
      assignmentStatus !== "ready" &&
      assignmentStatus !== "checkpointing" &&
      assignmentStatus !== "recovering" &&
      assignmentStatus !== "quarantined" &&
      assignmentStatus !== "retired" &&
      assignmentStatus !== "failed") ||
    (assignmentStatus === null &&
      (assignmentGeneration !== null || assignmentHighWater !== null)) ||
    (assignmentStatus !== null &&
      (assignmentGeneration === null ||
        assignmentHighWater === null ||
        assignmentHighWater < assignmentGeneration))
  ) {
    fail("journal_conflict");
  }

  const state: RuntimeWriteStateUpdate["state"] =
    sessionStatus === "ended" || assignmentStatus === "retired"
      ? "retired"
      : sessionStatus === "active" &&
          authorizationState === "enforced" &&
          assignmentStatus === "ready" &&
          assignmentGeneration === sessionGeneration &&
          generation === sessionGeneration
        ? "active"
        : "fenced";
  return Object.freeze({
    sessionId,
    runtimeAuthorizationGeneration: generation,
    state,
  });
}

function snapshotRows(value: unknown): ReadonlyArray<RuntimeWriteStateUpdate> {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
      fail("journal_conflict");
    }
    const length = Object.getOwnPropertyDescriptor(value, "length");
    if (
      !length ||
      length.enumerable ||
      !("value" in length) ||
      !Number.isSafeInteger(length.value) ||
      length.value < 0 ||
      length.value > 100_000
    ) {
      fail("journal_conflict");
    }
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== length.value + 1 ||
      !keys.includes("length") ||
      keys.some(
        (key) =>
          key !== "length" &&
          (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= length.value)
      )
    ) {
      fail("journal_conflict");
    }
    const result: RuntimeWriteStateUpdate[] = [];
    const sessionIds = new Set<string>();
    for (let index = 0; index < length.value; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        fail("journal_conflict");
      }
      const row = snapshotRow(descriptor.value as WriteStateRow);
      if (sessionIds.has(row.sessionId)) fail("journal_conflict");
      sessionIds.add(row.sessionId);
      result.push(row);
    }
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof RuntimeWriteStateSnapshotError) throw error;
    fail("journal_conflict");
  }
}

function exactDataRecord(
  value: unknown,
  expected: readonly PropertyKey[]
): Record<PropertyKey, unknown> {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) {
    fail("journal_conflict");
  }
  let prototype: object | null;
  let keys: readonly PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
    keys = Reflect.ownKeys(value);
  } catch {
    fail("journal_conflict");
  }
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== expected.length ||
    keys.some((key) => !expected.includes(key))
  ) {
    fail("journal_conflict");
  }
  for (const key of keys) dataValue(value as Record<PropertyKey, unknown>, key);
  return value as Record<PropertyKey, unknown>;
}

function dataValue(record: Record<PropertyKey, unknown>, key: PropertyKey): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, key);
  } catch {
    fail("journal_conflict");
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    fail("journal_conflict");
  }
  return descriptor.value;
}

function captureDataMethod(target: unknown, key: PropertyKey): (...args: unknown[]) => unknown {
  if ((typeof target !== "object" && typeof target !== "function") || target === null) {
    fail("journal_conflict");
  }
  try {
    const visited = new Set<object>();
    let current: object | null = target;
    for (let depth = 0; current !== null && depth < 32; depth += 1) {
      if (visited.has(current)) fail("journal_conflict");
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        if (!("value" in descriptor) || typeof descriptor.value !== "function") {
          fail("journal_conflict");
        }
        return descriptor.value as (...args: unknown[]) => unknown;
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
  } catch (error) {
    if (error instanceof RuntimeWriteStateSnapshotError) throw error;
    fail("journal_conflict");
  }
  fail("journal_conflict");
}

function identifier(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    value.trim() !== value ||
    /[\0\r\n\t]/.test(value)
  ) {
    fail("journal_conflict");
  }
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail("journal_conflict");
  return value as number;
}

function fail(code: RuntimeWriteStateSnapshotErrorCode): never {
  throw new RuntimeWriteStateSnapshotError(code);
}
