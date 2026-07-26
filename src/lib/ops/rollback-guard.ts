import * as path from "path";
import Database from "better-sqlite3";
import { TEAM_SESSION_SCHEMA_VERSION } from "../team-sessions/sqlite";

/**
 * Migration-aware rollback guard. A forward migration advances the on-disk
 * schema version; rolling back to an older binary would then run code that does
 * not understand the newer schema and can silently corrupt or misread durable
 * authority. This guard refuses that: if the database schema is newer than the
 * schema this binary understands, startup must abort with a clear operator
 * message pointing at the documented rollback path (restore the pre-migration
 * snapshot, then redeploy the matching binary).
 */

const TERMINALX_DATABASE_APPLICATION_ID = 0x54585331; // "TXS1"

export interface RollbackGuardResult {
  readonly ok: boolean;
  readonly binaryVersion: number;
  /** null when there is no recognized database to guard (fresh/first run). */
  readonly onDiskVersion: number | null;
  readonly message?: string;
}

export interface RollbackGuardOptions {
  readonly databaseFilename?: string;
}

function resolveDatabaseFilename(options: RollbackGuardOptions): string {
  if (options.databaseFilename) return options.databaseFilename;
  return (
    process.env.TERMINALX_TEAM_SESSION_DB_PATH ??
    path.join(process.cwd(), "data", "team-sessions.sqlite")
  );
}

export function evaluateRollbackGuard(options: RollbackGuardOptions = {}): RollbackGuardResult {
  const binaryVersion = TEAM_SESSION_SCHEMA_VERSION;
  const filename = resolveDatabaseFilename(options);
  if (filename === ":memory:") {
    return { ok: true, binaryVersion, onDiskVersion: null };
  }
  let db: Database.Database | undefined;
  let onDiskVersion: number | null = null;
  try {
    db = new Database(filename, { readonly: true, fileMustExist: true });
    const applicationId = db.pragma("application_id", { simple: true }) as number;
    if (applicationId !== TERMINALX_DATABASE_APPLICATION_ID) {
      // Not a recognized TerminalX database; startup validation owns that case.
      return { ok: true, binaryVersion, onDiskVersion: null };
    }
    onDiskVersion = db.pragma("user_version", { simple: true }) as number;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { ok: true, binaryVersion, onDiskVersion: null };
    }
    // A database we cannot read here is handled by the opener; do not block on it.
    return { ok: true, binaryVersion, onDiskVersion: null };
  } finally {
    db?.close();
  }

  if (Number.isSafeInteger(onDiskVersion) && (onDiskVersion as number) > binaryVersion) {
    return {
      ok: false,
      binaryVersion,
      onDiskVersion,
      message:
        `TerminalX understands database schema v${binaryVersion}, but the database on disk is at ` +
        `schema v${onDiskVersion} (newer). Refusing to start an older binary against a newer ` +
        `schema — doing so can corrupt durable authority. Restore the pre-migration snapshot ` +
        `(data/backups/pre-migration/) taken before the upgrade and redeploy the matching binary. ` +
        `See docs/production-readiness/canary-rollback.md.`,
    };
  }
  return { ok: true, binaryVersion, onDiskVersion };
}

/**
 * Assert the binary is not older than the on-disk schema. On violation it prints
 * the operator message and exits non-zero (fail closed) so a rollback that
 * skipped the runbook cannot start against a newer schema.
 */
export function assertRollbackGuard(options: RollbackGuardOptions = {}): void {
  const result = evaluateRollbackGuard(options);
  if (result.ok) return;
  console.error(`[rollback-guard] ${result.message}`);
  process.exit(1);
}
