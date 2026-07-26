import * as fs from "fs";
import * as path from "path";
import type Database from "better-sqlite3";

/**
 * A transactionally-consistent, online snapshot of the Team Session database
 * taken *before* any schema migration mutates it. It uses SQLite's `VACUUM INTO`
 * command, which produces a consistent copy of the committed database even under
 * WAL — it never copies a live `-wal` file, so the snapshot is always internally
 * consistent and safe to restore. It is the automatic pre-migration guard the
 * migration-aware rollback path restores from (see
 * `docs/production-readiness/canary-rollback.md`).
 */

export interface PreMigrationSnapshotInput {
  readonly db: Database.Database;
  /** Absolute path to the on-disk database being opened for migration. */
  readonly filename: string;
  readonly fromVersion: number;
  readonly toVersion: number;
}

export interface PreMigrationSnapshotResult {
  readonly path: string;
  readonly fromVersion: number;
  readonly toVersion: number;
}

const DEFAULT_KEEP = 10;
const KEEP_ENV = "TERMINALX_PRE_MIGRATION_SNAPSHOT_KEEP";
const DIR_ENV = "TERMINALX_PRE_MIGRATION_SNAPSHOT_DIR";
const SNAPSHOT_PREFIX = "team-sessions.pre-migration.";
const SNAPSHOT_PATTERN = /^team-sessions\.pre-migration\.v\d+-to-v\d+\.[0-9A-Za-z_-]+\.sqlite$/;

/** The directory pre-migration snapshots are written to for a given database. */
export function preMigrationSnapshotDir(databaseFilename: string): string {
  const override = process.env[DIR_ENV];
  if (typeof override === "string" && override.length > 0 && path.isAbsolute(override)) {
    return override;
  }
  return path.join(path.dirname(path.resolve(databaseFilename)), "backups", "pre-migration");
}

function configuredKeep(): number {
  const raw = process.env[KEEP_ENV];
  if (raw === undefined) return DEFAULT_KEEP;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1) return DEFAULT_KEEP;
  return Math.min(parsed, 1000);
}

/**
 * Take the snapshot. Fails closed: any error propagates so the caller refuses to
 * run the migration without a recovery point. Never copies a live WAL file.
 */
export function takePreMigrationSnapshot(
  input: PreMigrationSnapshotInput
): PreMigrationSnapshotResult {
  if (input.filename === ":memory:") {
    // Nothing durable to snapshot; the caller only invokes this for real files.
    return { path: ":memory:", fromVersion: input.fromVersion, toVersion: input.toVersion };
  }
  const dir = preMigrationSnapshotDir(input.filename);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[^0-9]/g, "");
  const nonce = Math.random().toString(36).slice(2, 10);
  const dest = path.join(
    dir,
    `${SNAPSHOT_PREFIX}v${input.fromVersion}-to-v${input.toVersion}.${stamp}${nonce}.sqlite`
  );
  // VACUUM INTO writes a fresh, committed-state copy. It refuses to overwrite an
  // existing file, and the unique name guarantees it never does.
  input.db.prepare("VACUUM INTO ?").run(dest);
  if (process.platform !== "win32") {
    fs.chmodSync(dest, 0o600);
  }
  rotateSnapshots(dir, configuredKeep());
  return { path: dest, fromVersion: input.fromVersion, toVersion: input.toVersion };
}

/** Keep the newest `keep` snapshots, deleting older ones. Best-effort. */
export function rotateSnapshots(dir: string, keep: number): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return;
  }
  const snapshots = entries
    .filter((name) => SNAPSHOT_PATTERN.test(name))
    .map((name) => {
      const full = path.join(dir, name);
      let mtimeMs = 0;
      try {
        mtimeMs = fs.statSync(full).mtimeMs;
      } catch {
        mtimeMs = 0;
      }
      return { full, mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  for (const stale of snapshots.slice(keep)) {
    try {
      fs.rmSync(stale.full, { force: true });
    } catch {
      // A snapshot we cannot prune is not fatal to a migration or a restore.
    }
  }
}
