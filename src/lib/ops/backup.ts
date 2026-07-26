import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

/**
 * Online backup and restore for the TerminalX SQLite database. Backups use
 * SQLite's Online Backup API (`Database.prototype.backup`), which produces a
 * single, transactionally-consistent file even while the database is open and
 * under WAL — it never copies a live `-wal`/`-shm` file, so a backup is always
 * internally consistent and safe to restore. All artifacts are written 0600 and
 * carry no plaintext secrets (the database itself stores only digests/handles).
 */

const TERMINALX_DATABASE_APPLICATION_ID = 0x54585331; // "TXS1"

export interface BackupResult {
  readonly source: string;
  readonly destination: string;
  readonly sizeBytes: number;
}

export interface BackupVerification {
  readonly ok: boolean;
  readonly applicationOk: boolean;
  readonly integrityOk: boolean;
  readonly schemaVersion: number | null;
}

function chmodPrivate(target: string): void {
  if (process.platform !== "win32") {
    fs.chmodSync(target, 0o600);
  }
}

/**
 * Back up `sourcePath` to `destinationPath` using the online backup API. The
 * destination's parent directory is created 0700 and the file is written 0600.
 */
export async function backupSqliteDatabase(
  sourcePath: string,
  destinationPath: string
): Promise<BackupResult> {
  if (sourcePath === ":memory:") {
    throw new Error("Cannot back up an in-memory database");
  }
  const parent = path.dirname(path.resolve(destinationPath));
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  // Open the source read-only; the online backup reads committed pages and never
  // mutates the source, so a live server can keep its own write connection open.
  const db = new Database(sourcePath, { readonly: true, fileMustExist: true });
  try {
    await db.backup(destinationPath);
  } finally {
    db.close();
  }
  chmodPrivate(destinationPath);
  const sizeBytes = fs.statSync(destinationPath).size;
  return { source: sourcePath, destination: destinationPath, sizeBytes };
}

/** Verify a backup file: recognized application id, integrity-clean, readable schema. */
export function verifyBackup(backupPath: string): BackupVerification {
  let db: Database.Database | undefined;
  try {
    db = new Database(backupPath, { readonly: true, fileMustExist: true });
    const applicationId = db.pragma("application_id", { simple: true }) as number;
    const applicationOk = applicationId === TERMINALX_DATABASE_APPLICATION_ID;
    const schemaVersion = db.pragma("user_version", { simple: true }) as number;
    const quickCheck = db.pragma("quick_check", { simple: true }) as string;
    const integrityOk = quickCheck === "ok";
    return {
      ok: applicationOk && integrityOk,
      applicationOk,
      integrityOk,
      schemaVersion: Number.isSafeInteger(schemaVersion) ? schemaVersion : null,
    };
  } catch {
    return { ok: false, applicationOk: false, integrityOk: false, schemaVersion: null };
  } finally {
    db?.close();
  }
}

/**
 * Restore a verified backup into `targetPath`. This is an OFFLINE operation — the
 * server must be stopped so no live connection holds the target. Any stale
 * `-wal`/`-shm`/`-journal` sidecars at the target are removed so the restored,
 * self-contained file is authoritative. Fails closed if the backup does not verify.
 */
export function restoreSqliteDatabase(
  backupPath: string,
  targetPath: string
): { restored: string; verification: BackupVerification } {
  const verification = verifyBackup(backupPath);
  if (!verification.ok) {
    throw new Error("Refusing to restore: backup failed verification");
  }
  const resolvedTarget = path.resolve(targetPath);
  const parent = path.dirname(resolvedTarget);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  for (const sidecar of ["-wal", "-shm", "-journal"]) {
    fs.rmSync(`${resolvedTarget}${sidecar}`, { force: true });
  }
  fs.copyFileSync(backupPath, resolvedTarget);
  chmodPrivate(resolvedTarget);
  const restoredVerification = verifyBackup(resolvedTarget);
  if (!restoredVerification.ok) {
    throw new Error("Restore verification failed after copy");
  }
  return { restored: resolvedTarget, verification: restoredVerification };
}

export interface FullBackupOptions {
  readonly sourcePath?: string;
  readonly backupDir?: string;
  readonly keep?: number;
  readonly now?: number;
}

const BACKUP_PREFIX = "team-sessions.backup.";
const BACKUP_PATTERN = /^team-sessions\.backup\.[0-9A-Za-z_-]+\.sqlite$/;
const DEFAULT_KEEP = 14;

function resolveSourcePath(options: FullBackupOptions): string {
  return (
    options.sourcePath ??
    process.env.TERMINALX_TEAM_SESSION_DB_PATH ??
    path.join(process.cwd(), "data", "team-sessions.sqlite")
  );
}

function resolveBackupDir(options: FullBackupOptions, sourcePath: string): string {
  if (options.backupDir) return options.backupDir;
  const override = process.env.TERMINALX_BACKUP_DIR;
  if (override && path.isAbsolute(override)) return override;
  return path.join(path.dirname(path.resolve(sourcePath)), "backups", "full");
}

/**
 * Take a full, rotated online backup of the canonical database (which is the
 * single file backing Team Sessions, canonical identity, connections, and mobile
 * auth). Retention keeps the newest `keep` backups.
 */
export async function backupTeamSessionDatabase(
  options: FullBackupOptions = {}
): Promise<BackupResult> {
  const sourcePath = resolveSourcePath(options);
  const backupDir = resolveBackupDir(options, sourcePath);
  const now = options.now ?? Date.now();
  const stamp = new Date(now).toISOString().replace(/[^0-9]/g, "");
  const nonce = Math.random().toString(36).slice(2, 10);
  const destination = path.join(backupDir, `${BACKUP_PREFIX}${stamp}${nonce}.sqlite`);
  const result = await backupSqliteDatabase(sourcePath, destination);
  rotateBackups(backupDir, options.keep ?? configuredKeep());
  return result;
}

function configuredKeep(): number {
  const raw = process.env.TERMINALX_BACKUP_KEEP;
  if (raw === undefined) return DEFAULT_KEEP;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1) return DEFAULT_KEEP;
  return Math.min(parsed, 1000);
}

/** Keep the newest `keep` full backups; delete older ones. Best-effort. */
export function rotateBackups(backupDir: string, keep: number): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(backupDir);
  } catch {
    return;
  }
  const backups = entries
    .filter((name) => BACKUP_PATTERN.test(name))
    .map((name) => {
      const full = path.join(backupDir, name);
      let mtimeMs = 0;
      try {
        mtimeMs = fs.statSync(full).mtimeMs;
      } catch {
        mtimeMs = 0;
      }
      return { full, mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  for (const stale of backups.slice(keep)) {
    try {
      fs.rmSync(stale.full, { force: true });
    } catch {
      // A backup we cannot prune now is retried on the next rotation.
    }
  }
}
