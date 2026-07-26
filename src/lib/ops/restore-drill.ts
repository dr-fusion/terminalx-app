import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Database from "better-sqlite3";
import { createTeamSessions } from "../team-sessions/module";
import { verifySessionEventChain } from "../team-sessions/session-event-chain";
import { backupSqliteDatabase, restoreSqliteDatabase, verifyBackup } from "./backup";

/**
 * A restore drill: back up the live database, restore the backup into a throwaway
 * location, and verify the restored copy — integrity, schema, and the Phase 10
 * append-only Session Event Chain over every session. It proves a backup is not
 * merely a file but a recoverable, tamper-evident database. It never touches the
 * live database beyond a read-only online backup.
 */

export interface RestoreDrillResult {
  readonly ok: boolean;
  readonly backupPath: string;
  readonly restoredPath: string;
  readonly integrityOk: boolean;
  readonly schemaOk: boolean;
  readonly sessionsVerified: number;
  readonly chainFailures: ReadonlyArray<{ sessionId: string; reason: string }>;
}

export interface RestoreDrillOptions {
  readonly sourcePath?: string;
  /** Working directory for the drill; a temp dir is created and cleaned when omitted. */
  readonly workDir?: string;
}

function resolveSourcePath(options: RestoreDrillOptions): string {
  return (
    options.sourcePath ??
    process.env.TERMINALX_TEAM_SESSION_DB_PATH ??
    path.join(process.cwd(), "data", "team-sessions.sqlite")
  );
}

function listSessionIds(filename: string): string[] {
  const db = new Database(filename, { readonly: true, fileMustExist: true });
  try {
    const rows = db.prepare("SELECT id FROM sessions ORDER BY id ASC").all() as Array<{
      id: string;
    }>;
    return rows.map((row) => row.id);
  } finally {
    db.close();
  }
}

export async function runRestoreDrill(
  options: RestoreDrillOptions = {}
): Promise<RestoreDrillResult> {
  const sourcePath = resolveSourcePath(options);
  const ownWorkDir = options.workDir === undefined;
  const workDir = options.workDir ?? fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-drill-"));
  fs.mkdirSync(workDir, { recursive: true, mode: 0o700 });
  const backupPath = path.join(workDir, "drill-backup.sqlite");
  const restoredPath = path.join(workDir, "drill-restored.sqlite");
  const chainFailures: Array<{ sessionId: string; reason: string }> = [];
  let sessionsVerified = 0;

  try {
    await backupSqliteDatabase(sourcePath, backupPath);
    const verification = verifyBackup(backupPath);
    const integrityOk = verification.integrityOk && verification.applicationOk;
    const schemaOk = verification.schemaVersion !== null;
    if (!integrityOk) {
      return {
        ok: false,
        backupPath,
        restoredPath,
        integrityOk,
        schemaOk,
        sessionsVerified: 0,
        chainFailures,
      };
    }

    restoreSqliteDatabase(backupPath, restoredPath);

    const sessionIds = listSessionIds(restoredPath);
    // Open the restored copy through the real opener so the drill also exercises
    // the migration/integrity gate, then verify each session's event chain.
    const teamSessions = createTeamSessions({ filename: restoredPath });
    try {
      for (const sessionId of sessionIds) {
        try {
          const bundle = teamSessions.exportSessionEventChain(sessionId);
          if (bundle.events.length === 0) {
            // A session with no events has no chain to break.
            sessionsVerified += 1;
            continue;
          }
          const chain = verifySessionEventChain(bundle.events, bundle.genesisRoot);
          if (chain.ok) {
            sessionsVerified += 1;
          } else {
            chainFailures.push({ sessionId, reason: chain.failure.kind });
          }
        } catch (error) {
          chainFailures.push({
            sessionId,
            reason: error instanceof Error ? error.name : "export-failed",
          });
        }
      }
    } finally {
      teamSessions.close();
    }

    return {
      ok: integrityOk && schemaOk && chainFailures.length === 0,
      backupPath,
      restoredPath,
      integrityOk,
      schemaOk,
      sessionsVerified,
      chainFailures,
    };
  } finally {
    if (ownWorkDir) {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  }
}
