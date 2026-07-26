import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import {
  backupSqliteDatabase,
  backupTeamSessionDatabase,
  restoreSqliteDatabase,
  rotateBackups,
  verifyBackup,
} from "@/lib/ops/backup";
import { runRestoreDrill } from "@/lib/ops/restore-drill";
import { insertChainedSessionEvent } from "../helpers/session-events";

let tmp: string;

function seedDatabase(filename: string): void {
  const database = openTeamSessionDatabase({ filename });
  const db = database.db;
  db.prepare("INSERT INTO teams (id, name, created_at_ms) VALUES ('t1','Team',1)").run();
  db.prepare(
    "INSERT INTO projects (id, team_id, name, created_at_ms) VALUES ('p1','t1','Project',1)"
  ).run();
  db.prepare(
    `INSERT INTO sessions
       (id, team_id, project_id, name, status, steering_policy,
        runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
     VALUES ('s1','t1','p1','S','active','shared','local-tmux','trusted-shared-host','s1-tmux',0,1)`
  ).run();
  for (let sequence = 1; sequence <= 3; sequence += 1) {
    insertChainedSessionEvent(db, {
      sessionId: "s1",
      sequence,
      eventId: `s1-e${sequence}`,
      type: "session.created",
      occurredAtMs: sequence,
      actorKind: "human",
      actorUserId: "u1",
      actorDisplayName: "User",
      sourceScope: "test",
      sourceKey: `k${sequence}`,
      payloadJson: JSON.stringify({ n: sequence }),
    });
  }
  database.close();
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-backup-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("online backup and restore", () => {
  it("backs up with the online API and verifies the copy", async () => {
    const source = path.join(tmp, "team-sessions.sqlite");
    seedDatabase(source);
    const destination = path.join(tmp, "out", "backup.sqlite");
    const result = await backupSqliteDatabase(source, destination);
    expect(result.sizeBytes).toBeGreaterThan(0);
    const verification = verifyBackup(destination);
    expect(verification.ok).toBe(true);
    expect(verification.integrityOk).toBe(true);
    expect(verification.schemaVersion).toBeGreaterThan(0);
    if (process.platform !== "win32") {
      expect(fs.statSync(destination).mode & 0o077).toBe(0);
    }
  });

  it("restores a verified backup into place and round-trips the data", async () => {
    const source = path.join(tmp, "team-sessions.sqlite");
    seedDatabase(source);
    const backup = path.join(tmp, "backup.sqlite");
    await backupSqliteDatabase(source, backup);
    const target = path.join(tmp, "restored", "team-sessions.sqlite");
    const { verification } = restoreSqliteDatabase(backup, target);
    expect(verification.ok).toBe(true);
    const db = new Database(target, { readonly: true });
    const count = db.prepare("SELECT COUNT(*) AS n FROM session_events").get() as { n: number };
    db.close();
    expect(count.n).toBe(3);
  });

  it("refuses to restore a backup that fails verification", () => {
    const bogus = path.join(tmp, "bogus.sqlite");
    const db = new Database(bogus);
    db.exec("CREATE TABLE t(x)");
    db.close();
    expect(() => restoreSqliteDatabase(bogus, path.join(tmp, "t.sqlite"))).toThrow();
  });

  it("rotates full backups, keeping the newest", async () => {
    const source = path.join(tmp, "team-sessions.sqlite");
    seedDatabase(source);
    const backupDir = path.join(tmp, "full");
    for (let i = 0; i < 4; i += 1) {
      await backupTeamSessionDatabase({ sourcePath: source, backupDir, keep: 100 });
    }
    expect(fs.readdirSync(backupDir).length).toBe(4);
    rotateBackups(backupDir, 2);
    expect(fs.readdirSync(backupDir).length).toBe(2);
  });
});

describe("restore drill", () => {
  it("backs up, restores, and verifies the event chain over every session", async () => {
    const source = path.join(tmp, "team-sessions.sqlite");
    seedDatabase(source);
    const result = await runRestoreDrill({ sourcePath: source });
    expect(result.ok).toBe(true);
    expect(result.integrityOk).toBe(true);
    expect(result.schemaOk).toBe(true);
    expect(result.sessionsVerified).toBe(1);
    expect(result.chainFailures).toHaveLength(0);
  });
});
