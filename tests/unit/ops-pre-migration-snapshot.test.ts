import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { openTeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import {
  preMigrationSnapshotDir,
  rotateSnapshots,
  takePreMigrationSnapshot,
  type PreMigrationSnapshotInput,
} from "@/lib/ops/pre-migration-snapshot";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-snap-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** A migrated (v18) database with its attention artifacts removed and version rolled to v17. */
function makeV17Database(): string {
  const filename = path.join(tmp, "team-sessions.sqlite");
  openTeamSessionDatabase({ filename }).close();
  const raw = new Database(filename);
  raw.exec(`
    DROP TABLE IF EXISTS attention_deliveries;
    DROP TABLE IF EXISTS attention_escalations;
    DROP TABLE IF EXISTS user_attention_reads;
    DROP TABLE IF EXISTS comment_attachments;
    DROP TABLE IF EXISTS comment_mentions;
  `);
  raw.pragma("user_version = 17");
  raw.close();
  return filename;
}

describe("pre-migration snapshot (direct)", () => {
  it("writes a consistent, restorable snapshot via VACUUM INTO", () => {
    const filename = path.join(tmp, "team-sessions.sqlite");
    const database = openTeamSessionDatabase({ filename });
    const result = takePreMigrationSnapshot({
      db: database.db,
      filename,
      fromVersion: 17,
      toVersion: 18,
    });
    database.close();
    expect(fs.existsSync(result.path)).toBe(true);
    if (process.platform !== "win32") {
      expect(fs.statSync(result.path).mode & 0o077).toBe(0);
    }
    const snapshot = new Database(result.path, { readonly: true });
    expect(snapshot.pragma("quick_check", { simple: true })).toBe("ok");
    snapshot.close();
  });

  it("rotates snapshots to the configured retention count", () => {
    const dir = path.join(tmp, "backups", "pre-migration");
    fs.mkdirSync(dir, { recursive: true });
    for (let i = 0; i < 5; i += 1) {
      fs.writeFileSync(
        path.join(dir, `team-sessions.pre-migration.v17-to-v18.2026010100000${i}a.sqlite`),
        "x"
      );
    }
    rotateSnapshots(dir, 2);
    expect(fs.readdirSync(dir).length).toBe(2);
  });

  it("derives the snapshot directory next to the database", () => {
    expect(preMigrationSnapshotDir("/data/team-sessions.sqlite")).toBe(
      "/data/backups/pre-migration"
    );
  });
});

describe("pre-migration snapshot hook in the migration dispatcher", () => {
  it("invokes the hook before the schema version is advanced", () => {
    const filename = makeV17Database();
    let observedAtCall: { fromVersion: number; toVersion: number; onDiskVersion: number } | null =
      null;
    const spy = vi.fn((input: PreMigrationSnapshotInput) => {
      observedAtCall = {
        fromVersion: input.fromVersion,
        toVersion: input.toVersion,
        onDiskVersion: input.db.pragma("user_version", { simple: true }) as number,
      };
    });
    const database = openTeamSessionDatabase({ filename, onBeforeMigrate: spy });
    try {
      expect(spy).toHaveBeenCalledTimes(1);
      expect(observedAtCall).toEqual({ fromVersion: 17, toVersion: 18, onDiskVersion: 17 });
      // The migration completed afterwards.
      expect(database.db.pragma("user_version", { simple: true })).toBe(18);
    } finally {
      database.close();
    }
  });

  it("fails closed: a snapshot error aborts the migration", () => {
    const filename = makeV17Database();
    expect(() =>
      openTeamSessionDatabase({
        filename,
        onBeforeMigrate: () => {
          throw new Error("snapshot device full");
        },
      })
    ).toThrow();
    const raw = new Database(filename, { readonly: true });
    // The database was left un-migrated at v17 because the snapshot failed first.
    expect(raw.pragma("user_version", { simple: true })).toBe(17);
    raw.close();
  });

  it("does not snapshot a fresh initialization", () => {
    const spy = vi.fn();
    const database = openTeamSessionDatabase({
      filename: path.join(tmp, "fresh.sqlite"),
      onBeforeMigrate: spy,
    });
    database.close();
    expect(spy).not.toHaveBeenCalled();
  });
});
