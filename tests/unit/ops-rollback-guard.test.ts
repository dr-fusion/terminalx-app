import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { evaluateRollbackGuard } from "@/lib/ops/rollback-guard";

describe("migration-aware rollback guard", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-rollback-"));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function currentDatabase(): string {
    const filename = path.join(tmp, "team-sessions.sqlite");
    openTeamSessionDatabase({ filename }).close();
    return filename;
  }

  it("admits a binary whose schema matches the database", () => {
    const filename = currentDatabase();
    const result = evaluateRollbackGuard({ databaseFilename: filename });
    expect(result.ok).toBe(true);
    expect(result.onDiskVersion).toBe(result.binaryVersion);
  });

  it("refuses an older binary against a newer on-disk schema", () => {
    const filename = currentDatabase();
    const raw = new Database(filename);
    raw.pragma(`user_version = ${999}`);
    raw.close();

    const result = evaluateRollbackGuard({ databaseFilename: filename });
    expect(result.ok).toBe(false);
    expect(result.onDiskVersion).toBe(999);
    expect(result.message).toContain("Refusing to start an older binary");
    expect(result.message).toContain("canary-rollback.md");
  });

  it("does not block a fresh install with no database", () => {
    const result = evaluateRollbackGuard({
      databaseFilename: path.join(tmp, "missing.sqlite"),
    });
    expect(result.ok).toBe(true);
    expect(result.onDiskVersion).toBeNull();
  });

  it("ignores files that are not a TerminalX database", () => {
    const foreign = path.join(tmp, "foreign.sqlite");
    const db = new Database(foreign);
    db.exec("CREATE TABLE t(x)");
    db.close();
    const result = evaluateRollbackGuard({ databaseFilename: foreign });
    expect(result.ok).toBe(true);
    expect(result.onDiskVersion).toBeNull();
  });
});
