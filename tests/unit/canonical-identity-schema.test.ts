import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

describe("canonical identity schema", () => {
  let database: TeamSessionDatabase | undefined;

  afterEach(() => {
    database?.close();
    database = undefined;
  });

  it("creates the versioned User and authentication identity authority", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });

    expect(database.db.pragma("user_version", { simple: true })).toBe(11);
    expect(
      database.db
        .prepare(
          `SELECT name
           FROM sqlite_schema
           WHERE type = 'table'
             AND name IN (
               'users',
               'auth_identities',
               'local_auth_credentials',
               'identity_migrations'
             )
           ORDER BY name`
        )
        .all()
    ).toEqual([
      { name: "auth_identities" },
      { name: "identity_migrations" },
      { name: "local_auth_credentials" },
      { name: "users" },
    ]);
  });

  it("enforces monotonic and irreversible canonical User revocation", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    database.db
      .prepare(
        `INSERT INTO users (
           id, username, display_name, legacy_role, status, generation,
           created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
         ) VALUES ('user-1', 'alice', 'Alice', 'user', 'active', 1, 100, 100, NULL, NULL)`
      )
      .run();

    expect(() => database!.db.prepare("DELETE FROM users WHERE id = 'user-1'").run()).toThrow(
      "history is immutable"
    );

    expect(() =>
      database!.db
        .prepare(
          `UPDATE users
           SET status = 'revoked', revoked_at_ms = 200, updated_at_ms = 200
           WHERE id = 'user-1'`
        )
        .run()
    ).toThrow("generation");

    database.db
      .prepare(
        `UPDATE users
         SET status = 'revoked', generation = 2, revoked_at_ms = 200, updated_at_ms = 200
         WHERE id = 'user-1'`
      )
      .run();
    expect(() => database!.db.prepare("DELETE FROM users WHERE id = 'user-1'").run()).toThrow(
      "history is immutable"
    );
    expect(() =>
      database!.db
        .prepare(
          `UPDATE users
           SET status = 'active', generation = 3, revoked_at_ms = NULL, updated_at_ms = 300
           WHERE id = 'user-1'`
        )
        .run()
    ).toThrow("revoked");
  });

  it("makes provider subjects immutable and identity revocation generation-fenced", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    expect(database.db.pragma("recursive_triggers", { simple: true })).toBe(1);
    database.db.exec(`
      INSERT INTO users (
        id, username, display_name, legacy_role, status, generation,
        created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
      ) VALUES ('user-1', 'alice', 'Alice', 'user', 'active', 1, 100, 100, NULL, NULL);
      INSERT INTO auth_identities (
        id, user_id, provider, subject, status, generation,
        created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
      ) VALUES (
        'identity-1', 'user-1', 'google', 'subject-1', 'active', 1,
        100, 100, 100, NULL
      );
    `);

    expect(() =>
      database!.db
        .prepare("UPDATE auth_identities SET subject = 'subject-2' WHERE id = 'identity-1'")
        .run()
    ).toThrow("immutable");
    expect(() =>
      database!.db.prepare("DELETE FROM auth_identities WHERE id = 'identity-1'").run()
    ).toThrow("history is immutable");
    database.db
      .prepare(
        `INSERT INTO users (
           id, username, display_name, legacy_role, status, generation,
           created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
         ) VALUES ('user-2', 'mallory', 'Mallory', 'user', 'active', 1, 300, 300, NULL, NULL)`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `INSERT OR REPLACE INTO auth_identities (
             id, user_id, provider, subject, status, generation,
             created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
           ) VALUES (
             'identity-2', 'user-2', 'google', 'subject-1', 'active', 1,
             300, 300, 300, NULL
           )`
        )
        .run()
    ).toThrow("history is immutable");
    expect(
      database.db
        .prepare("SELECT id, user_id, status, generation FROM auth_identities WHERE subject = ?")
        .get("subject-1")
    ).toEqual({ id: "identity-1", user_id: "user-1", status: "active", generation: 1 });
    expect(() =>
      database!.db
        .prepare(
          `UPDATE auth_identities
           SET status = 'revoked', revoked_at_ms = 200, updated_at_ms = 200
           WHERE id = 'identity-1'`
        )
        .run()
    ).toThrow("generation");

    database.db
      .prepare(
        `UPDATE auth_identities
         SET status = 'revoked', generation = 2, revoked_at_ms = 200, updated_at_ms = 200
         WHERE id = 'identity-1'`
      )
      .run();
    expect(() =>
      database!.db.prepare("DELETE FROM auth_identities WHERE id = 'identity-1'").run()
    ).toThrow("history is immutable");
    expect(() =>
      database!.db
        .prepare(
          `INSERT OR REPLACE INTO auth_identities (
             id, user_id, provider, subject, status, generation,
             created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
           ) VALUES (
             'identity-2', 'user-2', 'google', 'subject-1', 'active', 1,
             300, 300, 300, NULL
           )`
        )
        .run()
    ).toThrow("history is immutable");
    expect(
      database.db
        .prepare("SELECT id, user_id, status, generation FROM auth_identities WHERE subject = ?")
        .get("subject-1")
    ).toEqual({ id: "identity-1", user_id: "user-1", status: "revoked", generation: 2 });
    expect(() =>
      database!.db
        .prepare(
          `UPDATE auth_identities
           SET status = 'active', generation = 3, revoked_at_ms = NULL, updated_at_ms = 300
           WHERE id = 'identity-1'`
        )
        .run()
    ).toThrow("revoked");
  });

  it("makes the one-time legacy import marker immutable", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    database.db
      .prepare(
        `INSERT INTO identity_migrations (
           migration_key, source_digest, imported_count, completed_at_ms
         ) VALUES ('legacy-local-users-json-v1', ?, 0, 100)`
      )
      .run("a".repeat(64));

    expect(() =>
      database!.db
        .prepare("UPDATE identity_migrations SET imported_count = 1 WHERE migration_key = ?")
        .run("legacy-local-users-json-v1")
    ).toThrow("history is immutable");
    expect(() =>
      database!.db
        .prepare("DELETE FROM identity_migrations WHERE migration_key = ?")
        .run("legacy-local-users-json-v1")
    ).toThrow("history is immutable");
  });

  it("migrates a committed v10 database without losing existing Team state", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-identity-v10-"));
    const filename = path.join(directory, "team-sessions.sqlite");
    try {
      database = openTeamSessionDatabase({ filename });
      database.db
        .prepare("INSERT INTO teams (id, name, created_at_ms) VALUES ('team-1', 'Team', 100)")
        .run();
      database.db.exec(`
        DROP TABLE local_auth_credentials;
        DROP TABLE auth_identities;
        DROP TABLE users;
        DROP TABLE identity_migrations;
        PRAGMA user_version = 10;
      `);
      database.close();
      database = undefined;

      database = openTeamSessionDatabase({ filename });

      expect(database.db.pragma("user_version", { simple: true })).toBe(11);
      expect(database.db.prepare("SELECT id, name FROM teams").all()).toEqual([
        { id: "team-1", name: "Team" },
      ]);
      expect(database.db.pragma("foreign_key_check")).toEqual([]);
    } finally {
      database?.close();
      database = undefined;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
