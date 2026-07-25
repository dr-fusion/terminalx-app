import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

describe("canonical identity schema", () => {
  let database: TeamSessionDatabase | undefined;

  afterEach(() => {
    database?.close();
    database = undefined;
  });

  it("creates the versioned User and authentication identity authority", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });

    expect(database.db.pragma("user_version", { simple: true })).toBe(12);
    expect(
      database.db
        .prepare(
          `SELECT name
           FROM sqlite_schema
           WHERE type = 'table'
             AND name IN (
               'users',
               'auth_identities',
               'legacy_google_identity_bridges',
               'local_auth_credentials',
               'identity_migrations'
             )
           ORDER BY name`
        )
        .all()
    ).toEqual([
      { name: "auth_identities" },
      { name: "identity_migrations" },
      { name: "legacy_google_identity_bridges" },
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

  it("binds each immutable legacy Google bridge to its exact provider identity", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    database.db.exec(`
      INSERT INTO users (
        id, username, display_name, legacy_role, status, generation,
        created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
      ) VALUES
        ('google-subject-1', 'alice@example.com', 'Alice', 'admin', 'active', 1,
         100, 100, NULL, NULL),
        ('google-subject-2', 'mallory@example.com', 'Mallory', 'admin', 'active', 1,
         100, 100, NULL, NULL);
      INSERT INTO auth_identities (
        id, user_id, provider, subject, status, generation,
        created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
      ) VALUES
        ('identity-1', 'google-subject-1', 'google', 'subject-1', 'active', 1,
         100, 100, 100, NULL),
        ('identity-2', 'google-subject-2', 'google', 'subject-2', 'active', 1,
         100, 100, 100, NULL);
    `);

    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO legacy_google_identity_bridges (
             google_subject, legacy_user_id, auth_identity_id, bridged_at_ms
           ) VALUES ('subject-1', 'google-subject-1', 'identity-2', 100)`
        )
        .run()
    ).toThrow("does not match its authentication identity");

    database.db
      .prepare(
        `INSERT INTO legacy_google_identity_bridges (
           google_subject, legacy_user_id, auth_identity_id, bridged_at_ms
         ) VALUES ('subject-1', 'google-subject-1', 'identity-1', 100)`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE legacy_google_identity_bridges
           SET bridged_at_ms = 200 WHERE google_subject = 'subject-1'`
        )
        .run()
    ).toThrow("history is immutable");
    expect(() =>
      database!.db
        .prepare(
          `INSERT OR REPLACE INTO legacy_google_identity_bridges (
             google_subject, legacy_user_id, auth_identity_id, bridged_at_ms
           ) VALUES ('subject-1', 'google-subject-1', 'identity-1', 200)`
        )
        .run()
    ).toThrow("history is immutable");
    expect(() =>
      database!.db
        .prepare("DELETE FROM legacy_google_identity_bridges WHERE google_subject = 'subject-1'")
        .run()
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
        INSERT INTO projects (id, team_id, name, source_ref, created_at_ms)
        VALUES ('project-1', 'team-1', 'Project', NULL, 100);
        INSERT INTO team_memberships (
          team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
        ) VALUES (
          'team-1', 'google-google-subject-1', 'owner', 'active', 3, 100, NULL
        );
        INSERT INTO project_access (
          project_id, user_id, role, status, version, created_at_ms, revoked_at_ms
        ) VALUES (
          'project-1', 'google-google-subject-1', 'maintainer', 'active', 2, 100, NULL
        );
        DROP TABLE legacy_google_identity_bridges;
        DROP TABLE local_auth_credentials;
        DROP TABLE auth_identities;
        DROP TABLE users;
        DROP TABLE identity_migrations;
        PRAGMA user_version = 10;
      `);
      database.close();
      database = undefined;

      database = openTeamSessionDatabase({ filename });

      expect(database.db.pragma("user_version", { simple: true })).toBe(12);
      expect(database.db.prepare("SELECT id, name FROM teams").all()).toEqual([
        { id: "team-1", name: "Team" },
      ]);
      expect(
        database.db
          .prepare(
            `SELECT team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
             FROM team_memberships`
          )
          .all()
      ).toEqual([
        {
          team_id: "team-1",
          user_id: "google-google-subject-1",
          role: "owner",
          status: "active",
          version: 3,
          created_at_ms: 100,
          revoked_at_ms: null,
        },
      ]);
      expect(
        database.db
          .prepare(
            `SELECT project_id, user_id, role, status, version, created_at_ms, revoked_at_ms
             FROM project_access`
          )
          .all()
      ).toEqual([
        {
          project_id: "project-1",
          user_id: "google-google-subject-1",
          role: "maintainer",
          status: "active",
          version: 2,
          created_at_ms: 100,
          revoked_at_ms: null,
        },
      ]);
      expect(database.db.prepare("SELECT * FROM legacy_google_identity_bridges").all()).toEqual([]);
      expect(database.db.pragma("foreign_key_check")).toEqual([]);
    } finally {
      database?.close();
      database = undefined;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it("migrates a compatible pushed-v11 Google identity into an immutable bridge", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-identity-v11-google-"));
    const filename = path.join(directory, "team-sessions.sqlite");
    try {
      database = openTeamSessionDatabase({ filename });
      database.db.exec(`
        INSERT INTO users (
          id, username, display_name, legacy_role, status, generation,
          created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
        ) VALUES (
          'google-compatible-subject', 'alice@example.com', 'Alice', 'admin',
          'active', 1, 100, 100, NULL, NULL
        );
        INSERT INTO auth_identities (
          id, user_id, provider, subject, status, generation,
          created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
        ) VALUES (
          'google-compatible-identity', 'google-compatible-subject', 'google',
          'compatible-subject', 'active', 1, 100, 100, 100, NULL
        );
        DROP TABLE legacy_google_identity_bridges;
        PRAGMA user_version = 11;
      `);
      database.close();
      database = undefined;

      database = openTeamSessionDatabase({ filename });

      expect(database.db.pragma("user_version", { simple: true })).toBe(12);
      expect(database.db.prepare("SELECT * FROM legacy_google_identity_bridges").all()).toEqual([
        {
          google_subject: "compatible-subject",
          legacy_user_id: "google-compatible-subject",
          auth_identity_id: "google-compatible-identity",
          bridged_at_ms: 100,
        },
      ]);
    } finally {
      database?.close();
      database = undefined;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it("fails v11 migration atomically when an opaque Google id needs operator repair", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-identity-v11-opaque-"));
    const filename = path.join(directory, "team-sessions.sqlite");
    try {
      database = openTeamSessionDatabase({ filename });
      database.db.exec(`
        INSERT INTO users (
          id, username, display_name, legacy_role, status, generation,
          created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
        ) VALUES (
          'opaque-preview-user', 'alice@example.com', 'Alice', 'admin',
          'active', 1, 100, 100, NULL, NULL
        );
        INSERT INTO auth_identities (
          id, user_id, provider, subject, status, generation,
          created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
        ) VALUES (
          'opaque-preview-identity', 'opaque-preview-user', 'google',
          'preview-subject', 'active', 1, 100, 100, 100, NULL
        );
        DROP TABLE legacy_google_identity_bridges;
        PRAGMA user_version = 11;
      `);
      database.close();
      database = undefined;

      expect(() => openTeamSessionDatabase({ filename })).toThrow(
        "requires explicit repair of an incompatible v11 Google identity"
      );

      const unchanged = new Database(filename, { readonly: true, fileMustExist: true });
      try {
        expect(unchanged.pragma("user_version", { simple: true })).toBe(11);
        expect(
          unchanged
            .prepare("SELECT id, user_id, subject FROM auth_identities WHERE provider = 'google'")
            .all()
        ).toEqual([
          {
            id: "opaque-preview-identity",
            user_id: "opaque-preview-user",
            subject: "preview-subject",
          },
        ]);
        expect(
          unchanged
            .prepare(
              `SELECT name FROM sqlite_schema
               WHERE type = 'table' AND name = 'legacy_google_identity_bridges'`
            )
            .get()
        ).toBeUndefined();
      } finally {
        unchanged.close();
      }
    } finally {
      database?.close();
      database = undefined;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
