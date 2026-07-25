import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

const HANDLE_A = `txch_v1_${"a".repeat(64)}`;
const HANDLE_B = `txch_v1_${"b".repeat(64)}`;

describe("connection authority schema", () => {
  let database: TeamSessionDatabase | undefined;

  afterEach(() => {
    database?.close();
    database = undefined;
  });

  it("creates an additive v13 authority without secret-bearing columns", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });

    expect(database.db.pragma("user_version", { simple: true })).toBe(15);
    const tables = [
      "credential_handles",
      "channel_installations",
      "link_challenges",
      "identity_connections",
      "channel_bindings",
      "connection_authority_ledger",
      "provider_webhook_deliveries",
      "installation_webhook_auth_digests",
      "mobile_pairing_codes",
      "paired_devices",
      "mobile_auth_migrations",
    ];
    expect(
      database.db
        .prepare(
          `SELECT name FROM sqlite_schema
           WHERE type = 'table' AND name IN (${tables.map(() => "?").join(", ")})
           ORDER BY name`
        )
        .all(...tables)
    ).toEqual(tables.toSorted().map((name) => ({ name })));

    const forbidden = /(secret|token|ciphertext|private|plaintext|locator|credential_value)/i;
    for (const table of tables) {
      const columns = database.db.pragma(`table_info(${table})`) as Array<{ name: string }>;
      expect(columns.map(({ name }) => name).filter((name) => forbidden.test(name))).toEqual([]);
    }
  });

  it("migrates v12 atomically without inferring legacy provider state", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-connections-v12-"));
    const filename = path.join(directory, "team-sessions.sqlite");
    try {
      database = openTeamSessionDatabase({ filename });
      database.db
        .prepare("INSERT INTO teams (id, name, created_at_ms) VALUES ('team-1', 'Team', 100)")
        .run();
      database.db.exec(`
        DROP TABLE installation_webhook_auth_digests;
        DROP TABLE provider_webhook_deliveries;
        DROP TABLE mobile_auth_migrations;
        DROP TABLE paired_devices;
        DROP TABLE mobile_pairing_codes;
        DROP TABLE connection_authority_ledger;
        DROP TABLE channel_bindings;
        DROP TABLE identity_connections;
        DROP TABLE link_challenges;
        DROP TABLE channel_installations;
        DROP TABLE credential_handles;
        PRAGMA user_version = 12;
      `);
      database.close();
      database = undefined;

      fs.writeFileSync(
        path.join(directory, "telegram-config.json"),
        JSON.stringify({ botToken: "must-not-import", allowedUsers: ["legacy-admin"] })
      );
      database = openTeamSessionDatabase({ filename });

      expect(database.db.pragma("user_version", { simple: true })).toBe(15);
      expect(database.db.prepare("SELECT id, name FROM teams").all()).toEqual([
        { id: "team-1", name: "Team" },
      ]);
      for (const table of [
        "credential_handles",
        "channel_installations",
        "link_challenges",
        "identity_connections",
        "channel_bindings",
        "connection_authority_ledger",
        "provider_webhook_deliveries",
        "installation_webhook_auth_digests",
        "mobile_pairing_codes",
        "paired_devices",
        "mobile_auth_migrations",
      ]) {
        expect(database.db.prepare(`SELECT * FROM ${table}`).all()).toEqual([]);
      }
      expect(database.db.pragma("foreign_key_check")).toEqual([]);
    } finally {
      database?.close();
      database = undefined;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rolls back every v13 DDL statement when a later schema object fails", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-connections-v13-fail-"));
    const filename = path.join(directory, "team-sessions.sqlite");
    try {
      database = openTeamSessionDatabase({ filename });
      database.db.exec(`
        DROP TABLE mobile_auth_migrations;
        DROP TABLE paired_devices;
        DROP TABLE mobile_pairing_codes;
        DROP TABLE connection_authority_ledger;
        DROP TABLE channel_bindings;
        DROP TABLE identity_connections;
        DROP TABLE link_challenges;
        DROP TABLE channel_installations;
        DROP TABLE credential_handles;
        CREATE TABLE link_challenges (injected_failure_marker TEXT) STRICT;
        PRAGMA user_version = 12;
      `);
      database.close();
      database = undefined;

      expect(() => openTeamSessionDatabase({ filename })).toThrow(
        "table link_challenges already exists"
      );

      const verification = new Database(filename, { readonly: true });
      try {
        expect(verification.pragma("user_version", { simple: true })).toBe(12);
        expect(
          verification
            .prepare(
              `SELECT name FROM sqlite_schema
               WHERE type = 'table' AND name IN (
                 'credential_handles', 'channel_installations', 'link_challenges',
                 'identity_connections', 'channel_bindings', 'connection_authority_ledger',
                 'mobile_pairing_codes', 'paired_devices', 'mobile_auth_migrations'
               ) ORDER BY name`
            )
            .all()
        ).toEqual([{ name: "link_challenges" }]);
        expect(verification.pragma("table_info(link_challenges)")).toEqual([
          expect.objectContaining({ name: "injected_failure_marker" }),
        ]);
      } finally {
        verification.close();
      }
    } finally {
      database?.close();
      database = undefined;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it("generation-fences opaque Credential Handle revocation and replacement", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seedCanonicalOwner(database.db);

    expect(() => insertHandle(database!.db, "not-a-handle")).toThrow("CHECK constraint failed");
    insertHandle(database.db, HANDLE_A);
    expect(() =>
      database!.db.prepare("DELETE FROM credential_handles WHERE id = ?").run(HANDLE_A)
    ).toThrow("history is immutable");
    expect(() =>
      database!.db
        .prepare(
          `UPDATE credential_handles
           SET status = 'revoked', revoked_at_ms = 200, updated_at_ms = 200
           WHERE id = ?`
        )
        .run(HANDLE_A)
    ).toThrow("transition is invalid");

    database.db
      .prepare(
        `UPDATE credential_handles
         SET status = 'revoked', generation = 2, revoked_at_ms = 200, updated_at_ms = 200
         WHERE id = ?`
      )
      .run(HANDLE_A);
    expect(() =>
      insertHandle(database!.db, HANDLE_B, {
        replacesHandleId: HANDLE_A,
        replacesGeneration: 2,
        createdAtMs: 199,
        updatedAtMs: 199,
      })
    ).toThrow("replacement lineage is invalid");
    insertHandle(database.db, HANDLE_B, {
      replacesHandleId: HANDLE_A,
      replacesGeneration: 2,
      createdAtMs: 200,
      updatedAtMs: 200,
    });
    expect(() =>
      database!.db
        .prepare(
          `UPDATE credential_handles
           SET status = 'active', generation = 3, revoked_at_ms = NULL, updated_at_ms = 300
           WHERE id = ?`
        )
        .run(HANDLE_A)
    ).toThrow("transition is invalid");
    expect(
      database.db
        .prepare(
          `SELECT event_type, resource_id, resource_version
           FROM connection_authority_ledger
           WHERE event_type = 'credential-handle.mutation-recorded'
           ORDER BY sequence`
        )
        .all()
    ).toEqual([
      {
        event_type: "credential-handle.mutation-recorded",
        resource_id: HANDLE_A,
        resource_version: 1,
      },
      {
        event_type: "credential-handle.mutation-recorded",
        resource_id: HANDLE_A,
        resource_version: 2,
      },
      {
        event_type: "credential-handle.mutation-recorded",
        resource_id: HANDLE_B,
        resource_version: 1,
      },
    ]);
  });

  it("rejects non-canonical Credential Handle and Channel Installation insert states", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seedCanonicalOwner(database.db);

    expect(() =>
      insertHandle(database!.db, HANDLE_A, { status: "revoked", revokedAtMs: 100 })
    ).toThrow("initial authority snapshot is invalid");
    expect(() => insertHandle(database!.db, HANDLE_A, { generation: 2 })).toThrow(
      "initial authority snapshot is invalid"
    );
    expect(() => insertHandle(database!.db, HANDLE_A, { updatedAtMs: 101 })).toThrow(
      "initial authority snapshot is invalid"
    );
    expect(() => insertHandle(database!.db, HANDLE_A, { replacesGeneration: 1 })).toThrow(
      "CHECK constraint failed"
    );

    insertHandle(database.db, HANDLE_A);
    expect(() => insertInstallation(database!.db, { status: "revoked", revokedAtMs: 100 })).toThrow(
      "authority snapshot is invalid"
    );
    expect(() => insertInstallation(database!.db, { revision: 2 })).toThrow(
      "authority snapshot is invalid"
    );
    expect(() => insertInstallation(database!.db, { updatedAtMs: 101 })).toThrow(
      "authority snapshot is invalid"
    );

    insertInstallation(database.db);
    expect(
      database.db
        .prepare(
          `SELECT status, revision, created_at_ms, updated_at_ms, revoked_at_ms
           FROM channel_installations WHERE id = 'installation-1'`
        )
        .get()
    ).toEqual({
      status: "active",
      revision: 1,
      created_at_ms: 100,
      updated_at_ms: 100,
      revoked_at_ms: null,
    });
  });

  it("binds installations and challenges to exact reviewed authority snapshots", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seedCanonicalOwner(database.db);
    insertHandle(database.db, HANDLE_A);
    insertInstallation(database.db);

    expect(() =>
      insertChallenge(database!.db, {
        id: "challenge-too-long",
        tokenDigest: "c".repeat(64),
        requestedScopes: '["chat:write"]',
        expiresAtMs: 600_201,
      })
    ).toThrow("CHECK constraint failed");
    expect(() =>
      insertChallenge(database!.db, {
        id: "challenge-over-scoped",
        tokenDigest: "d".repeat(64),
        requestedScopes: '["admin:write"]',
        expiresAtMs: 600_200,
      })
    ).toThrow("authority snapshot is invalid");
    expect(() =>
      insertChallenge(database!.db, {
        id: "challenge-outlives-source",
        tokenDigest: "b".repeat(64),
        requestedScopes: '["chat:write"]',
        expiresAtMs: 600_200,
        authSessionExpiresAtMs: 600_199,
      })
    ).toThrow("CHECK constraint failed");

    insertChallenge(database.db, {
      id: "challenge-1",
      tokenDigest: "e".repeat(64),
      requestedScopes: '["chat:write"]',
      expiresAtMs: 600_200,
    });
    expect(() =>
      database!.db
        .prepare(
          `UPDATE link_challenges
           SET status = 'consumed', version = 2, resolved_at_ms = 300,
               provider_proof_replay_digest = ?, auth_session_expires_at_ms = 86400001
           WHERE id = 'challenge-1'`
        )
        .run("8".repeat(64))
    ).toThrow("transition is invalid");
    database.db
      .prepare(
        `UPDATE link_challenges
         SET status = 'consumed', version = 2, resolved_at_ms = 300,
             provider_proof_replay_digest = ?
         WHERE id = 'challenge-1'`
      )
      .run("9".repeat(64));
    expect(() =>
      database!.db
        .prepare(
          `UPDATE link_challenges
           SET status = 'revoked', version = 3, resolved_at_ms = 400
           WHERE id = 'challenge-1'`
        )
        .run()
    ).toThrow("transition is invalid");
    expect(() =>
      database!.db.prepare("DELETE FROM link_challenges WHERE id = 'challenge-1'").run()
    ).toThrow("history is immutable");
  });

  it("enforces Link Challenge minimum lifetime and issuance rate in SQLite", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seedCanonicalOwner(database.db);
    insertHandle(database.db, HANDLE_A);
    insertInstallation(database.db);

    expect(() =>
      insertChallenge(database!.db, {
        id: "challenge-too-short",
        tokenDigest: "a".repeat(64),
        requestedScopes: '["chat:write"]',
        issuedAtMs: 200,
        authenticatedAtMs: 100,
        authSessionIssuedAtMs: 150,
        expiresAtMs: 60_199,
      })
    ).toThrow("CHECK constraint failed");

    for (let index = 0; index < 12; index += 1) {
      const issuedAtMs = 200 + index * 60_001;
      insertChallenge(database.db, {
        id: `rate-challenge-${index}`,
        tokenDigest: index.toString(16).padStart(64, "0"),
        requestedScopes: '["chat:write"]',
        authenticatedAtMs: issuedAtMs - 100,
        authSessionIssuedAtMs: issuedAtMs - 50,
        issuedAtMs,
        expiresAtMs: issuedAtMs + 60_000,
      });
    }
    const thirteenthIssuedAtMs = 200 + 12 * 60_001;
    expect(() =>
      insertChallenge(database!.db, {
        id: "rate-challenge-12",
        tokenDigest: "f".repeat(64),
        requestedScopes: '["chat:write"]',
        authenticatedAtMs: thirteenthIssuedAtMs - 100,
        authSessionIssuedAtMs: thirteenthIssuedAtMs - 50,
        issuedAtMs: thirteenthIssuedAtMs,
        expiresAtMs: thirteenthIssuedAtMs + 60_000,
      })
    ).toThrow("authority snapshot is invalid");
    expect(database.db.prepare("SELECT COUNT(*) AS count FROM link_challenges").get()).toEqual({
      count: 12,
    });

    const userPlan = database.db
      .prepare(
        `EXPLAIN QUERY PLAN
         SELECT COUNT(*) FROM link_challenges
         WHERE user_id = ? AND installation_id = ? AND issued_at_ms >= ?`
      )
      .all("user-1", "installation-1", 0) as Array<{ detail: string }>;
    expect(userPlan.map(({ detail }) => detail).join("\n")).toContain(
      "USING COVERING INDEX link_challenges_by_user_installation_issuance"
    );

    const installationPlan = database.db
      .prepare(
        `EXPLAIN QUERY PLAN
         SELECT COUNT(*) FROM link_challenges
         WHERE installation_id = ? AND issued_at_ms >= ?`
      )
      .all("installation-1", 0) as Array<{ detail: string }>;
    expect(installationPlan.map(({ detail }) => detail).join("\n")).toContain(
      "USING COVERING INDEX link_challenges_by_installation_issuance"
    );

    const historyPlan = database.db
      .prepare(
        `EXPLAIN QUERY PLAN
         SELECT id, user_id, status
         FROM identity_connections historical
         WHERE installation_id = ? AND provider = ?
           AND external_tenant_id = ? AND external_subject = ?
           AND NOT EXISTS (
             SELECT 1 FROM identity_connections successor
             WHERE successor.replaces_connection_id = historical.id
           )
         ORDER BY historical.created_at_ms DESC, historical.id DESC
         LIMIT 1`
      )
      .all("installation-1", "slack", "tenant-1", "external-user-1") as Array<{
      detail: string;
    }>;
    const historyPlanDetails = historyPlan.map(({ detail }) => detail).join("\n");
    expect(historyPlanDetails).toContain(
      "USING COVERING INDEX identity_connections_by_installation_external_identity_history"
    );
    expect(historyPlanDetails).not.toContain("USE TEMP B-TREE");

    const ownerPlan = database.db
      .prepare(
        `EXPLAIN QUERY PLAN
         SELECT user_id FROM identity_connections
         WHERE provider = ? AND external_tenant_id = ? AND external_subject = ?
           AND user_id <> ?
         LIMIT 1`
      )
      .all("slack", "tenant-1", "external-user-1", "user-1") as Array<{
      detail: string;
    }>;
    expect(ownerPlan.map(({ detail }) => detail).join("\n")).toContain(
      "USING COVERING INDEX identity_connections_by_external_identity_owner"
    );
  });

  it("keeps the redacted authority ledger append-only", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seedCanonicalOwner(database.db);
    database.db
      .prepare(
        `INSERT INTO connection_authority_ledger (
           event_id, event_type, actor_kind, actor_user_id, actor_user_generation,
           actor_auth_identity_id, actor_auth_identity_generation,
           resource_kind, resource_id, resource_version,
           team_id, session_id, subject_user_id, provider, detail_digest, occurred_at_ms
         ) VALUES (
           'event-1', 'credential-handle.registered', 'human', 'user-1', 1,
           'identity-1', 1, 'credential-handle', ?, 1,
           'team-1', NULL, 'user-1', 'slack', ?, 100
         )`
      )
      .run(HANDLE_A, "f".repeat(64));

    expect(() =>
      database!.db
        .prepare(
          "UPDATE connection_authority_ledger SET occurred_at_ms = 200 WHERE event_id = 'event-1'"
        )
        .run()
    ).toThrow("ledger is immutable");
    expect(() =>
      database!.db
        .prepare("DELETE FROM connection_authority_ledger WHERE event_id = 'event-1'")
        .run()
    ).toThrow("ledger is immutable");
  });
});

function seedCanonicalOwner(db: Database.Database): void {
  db.exec(`
    INSERT INTO users (
      id, username, display_name, legacy_role, status, generation,
      created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
    ) VALUES ('user-1', 'alice', 'Alice', 'admin', 'active', 1, 100, 100, 100, NULL);
    INSERT INTO auth_identities (
      id, user_id, provider, subject, status, generation,
      created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
    ) VALUES ('identity-1', 'user-1', 'local', 'alice', 'active', 1, 100, 100, 100, NULL);
    INSERT INTO teams (id, name, created_at_ms) VALUES ('team-1', 'Team', 100);
    INSERT INTO team_memberships (
      team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
    ) VALUES ('team-1', 'user-1', 'owner', 'active', 1, 100, NULL);
  `);
}

function insertHandle(
  db: Database.Database,
  id: string,
  options: {
    replacesHandleId?: string;
    replacesGeneration?: number;
    status?: "active" | "revoked";
    generation?: number;
    createdAtMs?: number;
    updatedAtMs?: number;
    revokedAtMs?: number | null;
  } = {}
): void {
  db.prepare(
    `INSERT INTO credential_handles (
       id, provider, broker_kind, usage, broker_receipt_digest, authority_binding_digest,
       team_id, user_id, external_tenant_id, external_app_id,
       identity_installation_id, identity_installation_revision,
       external_subject, provider_proof_replay_digest, status, generation,
       replaces_handle_id, replaces_generation,
       created_by_user_id, created_by_user_generation,
       created_by_auth_identity_id, created_by_auth_identity_generation,
       updated_by_user_id, updated_by_user_generation,
       updated_by_auth_identity_id, updated_by_auth_identity_generation,
       created_at_ms, updated_at_ms, revoked_at_ms
     ) VALUES (
       ?, 'slack', 'oauth-envelope', 'installation', ?, ?,
       'team-1', NULL, 'tenant-1', 'app-1', NULL, NULL, NULL, NULL, ?, ?,
       ?, ?, 'user-1', 1, 'identity-1', 1, 'user-1', 1, 'identity-1', 1,
       ?, ?, ?
     )`
  ).run(
    id,
    id.slice(-1).repeat(64),
    "7".repeat(64),
    options.status ?? "active",
    options.generation ?? 1,
    options.replacesHandleId ?? null,
    options.replacesGeneration ?? null,
    options.createdAtMs ?? 100,
    options.updatedAtMs ?? 100,
    options.revokedAtMs ?? null
  );
}

function insertInstallation(
  db: Database.Database,
  options: {
    status?: "active" | "revoked";
    revision?: number;
    createdAtMs?: number;
    updatedAtMs?: number;
    revokedAtMs?: number | null;
  } = {}
): void {
  db.prepare(
    `INSERT INTO channel_installations (
       id, team_id, provider, external_tenant_id, external_app_id,
       credential_handle_id, credential_handle_generation,
       reviewed_scopes_schema, reviewed_scopes_json, reviewed_scopes_digest,
       capabilities_schema, capabilities_json, capabilities_digest, status, revision,
       created_by_user_id, created_under_membership_version,
       created_by_user_generation, created_by_auth_identity_id,
       created_by_auth_identity_generation, updated_by_user_id,
       updated_under_membership_version, updated_by_user_generation,
       updated_by_auth_identity_id, updated_by_auth_identity_generation,
       created_at_ms, updated_at_ms, revoked_at_ms
     ) VALUES (
       'installation-1', 'team-1', 'slack', 'tenant-1', 'app-1', ?, 1,
       1, '["chat:write","users:read"]', ?, 1, '["messages:write"]', ?, ?, ?,
       'user-1', 1, 1, 'identity-1', 1, 'user-1', 1, 1, 'identity-1', 1,
       ?, ?, ?
     )`
  ).run(
    HANDLE_A,
    "1".repeat(64),
    "2".repeat(64),
    options.status ?? "active",
    options.revision ?? 1,
    options.createdAtMs ?? 100,
    options.updatedAtMs ?? 100,
    options.revokedAtMs ?? null
  );
}

function insertChallenge(
  db: Database.Database,
  input: {
    id: string;
    tokenDigest: string;
    requestedScopes: string;
    expiresAtMs: number;
    authenticatedAtMs?: number;
    authSessionIssuedAtMs?: number;
    authSessionExpiresAtMs?: number;
    issuedAtMs?: number;
  }
): void {
  db.prepare(
    `INSERT INTO link_challenges (
       id, challenge_digest, user_id, user_generation,
       auth_identity_id, auth_identity_generation, auth_session_jti_digest,
       auth_session_issued_at_ms, auth_session_expires_at_ms,
       auth_session_provenance, auth_session_device_id,
       team_id, team_membership_version, installation_id, installation_revision,
       requested_scopes_schema, requested_scopes_json, requested_scopes_digest, authenticated_at_ms,
       status, version, issued_at_ms, expires_at_ms, resolved_at_ms,
       provider_proof_replay_digest
     ) VALUES (
       ?, ?, 'user-1', 1, 'identity-1', 1, ?, ?, ?, 'browser', NULL, 'team-1', 1,
       'installation-1', 1, 1, ?, ?, ?, 'active', 1, ?, ?, NULL, NULL
     )`
  ).run(
    input.id,
    input.tokenDigest,
    "3".repeat(64),
    input.authSessionIssuedAtMs ?? 150,
    input.authSessionExpiresAtMs ?? 86_400_000,
    input.requestedScopes,
    "4".repeat(64),
    input.authenticatedAtMs ?? 100,
    input.issuedAtMs ?? 200,
    input.expiresAtMs
  );
}
