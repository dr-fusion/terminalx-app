import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PairingIssuanceLimitError, createMobileAuthAuthority } from "@/lib/mobile-auth/authority";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

const IDENTITY = {
  userId: "user-1",
  username: "alice@example.com",
  displayName: "Alice",
  role: "admin",
  authProvider: "google" as const,
  authSubject: "google-subject-1",
  userGeneration: 4,
  authIdentityGeneration: 2,
};

const SOURCE_AUTHENTICATION = {
  credentialJtiDigest: "a".repeat(64),
  credentialExpiresAtMs: 4_000_000_000_000,
  device: { provenance: "browser" as const },
};

describe("SQLite mobile pairing authority", () => {
  let database: TeamSessionDatabase;
  let now: number;

  beforeEach(() => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    now = 1_700_000_000_000;
    insertUser(database.db, "user-1", "alice@example.com");
    insertUser(database.db, "user-2", "bob@example.com");
  });

  afterEach(() => database.close());

  it("persists only a domain-separated digest and consumes a code once", () => {
    const authority = createMobileAuthAuthority({ db: database.db, clock: () => now });
    const created = authority.createPairingCode({
      ...IDENTITY,
      authTime: Math.floor(now / 1000) - 120,
      sourceAuthentication: SOURCE_AUTHENTICATION,
    });

    const row = database.db
      .prepare("SELECT code_digest, auth_time_seconds FROM mobile_pairing_codes")
      .get() as { code_digest: string; auth_time_seconds: number };
    expect(row.code_digest).toBe(
      crypto
        .createHash("sha256")
        .update("terminalx:mobile-pairing:v1\0")
        .update(created.code)
        .digest("hex")
    );
    expect(JSON.stringify(row)).not.toContain(created.code);
    expect(row.auth_time_seconds).toBe(Math.floor(now / 1000) - 120);

    expect(authority.consumePairingCode(created.code)).toMatchObject({
      ...IDENTITY,
      authTime: Math.floor(now / 1000) - 120,
      sourceAuthentication: SOURCE_AUTHENTICATION,
    });
    expect(authority.consumePairingCode(created.code)).toBeNull();
  });

  it("caps expiry to the source credential and rejects expiry at the exact boundary", () => {
    const authority = createMobileAuthAuthority({ db: database.db, clock: () => now });
    const sourceExpiry = now + 90_000;
    const created = authority.createPairingCode({
      ...IDENTITY,
      sourceAuthentication: { ...SOURCE_AUTHENTICATION, credentialExpiresAtMs: sourceExpiry },
    });
    expect(created.expiresAt).toBe(sourceExpiry);
    now = sourceExpiry;
    expect(authority.consumePairingCode(created.code)).toBeNull();
  });

  it("enforces atomic active and rolling issuance limits with an exact retry", () => {
    const authority = createMobileAuthAuthority({
      db: database.db,
      clock: () => now,
      limits: {
        activePerUser: 10,
        activeGlobal: 20,
        issuedPerUserWindow: 3,
        issuedGlobalWindow: 30,
        windowMs: 60_000,
      },
    });
    const first = authority.createPairingCode({
      ...IDENTITY,
      sourceAuthentication: SOURCE_AUTHENTICATION,
    });
    authority.consumePairingCode(first.code);
    now += 1_000;
    authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION });
    now += 1_000;
    authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION });

    try {
      authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION });
      throw new Error("expected issuance to be limited");
    } catch (error) {
      expect(error).toBeInstanceOf(PairingIssuanceLimitError);
      expect(error).toMatchObject({
        name: "PairingIssuanceLimitError",
        code: "PAIRING_ISSUANCE_LIMIT",
        scope: "user-window",
        retryAfterSeconds: 58,
      });
    }

    now += 58_001;
    expect(() =>
      authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION })
    ).not.toThrow();
  });

  it("enforces the global active ceiling in the same write transaction", () => {
    const authority = createMobileAuthAuthority({
      db: database.db,
      clock: () => now,
      limits: {
        activePerUser: 10,
        activeGlobal: 1,
        issuedPerUserWindow: 10,
        issuedGlobalWindow: 10,
      },
    });
    authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION });

    expect(() =>
      authority.createPairingCode({
        ...IDENTITY,
        userId: "user-2",
        username: "bob@example.com",
        authSubject: "google-subject-2",
        sourceAuthentication: SOURCE_AUTHENTICATION,
      })
    ).toThrow(expect.objectContaining({ scope: "global-active", retryAfterSeconds: 120 }));
    expect(database.db.prepare("SELECT count(*) AS count FROM mobile_pairing_codes").get()).toEqual(
      {
        count: 1,
      }
    );
  });

  it("enforces the per-User active ceiling without blocking a different User", () => {
    const authority = createMobileAuthAuthority({
      db: database.db,
      clock: () => now,
      limits: {
        activePerUser: 1,
        activeGlobal: 10,
        issuedPerUserWindow: 10,
        issuedGlobalWindow: 20,
      },
    });
    authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION });

    expect(() =>
      authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION })
    ).toThrow(expect.objectContaining({ scope: "user-active", retryAfterSeconds: 120 }));
    expect(() =>
      authority.createPairingCode({
        ...IDENTITY,
        userId: "user-2",
        username: "bob@example.com",
        authSubject: "google-subject-2",
        sourceAuthentication: SOURCE_AUTHENTICATION,
      })
    ).not.toThrow();
  });

  it("enforces the global rolling ceiling after consumed rows stop being active", () => {
    const authority = createMobileAuthAuthority({
      db: database.db,
      clock: () => now,
      limits: {
        activePerUser: 10,
        activeGlobal: 10,
        issuedPerUserWindow: 10,
        issuedGlobalWindow: 2,
        windowMs: 60_000,
      },
    });
    const first = authority.createPairingCode({
      ...IDENTITY,
      sourceAuthentication: SOURCE_AUTHENTICATION,
    });
    authority.consumePairingCode(first.code);
    const second = authority.createPairingCode({
      ...IDENTITY,
      userId: "user-2",
      username: "bob@example.com",
      authSubject: "google-subject-2",
      sourceAuthentication: SOURCE_AUTHENTICATION,
    });
    authority.consumePairingCode(second.code);

    expect(() =>
      authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION })
    ).toThrow(expect.objectContaining({ scope: "global-window", retryAfterSeconds: 60 }));
  });

  it("cleans rows outside the rolling window without weakening its exact boundary", () => {
    const authority = createMobileAuthAuthority({
      db: database.db,
      clock: () => now,
      limits: { windowMs: 60_000 },
    });
    const old = authority.createPairingCode({
      ...IDENTITY,
      sourceAuthentication: SOURCE_AUTHENTICATION,
    });
    authority.consumePairingCode(old.code);
    now += 60_000;
    authority.createPairingCode({ ...IDENTITY, sourceAuthentication: SOURCE_AUTHENTICATION });

    expect(database.db.prepare("SELECT count(*) AS count FROM mobile_pairing_codes").get()).toEqual(
      {
        count: 1,
      }
    );
  });

  it("rejects a direct row whose TTL exceeds two minutes", () => {
    expect(() =>
      insertPairingRow(database.db, {
        expiresAt: now + 120_001,
        sourceExpiresAt: now + 120_001,
      })
    ).toThrow("CHECK constraint failed");
  });
});

function insertUser(db: TeamSessionDatabase["db"], id: string, username: string): void {
  db.prepare(
    `INSERT INTO users (
       id, username, display_name, legacy_role, status, generation,
       created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
     ) VALUES (?, ?, ?, 'admin', 'active', 1, 1, 1, NULL, NULL)`
  ).run(id, username, username);
}

function insertPairingRow(
  db: TeamSessionDatabase["db"],
  times: { expiresAt: number; sourceExpiresAt: number }
): void {
  db.prepare(
    `INSERT INTO mobile_pairing_codes (
       code_digest, user_id, username, display_name, legacy_role,
       auth_provider, auth_subject, user_generation, auth_identity_generation,
       auth_time_seconds, source_credential_jti_digest, source_credential_expires_at_ms,
       source_device_provenance, source_device_id, created_at_ms, expires_at_ms, consumed_at_ms
     ) VALUES (?, 'user-1', 'alice@example.com', 'Alice', 'admin', 'google',
       'google-subject-1', 1, 1, NULL, ?, ?, 'browser', NULL, ?, ?, NULL)`
  ).run("b".repeat(64), "c".repeat(64), times.sourceExpiresAt, 1_700_000_000_000, times.expiresAt);
}
