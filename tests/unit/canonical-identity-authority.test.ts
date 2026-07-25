import { afterEach, describe, expect, it } from "vitest";
import {
  createCanonicalIdentityAuthority,
  type CanonicalIdentityAuthority,
} from "@/lib/identity-authority";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

describe("canonical identity authority", () => {
  let database: TeamSessionDatabase | undefined;
  let authority: CanonicalIdentityAuthority | undefined;

  afterEach(() => {
    authority = undefined;
    database?.close();
    database = undefined;
  });

  it("provisions Google Users by provider subject and never by email or display name", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    const ids = ["identity-google-1", "identity-google-2"];
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => 1_700_000_000_000,
      idGenerator: () => ids.shift()!,
    });

    const first = authority.provisionGoogleIdentity({
      subject: "google-subject-1",
      email: "shared@example.com",
      displayName: "Shared Name",
      legacyRole: "admin",
    });
    const repeated = authority.provisionGoogleIdentity({
      subject: "google-subject-1",
      email: "renamed@example.com",
      displayName: "Renamed Profile",
      legacyRole: "admin",
    });
    const sameProfileDifferentSubject = authority.provisionGoogleIdentity({
      subject: "google-subject-2",
      email: "renamed@example.com",
      displayName: "Renamed Profile",
      legacyRole: "admin",
    });

    expect(repeated.user.id).toBe(first.user.id);
    expect(first.user.id).toBe("google-google-subject-1");
    expect(repeated.identity.id).toBe(first.identity.id);
    expect(repeated.identity.subject).toBe("google-subject-1");
    expect(repeated.user).toMatchObject({
      username: "renamed@example.com",
      displayName: "Renamed Profile",
      generation: 2,
      status: "active",
    });
    expect(sameProfileDifferentSubject.user.id).not.toBe(first.user.id);
    expect(sameProfileDifferentSubject.user.id).toBe("google-google-subject-2");
    expect(sameProfileDifferentSubject.identity.subject).toBe("google-subject-2");
  });

  it("transactionally preserves a pre-v11 Google User id without rewriting access", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    const legacyUserId = "google-google-subject-legacy";
    database.db.exec(`
      INSERT INTO teams (id, name, created_at_ms) VALUES ('team-legacy', 'Legacy Team', 100);
      INSERT INTO projects (id, team_id, name, source_ref, created_at_ms)
      VALUES ('project-legacy', 'team-legacy', 'Legacy Project', NULL, 100);
      INSERT INTO team_memberships (
        team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
      ) VALUES (
        'team-legacy', '${legacyUserId}', 'owner', 'active', 4, 100, NULL
      );
      INSERT INTO project_access (
        project_id, user_id, role, status, version, created_at_ms, revoked_at_ms
      ) VALUES (
        'project-legacy', '${legacyUserId}', 'maintainer', 'active', 3, 100, NULL
      );
    `);
    const accessBefore = database.db
      .prepare(
        `SELECT 'membership' AS kind, team_id AS scope_id, user_id, role, status,
                version, created_at_ms, revoked_at_ms
         FROM team_memberships
         UNION ALL
         SELECT 'project', project_id, user_id, role, status,
                version, created_at_ms, revoked_at_ms
         FROM project_access
         ORDER BY kind`
      )
      .all();
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => 1_700_000_000_000,
      idGenerator: () => "identity-google-legacy",
    });

    const provisioned = authority.provisionGoogleIdentity({
      subject: "google-subject-legacy",
      email: "alice@example.com",
      displayName: "Alice",
      legacyRole: "admin",
    });

    expect(provisioned.user.id).toBe(legacyUserId);
    expect(provisioned.identity).toMatchObject({
      id: "identity-google-legacy",
      userId: legacyUserId,
      provider: "google",
      subject: "google-subject-legacy",
    });
    expect(database.db.prepare("SELECT * FROM legacy_google_identity_bridges").all()).toEqual([
      {
        google_subject: "google-subject-legacy",
        legacy_user_id: legacyUserId,
        auth_identity_id: "identity-google-legacy",
        bridged_at_ms: 1_700_000_000_000,
      },
    ]);
    expect(
      database.db
        .prepare(
          `SELECT 'membership' AS kind, team_id AS scope_id, user_id, role, status,
                  version, created_at_ms, revoked_at_ms
           FROM team_memberships
           UNION ALL
           SELECT 'project', project_id, user_id, role, status,
                  version, created_at_ms, revoked_at_ms
           FROM project_access
           ORDER BY kind`
        )
        .all()
    ).toEqual(accessBefore);
  });

  it("rejects a legacy Google bridge when its derived User id belongs to another identity", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    const legacyUserId = "google-google-subject-collision";
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => 1_700_000_000_000,
      idGenerator: (() => {
        const ids = ["local-identity-collision", "must-not-be-used"];
        return () => ids.shift()!;
      })(),
    });
    authority.importLegacyLocalUsers({
      sourceDigest: "c".repeat(64),
      users: [
        {
          id: legacyUserId,
          username: "local-owner",
          role: "user",
          passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
          createdAt: "2023-11-14T22:13:20.000Z",
          lastLogin: null,
        },
      ],
    });
    database.db.exec(`
      INSERT INTO teams (id, name, created_at_ms) VALUES ('team-collision', 'Team', 100);
      INSERT INTO team_memberships (
        team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
      ) VALUES (
        'team-collision', '${legacyUserId}', 'owner', 'active', 1, 100, NULL
      );
    `);

    expect(() =>
      authority!.provisionGoogleIdentity({
        subject: "google-subject-collision",
        email: "mallory@example.com",
        displayName: "Mallory",
        legacyRole: "admin",
      })
    ).toThrow("collides with an existing canonical User");
    expect(
      database.db
        .prepare("SELECT provider, subject, user_id FROM auth_identities ORDER BY id")
        .all()
    ).toEqual([{ provider: "local", subject: "local-owner", user_id: legacyUserId }]);
    expect(database.db.prepare("SELECT * FROM legacy_google_identity_bridges").all()).toEqual([]);
  });

  it("fails closed if a previously provisioned Google identity would orphan legacy authority", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    let now = 1_700_000_000_000;
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => now,
      idGenerator: () => "must-not-be-used",
    });
    database.db.exec(`
      INSERT INTO users (
        id, username, display_name, legacy_role, status, generation,
        created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
      ) VALUES (
        'opaque-google-user', 'alice@example.com', 'Alice', 'admin', 'active', 1,
        ${now}, ${now}, NULL, NULL
      );
      INSERT INTO auth_identities (
        id, user_id, provider, subject, status, generation,
        created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
      ) VALUES (
        'opaque-google-identity', 'opaque-google-user', 'google',
        'google-subject-orphaned', 'active', 1, ${now}, ${now}, ${now}, NULL
      );
      INSERT INTO teams (id, name, created_at_ms) VALUES ('team-orphaned', 'Team', 100);
      INSERT INTO team_memberships (
        team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
      ) VALUES (
        'team-orphaned', 'google-google-subject-orphaned', 'owner', 'active', 1, 100, NULL
      );
    `);
    now += 1_000;

    expect(() =>
      authority!.provisionGoogleIdentity({
        subject: "google-subject-orphaned",
        email: "changed@example.com",
        displayName: "Changed",
        legacyRole: "admin",
      })
    ).toThrow("conflicts with legacy User continuity");
    expect(
      database.db
        .prepare(
          `SELECT username, display_name, generation FROM users WHERE id = 'opaque-google-user'`
        )
        .get()
    ).toEqual({ username: "alice@example.com", display_name: "Alice", generation: 1 });
    expect(
      database.db
        .prepare(
          `SELECT last_authenticated_at_ms FROM auth_identities
           WHERE id = 'opaque-google-identity'`
        )
        .get()
    ).toEqual({ last_authenticated_at_ms: 1_700_000_000_000 });
  });

  it("rejects normalized or unrepresentable substitutes for an exact Google subject", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => 1_700_000_000_000,
      idGenerator: () => "identity-must-not-be-created",
    });

    expect(() =>
      authority!.provisionGoogleIdentity({
        subject: " google-subject-new",
        email: "alice@example.com",
        displayName: "Alice",
        legacyRole: "admin",
      })
    ).toThrow("Google subject is invalid");
    expect(() =>
      authority!.provisionGoogleIdentity({
        subject: "s".repeat(294),
        email: "alice@example.com",
        displayName: "Alice",
        legacyRole: "admin",
      })
    ).toThrow("cannot be represented canonically");
    expect(database.db.prepare("SELECT * FROM users").all()).toEqual([]);
  });

  it("generation-fences authentication identity revocation", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => 1_700_000_000_000,
      idGenerator: (() => {
        const ids = ["user-google-1", "identity-google-1"];
        return () => ids.shift()!;
      })(),
    });
    const provisioned = authority.provisionGoogleIdentity({
      subject: "google-subject-1",
      email: "alice@example.com",
      displayName: "Alice",
      legacyRole: "admin",
    });

    expect(
      authority.resolveAuthenticationIdentity({
        userId: provisioned.user.id,
        userGeneration: 1,
        provider: "google",
        subject: provisioned.identity.subject,
        identityGeneration: 1,
      })
    ).toEqual(provisioned);

    const revoked = authority.revokeAuthenticationIdentity({
      provider: "google",
      subject: provisioned.identity.subject,
      expectedGeneration: 1,
    });

    expect(revoked).toMatchObject({ status: "revoked", generation: 2 });
    expect(
      authority.resolveAuthenticationIdentity({
        userId: provisioned.user.id,
        userGeneration: 1,
        provider: "google",
        subject: provisioned.identity.subject,
        identityGeneration: 1,
      })
    ).toBeNull();
    expect(() =>
      authority!.provisionGoogleIdentity({
        subject: "google-subject-1",
        email: "alice@example.com",
        displayName: "Alice",
        legacyRole: "admin",
      })
    ).toThrow("revoked");
  });

  it("imports legacy local Users exactly once without changing their canonical IDs", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    const generatedIds = ["local-identity-1", "local-identity-ignored"];
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => 1_700_000_000_000,
      idGenerator: () => generatedIds.shift()!,
    });
    const legacyUser = {
      id: "stable-local-user-id",
      username: "alice",
      role: "user" as const,
      passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
      createdAt: "2023-11-14T22:13:20.000Z",
      lastLogin: "2023-11-15T22:13:20.000Z",
    };

    const first = authority.importLegacyLocalUsers({
      sourceDigest: "a".repeat(64),
      users: [legacyUser],
    });
    const replay = authority.importLegacyLocalUsers({
      sourceDigest: "b".repeat(64),
      users: [{ ...legacyUser, id: "must-not-be-imported", username: "mallory" }],
    });

    expect(first).toEqual({
      status: "imported",
      sourceDigest: "a".repeat(64),
      importedCount: 1,
    });
    expect(replay).toEqual({
      status: "already-imported",
      sourceDigest: "a".repeat(64),
      importedCount: 1,
    });
    expect(authority.getLocalUserByUsername("alice")).toEqual(legacyUser);
    expect(authority.getLocalUserByUsername("mallory")).toBeNull();
    expect(
      database.db.prepare("SELECT updated_at_ms FROM users WHERE id = ?").get(legacyUser.id)
    ).toEqual({ updated_at_ms: Date.parse(legacyUser.lastLogin) });
  });

  it("does not reuse a revoked local authentication subject", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    const ids = ["local-user-1", "local-identity-1", "local-user-2", "local-identity-2"];
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => 1_700_000_000_000,
      idGenerator: () => ids.shift()!,
    });
    const created = authority.createLocalUser({
      username: "alice",
      passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
      legacyRole: "user",
    });

    authority.revokeUser(created.id);

    expect(() =>
      authority!.createLocalUser({
        username: "alice",
        passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
        legacyRole: "user",
      })
    ).toThrow("Username already exists");
  });

  it("revokes a User after its last authentication identity was revoked first", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    authority = createCanonicalIdentityAuthority({
      db: database.db,
      clock: () => 1_700_000_000_000,
      idGenerator: (() => {
        const ids = ["google-user-1", "google-identity-1"];
        return () => ids.shift()!;
      })(),
    });
    const provisioned = authority.provisionGoogleIdentity({
      subject: "google-subject-identity-first",
      email: "alice@example.com",
      displayName: "Alice",
      legacyRole: "admin",
    });

    authority.revokeAuthenticationIdentity({
      provider: "google",
      subject: provisioned.identity.subject,
      expectedGeneration: 1,
    });
    expect(() => authority!.revokeUser(provisioned.user.id)).not.toThrow();

    expect(
      database.db
        .prepare("SELECT status, generation FROM users WHERE id = ?")
        .get(provisioned.user.id)
    ).toEqual({ status: "revoked", generation: 2 });
    expect(
      database.db
        .prepare("SELECT status, generation FROM auth_identities WHERE id = ?")
        .get(provisioned.identity.id)
    ).toEqual({ status: "revoked", generation: 2 });
  });
});
