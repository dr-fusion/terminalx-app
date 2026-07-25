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
    const ids = ["user-google-1", "identity-google-1", "user-google-2", "identity-google-2"];
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
    expect(repeated.identity.id).toBe(first.identity.id);
    expect(repeated.identity.subject).toBe("google-subject-1");
    expect(repeated.user).toMatchObject({
      username: "renamed@example.com",
      displayName: "Renamed Profile",
      generation: 2,
      status: "active",
    });
    expect(sameProfileDifferentSubject.user.id).not.toBe(first.user.id);
    expect(sameProfileDifferentSubject.identity.subject).toBe("google-subject-2");
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
