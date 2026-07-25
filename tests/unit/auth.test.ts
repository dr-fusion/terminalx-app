import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// Set up temp data dir before importing auth module
const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-auth-test-"));
process.env.TERMINALX_JWT_SECRET = "test-secret-that-is-at-least-32-chars-long-for-hmac";
process.env.TERMINALX_TEAM_SESSION_DB_PATH = path.join(TEST_DATA_DIR, "team-sessions.sqlite");
process.env.TERMINALX_LEGACY_USERS_FILE = path.join(TEST_DATA_DIR, "users.json");

// Dynamically import after env is set
let signJwt: typeof import("@/lib/auth").signJwt;
let verifyJwt: typeof import("@/lib/auth").verifyJwt;
let hashPassword: typeof import("@/lib/auth").hashPassword;
let comparePassword: typeof import("@/lib/auth").comparePassword;
let parseCookies: typeof import("@/lib/auth").parseCookies;
let revokeToken: typeof import("@/lib/auth").revokeToken;
let canonicalLocalPayload: import("@/lib/auth").JwtPayload;

beforeAll(async () => {
  const auth = await import("@/lib/auth");
  signJwt = auth.signJwt;
  verifyJwt = auth.verifyJwt;
  hashPassword = auth.hashPassword;
  comparePassword = auth.comparePassword;
  parseCookies = auth.parseCookies;
  revokeToken = auth.revokeToken;
  const { openTeamSessionDatabase } = await import("@/lib/team-sessions/sqlite");
  const { createCanonicalIdentityAuthority } = await import("@/lib/identity-authority");
  const database = openTeamSessionDatabase({
    filename: process.env.TERMINALX_TEAM_SESSION_DB_PATH!,
  });
  try {
    const authority = createCanonicalIdentityAuthority({
      db: database.db,
      idGenerator: () => "auth-test-local-identity",
    });
    authority.importLegacyLocalUsers({
      sourceDigest: "a".repeat(64),
      users: [
        {
          id: "auth-test-local-user",
          username: "alice",
          role: "user",
          passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
          createdAt: "2023-11-14T22:13:20.000Z",
          lastLogin: null,
        },
      ],
    });
    const provisioned = authority.getLocalAuthenticationIdentity("auth-test-local-user")!;
    canonicalLocalPayload = {
      userId: provisioned.user.id,
      username: provisioned.user.username,
      displayName: provisioned.user.displayName,
      role: provisioned.user.legacyRole,
      authProvider: provisioned.identity.provider,
      authSubject: provisioned.identity.subject,
      userGeneration: provisioned.user.generation,
      authIdentityGeneration: provisioned.identity.generation,
    };
  } finally {
    database.close();
  }
});

afterAll(() => {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  delete process.env.TERMINALX_JWT_SECRET;
  delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
  delete process.env.TERMINALX_LEGACY_USERS_FILE;
});

afterEach(() => {
  delete process.env.TERMINALX_AUTH_MODE;
  delete process.env.TERMINALX_ALLOWED_EMAILS;
});

describe("JWT sign and verify", () => {
  it("signs and verifies a valid token", async () => {
    const token = await signJwt(canonicalLocalPayload);

    expect(token).toBeTruthy();
    expect(typeof token).toBe("string");
    expect(token.split(".")).toHaveLength(3);

    const verified = await verifyJwt(token);
    expect(verified).not.toBeNull();
    expect(verified!.userId).toBe("auth-test-local-user");
    expect(verified!.username).toBe("alice");
    expect(verified!.role).toBe("user");
  });

  it("returns null for tampered token", async () => {
    const token = await signJwt({ userId: "single-user", username: "user", role: "user" });
    const tampered = token.slice(0, -5) + "XXXXX";
    const result = await verifyJwt(tampered);
    expect(result).toBeNull();
  });

  it("returns null for empty string", async () => {
    const result = await verifyJwt("");
    expect(result).toBeNull();
  });

  it("returns null for garbage input", async () => {
    const result = await verifyJwt("not.a.jwt");
    expect(result).toBeNull();
  });

  it("returns null for non-existent user", async () => {
    const token = await signJwt({ userId: "deleted-user-id", username: "ghost", role: "user" });
    const result = await verifyJwt(token);
    expect(result).toBeNull();
  });

  it("fails closed when any canonical identity snapshot claim is malformed", async () => {
    const malformed = await signJwt({
      userId: "single-user",
      username: "admin",
      role: "admin",
      authProvider: "unsupported" as never,
    });

    await expect(verifyJwt(malformed)).resolves.toBeNull();
  });

  it("generation-fences a provisioned Google authentication identity", async () => {
    process.env.TERMINALX_AUTH_MODE = "google";
    process.env.TERMINALX_ALLOWED_EMAILS = "alice@example.com";
    const { openTeamSessionDatabase } = await import("@/lib/team-sessions/sqlite");
    const { createCanonicalIdentityAuthority } = await import("@/lib/identity-authority");
    const database = openTeamSessionDatabase({
      filename: process.env.TERMINALX_TEAM_SESSION_DB_PATH!,
    });
    try {
      const ids = ["canonical-google-user", "canonical-google-identity"];
      const authority = createCanonicalIdentityAuthority({
        db: database.db,
        clock: () => 1_700_000_000_000,
        idGenerator: () => ids.shift()!,
      });
      const provisioned = authority.provisionGoogleIdentity({
        subject: "google-subject-1",
        email: "alice@example.com",
        displayName: "Alice",
        legacyRole: "admin",
      });
      const token = await signJwt({
        userId: provisioned.user.id,
        username: provisioned.user.username,
        displayName: provisioned.user.displayName,
        role: provisioned.user.legacyRole,
        authProvider: provisioned.identity.provider,
        authSubject: provisioned.identity.subject,
        userGeneration: provisioned.user.generation,
        authIdentityGeneration: provisioned.identity.generation,
      });

      await expect(verifyJwt(token)).resolves.toMatchObject({
        userId: "canonical-google-user",
        username: "alice@example.com",
        displayName: "Alice",
        authProvider: "google",
      });

      process.env.TERMINALX_AUTH_MODE = "local";
      await expect(verifyJwt(token)).resolves.toBeNull();
      process.env.TERMINALX_AUTH_MODE = "google";

      authority.revokeAuthenticationIdentity({
        provider: "google",
        subject: "google-subject-1",
        expectedGeneration: 1,
      });
      await expect(verifyJwt(token)).resolves.toBeNull();
    } finally {
      database.close();
    }
  });

  it("rejects legacy shared-password tokens and invalidates canonical tokens on revocation", async () => {
    process.env.TERMINALX_AUTH_MODE = "password";
    const { openTeamSessionDatabase } = await import("@/lib/team-sessions/sqlite");
    const { createCanonicalIdentityAuthority } = await import("@/lib/identity-authority");
    const database = openTeamSessionDatabase({
      filename: process.env.TERMINALX_TEAM_SESSION_DB_PATH!,
    });
    try {
      const authority = createCanonicalIdentityAuthority({
        db: database.db,
        idGenerator: () => "auth-test-password-identity",
      });
      const provisioned = authority.provisionPasswordIdentity();
      const legacyToken = await signJwt({
        userId: "single-user",
        username: "admin",
        role: "admin",
      });
      const canonicalToken = await signJwt({
        userId: provisioned.user.id,
        username: provisioned.user.username,
        displayName: provisioned.user.displayName,
        role: provisioned.user.legacyRole,
        authProvider: provisioned.identity.provider,
        authSubject: provisioned.identity.subject,
        userGeneration: provisioned.user.generation,
        authIdentityGeneration: provisioned.identity.generation,
      });

      await expect(verifyJwt(legacyToken)).resolves.toBeNull();
      await expect(verifyJwt(canonicalToken)).resolves.toMatchObject({
        authProvider: "password",
      });
      authority.revokeUser(provisioned.user.id);
      await expect(verifyJwt(legacyToken)).resolves.toBeNull();
      await expect(verifyJwt(canonicalToken)).resolves.toBeNull();
    } finally {
      database.close();
    }
  });

  it("includes JTI claim for revocation", async () => {
    const token = await signJwt({ userId: "single-user", username: "user", role: "user" });
    const parts = token.split(".");
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
    expect(payload.jti).toBeTruthy();
    expect(typeof payload.jti).toBe("string");
  });

  it("sets 24h expiry", async () => {
    const token = await signJwt({ userId: "single-user", username: "user", role: "user" });
    const parts = token.split(".");
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
    const expiry = payload.exp - payload.iat;
    expect(expiry).toBe(86400); // 24 hours in seconds
  });
});

describe("password hashing", () => {
  it("hashes and verifies password correctly", async () => {
    const password = "my-secure-password-123";
    const hash = await hashPassword(password);

    expect(hash).not.toBe(password);
    expect(hash.startsWith("$2")).toBe(true); // bcrypt prefix

    const valid = await comparePassword(password, hash);
    expect(valid).toBe(true);
  });

  it("rejects wrong password", async () => {
    const hash = await hashPassword("correct-password");
    const valid = await comparePassword("wrong-password", hash);
    expect(valid).toBe(false);
  });
});

describe("parseCookies", () => {
  it("returns empty object for null/undefined", () => {
    expect(parseCookies(null)).toEqual({});
    expect(parseCookies(undefined)).toEqual({});
    expect(parseCookies("")).toEqual({});
  });

  it("parses single cookie", () => {
    const result = parseCookies("session=abc123");
    expect(result).toEqual({ session: "abc123" });
  });

  it("parses multiple cookies", () => {
    const result = parseCookies("session=abc; theme=dark; lang=en");
    expect(result).toEqual({ session: "abc", theme: "dark", lang: "en" });
  });

  it("handles URL-encoded values", () => {
    const result = parseCookies("name=hello%20world");
    expect(result).toEqual({ name: "hello world" });
  });

  it("handles cookies without value", () => {
    const result = parseCookies("novalue");
    expect(result).toEqual({});
  });
});

describe("token revocation", () => {
  it("revoked token is rejected by verifyJwt", async () => {
    const token = await signJwt(canonicalLocalPayload);

    // Token works before revocation
    const before = await verifyJwt(token);
    expect(before).not.toBeNull();

    // Revoke it
    revokeToken(token);

    // Token rejected after revocation
    const after = await verifyJwt(token);
    expect(after).toBeNull();
  });
});

describe("/api/auth/me", () => {
  it("ignores spoofed identity headers when no session cookie is present", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const { GET } = await import("@/app/api/auth/me/route");
    const req = {
      headers: {
        get: (name: string) =>
          ({
            "x-username": "admin",
            "x-user-role": "admin",
          })[name.toLowerCase()] ?? null,
      },
    } as never;

    const res = await GET(req);
    expect(res.status).toBe(401);
  });

  it("returns the canonical user id needed for attributed collaboration", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const token = await signJwt(canonicalLocalPayload);
    const { GET } = await import("@/app/api/auth/me/route");
    const req = {
      headers: {
        get: (name: string) =>
          name.toLowerCase() === "cookie" ? `terminalx-session=${token}` : null,
      },
    } as never;

    const res = await GET(req);
    await expect(res.json()).resolves.toMatchObject({
      userId: "auth-test-local-user",
      username: "alice",
      displayName: "alice",
      role: "user",
    });
  });
});
