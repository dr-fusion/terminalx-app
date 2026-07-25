import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { createHash } from "node:crypto";
import { SignJWT } from "jose";

// Set up temp data dir before importing auth module
const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-auth-test-"));
const TEST_REVOKED_TOKENS_FILE = path.join(TEST_DATA_DIR, "revoked-tokens.json");
const TEST_REVOCATION_TOMBSTONE_DIR = `${TEST_REVOKED_TOKENS_FILE}.d`;
const STARTUP_MALFORMED_REGISTRY = '{"revocations":"startup-indeterminate"}';
process.env.TERMINALX_JWT_SECRET = "test-secret-that-is-at-least-32-chars-long-for-hmac";
process.env.TERMINALX_TEAM_SESSION_DB_PATH = path.join(TEST_DATA_DIR, "team-sessions.sqlite");
process.env.TERMINALX_LEGACY_USERS_FILE = path.join(TEST_DATA_DIR, "users.json");
process.env.TERMINALX_REVOKED_TOKENS_FILE = TEST_REVOKED_TOKENS_FILE;
fs.writeFileSync(TEST_REVOKED_TOKENS_FILE, STARTUP_MALFORMED_REGISTRY, { mode: 0o600 });

// Dynamically import after env is set
let signJwt: typeof import("@/lib/auth").signJwt;
let verifyJwt: typeof import("@/lib/auth").verifyJwt;
let hashPassword: typeof import("@/lib/auth").hashPassword;
let comparePassword: typeof import("@/lib/auth").comparePassword;
let parseCookies: typeof import("@/lib/auth").parseCookies;
let revokeToken: typeof import("@/lib/auth").revokeToken;
let isJwtIdentifierDigestActive: typeof import("@/lib/auth").isJwtIdentifierDigestActive;
let getJwtSecret: typeof import("@/lib/auth").getJwtSecret;
let canonicalLocalPayload: import("@/lib/auth").JwtPayload;
let rawJwtCounter = 0;
let startupCleanupPreservedMalformedRegistry = false;

async function signRawJwt(payload: Record<string, unknown>): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const signer = new SignJWT({
    iat: now,
    jti: `raw-test-jti-${rawJwtCounter++}`,
    ...payload,
  }).setProtectedHeader({ alg: "HS256" });
  if (!Object.hasOwn(payload, "exp")) signer.setExpirationTime("24h");
  return signer.sign(getJwtSecret());
}

beforeAll(async () => {
  const auth = await import("@/lib/auth");
  startupCleanupPreservedMalformedRegistry =
    fs.readFileSync(TEST_REVOKED_TOKENS_FILE, "utf8") === STARTUP_MALFORMED_REGISTRY;
  fs.writeFileSync(TEST_REVOKED_TOKENS_FILE, "[]", { mode: 0o600 });
  signJwt = auth.signJwt;
  verifyJwt = auth.verifyJwt;
  hashPassword = auth.hashPassword;
  comparePassword = auth.comparePassword;
  parseCookies = auth.parseCookies;
  revokeToken = auth.revokeToken;
  isJwtIdentifierDigestActive = auth.isJwtIdentifierDigestActive;
  getJwtSecret = auth.getJwtSecret;
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

afterAll(async () => {
  const { closeCanonicalIdentityAuthorityService } = await import("@/lib/identity-service");
  closeCanonicalIdentityAuthorityService();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  delete process.env.TERMINALX_JWT_SECRET;
  delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
  delete process.env.TERMINALX_LEGACY_USERS_FILE;
  delete process.env.TERMINALX_REVOKED_TOKENS_FILE;
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

  it("binds a paired-device credential to the exact canonical User", async () => {
    const { registerDevice } = await import("@/lib/devices");
    const { withCanonicalIdentityAuthority } = await import("@/lib/identity-service");
    const device = await registerDevice({
      userId: canonicalLocalPayload.userId,
      username: canonicalLocalPayload.username,
      name: "Owner phone",
    });
    const ownerToken = await signJwt({ ...canonicalLocalPayload, deviceId: device.id });
    await expect(verifyJwt(ownerToken)).resolves.toMatchObject({
      userId: canonicalLocalPayload.userId,
      deviceId: device.id,
    });

    const other = withCanonicalIdentityAuthority((authority) => {
      const user = authority.createLocalUser({
        username: "paired-device-other-user",
        passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
        legacyRole: "user",
      });
      return authority.getLocalAuthenticationIdentity(user.id)!;
    });
    const wrongOwnerToken = await signJwt({
      userId: other.user.id,
      username: other.user.username,
      displayName: other.user.displayName,
      role: other.user.legacyRole,
      authProvider: other.identity.provider,
      authSubject: other.identity.subject,
      userGeneration: other.user.generation,
      authIdentityGeneration: other.identity.generation,
      deviceId: device.id,
    });

    await expect(verifyJwt(wrongOwnerToken)).resolves.toBeNull();
  });

  it("strictly exposes signed issuance, token id, and primary-authentication claims", async () => {
    const authTime = Math.floor(Date.now() / 1000) - 60;
    const token = await signJwt({ ...canonicalLocalPayload, authTime });

    const verified = await verifyJwt(token);
    expect(verified).toMatchObject({
      authTime,
      iat: expect.any(Number),
      exp: expect.any(Number),
      jti: expect.any(String),
    });
    expect(verified!.iat).toBeGreaterThanOrEqual(authTime);
    expect(verified!.exp).toBeGreaterThan(verified!.iat);
    expect(verified!.jti).not.toHaveLength(0);
  });

  it("keeps pre-auth_time credentials valid without inventing recent authentication", async () => {
    const token = await signJwt(canonicalLocalPayload);

    const verified = await verifyJwt(token);
    expect(verified).not.toBeNull();
    expect(verified).not.toHaveProperty("authTime");
  });

  it("returns null for tampered token", async () => {
    const token = await signJwt(canonicalLocalPayload);
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
    const token = await signJwt({
      userId: "deleted-user-id",
      username: "ghost",
      role: "user",
      authProvider: "local",
      authSubject: "deleted-user-id",
      userGeneration: 1,
      authIdentityGeneration: 1,
    });
    const result = await verifyJwt(token);
    expect(result).toBeNull();
  });

  it("fails closed when any canonical identity snapshot claim is malformed", async () => {
    const malformed = await signRawJwt({
      userId: "single-user",
      username: "admin",
      role: "admin",
      authProvider: "unsupported",
    });

    await expect(verifyJwt(malformed)).resolves.toBeNull();
  });

  it.each([
    ["missing iat", { iat: undefined }],
    ["non-integer iat", { iat: 1.5 }],
    ["future iat", { iat: Math.floor(Date.now() / 1000) + 60 }],
    ["missing exp", { exp: undefined }],
    ["non-integer exp", { exp: 1.5 }],
    ["expiry before issuance", { exp: 0 }],
    ["overlong expiry", { exp: Math.floor(Date.now() / 1000) + 90_000 }],
    ["missing jti", { jti: undefined }],
    ["empty jti", { jti: "" }],
    ["non-string jti", { jti: 42 }],
    ["non-integer auth_time", { auth_time: 1.5 }],
    ["future auth_time", { auth_time: Math.floor(Date.now() / 1000) + 60 }],
    ["malformed device provenance", { deviceId: 42 }],
  ])("rejects a JWT with %s", async (_label, malformedClaims) => {
    const token = await signRawJwt({ ...canonicalLocalPayload, ...malformedClaims });

    await expect(verifyJwt(token)).resolves.toBeNull();
  });

  it("refuses to issue a JWT with malformed or future primary-authentication time", async () => {
    await expect(
      signJwt({ ...canonicalLocalPayload, authTime: Math.floor(Date.now() / 1000) + 60 })
    ).rejects.toThrow("JWT authentication identity snapshot is invalid");
    await expect(signJwt({ ...canonicalLocalPayload, authTime: 1.5 })).rejects.toThrow(
      "JWT authentication identity snapshot is invalid"
    );
  });

  it("refuses to issue a JWT without a complete canonical identity snapshot", async () => {
    await expect(
      signJwt({ userId: "single-user", username: "admin", role: "admin" } as never)
    ).rejects.toThrow("JWT authentication identity snapshot is invalid");
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
        userId: "google-google-subject-1",
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
      const legacyToken = await signRawJwt({
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
    const token = await signJwt(canonicalLocalPayload);
    const parts = token.split(".");
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
    expect(payload.jti).toBeTruthy();
    expect(typeof payload.jti).toBe("string");
  });

  it("sets 24h expiry", async () => {
    const token = await signJwt(canonicalLocalPayload);
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
  it("does not erase indeterminate revocation state during startup cleanup", () => {
    expect(startupCleanupPreservedMalformedRegistry).toBe(true);
  });

  it("checks revocation from a SHA-256 JTI digest without returning the raw JTI", async () => {
    const token = await signJwt(canonicalLocalPayload);
    const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()) as {
      jti: string;
    };
    const digestHex = createHash("sha256").update(payload.jti, "utf8").digest("hex");

    expect(isJwtIdentifierDigestActive(digestHex)).toBe(true);
    await expect(revokeToken(token)).resolves.toMatchObject({ status: "persisted" });
    expect(isJwtIdentifierDigestActive(digestHex)).toBe(false);
    expect(isJwtIdentifierDigestActive(payload.jti)).toBe(false);
  });

  it("fails closed without erasing a malformed revocation registry", async () => {
    const token = await signJwt(canonicalLocalPayload);
    const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()) as {
      jti: string;
    };
    const registryPath = process.env.TERMINALX_REVOKED_TOKENS_FILE!;
    const malformed = '{"revocations":"indeterminate"}';
    fs.writeFileSync(registryPath, malformed, { mode: 0o600 });
    try {
      const digest = createHash("sha256").update(payload.jti, "utf8").digest("hex");
      expect(isJwtIdentifierDigestActive(digest)).toBe(false);
      await expect(revokeToken(token)).resolves.toMatchObject({ status: "persisted" });
      expect(fs.readFileSync(registryPath, "utf8")).toBe(malformed);
      await expect(verifyJwt(token)).resolves.toBeNull();
    } finally {
      fs.writeFileSync(registryPath, "[]", { mode: 0o600 });
    }
    await expect(verifyJwt(token)).resolves.toBeNull();
  });

  it("reports failure when a revocation tombstone cannot be persisted", async () => {
    const token = await signJwt(canonicalLocalPayload);
    const backup = `${TEST_REVOCATION_TOMBSTONE_DIR}.backup`;
    const hadDirectory = fs.existsSync(TEST_REVOCATION_TOMBSTONE_DIR);
    if (hadDirectory) fs.renameSync(TEST_REVOCATION_TOMBSTONE_DIR, backup);
    fs.writeFileSync(TEST_REVOCATION_TOMBSTONE_DIR, "not-a-directory", { mode: 0o600 });
    try {
      await expect(revokeToken(token)).rejects.toThrow(
        "Token revocation could not be persisted durably"
      );
    } finally {
      fs.unlinkSync(TEST_REVOCATION_TOMBSTONE_DIR);
      if (hadDirectory) fs.renameSync(backup, TEST_REVOCATION_TOMBSTONE_DIR);
    }
    await expect(verifyJwt(token)).resolves.not.toBeNull();
  });

  it("revoked token is rejected by verifyJwt", async () => {
    const token = await signJwt(canonicalLocalPayload);

    // Token works before revocation
    const before = await verifyJwt(token);
    expect(before).not.toBeNull();

    // Revoke it
    await expect(revokeToken(token)).resolves.toMatchObject({ status: "persisted" });

    // Token rejected after revocation
    const after = await verifyJwt(token);
    expect(after).toBeNull();
  });

  it("tombstones an authentic token while mutable auth policy disables it", async () => {
    const token = await signJwt(canonicalLocalPayload);
    process.env.TERMINALX_AUTH_MODE = "password";
    await expect(verifyJwt(token)).resolves.toBeNull();

    await expect(revokeToken(token)).resolves.toMatchObject({ status: "persisted" });

    process.env.TERMINALX_AUTH_MODE = "local";
    await expect(verifyJwt(token)).resolves.toBeNull();
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
