import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// Set up temp data dir before importing auth module
const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-auth-test-"));
process.env.TERMINALX_JWT_SECRET = "test-secret-that-is-at-least-32-chars-long-for-hmac";

// Dynamically import after env is set
let signJwt: typeof import("@/lib/auth").signJwt;
let verifyJwt: typeof import("@/lib/auth").verifyJwt;
let hashPassword: typeof import("@/lib/auth").hashPassword;
let comparePassword: typeof import("@/lib/auth").comparePassword;
let parseCookies: typeof import("@/lib/auth").parseCookies;
let revokeToken: typeof import("@/lib/auth").revokeToken;

beforeAll(async () => {
  const auth = await import("@/lib/auth");
  signJwt = auth.signJwt;
  verifyJwt = auth.verifyJwt;
  hashPassword = auth.hashPassword;
  comparePassword = auth.comparePassword;
  parseCookies = auth.parseCookies;
  revokeToken = auth.revokeToken;
});

afterAll(() => {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  delete process.env.TERMINALX_JWT_SECRET;
});

describe("JWT sign and verify", () => {
  // Use "single-user" userId to bypass the user-existence check in verifyJwt.
  // The user-existence check is tested separately below.
  it("signs and verifies a valid token", async () => {
    const payload = { userId: "single-user", username: "admin", role: "admin" };
    const token = await signJwt(payload);

    expect(token).toBeTruthy();
    expect(typeof token).toBe("string");
    expect(token.split(".")).toHaveLength(3);

    const verified = await verifyJwt(token);
    expect(verified).not.toBeNull();
    expect(verified!.userId).toBe("single-user");
    expect(verified!.username).toBe("admin");
    expect(verified!.role).toBe("admin");
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
    const token = await signJwt({ userId: "single-user", username: "admin", role: "admin" });

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
