import { SignJWT, jwtVerify } from "jose";
import { hash, compare } from "bcryptjs";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { ensureSecureDir } from "./secure-dir";
import { getAuthMode as configuredAuthMode } from "./auth-config";

// ── JWT Secret ──────────────────────────────────────────────────────────────

const DATA_DIR = path.join(process.cwd(), "data");
const SECRET_FILE = path.join(DATA_DIR, ".terminalx-secret");

let cachedSecret: Uint8Array | null = null;

export function getJwtSecret(): Uint8Array {
  if (cachedSecret) return cachedSecret;

  // Prefer env var
  const envSecret = process.env.TERMINALX_JWT_SECRET;
  if (envSecret) {
    cachedSecret = new TextEncoder().encode(envSecret);
    return cachedSecret;
  }

  // Read or create secret file
  try {
    const existing = fs.readFileSync(SECRET_FILE, "utf-8").trim();
    if (existing.length >= 32) {
      cachedSecret = new TextEncoder().encode(existing);
      return cachedSecret;
    }
  } catch {
    // File doesn't exist, create it
  }

  const generated = crypto.randomBytes(48).toString("base64");
  ensureSecureDir(DATA_DIR);
  fs.writeFileSync(SECRET_FILE, generated, { mode: 0o600 });
  cachedSecret = new TextEncoder().encode(generated);
  return cachedSecret;
}

// ── Token Revocation (persistent, JTI-based) ──────────────────────────────

interface RevokedEntry {
  jti: string;
  exp: number; // Unix timestamp when the original JWT expires
}

const REVOKED_FILE = path.join(process.cwd(), "data", ".revoked-tokens.json");

function loadRevokedTokens(): RevokedEntry[] {
  try {
    const raw = fs.readFileSync(REVOKED_FILE, "utf-8");
    return JSON.parse(raw) as RevokedEntry[];
  } catch {
    return [];
  }
}

function saveRevokedTokens(entries: RevokedEntry[]): void {
  ensureSecureDir(path.dirname(REVOKED_FILE));
  const tmpFile = REVOKED_FILE + ".tmp";
  fs.writeFileSync(tmpFile, JSON.stringify(entries), { mode: 0o600 });
  fs.renameSync(tmpFile, REVOKED_FILE);
}

function cleanupExpiredRevocations(): void {
  try {
    const now = Math.floor(Date.now() / 1000);
    const entries = loadRevokedTokens().filter((e) => e.exp > now);
    saveRevokedTokens(entries);
  } catch {
    // Ignore errors during build time or if data dir is not writable
  }
}

// Cleanup on startup and every hour (skip during build)
if (process.env.NODE_ENV !== "production" || !process.env.NEXT_PHASE) {
  cleanupExpiredRevocations();
}
setInterval(cleanupExpiredRevocations, 3600_000);

export function revokeToken(token: string): void {
  try {
    // Extract JTI and exp without verifying signature (token may be about to expire)
    const parts = token.split(".");
    if (parts.length !== 3) return;
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
    const jti = payload.jti as string;
    const exp = (payload.exp as number) || Math.floor(Date.now() / 1000) + 86400;
    if (!jti) return;

    const entries = loadRevokedTokens();
    if (!entries.some((e) => e.jti === jti)) {
      entries.push({ jti, exp });
      saveRevokedTokens(entries);
    }
  } catch {
    // Fallback: if we can't parse the token, ignore (it will expire naturally)
  }
}

function isTokenRevoked(token: string): boolean {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
    const jti = payload.jti as string;
    if (!jti) return false;
    return loadRevokedTokens().some((e) => e.jti === jti);
  } catch {
    return false;
  }
}

// ── JWT Sign / Verify ───────────────────────────────────────────────────────

interface JwtSubjectPayload {
  userId: string;
  username: string;
  displayName?: string;
  role: string;
  /** Set on tokens issued via mobile pairing — used to revoke a single device. */
  deviceId?: string;
}

export interface CanonicalAuthenticationClaims {
  authProvider: "local" | "google" | "password";
  authSubject: string;
  userGeneration: number;
  authIdentityGeneration: number;
}

/** Every newly issued authenticated JWT is structurally generation-fenced. */
export interface JwtPayload extends JwtSubjectPayload, CanonicalAuthenticationClaims {}

/** Verification temporarily supports pre-v11 local JWTs without identity claims. */
export type VerifiedJwtPayload = JwtSubjectPayload & Partial<CanonicalAuthenticationClaims>;

export async function signJwt(payload: JwtPayload): Promise<string> {
  if (
    (payload.authProvider !== "local" &&
      payload.authProvider !== "google" &&
      payload.authProvider !== "password") ||
    payload.authProvider !== configuredAuthMode() ||
    typeof payload.authSubject !== "string" ||
    payload.authSubject.length < 1 ||
    payload.authSubject.length > 1024 ||
    !Number.isSafeInteger(payload.userGeneration) ||
    payload.userGeneration < 1 ||
    !Number.isSafeInteger(payload.authIdentityGeneration) ||
    payload.authIdentityGeneration < 1
  ) {
    throw new TypeError("JWT authentication identity snapshot is invalid");
  }
  const secret = getJwtSecret();
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .setExpirationTime("24h")
    .sign(secret);
}

export async function verifyJwt(token: string): Promise<VerifiedJwtPayload | null> {
  try {
    if (isTokenRevoked(token)) {
      return null;
    }
    const secret = getJwtSecret();
    const { payload } = await jwtVerify(token, secret);
    if (
      typeof payload.userId !== "string" ||
      !payload.userId ||
      typeof payload.username !== "string" ||
      !payload.username ||
      typeof payload.role !== "string" ||
      !payload.role
    ) {
      return null;
    }
    const result: VerifiedJwtPayload = {
      userId: payload.userId,
      username: payload.username,
      role: payload.role,
      displayName: typeof payload.displayName === "string" ? payload.displayName : undefined,
      authProvider:
        payload.authProvider === "local" ||
        payload.authProvider === "google" ||
        payload.authProvider === "password"
          ? payload.authProvider
          : undefined,
      authSubject: typeof payload.authSubject === "string" ? payload.authSubject : undefined,
      userGeneration:
        typeof payload.userGeneration === "number" ? payload.userGeneration : undefined,
      authIdentityGeneration:
        typeof payload.authIdentityGeneration === "number"
          ? payload.authIdentityGeneration
          : undefined,
      deviceId: typeof payload.deviceId === "string" ? payload.deviceId : undefined,
    };

    // Tokens issued via mobile pairing carry a deviceId — reject if the
    // device has been revoked or deleted from the registry.
    if (result.deviceId) {
      const { isDeviceActive } = await import("./devices");
      if (!isDeviceActive(result.deviceId)) return null;
    }

    const identityClaimNames = [
      "authProvider",
      "authSubject",
      "userGeneration",
      "authIdentityGeneration",
    ] as const;
    const identityClaimCount = identityClaimNames.filter((claim) =>
      Object.hasOwn(payload, claim)
    ).length;
    if (identityClaimCount > 0) {
      if (
        identityClaimCount !== 4 ||
        !result.authProvider ||
        !result.authSubject ||
        !Number.isSafeInteger(result.userGeneration) ||
        result.userGeneration! < 1 ||
        !Number.isSafeInteger(result.authIdentityGeneration) ||
        result.authIdentityGeneration! < 1
      ) {
        return null;
      }
      if (result.authProvider !== configuredAuthMode()) return null;
      const { withCanonicalIdentityAuthority } = await import("./identity-service");
      const resolved = withCanonicalIdentityAuthority((authority) =>
        authority.resolveAuthenticationIdentity({
          userId: result.userId,
          userGeneration: result.userGeneration!,
          provider: result.authProvider!,
          subject: result.authSubject!,
          identityGeneration: result.authIdentityGeneration!,
        })
      );
      if (!resolved) return null;
      if (resolved.identity.provider === "google") {
        const { isEmailAllowed } = await import("./auth-config");
        if (!isEmailAllowed(resolved.user.username)) return null;
      }
      result.userId = resolved.user.id;
      result.username = resolved.user.username;
      result.displayName = resolved.user.displayName;
      result.role = resolved.user.legacyRole;
      result.userGeneration = resolved.user.generation;
      result.authIdentityGeneration = resolved.identity.generation;
    } else {
      // Backward-compatible bridge for pre-v11 local JWTs. Google JWTs were
      // synthetic and are deliberately not auto-provisioned from email/name;
      // those Users must complete Google OAuth again.
      if (
        configuredAuthMode() !== "local" ||
        result.userId === "single-user" ||
        result.userId.startsWith("google-")
      ) {
        return null;
      }
      const { getUserById } = await import("./users");
      const user = getUserById(result.userId);
      if (!user) return null;
      result.username = user.username;
      result.displayName = user.username;
      result.role = user.role;
    }

    return result;
  } catch {
    return null;
  }
}

// ── Password Hashing ────────────────────────────────────────────────────────

export async function hashPassword(password: string): Promise<string> {
  return hash(password, 12);
}

export async function comparePassword(password: string, passwordHash: string): Promise<boolean> {
  return compare(password, passwordHash);
}

// ── Cookie Parsing ──────────────────────────────────────────────────────────

export function parseCookies(cookieHeader: string | undefined | null): Record<string, string> {
  if (!cookieHeader) return {};
  const cookies: Record<string, string> = {};
  for (const part of cookieHeader.split("; ")) {
    const eqIdx = part.indexOf("=");
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim();
    const value = part.slice(eqIdx + 1).trim();
    cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

// ── Re-export auth mode ─────────────────────────────────────────────────────

export { getAuthMode } from "./auth-config";
