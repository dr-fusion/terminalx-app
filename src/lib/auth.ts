import { SignJWT, jwtVerify } from "jose";
import { hash, compare } from "bcryptjs";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { ensureSecureDir } from "./secure-dir";
import { getAuthMode as configuredAuthMode } from "./auth-config";

// ── JWT Secret ──────────────────────────────────────────────────────────────

const DATA_DIR = path.join(/* turbopackIgnore: true */ process.cwd(), "data");
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
    const existing = fs.readFileSync(/* turbopackIgnore: true */ SECRET_FILE, "utf-8").trim();
    if (existing.length >= 32) {
      cachedSecret = new TextEncoder().encode(existing);
      return cachedSecret;
    }
  } catch {
    // File doesn't exist, create it
  }

  const generated = crypto.randomBytes(48).toString("base64");
  ensureSecureDir(DATA_DIR);
  fs.writeFileSync(/* turbopackIgnore: true */ SECRET_FILE, generated, { mode: 0o600 });
  cachedSecret = new TextEncoder().encode(generated);
  return cachedSecret;
}

// ── Token Revocation (persistent, JTI-based) ──────────────────────────────

interface RevokedEntry {
  jti: string;
  exp: number; // Unix timestamp when the original JWT expires
}

const REVOKED_FILE =
  process.env.TERMINALX_REVOKED_TOKENS_FILE ??
  path.join(/* turbopackIgnore: true */ process.cwd(), "data", ".revoked-tokens.json");
const REVOCATION_TOMBSTONE_DIR =
  process.env.TERMINALX_REVOKED_TOKEN_TOMBSTONE_DIR ?? `${REVOKED_FILE}.d`;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const JWT_MAX_LIFETIME_SECONDS = 24 * 60 * 60;

interface RevocationTombstone {
  schema: 1;
  jtiDigest: string;
  exp: number;
}

type RevocationTombstoneState =
  | { kind: "missing" }
  | { kind: "present"; value: RevocationTombstone }
  | { kind: "indeterminate" };

function errorCodeIs(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === code
  );
}

function jwtIdentifierDigest(jti: string): string {
  return crypto.createHash("sha256").update(jti, "utf8").digest("hex");
}

function tombstonePath(jtiDigest: string): string {
  return path.join(/* turbopackIgnore: true */ REVOCATION_TOMBSTONE_DIR, `${jtiDigest}.json`);
}

function loadRevocationTombstone(jtiDigest: string): RevocationTombstoneState {
  let raw: string;
  try {
    raw = fs.readFileSync(/* turbopackIgnore: true */ tombstonePath(jtiDigest), "utf8");
  } catch (error) {
    return errorCodeIs(error, "ENOENT") ? { kind: "missing" } : { kind: "indeterminate" };
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Object.keys(parsed).sort().join(",") !== "exp,jtiDigest,schema" ||
      !("schema" in parsed) ||
      parsed.schema !== 1 ||
      !("jtiDigest" in parsed) ||
      parsed.jtiDigest !== jtiDigest ||
      typeof parsed.jtiDigest !== "string" ||
      !SHA256_HEX.test(parsed.jtiDigest) ||
      !("exp" in parsed) ||
      !Number.isSafeInteger(parsed.exp) ||
      (parsed.exp as number) < 0
    ) {
      return { kind: "indeterminate" };
    }
    return {
      kind: "present",
      value: { schema: 1, jtiDigest: parsed.jtiDigest, exp: parsed.exp as number },
    };
  } catch {
    return { kind: "indeterminate" };
  }
}

function syncDirectory(directory: string): void {
  const descriptor = fs.openSync(/* turbopackIgnore: true */ directory, "r");
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function writeFileAtomicallyDurable(filename: string, contents: string): void {
  const directory = path.dirname(/* turbopackIgnore: true */ filename);
  ensureSecureDir(directory);
  const temporary = path.join(
    directory,
    `.${path.basename(filename)}.${process.pid}.${crypto.randomBytes(12).toString("hex")}.tmp`
  );
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(/* turbopackIgnore: true */ temporary, "wx", 0o600);
    fs.writeFileSync(descriptor, contents, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(/* turbopackIgnore: true */ temporary, /* turbopackIgnore: true */ filename);
    syncDirectory(directory);
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // The original persistence error remains authoritative.
      }
    }
    try {
      fs.unlinkSync(/* turbopackIgnore: true */ temporary);
    } catch {
      // A successfully renamed temporary path no longer exists.
    }
    throw error;
  }
}

function persistRevocationTombstone(input: {
  jtiDigest: string;
  exp: number;
}): "persisted" | "already-revoked" {
  const existing = loadRevocationTombstone(input.jtiDigest);
  if (existing.kind === "present" && existing.value.exp >= input.exp) {
    syncDirectory(REVOCATION_TOMBSTONE_DIR);
    return "already-revoked";
  }
  const tombstone: RevocationTombstone = {
    schema: 1,
    jtiDigest: input.jtiDigest,
    exp: Math.max(input.exp, existing.kind === "present" ? existing.value.exp : 0),
  };
  writeFileAtomicallyDurable(tombstonePath(input.jtiDigest), JSON.stringify(tombstone));
  return existing.kind === "present" ? "already-revoked" : "persisted";
}

/** Missing is an empty registry; unreadable or malformed state is indeterminate. */
function loadRevokedTokens(): RevokedEntry[] | null {
  let raw: string;
  try {
    raw = fs.readFileSync(/* turbopackIgnore: true */ REVOKED_FILE, "utf-8");
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return [];
    }
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    const entries: RevokedEntry[] = [];
    for (const value of parsed) {
      if (
        typeof value !== "object" ||
        value === null ||
        !("jti" in value) ||
        typeof value.jti !== "string" ||
        value.jti.length < 1 ||
        value.jti.length > 1024 ||
        !("exp" in value) ||
        !Number.isSafeInteger(value.exp) ||
        (value.exp as number) < 0
      ) {
        return null;
      }
      entries.push({ jti: value.jti, exp: value.exp as number });
    }
    return entries;
  } catch {
    return null;
  }
}

function saveRevokedTokens(entries: RevokedEntry[]): void {
  writeFileAtomicallyDurable(REVOKED_FILE, JSON.stringify(entries));
}

function cleanupExpiredRevocationTombstones(): void {
  const now = Math.floor(Date.now() / 1000);
  let names: string[];
  try {
    names = fs.readdirSync(/* turbopackIgnore: true */ REVOCATION_TOMBSTONE_DIR);
  } catch (error) {
    if (errorCodeIs(error, "ENOENT")) return;
    return;
  }
  let removed = false;
  for (const name of names) {
    const match = /^([0-9a-f]{64})\.json$/.exec(name);
    if (!match) continue;
    const state = loadRevocationTombstone(match[1]!);
    if (state.kind !== "present" || state.value.exp > now) continue;
    try {
      fs.unlinkSync(/* turbopackIgnore: true */ tombstonePath(match[1]!));
      removed = true;
    } catch {
      // Leaving an expired tombstone in place is fail-safe.
    }
  }
  if (removed) {
    try {
      syncDirectory(REVOCATION_TOMBSTONE_DIR);
    } catch {
      // Cleanup is optional; issuance never relies on its success.
    }
  }
}

function cleanupExpiredRevocations(): void {
  try {
    const now = Math.floor(Date.now() / 1000);
    const stored = loadRevokedTokens();
    if (stored === null) return;
    const active = stored.filter((entry) => entry.exp > now);
    if (active.length !== stored.length) saveRevokedTokens(active);
  } catch {
    // Ignore errors during build time or if data dir is not writable
  }
  cleanupExpiredRevocationTombstones();
}

// Cleanup on startup and every hour (skip during build)
if (process.env.NODE_ENV !== "production" || !process.env.NEXT_PHASE) {
  cleanupExpiredRevocations();
}
setInterval(cleanupExpiredRevocations, 3600_000);

export interface TokenRevocationReceipt {
  status: "persisted" | "already-revoked";
  userId: string;
  username: string;
  expiresAtMs: number;
}

export class TokenRevocationPersistenceError extends Error {
  constructor() {
    super("Token revocation could not be persisted durably");
    this.name = "TokenRevocationPersistenceError";
  }
}

/**
 * Verify an authentic, structurally valid, unexpired credential and durably persist a
 * digest-only tombstone before reporting logout success. Tombstones are
 * authoritative even when the legacy JSON registry is corrupt or later
 * repaired, so a copied bearer token cannot revive after a successful logout.
 */
export async function revokeToken(token: string): Promise<TokenRevocationReceipt | null> {
  const verified = await verifyJwtInternal(token, {
    enforceRevocation: false,
    enforceCurrentAuthority: false,
  });
  if (!verified) return null;
  let status: TokenRevocationReceipt["status"];
  try {
    status = persistRevocationTombstone({
      jtiDigest: jwtIdentifierDigest(verified.jti),
      exp: verified.exp,
    });
  } catch {
    throw new TokenRevocationPersistenceError();
  }
  return Object.freeze({
    status,
    userId: verified.userId,
    username: verified.username,
    expiresAtMs: verified.exp * 1000,
  });
}

function isTokenRevoked(token: string): boolean {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
    const jti = payload.jti as string;
    if (!jti) return false;
    const tombstone = loadRevocationTombstone(jwtIdentifierDigest(jti));
    if (tombstone.kind !== "missing") return true;
    const entries = loadRevokedTokens();
    // Authentication must not convert unreadable revocation state into an
    // implicit allow decision.
    return entries === null || entries.some((entry) => entry.jti === jti);
  } catch {
    return false;
  }
}

// ── JWT Sign / Verify ───────────────────────────────────────────────────────

/**
 * Validate a digest-only snapshot of a signed JWT identifier against the
 * raw-JTI revocation registry. The raw identifier is hashed and compared
 * entirely inside this module and is never returned to connection code.
 *
 * Malformed input or an unreadable/corrupt registry returns false so callers
 * can use this directly in a fail-closed completion check.
 */
export function isJwtIdentifierDigestActive(jtiDigest: string): boolean {
  try {
    if (typeof jtiDigest !== "string" || !SHA256_HEX.test(jtiDigest)) return false;
    const tombstone = loadRevocationTombstone(jtiDigest);
    if (tombstone.kind !== "missing") return false;
    const entries = loadRevokedTokens();
    if (!entries) return false;
    const expected = Buffer.from(jtiDigest, "hex");
    return !entries.some((entry) => {
      const actual = crypto.createHash("sha256").update(entry.jti, "utf8").digest();
      return crypto.timingSafeEqual(actual, expected);
    });
  } catch {
    return false;
  }
}

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
export interface JwtPayload extends JwtSubjectPayload, CanonicalAuthenticationClaims {
  /**
   * Unix timestamp (seconds) of the primary credential check. Pairing must
   * preserve this value instead of treating issuance of a device JWT as a new
   * authentication event. Omitted only when bridging an older credential that
   * did not carry auth_time.
   */
  authTime?: number;
}

/** Verification temporarily supports pre-v11 local JWTs without identity claims. */
export type VerifiedJwtPayload = JwtSubjectPayload &
  Partial<CanonicalAuthenticationClaims> & {
    /** Verified registered JWT claims; callers must never expose the raw JTI. */
    iat: number;
    exp: number;
    jti: string;
    /** Verified primary-authentication time, absent on pre-auth_time credentials. */
    authTime?: number;
  };

export interface IssuedJwt {
  token: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export async function signJwtWithMetadata(payload: JwtPayload): Promise<IssuedJwt> {
  const issuedAt = Math.floor(Date.now() / 1000);
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
    payload.authIdentityGeneration < 1 ||
    (payload.authTime !== undefined &&
      (!Number.isSafeInteger(payload.authTime) ||
        payload.authTime < 0 ||
        payload.authTime > issuedAt)) ||
    (payload.deviceId !== undefined &&
      (typeof payload.deviceId !== "string" ||
        payload.deviceId.length < 1 ||
        payload.deviceId.length > 300))
  ) {
    throw new TypeError("JWT authentication identity snapshot is invalid");
  }
  const expiresAt = issuedAt + JWT_MAX_LIFETIME_SECONDS;
  const secret = getJwtSecret();
  const token = await new SignJWT({
    userId: payload.userId,
    username: payload.username,
    ...(payload.displayName !== undefined ? { displayName: payload.displayName } : {}),
    role: payload.role,
    authProvider: payload.authProvider,
    authSubject: payload.authSubject,
    userGeneration: payload.userGeneration,
    authIdentityGeneration: payload.authIdentityGeneration,
    ...(payload.deviceId !== undefined ? { deviceId: payload.deviceId } : {}),
    ...(payload.authTime !== undefined ? { auth_time: payload.authTime } : {}),
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(issuedAt)
    .setJti(crypto.randomUUID())
    .setExpirationTime(expiresAt)
    .sign(secret);
  return Object.freeze({
    token,
    issuedAtMs: issuedAt * 1000,
    expiresAtMs: expiresAt * 1000,
  });
}

export async function signJwt(payload: JwtPayload): Promise<string> {
  return (await signJwtWithMetadata(payload)).token;
}

export async function verifyJwt(token: string): Promise<VerifiedJwtPayload | null> {
  return verifyJwtInternal(token, {
    enforceRevocation: true,
    enforceCurrentAuthority: true,
  });
}

async function verifyJwtInternal(
  token: string,
  options: { enforceRevocation: boolean; enforceCurrentAuthority: boolean }
): Promise<VerifiedJwtPayload | null> {
  try {
    if (options.enforceRevocation && isTokenRevoked(token)) {
      return null;
    }
    const secret = getJwtSecret();
    const { payload } = await jwtVerify(token, secret, { algorithms: ["HS256"] });
    const now = Math.floor(Date.now() / 1000);
    const issuedAt = payload.iat;
    const expiresAt = payload.exp;
    const jwtId = payload.jti;
    const hasAuthenticationTime = Object.hasOwn(payload, "auth_time");
    const authenticationTime = payload.auth_time;
    const hasDeviceId = Object.hasOwn(payload, "deviceId");
    const deviceId = payload.deviceId;
    if (
      !Number.isSafeInteger(issuedAt) ||
      issuedAt! < 0 ||
      issuedAt! > now ||
      !Number.isSafeInteger(issuedAt! * 1000) ||
      !Number.isSafeInteger(expiresAt) ||
      expiresAt! <= now ||
      expiresAt! < issuedAt! ||
      expiresAt! - issuedAt! > JWT_MAX_LIFETIME_SECONDS ||
      !Number.isSafeInteger(expiresAt! * 1000) ||
      typeof jwtId !== "string" ||
      jwtId.length < 1 ||
      jwtId.length > 1024 ||
      (hasAuthenticationTime &&
        (!Number.isSafeInteger(authenticationTime) ||
          (authenticationTime as number) < 0 ||
          (authenticationTime as number) > issuedAt! ||
          !Number.isSafeInteger((authenticationTime as number) * 1000))) ||
      (hasDeviceId &&
        (typeof deviceId !== "string" || deviceId.length < 1 || deviceId.length > 300)) ||
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
      iat: issuedAt!,
      exp: expiresAt!,
      jti: jwtId,
      ...(hasAuthenticationTime ? { authTime: authenticationTime as number } : {}),
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
      ...(hasDeviceId ? { deviceId: deviceId as string } : {}),
    };

    // Logout needs only authentic, registered, unexpired JWT claims. Mutable
    // policy must not prevent tombstoning: an allowlist, auth mode, identity,
    // or device can later be restored while a copied bearer token still exists.
    if (!options.enforceCurrentAuthority) return result;

    // Tokens issued via mobile pairing carry a deviceId. Re-resolve the exact
    // owner as well as revocation state: an active device is not a transferable
    // capability that can validate a credential signed for another User.
    if (result.deviceId) {
      const { getDevice } = await import("./devices");
      const device = getDevice(result.deviceId);
      if (!device || device.userId !== result.userId || device.revokedAt !== null) return null;
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
