import { createHash } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { signJwtWithMetadata } from "@/lib/auth";
import { getAuthMode, isEmailAllowed } from "@/lib/auth-config";
import { withCanonicalIdentityAuthority } from "@/lib/identity-service";
import { consumePairingCode, type ConsumedPairingCode } from "@/lib/pairing";
import { getDevice, registerDevice, revokeDevice } from "@/lib/devices";
import { audit } from "@/lib/audit-log";
import { clientIp, isPairingSourceRateLimited, isRateLimited } from "@/lib/rate-limit";
import { isStoredAuthenticationSessionActive } from "@/lib/auth-session-snapshot";

const NO_STORE_HEADERS = { "Cache-Control": "no-store, max-age=0" } as const;
const PAIRING_CODE_PATTERN = /^[A-Za-z0-9_-]{32}$/;
const PAIR_RATE_LIMIT_RETRY_AFTER_SECONDS = 60;

// POST /api/auth/pair
// Public endpoint. Body: { code, deviceName }. Exchanges a one-time pairing
// code (created by the web app via POST /api/auth/pairing-codes) for a 24h
// JWT scoped to the new device. The device row is persisted so it can be
// revoked from web settings — verifyJwt() rejects tokens whose device has
// been revoked.
export async function POST(req: NextRequest) {
  // Bound total parser and authority work before reading an attacker-sized
  // body. This high-volume source/global guard has dedicated state that
  // attacker-cardinality code keys cannot evict.
  if (isPairingSourceRateLimited(clientIp(req))) {
    audit("rate_limited", { detail: "pairing redemption source" });
    return pairError("Too many attempts. Try again later.", 429, {
      "Retry-After": String(PAIR_RATE_LIMIT_RETRY_AFTER_SECONDS),
    });
  }

  let body: { code?: unknown; deviceName?: unknown };
  try {
    body = (await req.json()) as { code?: unknown; deviceName?: unknown };
  } catch {
    return pairError("Invalid JSON body", 400);
  }

  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceName =
    typeof body.deviceName === "string" && body.deviceName.trim()
      ? body.deviceName.trim()
      : "Mobile device";
  if (!code) {
    return pairError("Missing pairing code", 400);
  }
  if (!PAIRING_CODE_PATTERN.test(code)) {
    return pairError("Invalid pairing code", 400);
  }

  // Codes contain 192 bits of randomness. This separate digest-scoped bucket
  // gives repeated guesses a much lower ceiling without letting a shared
  // proxy/NAT peer block unrelated codes after only five attempts. The raw
  // bearer code never enters limiter or audit state.
  const rateLimitKey = `pair:code:${createHash("sha256").update(code, "utf8").digest("hex")}`;
  if (isRateLimited(rateLimitKey)) {
    audit("rate_limited", { detail: "pairing code redemption" });
    return pairError("Too many attempts. Try again later.", 429, {
      "Retry-After": String(PAIR_RATE_LIMIT_RETRY_AFTER_SECONDS),
    });
  }

  let consumed: Awaited<ReturnType<typeof consumePairingCode>>;
  try {
    consumed = await consumePairingCode(code);
  } catch {
    audit("pair_failed", { detail: "pairing claim persistence unavailable" });
    return pairError("Pairing state is temporarily unavailable. Try again.", 503);
  }
  if (!consumed) {
    audit("pair_failed", { detail: "invalid or expired code" });
    return pairError("Invalid or expired code", 401);
  }

  const initialIdentity = safelyResolvePairingIdentity(consumed);
  if (initialIdentity.kind === "unavailable") {
    audit("pair_failed", { detail: "pairing identity authority unavailable after consumption" });
    return consumedCodeFailure();
  }
  if (initialIdentity.kind === "unauthorized") {
    audit("pair_failed", { detail: "pairing identity is no longer authorized" });
    return pairError("Invalid or expired code", 401);
  }
  const identity = initialIdentity.identity;

  let device: Awaited<ReturnType<typeof registerDevice>>;
  try {
    device = await registerDevice({
      userId: identity.userId,
      username: identity.username,
      name: deviceName,
    });
  } catch {
    audit("pair_failed", {
      username: identity.username,
      userId: identity.userId,
      detail: "device registration failed after pairing code consumption",
    });
    return consumedCodeFailure();
  }

  if (!(await exactDeviceRegistrationIsActive(device.id, identity))) {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", {
      username: identity.username,
      userId: identity.userId,
      detail: "device registration durability recheck failed",
    });
    return consumedCodeFailure();
  }

  // Device storage is a separate durability boundary from canonical identity
  // state. Re-resolve after that write and revoke the new row before issuing a
  // credential if revocation, a generation change, or an auth-mode change won
  // the race. Every later token use is generation-fenced again by verifyJwt.
  const identityAfterRegistration = safelyResolvePairingIdentity(consumed);
  if (identityAfterRegistration.kind === "unavailable") {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", { detail: "pairing identity authority unavailable after registration" });
    return consumedCodeFailure();
  }
  if (
    identityAfterRegistration.kind === "unauthorized" ||
    !samePairingIdentity(identity, identityAfterRegistration.identity)
  ) {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", { detail: "pairing identity changed during device registration" });
    return pairError("Invalid or expired code", 401);
  }

  let issuance: Awaited<ReturnType<typeof signJwtWithMetadata>>;
  try {
    issuance = await signJwtWithMetadata({
      ...identity,
      deviceId: device.id,
    });
  } catch {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", { detail: "device credential issuance failed" });
    return pairError("Invalid or expired code", 401);
  }

  if (!(await exactDeviceRegistrationIsActive(device.id, identity))) {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", {
      username: identity.username,
      userId: identity.userId,
      detail: "device registration recheck failed after credential signing",
    });
    return consumedCodeFailure();
  }

  // Signing is an asynchronous authority boundary too. If the source JWT is
  // logged out, expires, its device is revoked, or canonical identity changes
  // while signing, invalidate the newly minted device before it can escape.
  const identityAfterSigning = safelyResolvePairingIdentity(consumed);
  if (identityAfterSigning.kind === "unavailable") {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", { detail: "pairing identity authority unavailable after signing" });
    return consumedCodeFailure();
  }
  if (
    identityAfterSigning.kind === "unauthorized" ||
    !samePairingIdentity(identity, identityAfterSigning.identity)
  ) {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", { detail: "pairing identity changed during credential issuance" });
    return pairError("Invalid or expired code", 401);
  }

  audit("pair_success", { username: identity.username, userId: identity.userId });

  return NextResponse.json(
    {
      token: issuance.token,
      expiresAt: issuance.expiresAtMs,
      deviceId: device.id,
      user: { id: identity.userId, name: identity.username },
    },
    { headers: NO_STORE_HEADERS }
  );
}

function pairError(error: string, status: number, headers?: Record<string, string>) {
  return NextResponse.json(
    { error },
    { status, headers: { ...NO_STORE_HEADERS, ...(headers ?? {}) } }
  );
}

function consumedCodeFailure() {
  return pairError(
    "Pairing could not be completed after the code was consumed. Generate a new pairing code and try again.",
    503
  );
}

async function exactDeviceRegistrationIsActive(
  deviceId: string,
  identity: Pick<PairingIdentity, "userId" | "username">
): Promise<boolean> {
  try {
    const persisted = await getDevice(deviceId);
    return (
      persisted?.id === deviceId &&
      persisted.userId === identity.userId &&
      persisted.username === identity.username &&
      persisted.revokedAt === null
    );
  } catch {
    return false;
  }
}

interface PairingIdentity {
  userId: string;
  username: string;
  displayName?: string;
  role: string;
  authProvider: "local" | "google" | "password";
  authSubject: string;
  userGeneration: number;
  authIdentityGeneration: number;
  /** Original primary authentication, never the device-token issuance time. */
  authTime?: number;
}

type PairingIdentityResolution =
  | { kind: "resolved"; identity: PairingIdentity }
  | { kind: "unauthorized" }
  | { kind: "unavailable" };

function safelyResolvePairingIdentity(consumed: ConsumedPairingCode): PairingIdentityResolution {
  try {
    const identity = resolvePairingIdentity(consumed);
    return identity ? { kind: "resolved", identity } : { kind: "unauthorized" };
  } catch {
    return { kind: "unavailable" };
  }
}

function samePairingIdentity(left: PairingIdentity, right: PairingIdentity): boolean {
  return (
    left.userId === right.userId &&
    left.username === right.username &&
    left.displayName === right.displayName &&
    left.role === right.role &&
    left.authProvider === right.authProvider &&
    left.authSubject === right.authSubject &&
    left.userGeneration === right.userGeneration &&
    left.authIdentityGeneration === right.authIdentityGeneration &&
    left.authTime === right.authTime
  );
}

function resolvePairingIdentity(consumed: ConsumedPairingCode): PairingIdentity | null {
  const mode = getAuthMode();
  if (
    consumed.authTime !== undefined &&
    (!Number.isSafeInteger(consumed.authTime) ||
      consumed.authTime < 0 ||
      consumed.authTime > Math.floor(Date.now() / 1000))
  ) {
    return null;
  }
  const snapshotValues = [
    consumed.authProvider,
    consumed.authSubject,
    consumed.userGeneration,
    consumed.authIdentityGeneration,
  ];
  const snapshotFieldCount = snapshotValues.filter((value) => value !== undefined).length;

  if (
    snapshotFieldCount !== snapshotValues.length ||
    consumed.authProvider !== mode ||
    !consumed.authSubject ||
    !Number.isSafeInteger(consumed.userGeneration) ||
    consumed.userGeneration! < 1 ||
    !Number.isSafeInteger(consumed.authIdentityGeneration) ||
    consumed.authIdentityGeneration! < 1
  ) {
    return null;
  }
  const resolved = withCanonicalIdentityAuthority((authority) =>
    authority.resolveAuthenticationIdentity({
      userId: consumed.userId,
      userGeneration: consumed.userGeneration!,
      provider: consumed.authProvider!,
      subject: consumed.authSubject!,
      identityGeneration: consumed.authIdentityGeneration!,
    })
  );
  if (!resolved) return null;
  if (resolved.identity.provider === "google" && !isEmailAllowed(resolved.user.username)) {
    return null;
  }
  const pairingIdentity: PairingIdentity = {
    userId: resolved.user.id,
    username: resolved.user.username,
    displayName: resolved.user.displayName,
    role: resolved.user.legacyRole,
    authProvider: resolved.identity.provider,
    authSubject: resolved.identity.subject,
    userGeneration: resolved.user.generation,
    authIdentityGeneration: resolved.identity.generation,
    ...(consumed.authTime !== undefined ? { authTime: consumed.authTime } : {}),
  };
  return pairingSourceAuthenticationIsActive(consumed, pairingIdentity) ? pairingIdentity : null;
}

function pairingSourceAuthenticationIsActive(
  consumed: ConsumedPairingCode,
  identity: PairingIdentity
): boolean {
  if (!consumed.sourceAuthentication) return false;
  return isStoredAuthenticationSessionActive({
    canonicalUserId: identity.userId,
    canonicalUsername: identity.username,
    provider: identity.authProvider,
    credentialJtiDigest: consumed.sourceAuthentication.credentialJtiDigest,
    credentialExpiresAtMs: consumed.sourceAuthentication.credentialExpiresAtMs,
    device: consumed.sourceAuthentication.device,
  });
}
