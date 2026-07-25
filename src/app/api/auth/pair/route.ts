import { NextRequest, NextResponse } from "next/server";
import { signJwt } from "@/lib/auth";
import { getAuthMode, isEmailAllowed } from "@/lib/auth-config";
import { withCanonicalIdentityAuthority } from "@/lib/identity-service";
import { consumePairingCode, type ConsumedPairingCode } from "@/lib/pairing";
import { registerDevice, revokeDevice } from "@/lib/devices";
import { getLocalAuthenticationIdentity } from "@/lib/users";
import { audit } from "@/lib/audit-log";
import { isRateLimited } from "@/lib/rate-limit";
import { trustProxyHeaders } from "@/lib/security-config";

// POST /api/auth/pair
// Public endpoint. Body: { code, deviceName }. Exchanges a one-time pairing
// code (created by the web app via POST /api/auth/pairing-codes) for a 24h
// JWT scoped to the new device. The device row is persisted so it can be
// revoked from web settings — verifyJwt() rejects tokens whose device has
// been revoked.
export async function POST(req: NextRequest) {
  // Rate-limit pair attempts per source IP to slow brute force of the code
  // space (even though codes are 24 bytes of randomness, this is cheap insurance).
  const ip = trustProxyHeaders()
    ? req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      req.headers.get("x-real-ip") ||
      "unknown"
    : "direct-client";
  if (isRateLimited(`pair:${ip}`)) {
    audit("rate_limited", { detail: `pair from ${ip}` });
    return NextResponse.json({ error: "Too many attempts. Try again later." }, { status: 429 });
  }

  let body: { code?: unknown; deviceName?: unknown };
  try {
    body = (await req.json()) as { code?: unknown; deviceName?: unknown };
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const code = typeof body.code === "string" ? body.code.trim() : "";
  const deviceName =
    typeof body.deviceName === "string" && body.deviceName.trim()
      ? body.deviceName.trim()
      : "Mobile device";
  if (!code) {
    return NextResponse.json({ error: "Missing pairing code" }, { status: 400 });
  }

  const consumed = await consumePairingCode(code);
  if (!consumed) {
    audit("pair_failed", { detail: "invalid or expired code" });
    return NextResponse.json({ error: "Invalid or expired code" }, { status: 401 });
  }

  const identity = resolvePairingIdentity(consumed);
  if (!identity) {
    audit("pair_failed", { detail: "pairing identity is no longer authorized" });
    return NextResponse.json({ error: "Invalid or expired code" }, { status: 401 });
  }

  const device = await registerDevice({
    userId: identity.userId,
    username: identity.username,
    name: deviceName,
  });

  // Device storage is a separate durability boundary from canonical identity
  // state. Re-resolve after that write and revoke the new row before issuing a
  // credential if revocation, a generation change, or an auth-mode change won
  // the race. Every later token use is generation-fenced again by verifyJwt.
  const identityAfterRegistration = resolvePairingIdentity(consumed);
  if (!identityAfterRegistration || !samePairingIdentity(identity, identityAfterRegistration)) {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", { detail: "pairing identity changed during device registration" });
    return NextResponse.json({ error: "Invalid or expired code" }, { status: 401 });
  }

  let token: string;
  try {
    token = await signJwt({
      ...identity,
      deviceId: device.id,
    });
  } catch {
    await revokeDevice(device.id, identity.userId).catch(() => false);
    audit("pair_failed", { detail: "device credential issuance failed" });
    return NextResponse.json({ error: "Invalid or expired code" }, { status: 401 });
  }

  // signJwt sets 24h expiry — surface that so the client can show countdown.
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
  audit("pair_success", { username: identity.username, detail: device.id });

  return NextResponse.json(
    {
      token,
      expiresAt,
      deviceId: device.id,
      user: { id: identity.userId, name: identity.username },
    },
    { headers: { "Cache-Control": "no-store, max-age=0" } }
  );
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
    left.authIdentityGeneration === right.authIdentityGeneration
  );
}

function resolvePairingIdentity(consumed: ConsumedPairingCode): PairingIdentity | null {
  const mode = getAuthMode();
  const snapshotValues = [
    consumed.authProvider,
    consumed.authSubject,
    consumed.userGeneration,
    consumed.authIdentityGeneration,
  ];
  const snapshotFieldCount = snapshotValues.filter((value) => value !== undefined).length;

  if (snapshotFieldCount > 0) {
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
    return {
      userId: resolved.user.id,
      username: resolved.user.username,
      displayName: resolved.user.displayName,
      role: resolved.user.legacyRole,
      authProvider: resolved.identity.provider,
      authSubject: resolved.identity.subject,
      userGeneration: resolved.user.generation,
      authIdentityGeneration: resolved.identity.generation,
    };
  }

  if (
    mode !== "local" ||
    consumed.userId === "single-user" ||
    consumed.userId.startsWith("google-")
  ) {
    return null;
  }
  const resolved = getLocalAuthenticationIdentity(consumed.userId);
  if (!resolved) return null;
  return {
    userId: resolved.user.id,
    username: resolved.user.username,
    displayName: resolved.user.displayName,
    role: resolved.user.legacyRole,
    authProvider: resolved.identity.provider,
    authSubject: resolved.identity.subject,
    userGeneration: resolved.user.generation,
    authIdentityGeneration: resolved.identity.generation,
  };
}
