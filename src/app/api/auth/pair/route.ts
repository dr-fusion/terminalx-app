import { NextRequest, NextResponse } from "next/server";
import { signJwt } from "@/lib/auth";
import { consumePairingCode } from "@/lib/pairing";
import { registerDevice } from "@/lib/devices";
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

  const device = await registerDevice({
    userId: consumed.userId,
    username: consumed.username,
    name: deviceName,
  });

  const token = await signJwt({
    userId: consumed.userId,
    username: consumed.username,
    role: consumed.role,
    deviceId: device.id,
  });

  // signJwt sets 24h expiry — surface that so the client can show countdown.
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
  audit("pair_success", { username: consumed.username, detail: device.id });

  return NextResponse.json(
    {
      token,
      expiresAt,
      deviceId: device.id,
      user: { id: consumed.userId, name: consumed.username },
    },
    { headers: { "Cache-Control": "no-store, max-age=0" } }
  );
}
