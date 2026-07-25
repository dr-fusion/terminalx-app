import { NextRequest, NextResponse } from "next/server";
import { createPairingCode } from "@/lib/pairing";
import { audit } from "@/lib/audit-log";
import { resolveRequestActor } from "@/lib/request-actor";

const NO_STORE_HEADERS = { "Cache-Control": "no-store, max-age=0" } as const;

// POST /api/auth/pairing-codes
// Authenticated (via middleware, cookie or Bearer). Returns a short-lived
// single-use code that a mobile client can redeem at POST /api/auth/pair to
// receive a 24h device-scoped JWT.
export async function POST(req: NextRequest) {
  const actor = await resolveRequestActor(req.headers);
  if (!actor) {
    return pairingCodeError("Not authenticated", 401);
  }
  if (!actor.authentication) {
    return pairingCodeError("Sign in again before pairing a device", 401);
  }

  let created: Awaited<ReturnType<typeof createPairingCode>>;
  try {
    created = await createPairingCode({
      userId: actor.userId,
      username: actor.username,
      displayName: actor.displayName,
      role: actor.legacyRole,
      authProvider: actor.authentication.provider,
      authSubject: actor.authentication.subject,
      userGeneration: actor.authentication.userGeneration,
      authIdentityGeneration: actor.authentication.identityGeneration,
      sourceAuthentication: {
        credentialJtiDigest: actor.authentication.credentialJtiDigest,
        credentialExpiresAtMs: actor.authentication.credentialExpiresAtMs,
        device: actor.authentication.device,
      },
      ...(actor.authentication.authenticatedAtMs !== undefined
        ? { authTime: actor.authentication.authenticatedAtMs / 1000 }
        : {}),
    });
  } catch (error) {
    const retryAfterSeconds = pairingIssuanceRetryAfterSeconds(error);
    if (retryAfterSeconds !== null) {
      audit("rate_limited", {
        username: actor.username,
        userId: actor.userId,
        detail: "pairing code issuance",
      });
      return pairingCodeError("Too many pairing codes requested. Try again later.", 429, {
        "Retry-After": String(retryAfterSeconds),
      });
    }
    audit("pair_failed", {
      username: actor.username,
      userId: actor.userId,
      detail: "pairing code persistence unavailable",
    });
    return pairingCodeError("Pairing state is temporarily unavailable. Try again.", 503);
  }

  audit("pairing_code_created", { username: actor.username, userId: actor.userId });
  return NextResponse.json(created, { headers: NO_STORE_HEADERS });
}

function pairingCodeError(error: string, status: number, headers?: Record<string, string>) {
  return NextResponse.json(
    { error },
    { status, headers: { ...NO_STORE_HEADERS, ...(headers ?? {}) } }
  );
}

function pairingIssuanceRetryAfterSeconds(error: unknown): number | null {
  if (typeof error !== "object" || error === null) return null;
  const candidate = error as Record<string, unknown>;
  const isIssuanceLimit =
    candidate.name === "PairingIssuanceLimitError" ||
    candidate.code === "PAIRING_ISSUANCE_LIMIT" ||
    candidate.code === "pairing_issuance_limit";
  const retryAfterSeconds = candidate.retryAfterSeconds;
  if (
    !isIssuanceLimit ||
    typeof retryAfterSeconds !== "number" ||
    !Number.isSafeInteger(retryAfterSeconds) ||
    retryAfterSeconds < 1
  ) {
    return null;
  }
  return retryAfterSeconds;
}
