import { NextRequest, NextResponse } from "next/server";
import { createPairingCode } from "@/lib/pairing";
import { audit } from "@/lib/audit-log";
import { resolveRequestActor } from "@/lib/request-actor";

// POST /api/auth/pairing-codes
// Authenticated (via middleware, cookie or Bearer). Returns a short-lived
// single-use code that a mobile client can redeem at POST /api/auth/pair to
// receive a 24h device-scoped JWT.
export async function POST(req: NextRequest) {
  const actor = await resolveRequestActor(req.headers);
  if (!actor) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const { code, expiresAt } = await createPairingCode({
    userId: actor.userId,
    username: actor.username,
    displayName: actor.displayName,
    role: actor.legacyRole,
    ...(actor.authentication
      ? {
          authProvider: actor.authentication.provider,
          authSubject: actor.authentication.subject,
          userGeneration: actor.authentication.userGeneration,
          authIdentityGeneration: actor.authentication.identityGeneration,
        }
      : {}),
  });

  audit("pairing_code_created", { username: actor.username, userId: actor.userId });
  return NextResponse.json(
    { code, expiresAt },
    { headers: { "Cache-Control": "no-store, max-age=0" } }
  );
}
