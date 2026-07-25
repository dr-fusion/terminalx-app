import { NextRequest, NextResponse } from "next/server";
import { revokeToken } from "@/lib/auth";
import { audit } from "@/lib/audit-log";

export async function POST(req: NextRequest) {
  const cookieToken = req.cookies.get("terminalx-session")?.value;
  const authorization = req.headers.get("authorization") ?? "";
  const bearerToken = authorization.toLowerCase().startsWith("bearer ")
    ? authorization.slice(7).trim()
    : undefined;
  const token = cookieToken || bearerToken;
  let revocation: Awaited<ReturnType<typeof revokeToken>> = null;

  // revokeToken verifies the signature, registered claims, and validity window
  // without relying on mutable authorization state, then fsyncs a digest-only tombstone.
  // Never clear the cookie or report success if that durable write fails: a
  // copied bearer token would otherwise remain live outside the browser.
  if (token) {
    try {
      revocation = await revokeToken(token);
    } catch {
      audit("logout_failed", { detail: "token revocation persistence unavailable" });
      return NextResponse.json(
        { success: false, error: "Logout could not be completed safely. Try again." },
        { status: 503, headers: { "Cache-Control": "no-store, max-age=0" } }
      );
    }
  }

  audit("logout", { username: revocation?.username, userId: revocation?.userId });

  const res = NextResponse.json(
    { success: true },
    { headers: { "Cache-Control": "no-store, max-age=0" } }
  );
  res.headers.set("Set-Cookie", "terminalx-session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
  return res;
}
