import { NextRequest, NextResponse } from "next/server";
import { revokeToken, verifyJwt } from "@/lib/auth";
import { audit } from "@/lib/audit-log";

export async function POST(req: NextRequest) {
  const cookieToken = req.cookies.get("terminalx-session")?.value;
  const authorization = req.headers.get("authorization") ?? "";
  const bearerToken = authorization.toLowerCase().startsWith("bearer ")
    ? authorization.slice(7).trim()
    : undefined;
  const token = cookieToken || bearerToken;
  const actor = token ? await verifyJwt(token) : null;

  // Only persist a revocation for a currently valid token. The endpoint is
  // public so clients can always clear a bad cookie; accepting arbitrary JTIs
  // here would let anonymous callers grow the revocation store indefinitely.
  if (token && actor) {
    revokeToken(token);
  }

  audit("logout", { username: actor?.username, userId: actor?.userId });

  const res = NextResponse.json(
    { success: true },
    { headers: { "Cache-Control": "no-store, max-age=0" } }
  );
  res.headers.set("Set-Cookie", "terminalx-session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
  return res;
}
