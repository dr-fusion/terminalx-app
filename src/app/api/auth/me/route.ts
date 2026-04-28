import { NextRequest, NextResponse } from "next/server";
import { verifyJwt, parseCookies } from "@/lib/auth";
import { getAuthMode } from "@/lib/auth-config";

export async function GET(req: NextRequest) {
  const authMode = getAuthMode();

  if (authMode === "none") {
    return NextResponse.json({
      username: "admin",
      role: "admin",
      authMode: "none",
    });
  }

  // This route is intentionally public so the login page can call it. Do not
  // trust identity headers here; verify the session cookie directly.
  const cookieHeader = req.headers.get("cookie");
  const cookies = parseCookies(cookieHeader);
  const token = cookies["terminalx-session"];
  if (!token) {
    return NextResponse.json({ error: "Not authenticated", authMode }, { status: 401 });
  }

  const payload = await verifyJwt(token);
  if (!payload) {
    return NextResponse.json({ error: "Invalid session", mode: authMode }, { status: 401 });
  }

  return NextResponse.json({
    username: payload.username,
    role: payload.role,
    authMode,
  });
}
