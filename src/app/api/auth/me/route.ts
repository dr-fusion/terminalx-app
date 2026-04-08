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

  // Try headers set by middleware first
  const headerUsername = req.headers.get("x-username");
  const headerRole = req.headers.get("x-user-role");
  if (headerUsername && headerRole) {
    return NextResponse.json({
      username: headerUsername,
      role: headerRole,
      authMode,
    });
  }

  // Fallback: verify JWT directly
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
