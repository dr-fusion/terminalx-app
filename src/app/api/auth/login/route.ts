import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { signJwt, comparePassword } from "@/lib/auth";
import { getAuthMode, getSinglePassword } from "@/lib/auth-config";
import { getUserByUsername, updateLastLogin, ensureDefaultAdmin } from "@/lib/users";
import { audit } from "@/lib/audit-log";
import { isRateLimited } from "@/lib/rate-limit";

// ── Cookie helper ───────────────────────────────────────────────────────────

function makeSessionCookie(token: string, req: NextRequest): string {
  const proto = req.headers.get("x-forwarded-proto") || req.nextUrl.protocol.replace(":", "");
  const secure = proto === "https";
  const parts = [
    `terminalx-session=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${24 * 60 * 60}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

// ── POST /api/auth/login ────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  const authMode = getAuthMode();

  if (authMode === "none") {
    return NextResponse.json({ error: "Authentication is disabled" }, { status: 400 });
  }

  let body: { username?: string; password?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { password } = body;
  if (!password || typeof password !== "string") {
    return NextResponse.json({ error: "Password is required" }, { status: 400 });
  }

  // Rate limit per username to prevent brute force without locking out all users.
  // For password mode (no username), rate limit per the literal key "password-mode".
  const rateLimitKey = body.username || "password-mode";
  if (isRateLimited(rateLimitKey)) {
    audit("rate_limited", { username: body.username, detail: "login" });
    return NextResponse.json(
      { error: "Too many login attempts. Try again later." },
      { status: 429 }
    );
  }

  // ── Password mode: single shared password ──
  if (authMode === "password") {
    const expected = getSinglePassword();
    if (!expected) {
      return NextResponse.json(
        { error: "Server misconfigured: TERMINALX_PASSWORD not set" },
        { status: 500 }
      );
    }

    const a = Buffer.from(password);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      audit("login_failed", { detail: "password mode: invalid password" });
      return NextResponse.json({ error: "Invalid password" }, { status: 401 });
    }

    const token = await signJwt({
      userId: "single-user",
      username: "admin",
      role: "admin",
    });

    audit("login_success", { username: "admin", detail: "password mode" });
    const res = NextResponse.json({ success: true, username: "admin" });
    res.headers.set("Set-Cookie", makeSessionCookie(token, req));
    return res;
  }

  // ── Local mode: username + password ──
  if (authMode === "local") {
    const { username } = body;
    if (!username || typeof username !== "string") {
      return NextResponse.json({ error: "Username is required" }, { status: 400 });
    }

    // Ensure default admin exists on first login attempt
    await ensureDefaultAdmin();

    const user = getUserByUsername(username);
    if (!user) {
      audit("login_failed", { username, detail: "unknown user" });
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    const valid = await comparePassword(password, user.passwordHash);
    if (!valid) {
      audit("login_failed", { username, detail: "wrong password" });
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    await updateLastLogin(user.id);

    const token = await signJwt({
      userId: user.id,
      username: user.username,
      role: user.role,
    });

    audit("login_success", { username: user.username, userId: user.id });
    const res = NextResponse.json({
      success: true,
      username: user.username,
      role: user.role,
    });
    res.headers.set("Set-Cookie", makeSessionCookie(token, req));
    return res;
  }

  return NextResponse.json(
    { error: `Auth mode '${authMode}' not supported for login` },
    { status: 400 }
  );
}
