import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from "jose";
import { audit } from "@/lib/audit-log";

// Next.js edge middleware cannot use Node.js APIs, so we inline the secret
// logic here (reads env var only; file-based fallback is server-side only).

function getJwtSecretEdge(): Uint8Array | null {
  const secret = process.env.TERMINALX_JWT_SECRET;
  if (!secret) return null;
  return new TextEncoder().encode(secret);
}

function getAuthModeEdge(): "none" | "password" | "local" | "google" {
  const mode = process.env.TERMINALX_AUTH_MODE || "none";
  if (mode === "password" || mode === "local" || mode === "google") {
    return mode;
  }
  return "none";
}

const PUBLIC_PATHS = [
  "/login",
  "/api/auth/",
  "/api/auth/google",
  "/api/auth/google/callback",
  "/api/health",
  "/_next/",
  "/favicon.ico",
];

/**
 * Strip user identity headers to prevent spoofing from untrusted clients.
 * These headers are only set by the middleware itself after JWT verification.
 */
function stripUserHeaders(response: NextResponse): NextResponse {
  response.headers.set("x-user-id", "");
  response.headers.set("x-user-role", "");
  response.headers.set("x-username", "");
  return response;
}

export async function middleware(req: NextRequest) {
  const authMode = getAuthModeEdge();

  // No auth required
  if (authMode === "none") {
    return stripUserHeaders(NextResponse.next());
  }

  const { pathname } = req.nextUrl;

  // Skip auth for public paths
  for (const p of PUBLIC_PATHS) {
    if (pathname === p || pathname.startsWith(p)) {
      return stripUserHeaders(NextResponse.next());
    }
  }

  // Build external-facing base URL for redirects (behind reverse proxy)
  const proto = req.headers.get("x-forwarded-proto") || req.nextUrl.protocol.replace(":", "");
  const host = req.headers.get("x-forwarded-host") || req.headers.get("host") || req.nextUrl.host;
  const base = `${proto}://${host}`;

  // Parse JWT from cookie
  const token = req.cookies.get("terminalx-session")?.value;
  if (!token) {
    return stripUserHeaders(NextResponse.redirect(new URL("/login", base)));
  }

  const secret = getJwtSecretEdge();
  if (!secret) {
    return stripUserHeaders(NextResponse.redirect(new URL("/login", base)));
  }

  try {
    const { payload } = await jwtVerify(token, secret);
    const response = NextResponse.next();
    response.headers.set("x-user-id", (payload.userId as string) || "");
    response.headers.set("x-user-role", (payload.role as string) || "");
    response.headers.set("x-username", (payload.username as string) || "");
    return response;
  } catch (err) {
    const reason = err instanceof Error ? err.message : "unknown";
    audit("jwt_verify_failed", { detail: `${pathname} :: ${reason}` });
    const response = NextResponse.redirect(new URL("/login", base));
    response.cookies.delete("terminalx-session");
    return stripUserHeaders(response);
  }
}

export const config = {
  matcher: [
    /*
     * Match all paths except static files.
     * _next/static and _next/image are handled by Next.js.
     */
    "/((?!_next/static|_next/image).*)",
  ],
};
