import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from "jose";
import { audit } from "@/lib/audit-log";
import { externalBaseUrl } from "@/lib/security-config";

// Next.js edge middleware cannot use Node.js APIs, so we inline the secret
// logic here (reads env var only; file-based fallback is server-side only).

function getJwtSecretEdge(): Uint8Array | null {
  const secret = process.env.TERMINALX_JWT_SECRET;
  if (!secret) return null;
  return new TextEncoder().encode(secret);
}

function getAuthModeEdge(): "none" | "password" | "local" | "google" {
  const mode = process.env.TERMINALX_AUTH_MODE || "local";
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
  // Telegram webhook is gated by its own secret-token header check inside
  // the route handler, so we let it through middleware.
  "/api/telegram/webhook",
  "/_next/",
  "/favicon.ico",
];

const USER_HEADER_NAMES = ["x-user-id", "x-user-role", "x-username"];

function sanitizedRequestHeaders(req: NextRequest): Headers {
  const headers = new Headers(req.headers);
  for (const name of USER_HEADER_NAMES) {
    headers.delete(name);
  }
  return headers;
}

function nextWithHeaders(headers: Headers): NextResponse {
  return NextResponse.next({ request: { headers } });
}

export async function middleware(req: NextRequest) {
  const authMode = getAuthModeEdge();
  const requestHeaders = sanitizedRequestHeaders(req);

  // No auth required
  if (authMode === "none") {
    return nextWithHeaders(requestHeaders);
  }

  const { pathname } = req.nextUrl;

  // Skip auth for public paths
  for (const p of PUBLIC_PATHS) {
    if (pathname === p || pathname.startsWith(p)) {
      return nextWithHeaders(requestHeaders);
    }
  }

  const base = externalBaseUrl(req);

  // Parse JWT from cookie
  const token = req.cookies.get("terminalx-session")?.value;
  if (!token) {
    return NextResponse.redirect(new URL("/login", base));
  }

  const secret = getJwtSecretEdge();
  if (!secret) {
    return NextResponse.redirect(new URL("/login", base));
  }

  try {
    const { payload } = await jwtVerify(token, secret);
    requestHeaders.set("x-user-id", (payload.userId as string) || "");
    requestHeaders.set("x-user-role", (payload.role as string) || "");
    requestHeaders.set("x-username", (payload.username as string) || "");
    return nextWithHeaders(requestHeaders);
  } catch (err) {
    const reason = err instanceof Error ? err.message : "unknown";
    audit("jwt_verify_failed", { detail: `${pathname} :: ${reason}` });
    const response = NextResponse.redirect(new URL("/login", base));
    response.cookies.delete("terminalx-session");
    return response;
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
