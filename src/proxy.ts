import { NextRequest, NextResponse } from "next/server";
import { audit } from "@/lib/audit-log";
import { externalBaseUrl } from "@/lib/security-config";
import { resolveRequestActor } from "@/lib/request-actor";

function getAuthModeEdge(): "none" | "password" | "local" | "google" {
  const mode = process.env.TERMINALX_AUTH_MODE || "local";
  if (mode === "password" || mode === "local" || mode === "google") {
    return mode;
  }
  return "none";
}

const PUBLIC_EXACT_PATHS = new Set([
  "/login",
  // List specific auth endpoints — anything else under /api/auth/ (e.g.
  // /api/auth/pairing-codes for issuing mobile pair codes) requires auth.
  "/api/auth/login",
  "/api/auth/logout",
  "/api/auth/me",
  "/api/auth/google",
  "/api/auth/google/callback",
  "/api/auth/pair",
  "/api/health",
  // Telegram webhook is gated by its own secret-token header check inside
  // the route handler, so we let it through middleware.
  "/api/telegram/webhook",
  "/favicon.ico",
]);

const PUBLIC_PATH_PREFIXES = ["/_next/"];

function isPublicPath(pathname: string): boolean {
  return (
    PUBLIC_EXACT_PATHS.has(pathname) ||
    PUBLIC_PATH_PREFIXES.some((prefix) => pathname.startsWith(prefix))
  );
}

const USER_HEADER_NAMES = ["x-user-id", "x-user-role", "x-username", "x-device-id"];

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

export async function proxy(req: NextRequest) {
  const authMode = getAuthModeEdge();
  const requestHeaders = sanitizedRequestHeaders(req);

  // No auth required
  if (authMode === "none") {
    return nextWithHeaders(requestHeaders);
  }

  const { pathname } = req.nextUrl;

  // Skip auth for public paths
  if (isPublicPath(pathname)) {
    return nextWithHeaders(requestHeaders);
  }

  const base = externalBaseUrl(req);
  const isApi = pathname.startsWith("/api/");

  const actor = await resolveRequestActor(req.headers);
  if (actor) {
    requestHeaders.set("x-user-id", actor.userId);
    requestHeaders.set("x-user-role", actor.legacyRole);
    requestHeaders.set("x-username", actor.username);
    return nextWithHeaders(requestHeaders);
  }

  audit("jwt_verify_failed", { detail: pathname });
  if (isApi) {
    return NextResponse.json({ error: "Invalid session", authMode }, { status: 401 });
  }
  const response = NextResponse.redirect(new URL("/login", base));
  response.cookies.delete("terminalx-session");
  return response;
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
