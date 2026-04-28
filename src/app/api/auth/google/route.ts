import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { getAuthMode, getGoogleClientId, getGoogleCallbackUrl } from "@/lib/auth-config";
import { externalBaseUrl, isSecureRequest } from "@/lib/security-config";

/**
 * GET /api/auth/google — Redirects to Google's OAuth2 consent screen.
 */
export async function GET(req: NextRequest) {
  if (getAuthMode() !== "google") {
    return NextResponse.json({ error: "Google auth not enabled" }, { status: 400 });
  }

  const clientId = getGoogleClientId();
  if (!clientId) {
    return NextResponse.json({ error: "Google OAuth not configured" }, { status: 500 });
  }

  const base = externalBaseUrl(req);
  const callbackPath = getGoogleCallbackUrl();
  const redirectUri = callbackPath.startsWith("http") ? callbackPath : `${base}${callbackPath}`;

  // Generate CSRF state token
  const state = crypto.randomBytes(32).toString("hex");

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email profile",
    access_type: "online",
    state,
    prompt: "select_account",
  });

  const url = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;

  const response = NextResponse.redirect(url);
  // Store state in cookie for CSRF validation
  response.cookies.set("oauth-state", state, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 600, // 10 minutes
    path: "/",
    secure: isSecureRequest(req),
  });

  return response;
}
