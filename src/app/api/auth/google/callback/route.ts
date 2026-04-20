import { NextRequest, NextResponse } from "next/server";
import { signJwt } from "@/lib/auth";
import {
  getAuthMode,
  getGoogleClientId,
  getGoogleClientSecret,
  getGoogleCallbackUrl,
  isEmailAllowed,
} from "@/lib/auth-config";
import { audit } from "@/lib/audit-log";
import { isRateLimited, clientIp } from "@/lib/rate-limit";

interface GoogleTokenResponse {
  access_token: string;
  id_token: string;
  token_type: string;
}

interface GoogleUserInfo {
  sub: string;
  email: string;
  email_verified: boolean;
  name: string;
  picture: string;
}

/** Build the external-facing base URL (respects reverse proxy headers). */
function getExternalBase(req: NextRequest): string {
  const proto = req.headers.get("x-forwarded-proto") || req.nextUrl.protocol.replace(":", "");
  const host = req.headers.get("x-forwarded-host") || req.headers.get("host") || req.nextUrl.host;
  return `${proto}://${host}`;
}

/**
 * GET /api/auth/google/callback — Handles the OAuth2 callback from Google.
 */
export async function GET(req: NextRequest) {
  const base = getExternalBase(req);

  if (getAuthMode() !== "google") {
    return NextResponse.redirect(new URL("/login", base));
  }

  // Rate limit by caller IP to prevent OAuth code-exchange abuse.
  const ip = clientIp(req);
  if (isRateLimited(`oauth-callback:${ip}`)) {
    audit("rate_limited", { detail: `oauth callback ip=${ip}` });
    return NextResponse.redirect(new URL("/login?error=rate_limited", base));
  }

  const { searchParams } = req.nextUrl;
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const errorParam = searchParams.get("error");

  // Handle user denial or errors from Google
  if (errorParam) {
    audit("login_failed", { detail: `google oauth error: ${errorParam}` });
    return NextResponse.redirect(new URL("/login?error=oauth_denied", base));
  }

  if (!code || !state) {
    audit("login_failed", { detail: "google oauth: missing code or state" });
    return NextResponse.redirect(new URL("/login?error=oauth_invalid", base));
  }

  // Validate CSRF state
  const storedState = req.cookies.get("oauth-state")?.value;
  if (!storedState || storedState !== state) {
    audit("login_failed", { detail: "google oauth: state mismatch (CSRF)" });
    return NextResponse.redirect(new URL("/login?error=oauth_invalid", base));
  }

  const clientId = getGoogleClientId();
  const clientSecret = getGoogleClientSecret();
  const callbackPath = getGoogleCallbackUrl();

  // Build absolute redirect URI (must match what was sent to Google)
  const redirectUri = callbackPath.startsWith("http") ? callbackPath : `${base}${callbackPath}`;

  // Exchange authorization code for tokens
  let tokenData: GoogleTokenResponse;
  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
      }),
    });

    if (!tokenRes.ok) {
      const errText = await tokenRes.text();
      audit("login_failed", { detail: `google token exchange failed: ${errText}` });
      return NextResponse.redirect(new URL("/login?error=oauth_failed", base));
    }

    tokenData = await tokenRes.json();
  } catch (err) {
    audit("login_failed", { detail: `google token exchange error: ${err}` });
    return NextResponse.redirect(new URL("/login?error=oauth_failed", base));
  }

  // Fetch user info from Google
  let userInfo: GoogleUserInfo;
  try {
    const userRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    if (!userRes.ok) {
      audit("login_failed", { detail: "google userinfo fetch failed" });
      return NextResponse.redirect(new URL("/login?error=oauth_failed", base));
    }

    userInfo = await userRes.json();
  } catch (err) {
    audit("login_failed", { detail: `google userinfo error: ${err}` });
    return NextResponse.redirect(new URL("/login?error=oauth_failed", base));
  }

  if (!userInfo.email_verified) {
    audit("login_failed", { username: userInfo.email, detail: "email not verified" });
    return NextResponse.redirect(new URL("/login?error=email_not_verified", base));
  }

  // Check allowed email list
  if (!isEmailAllowed(userInfo.email)) {
    audit("login_failed", { username: userInfo.email, detail: "email not in allowed list" });
    return NextResponse.redirect(new URL("/login?error=not_allowed", base));
  }

  // Sign JWT — Google-authenticated users get "admin" role (they're on the allowed list)
  const token = await signJwt({
    userId: `google-${userInfo.sub}`,
    username: userInfo.email,
    role: "admin",
  });

  audit("login_success", { username: userInfo.email, detail: "google oauth" });

  // Set session cookie and clear OAuth state cookie using the cookies API
  // (mixing headers.set("Set-Cookie") with cookies.delete() causes Next.js to clobber the header)
  const loginRedirect = NextResponse.redirect(new URL("/", base));
  const secureCookie = base.startsWith("https");

  loginRedirect.cookies.set("terminalx-session", token, {
    path: "/",
    httpOnly: true,
    sameSite: "lax",
    secure: secureCookie,
    maxAge: 24 * 60 * 60,
  });

  loginRedirect.cookies.delete("oauth-state");

  return loginRedirect;
}
