// Auth configuration — single source of truth for auth-related env vars

export type AuthMode = "none" | "password" | "local" | "google";

export function getAuthMode(): AuthMode {
  const mode = process.env.TERMINALX_AUTH_MODE || "none";
  if (mode === "password" || mode === "local" || mode === "google") {
    return mode;
  }
  return "none";
}

export function getAdminUsername(): string {
  return process.env.TERMINALX_ADMIN_USERNAME || "admin";
}

export function getAdminPassword(): string | undefined {
  return process.env.TERMINALX_ADMIN_PASSWORD;
}

export function getSinglePassword(): string | undefined {
  return process.env.TERMINALX_PASSWORD;
}

// ── Google OAuth Config ────────────────────────────────────────────────────

export function getGoogleClientId(): string {
  return process.env.TERMINALX_GOOGLE_CLIENT_ID || "";
}

export function getGoogleClientSecret(): string {
  return process.env.TERMINALX_GOOGLE_CLIENT_SECRET || "";
}

export function getGoogleCallbackUrl(): string {
  return process.env.TERMINALX_GOOGLE_CALLBACK_URL || "/api/auth/google/callback";
}

/**
 * Comma-separated list of allowed email addresses.
 * If empty, all Google-authenticated users are denied.
 */
export function getAllowedEmails(): string[] {
  const raw = process.env.TERMINALX_ALLOWED_EMAILS || "";
  if (!raw.trim()) return [];
  return raw.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
}

/**
 * Check if an email is in the allowed list.
 */
export function isEmailAllowed(email: string): boolean {
  const allowed = getAllowedEmails();
  if (allowed.length === 0) return false;
  return allowed.includes(email.toLowerCase());
}
