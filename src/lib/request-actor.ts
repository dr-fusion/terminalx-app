import { createHash } from "node:crypto";
import { parseCookies, verifyJwt } from "./auth";
import { getAuthMode } from "./auth-config";

export interface RequestHeaders {
  get(name: string): string | null;
}

/**
 * A freshly verified Terminal X identity. Team and Session authorization must
 * still be resolved by the Team Session module; `legacyRole` is descriptive
 * compatibility data and never grants Team, Project, or Session access.
 */
export interface RequestActor {
  kind: "human";
  userId: string;
  username: string;
  displayName: string;
  legacyRole: string;
  authentication?: {
    provider: "local" | "google" | "password";
    subject: string;
    userGeneration: number;
    identityGeneration: number;
    /** Absent on older JWTs that predate the signed auth_time claim. */
    authenticatedAtMs?: number;
    credentialIssuedAtMs: number;
    credentialExpiresAtMs: number;
    /** SHA-256 of the signed JTI. The raw token identifier never leaves auth. */
    credentialJtiDigest: string;
    device: { provenance: "browser" } | { provenance: "paired-device"; id: string };
  };
}

function bearerToken(headers: RequestHeaders): string | undefined {
  const value = headers.get("authorization") ?? "";
  if (!value.toLowerCase().startsWith("bearer ")) return undefined;
  const token = value.slice(7).trim();
  return token || undefined;
}

/**
 * Resolve an actor from the original cookie or bearer credential and run the
 * complete Node-side JWT verification path. Never trust middleware-projected
 * `x-user-*` headers: those claims may be stale after logout, device/user
 * revocation, role changes, or Google allowlist changes.
 */
export async function resolveRequestActor(headers: RequestHeaders): Promise<RequestActor | null> {
  const authMode = getAuthMode();
  if (authMode === "none") {
    // This module is also used by standalone Next.js route handlers, which do
    // not necessarily pass through the custom server's startup validation.
    // Require both explicit values here so an invalid auth-mode typo cannot
    // silently become an unauthenticated Team Session actor.
    if (
      process.env.TERMINALX_AUTH_MODE !== "none" ||
      process.env.TERMINALX_ALLOW_AUTH_NONE !== "true"
    ) {
      return null;
    }
    return {
      kind: "human",
      userId: "single-user",
      username: "admin",
      displayName: "admin",
      legacyRole: "admin",
    };
  }

  let cookies: Record<string, string>;
  try {
    cookies = parseCookies(headers.get("cookie"));
  } catch {
    return null;
  }
  const token = cookies["terminalx-session"] || bearerToken(headers);
  if (!token) return null;

  const payload = await verifyJwt(token);
  if (!payload?.userId || !payload.username) return null;

  const authentication =
    payload.authProvider &&
    payload.authSubject &&
    payload.userGeneration !== undefined &&
    payload.authIdentityGeneration !== undefined
      ? {
          provider: payload.authProvider,
          subject: payload.authSubject,
          userGeneration: payload.userGeneration,
          identityGeneration: payload.authIdentityGeneration,
          ...(payload.authTime !== undefined ? { authenticatedAtMs: payload.authTime * 1000 } : {}),
          credentialIssuedAtMs: payload.iat * 1000,
          credentialExpiresAtMs: payload.exp * 1000,
          credentialJtiDigest: createHash("sha256").update(payload.jti, "utf8").digest("hex"),
          device: payload.deviceId
            ? { provenance: "paired-device" as const, id: payload.deviceId }
            : { provenance: "browser" as const },
        }
      : undefined;

  return {
    kind: "human",
    userId: payload.userId,
    username: payload.username,
    displayName: payload.displayName || payload.username,
    legacyRole: payload.role,
    ...(authentication ? { authentication } : {}),
  };
}

/**
 * Defense-in-depth admin check for privilege GRANT decisions.
 *
 * Re-derives the actor straight from the session cookie / bearer credential —
 * running the full JWT verification path via {@link resolveRequestActor} — rather
 * than trusting the middleware-projected `x-user-role` header. Callers should AND
 * this with their existing header-derived gate so the decision fails closed if the
 * proxy middleware is ever bypassed, removed, or renamed: a spoofed
 * `x-user-role: admin` header without a valid session can no longer grant admin.
 *
 * Mirrors the pattern already used by the metrics endpoint (see
 * `src/lib/ops/http.ts`). Never throws; any error resolves to `false`.
 */
export async function requireVerifiedAdmin(headers: RequestHeaders): Promise<boolean> {
  try {
    const actor = await resolveRequestActor(headers);
    return actor !== null && actor.legacyRole === "admin";
  } catch {
    return false;
  }
}
