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
    // Production startup rejects `none`; retain the legacy development actor
    // so tests and explicitly unsupported local setups remain deterministic.
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

  return {
    kind: "human",
    userId: payload.userId,
    username: payload.username,
    displayName: payload.username,
    legacyRole: payload.role,
  };
}
