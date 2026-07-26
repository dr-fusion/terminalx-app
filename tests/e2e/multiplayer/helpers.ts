import {
  expect,
  type APIRequestContext,
  type Browser,
  type BrowserContext,
} from "@playwright/test";
import * as crypto from "node:crypto";
import { LOCAL_AUTH_BASE_URL, ALICE_STATE, BOB_STATE } from "./config";

/**
 * Shared helpers for the hermetic local-auth multi-user Playwright suite.
 *
 * Users are seeded by `local-auth-serve.ts` (alice = admin, bob = member). The
 * session cookie is HttpOnly, so we establish a per-user authenticated
 * BrowserContext by POSTing to /api/auth/login through the context's request
 * client, which captures the Set-Cookie into that context's cookie jar. Both the
 * context's pages and its `request` client then share the authenticated jar.
 */

export const USERS = {
  alice: { username: "alice", password: "alice-password-123", role: "admin" as const },
  bob: { username: "bob", password: "bob-password-123", role: "user" as const },
};

export function uniqueSuffix(): string {
  return crypto.randomBytes(6).toString("hex");
}

const STATE_BY_ROLE = { alice: ALICE_STATE, bob: BOB_STATE } as const;

/**
 * Return an authenticated BrowserContext for a seeded user by reusing the
 * storage state captured once in auth.setup.ts (no per-test login → no
 * rate-limiting across the Chromium/WebKit/mobile matrix). Both the context's
 * pages and its `request` client carry the authenticated cookie.
 */
export async function contextFor(
  browser: Browser,
  role: keyof typeof STATE_BY_ROLE
): Promise<BrowserContext> {
  return browser.newContext({ storageState: STATE_BY_ROLE[role] });
}

export interface CommandResult {
  accepted: boolean;
  commandType: string;
  replayed: boolean;
  data: Record<string, unknown>;
  events?: unknown[];
}

/**
 * Submit a Team Session command through the single mutation endpoint. Mirrors the
 * browser client: generates the required Idempotency-Key header and posts to the
 * same-origin command bus. Throws with the server error code on failure.
 */
export async function submitCommand(
  request: APIRequestContext,
  command: Record<string, unknown>,
  idempotencyKey = `e2e-${crypto.randomUUID()}`
): Promise<CommandResult> {
  const res = await request.post("/api/team-sessions/commands", {
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
      // Cookie-authenticated mutations must be same-origin (assertMutationOrigin).
      Origin: LOCAL_AUTH_BASE_URL,
    },
    data: command,
  });
  const json = (await res.json()) as
    | { result: CommandResult }
    | { error: { code: string; message: string } };
  if (!res.ok() || "error" in json) {
    const detail = "error" in json ? `${json.error.code}: ${json.error.message}` : res.status();
    throw new Error(`command ${String(command.type)} failed: ${detail}`);
  }
  return json.result;
}

function requireString(data: Record<string, unknown>, key: string): string {
  const value = data[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`server did not return ${key}`);
  }
  return value;
}

export interface CreatedSession {
  teamId: string;
  projectId: string;
  sessionId: string;
}

/** alice creates team → project → session and returns their server-issued ids. */
export async function createTeamSession(
  request: APIRequestContext,
  names: { team: string; project: string; session: string; steeringPolicy?: "single" | "shared" }
): Promise<CreatedSession> {
  const team = await submitCommand(request, { type: "team.create", name: names.team });
  const teamId = requireString(team.data, "teamId");

  const project = await submitCommand(request, {
    type: "project.create",
    teamId,
    name: names.project,
  });
  const projectId = requireString(project.data, "projectId");

  const session = await submitCommand(request, {
    type: "session.start",
    teamId,
    projectId,
    name: names.session,
    steeringPolicy: names.steeringPolicy ?? "single",
  });
  const sessionId = requireString(session.data, "sessionId");

  return { teamId, projectId, sessionId };
}

export interface SessionDetail {
  viewer: {
    basis: Record<string, number>;
    capabilities: Record<string, boolean>;
  };
  participants: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export async function readSessionDetail(
  request: APIRequestContext,
  sessionId: string
): Promise<SessionDetail> {
  const res = await request.get(`/api/team-sessions/sessions/${encodeURIComponent(sessionId)}`);
  expect(res.ok(), `session detail ${sessionId} should be readable`).toBeTruthy();
  const body = (await res.json()) as { session: SessionDetail };
  return body.session;
}

export async function readAdmission(
  request: APIRequestContext,
  sessionId: string
): Promise<{
  accessRevision: number;
  accessCandidates: Array<{
    invitationId: string;
    userId: string;
    membershipRole: string;
    requiredGrant: string;
    expectedProjectAccessVersion?: number;
  }>;
}> {
  const res = await request.get(
    `/api/team-sessions/sessions/${encodeURIComponent(sessionId)}/admission`
  );
  expect(res.ok(), "admission queue should be readable by a manager").toBeTruthy();
  const body = (await res.json()) as {
    admission: {
      accessRevision: number;
      accessCandidates: Array<{
        invitationId: string;
        userId: string;
        membershipRole: string;
        requiredGrant: string;
        expectedProjectAccessVersion?: number;
      }>;
    };
  };
  return body.admission;
}

export interface AttentionInbox {
  items: Array<{
    itemId: string;
    kind: string;
    sessionId: string;
    itemSequence: number;
    read: boolean;
    summary: string;
  }>;
  unreadCount: number;
  nextCursor: string | null;
}

export async function readAttention(request: APIRequestContext): Promise<AttentionInbox> {
  const res = await request.get("/api/attention");
  expect(res.ok(), "attention inbox should be readable").toBeTruthy();
  const body = (await res.json()) as { inbox: AttentionInbox };
  return body.inbox;
}

export async function markAttentionRead(
  request: APIRequestContext,
  sessionId: string,
  throughSequence: number
): Promise<void> {
  const res = await request.post("/api/attention/read", {
    headers: { "Content-Type": "application/json", Origin: LOCAL_AUTH_BASE_URL },
    data: { sessionId, throughSequence },
  });
  expect(res.ok(), "mark-read should succeed for an active participant").toBeTruthy();
}

/** Resolve the authenticated user's own id via /api/auth/me. */
export async function whoami(request: APIRequestContext): Promise<string> {
  const res = await request.get("/api/auth/me");
  expect(res.ok()).toBeTruthy();
  const body = (await res.json()) as { userId: string };
  return body.userId;
}
