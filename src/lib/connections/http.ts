import { resolveRequestActor, type RequestActor, type RequestHeaders } from "../request-actor";
import { connectionActorSnapshot } from "./request-actor";
import { withConnectionAuthority as defaultWithConnectionAuthority } from "../identity-service";
import type { ConnectionActorSnapshot } from "./contracts";
import type { ConnectionAuthority } from "./authority";

/**
 * HTTP surface for the connection authority (Slice 8E, decision 5). Every mutation
 * runs behind an authenticated request actor and the authority's live-session gate
 * (Team owner/admin authority and revocation checks are enforced inside the
 * authority transaction, not here), and same-origin is required for cookie-auth
 * mutations. Handlers are dependency-injected so they are unit-testable without a
 * live database.
 */
export class ConnectionHttpProblem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "ConnectionHttpProblem";
  }
}

export interface ConnectionHttpDependencies {
  resolveActor?: (headers: RequestHeaders) => Promise<RequestActor | null>;
  withConnectionAuthority?: <T>(operation: (authority: ConnectionAuthority) => T) => T;
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

async function withErrors(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (error) {
    if (error instanceof ConnectionHttpProblem) {
      return jsonResponse({ error: { code: error.code } }, error.status);
    }
    const mapped = mapAuthorityError(error);
    return jsonResponse({ error: { code: mapped.code } }, mapped.status);
  }
}

/**
 * Map an authority Error to an HTTP status without disclosing existence to
 * non-members. Authority/ownership failures and stale/fenced snapshots are 403 or
 * 409; an unavailable authority (no broker/verifier composed, or a closed
 * session) is 404/503; anything else is a generic 400.
 */
function mapAuthorityError(error: unknown): { status: number; code: string } {
  const message = error instanceof Error ? error.message : "";
  if (
    /authority is required|owner or admin|membership is required|owner authority/i.test(message)
  ) {
    return { status: 403, code: "not-authorized" };
  }
  if (
    /authentication session is unavailable|snapshot is stale|Recent primary authentication/i.test(
      message
    )
  ) {
    return { status: 403, code: "authentication-required" };
  }
  if (
    /was fenced|revision is stale|already used|already linked|cannot be transferred/i.test(message)
  ) {
    return { status: 409, code: "conflict" };
  }
  // The broker/verifier-unavailable class is checked before the generic
  // "unavailable"/"not found" mapping so a half-composed credential boundary
  // surfaces as a retryable 503 rather than a 404.
  if (
    /Verified Secret Broker|Verified provider|validation is unavailable|completion is unavailable/i.test(
      message
    )
  ) {
    return { status: 503, code: "connection-unavailable" };
  }
  if (/is unavailable|not found|is required/i.test(message)) {
    return { status: 404, code: "not-found" };
  }
  return { status: 400, code: "invalid-request" };
}

async function requireActor(
  request: Request,
  deps: ConnectionHttpDependencies
): Promise<ConnectionActorSnapshot> {
  const resolve = deps.resolveActor ?? resolveRequestActor;
  const actor = await resolve(request.headers as unknown as RequestHeaders);
  if (!actor) throw new ConnectionHttpProblem(401, "authentication-required", "auth required");
  const snapshot = connectionActorSnapshot(actor);
  // Auth-disabled and legacy credentials cannot register or steer connections.
  if (!snapshot) {
    throw new ConnectionHttpProblem(401, "authentication-required", "canonical identity required");
  }
  return snapshot;
}

function assertMutationOrigin(request: Request): void {
  // A bearer-token (non-cookie) caller is not subject to CSRF; a cookie caller
  // must be same-origin.
  const cookie = request.headers.get("cookie");
  if (!cookie || !cookie.includes("terminalx-session")) return;
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (origin) {
    let originHost: string;
    try {
      originHost = new URL(origin).host;
    } catch {
      throw new ConnectionHttpProblem(403, "forbidden-origin", "bad origin");
    }
    if (host && originHost !== host) {
      throw new ConnectionHttpProblem(403, "forbidden-origin", "cross-origin");
    }
  }
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    throw new ConnectionHttpProblem(400, "invalid-json", "invalid JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new ConnectionHttpProblem(400, "invalid-request", "object body required");
  }
  return body as Record<string, unknown>;
}

function run<T>(
  deps: ConnectionHttpDependencies,
  operation: (authority: ConnectionAuthority) => T
): T {
  return (deps.withConnectionAuthority ?? defaultWithConnectionAuthority)(operation);
}

function positiveInt(value: unknown, code: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new ConnectionHttpProblem(400, code, "invalid version");
  }
  return value as number;
}

function stringSet(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw new ConnectionHttpProblem(400, "invalid-scopes", "scopes must be strings");
  }
  return value as string[];
}

/** Issue a Link Challenge for a Channel Installation (any Team member). */
export async function handleIssueLinkChallenge(
  request: Request,
  deps: ConnectionHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    assertMutationOrigin(request);
    const body = await readJson(request);
    const issued = run(deps, (authority) =>
      authority.issueLinkChallenge({
        actor,
        installationId: String(body.installationId ?? ""),
        expectedInstallationRevision: positiveInt(
          body.expectedInstallationRevision,
          "invalid-revision"
        ),
        requestedScopes: stringSet(body.requestedScopes),
        ...(body.ttlMs === undefined ? {} : { ttlMs: positiveInt(body.ttlMs, "invalid-ttl") }),
      })
    );
    // The raw challenge is returned once; only its digest is persisted.
    return jsonResponse({ linkChallenge: issued });
  });
}

/** Create a Channel Binding (Team owner/admin, enforced in the authority). */
export async function handleCreateBinding(
  request: Request,
  deps: ConnectionHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    assertMutationOrigin(request);
    const body = await readJson(request);
    const binding = run(deps, (authority) =>
      authority.createChannelBinding({
        actor,
        sessionId: String(body.sessionId ?? ""),
        installationId: String(body.installationId ?? ""),
        expectedInstallationRevision: positiveInt(
          body.expectedInstallationRevision,
          "invalid-revision"
        ),
        conversationKind: body.conversationKind as "channel" | "thread" | "topic",
        externalConversationId: String(body.externalConversationId ?? ""),
        ...(body.externalThreadId === undefined
          ? {}
          : { externalThreadId: String(body.externalThreadId) }),
        inboundPolicy: body.inboundPolicy as never,
        outboundPolicy: body.outboundPolicy as never,
      })
    );
    return jsonResponse({ binding }, 201);
  });
}

/** Update a Channel Binding policy (Team owner/admin). */
export async function handleUpdateBinding(
  request: Request,
  bindingId: string,
  deps: ConnectionHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    assertMutationOrigin(request);
    const body = await readJson(request);
    const binding = run(deps, (authority) =>
      authority.updateChannelBinding({
        actor,
        bindingId,
        expectedRevision: positiveInt(body.expectedRevision, "invalid-revision"),
        expectedInstallationRevision: positiveInt(
          body.expectedInstallationRevision,
          "invalid-revision"
        ),
        inboundPolicy: body.inboundPolicy as never,
        outboundPolicy: body.outboundPolicy as never,
      })
    );
    return jsonResponse({ binding });
  });
}

/** Revoke a Channel Binding (Team owner/admin). */
export async function handleRevokeBinding(
  request: Request,
  bindingId: string,
  deps: ConnectionHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    assertMutationOrigin(request);
    const body = await readJson(request);
    const binding = run(deps, (authority) =>
      authority.revokeChannelBinding({
        actor,
        bindingId,
        expectedRevision: positiveInt(body.expectedRevision, "invalid-revision"),
      })
    );
    return jsonResponse({ binding });
  });
}

/** Revoke a Channel Installation (Team owner/admin). */
export async function handleRevokeInstallation(
  request: Request,
  installationId: string,
  deps: ConnectionHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    assertMutationOrigin(request);
    const body = await readJson(request);
    const installation = run(deps, (authority) =>
      authority.revokeChannelInstallation({
        actor,
        installationId,
        expectedRevision: positiveInt(body.expectedRevision, "invalid-revision"),
      })
    );
    return jsonResponse({ installation });
  });
}

/** Revoke an Identity Connection (only the owning User). */
export async function handleRevokeIdentityConnection(
  request: Request,
  connectionId: string,
  deps: ConnectionHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    assertMutationOrigin(request);
    const body = await readJson(request);
    const connection = run(deps, (authority) =>
      authority.revokeIdentityConnection({
        actor,
        connectionId,
        expectedGeneration: positiveInt(body.expectedGeneration, "invalid-generation"),
      })
    );
    return jsonResponse({ connection });
  });
}
