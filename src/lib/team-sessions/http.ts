import { createHash } from "node:crypto";
import { resolveRequestActor, type RequestActor } from "../request-actor";
import { getPublicUrl, isReadOnlyMode, trustProxyHeaders } from "../security-config";
import { isValidTmuxSessionName } from "../tmux";
import { projectPublicSessionEvent } from "./public-event";
import { getTeamSessions } from "./service";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  TeamSessionError,
  type ActorContext,
  type ProjectAccessView,
  type PublicSessionRunStateView,
  type SessionAdmissionView,
  type SessionDetailView,
  type SessionCommand,
  type SessionEvent,
  type SessionInboxItemView,
  type TeamAccessView,
  type TeamSessions,
  type WorkspaceDiscoveryView,
} from "./index";

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_ENTRIES = 2_000;
const RESERVED_COMMAND_FIELDS = new Set(["actor", "schemaVersion", "idempotency"]);
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~:-]{0,127}$/;
const SAFE_IDENTIFIER_PATTERN = /^[^\u0000-\u001f\u007f]{1,300}$/;

type HumanCommandType = Exclude<
  SessionCommand["type"],
  | "runtime.outbox.acknowledge"
  | "runtime.outbox.fail"
  | Extract<SessionCommand["type"], `run.${string}` | `goal.${string}`>
>;

const HUMAN_COMMAND_FIELDS = {
  "team.create": ["name"],
  "project.create": ["teamId", "name", "sourceRef"],
  "team.membership.grant": ["teamId", "userId", "role", "expectedMembershipVersion"],
  "project.access.grant": ["projectId", "userId", "role", "expectedAccessVersion"],
  "project.access.revoke": ["projectId", "userId", "expectedAccessVersion"],
  "team.membership.revoke": ["teamId", "userId", "expectedMembershipVersion"],
  "session.start": ["teamId", "projectId", "name", "steeringPolicy"],
  "session.invitation.create": [
    "sessionId",
    "membershipRole",
    "expiresAtMs",
    "expectedAccessRevision",
  ],
  "session.invitation.revoke": ["sessionId", "invitationId", "expectedInvitationVersion"],
  "session.invitation.redeem": ["token"],
  "session.join": ["sessionId", "invitationId"],
  "session.share.create": ["sessionId", "userId", "expectedAccessRevision"],
  "session.share.revoke": ["sessionId", "userId", "expectedShareVersion"],
  "session.participant.grant": [
    "sessionId",
    "userId",
    "expectedParticipantVersion",
    "expectedAccessRevision",
  ],
  "session.participant.revoke": ["sessionId", "userId", "expectedParticipantVersion"],
  "session.responsibility.grant": [
    "sessionId",
    "userId",
    "responsibility",
    "expectedParticipantVersion",
  ],
  "session.responsibility.revoke": ["sessionId", "userId", "responsibility"],
  "session.control.transfer": [
    "sessionId",
    "userId",
    "expectedControlRevision",
    "expectedControlEpoch",
    "expectedParticipantVersion",
  ],
  "session.control.release": ["sessionId", "expectedControlRevision", "expectedControlEpoch"],
  "session.assignee.claim": ["sessionId", "expectedAssigneeRevision", "expectedAccessRevision"],
  "session.handoff.offer": [
    "sessionId",
    "recipientParticipantId",
    "expectedAssigneeRevision",
    "expectedRecipientParticipantVersion",
    "expectedOffererResponsibilityVersion",
    "expiresAtMs",
    "briefing",
  ],
  "session.handoff.accept": ["sessionId", "handoffId", "expectedHandoffVersion"],
  "session.handoff.cancel": ["sessionId", "handoffId", "expectedHandoffVersion"],
  "comment.add": ["sessionId", "body"],
  "suggestion.add": ["sessionId", "body"],
  "suggestion.resolve": [
    "sessionId",
    "suggestionId",
    "resolution",
    "expectedSuggestionVersion",
    "expectedSteeringRevision",
    "editedBody",
  ],
  "directive.enqueue": ["sessionId", "body", "expectedSteeringRevision"],
} as const satisfies Record<HumanCommandType, readonly string[]>;

/**
 * Command receipts cross a separate trust boundary from the kernel. Keep this
 * list independent from the kernel's result shape so a newly-added internal
 * field is private by default until the HTTP contract deliberately exposes it.
 */
const PUBLIC_COMMAND_RESULT_FIELDS = {
  "team.create": ["teamId"],
  "project.create": ["projectId", "teamId"],
  "team.membership.grant": ["teamId", "userId", "role", "membershipVersion", "previousRole"],
  "project.access.grant": ["projectId", "userId", "role", "accessVersion"],
  "project.access.revoke": ["projectId", "userId"],
  "team.membership.revoke": ["teamId", "userId"],
  "session.start": ["sessionId"],
  "session.invitation.create": [
    "invitationId",
    "sessionId",
    "invitationToken",
    "invitationVersion",
    "accessRevision",
    "invitationTokenUnavailable",
    "recoveryAction",
  ],
  "session.invitation.revoke": ["invitationId", "invitationVersion", "accessRevision"],
  "session.invitation.redeem": [
    "invitationId",
    "invitationVersion",
    "teamId",
    "sessionId",
    "membershipRole",
    "projectAccessGranted",
    "sessionShareGranted",
    "participantGranted",
    "accessRevision",
  ],
  "session.join": ["sessionId", "participantId", "participantVersion", "accessRevision"],
  "session.share.create": ["sessionId", "userId", "shareVersion", "accessRevision"],
  "session.share.revoke": ["sessionId", "userId", "shareVersion", "accessRevision"],
  "session.participant.grant": [
    "sessionId",
    "participantId",
    "participantVersion",
    "accessRevision",
  ],
  "session.participant.revoke": ["sessionId", "userId", "participantVersion", "accessRevision"],
  "session.responsibility.grant": [
    "sessionId",
    "userId",
    "supervisionRevision",
    "steeringRevision",
  ],
  "session.responsibility.revoke": [
    "sessionId",
    "userId",
    "supervisionRevision",
    "steeringRevision",
    "controlRevision",
    "controlEpoch",
  ],
  "session.control.transfer": [
    "sessionId",
    "controllerUserId",
    "steeringRevision",
    "controlRevision",
    "controlEpoch",
  ],
  "session.control.release": ["sessionId", "steeringRevision", "controlRevision", "controlEpoch"],
  "session.assignee.claim": [
    "sessionId",
    "assigneeUserId",
    "assigneeRevision",
    "supervisionRevision",
    "runtimeAuthorizationGeneration",
    "runtimeAuthorizationState",
  ],
  "session.handoff.offer": ["sessionId", "handoffId", "handoffVersion", "expiresAtMs"],
  "session.handoff.accept": [
    "sessionId",
    "handoffId",
    "handoffVersion",
    "handoffAccepted",
    "reason",
    "assigneeUserId",
    "assigneeRevision",
    "supervisionRevision",
    "steeringRevision",
    "controlRevision",
    "controlEpoch",
  ],
  "session.handoff.cancel": ["sessionId", "handoffId", "handoffVersion", "reason"],
  "comment.add": ["sessionId", "commentId", "sequence"],
  "suggestion.add": ["sessionId", "suggestionId", "suggestionVersion", "sequence"],
  "suggestion.resolve": [
    "sessionId",
    "suggestionId",
    "suggestionVersion",
    "resolutionId",
    "resolution",
    "directiveId",
    "directiveStatus",
    "directiveQueueSequence",
  ],
  "directive.enqueue": [
    "sessionId",
    "directiveId",
    "directiveStatus",
    "queueSequence",
    "steeringRevision",
  ],
} as const satisfies Record<HumanCommandType, readonly string[]>;

const RESPONSE_HEADERS = {
  "Cache-Control": "private, no-store",
  Pragma: "no-cache",
  Vary: "Cookie, Authorization",
  "X-Content-Type-Options": "nosniff",
} as const;

interface HttpProblemBody {
  error: {
    code: string;
    message: string;
  };
}

class HttpProblem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly publicMessage: string
  ) {
    super(publicMessage);
    this.name = "HttpProblem";
  }
}

export interface TeamSessionHttpDependencies {
  teamSessions?: TeamSessions;
  resolveActor?: (headers: Headers) => Promise<RequestActor | null>;
  maxBodyBytes?: number;
  isReadOnly?: () => boolean;
  reportInternalError?: (errorName: "InternalError") => void;
}

function jsonResponse(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: RESPONSE_HEADERS });
}

function problemResponse(status: number, code: string, message: string): Response {
  return jsonResponse({ error: { code, message } } satisfies HttpProblemBody, status);
}

function reportInternalError(
  _error: unknown,
  reporter: TeamSessionHttpDependencies["reportInternalError"]
): void {
  const errorName = "InternalError" as const;
  if (reporter) {
    reporter(errorName);
    return;
  }
  // Raw adapter errors can contain paths, process output, or provider details.
  // Keep those values out of both the HTTP response and the default log line.
  console.error(`[team-sessions/http] ${errorName}`);
}

function teamSessionProblem(error: TeamSessionError): HttpProblem {
  switch (error.code) {
    case "invalid-command":
      return new HttpProblem(400, "invalid-request", "Invalid request");
    case "not-found":
    case "not-authorized":
      return new HttpProblem(404, "resource-unavailable", "Resource is unavailable");
    case "conflict":
      return new HttpProblem(409, "state-conflict", "The requested state transition conflicts");
    case "stale-revision":
      return new HttpProblem(409, "stale-revision", "State changed; refresh and retry");
    case "idempotency-conflict":
      return new HttpProblem(
        409,
        "idempotency-conflict",
        "The idempotency key was already used for another request"
      );
    case "invitation-expired":
    case "invitation-revoked":
    case "invitation-used":
      return new HttpProblem(410, "invitation-unavailable", "Invitation is unavailable");
  }
}

async function withHttpErrors(
  dependencies: TeamSessionHttpDependencies,
  work: () => Promise<Response>
): Promise<Response> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof HttpProblem) {
      return problemResponse(error.status, error.code, error.publicMessage);
    }
    if (error instanceof TeamSessionError) {
      const problem = teamSessionProblem(error);
      return problemResponse(problem.status, problem.code, problem.publicMessage);
    }
    reportInternalError(error, dependencies.reportInternalError);
    return problemResponse(500, "internal-error", "Internal server error");
  }
}

async function requireActor(
  request: Request,
  dependencies: TeamSessionHttpDependencies
): Promise<ActorContext> {
  const requestActor = await (dependencies.resolveActor ?? resolveRequestActor)(request.headers);
  if (!requestActor) {
    throw new HttpProblem(401, "authentication-required", "Authentication required");
  }
  return {
    kind: "human",
    userId: requestActor.userId,
    displayName: requestActor.displayName,
  };
}

function sessions(dependencies: TeamSessionHttpDependencies): TeamSessions {
  return dependencies.teamSessions ?? getTeamSessions();
}

/** A stable namespace that cannot be selected or collided by an HTTP client. */
export function deriveHttpIdempotencyScope(userId: string): string {
  const digest = createHash("sha256").update(userId, "utf8").digest("base64url");
  return `http:user:${digest}`;
}

/** Never persist or echo a caller-controlled Idempotency-Key verbatim. */
export function deriveHttpIdempotencyKey(externalKey: string): string {
  const digest = createHash("sha256")
    .update("terminalx-http-idempotency-key-v1\0", "utf8")
    .update(externalKey, "utf8")
    .digest("base64url");
  return `http:key:${digest}`;
}

/**
 * Materialize public resource IDs without mutable server state. The UUID's
 * version and variant bits follow RFC 4122 v4 while its remaining bits are a
 * domain-separated digest of the authenticated caller and idempotent request.
 */
export function deriveHttpResourceId(
  resourceKind: "team" | "project" | "session",
  userId: string,
  internalIdempotencyKey: string
): string {
  const digest = createHash("sha256")
    .update("terminalx-http-resource-id-v1\0", "utf8")
    .update(resourceKind, "utf8")
    .update("\0", "utf8")
    .update(deriveHttpIdempotencyScope(userId), "utf8")
    .update("\0", "utf8")
    .update(internalIdempotencyKey, "utf8")
    .digest()
    .subarray(0, 16);
  digest[6] = (digest[6]! & 0x0f) | 0x40;
  digest[8] = (digest[8]! & 0x3f) | 0x80;
  const hex = digest.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Derive a non-user-selected tmux name from the canonical Session ID. */
export function deriveHttpTmuxName(sessionId: string): string {
  const digest = createHash("sha256")
    .update("terminalx-http-tmux-name-v1\0", "utf8")
    .update(sessionId, "utf8")
    .digest("hex");
  const tmuxName = `txs-${digest.slice(0, 32)}`;
  if (!isValidTmuxSessionName(tmuxName)) {
    throw new Error("Derived tmux name is invalid");
  }
  return tmuxName;
}

function requireIdempotencyKey(request: Request): string {
  const key = request.headers.get("idempotency-key");
  if (!key) {
    throw new HttpProblem(400, "idempotency-key-required", "Idempotency-Key is required");
  }
  if (!IDEMPOTENCY_KEY_PATTERN.test(key)) {
    throw new HttpProblem(400, "invalid-idempotency-key", "Idempotency-Key is invalid");
  }
  return key;
}

function usesSessionCookie(request: Request): boolean {
  return /(?:^|;)\s*terminalx-session=/.test(request.headers.get("cookie") ?? "");
}

/**
 * Browser mutations authenticated by a session cookie must be same-origin.
 * Bearer-only API clients may omit Origin. JSON plus Idempotency-Key also keeps
 * the mutation endpoint outside the browser's "simple request" CSRF surface.
 */
function assertMutationOrigin(request: Request): void {
  if (!usesSessionCookie(request)) return;

  const originValue = request.headers.get("origin");
  if (!originValue || originValue === "null") {
    throw new HttpProblem(403, "cross-origin-request", "Cross-origin request denied");
  }

  let origin: URL;
  let requestUrl: URL;
  try {
    origin = new URL(originValue);
    requestUrl = new URL(request.url);
  } catch {
    throw new HttpProblem(403, "cross-origin-request", "Cross-origin request denied");
  }
  if (
    (origin.protocol !== "http:" && origin.protocol !== "https:") ||
    originValue !== origin.origin
  ) {
    throw new HttpProblem(403, "cross-origin-request", "Cross-origin request denied");
  }

  let expectedOrigin: string;
  const publicUrl = getPublicUrl();
  if (publicUrl) {
    expectedOrigin = new URL(publicUrl).origin;
  } else {
    let expectedHost = request.headers.get("host") ?? requestUrl.host;
    let expectedProtocol = requestUrl.protocol;
    if (trustProxyHeaders()) {
      expectedHost =
        request.headers.get("x-forwarded-host")?.split(",", 1)[0]?.trim() || expectedHost;
      const forwardedProtocol = request.headers
        .get("x-forwarded-proto")
        ?.split(",", 1)[0]
        ?.trim()
        .toLowerCase();
      if (forwardedProtocol === "http" || forwardedProtocol === "https") {
        expectedProtocol = `${forwardedProtocol}:`;
      }
    }
    try {
      expectedOrigin = new URL(`${expectedProtocol}//${expectedHost}`).origin;
    } catch {
      throw new HttpProblem(403, "cross-origin-request", "Cross-origin request denied");
    }
  }
  if (origin.origin !== expectedOrigin) {
    throw new HttpProblem(403, "cross-origin-request", "Cross-origin request denied");
  }
}

function assertJsonRequest(request: Request): void {
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new HttpProblem(415, "unsupported-media-type", "Content-Type must be application/json");
  }
}

function maxBodyBytes(dependencies: TeamSessionHttpDependencies): number {
  const value = dependencies.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isSafeInteger(value) || value < 1 || value > 1024 * 1024) {
    throw new Error("Invalid Team Session HTTP body limit");
  }
  return value;
}

async function readLimitedJson(
  request: Request,
  dependencies: TeamSessionHttpDependencies
): Promise<Record<string, unknown>> {
  assertJsonRequest(request);
  const limit = maxBodyBytes(dependencies);
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new HttpProblem(400, "invalid-content-length", "Content-Length is invalid");
    }
    const declaredLength = Number(contentLength);
    if (!Number.isSafeInteger(declaredLength)) {
      throw new HttpProblem(400, "invalid-content-length", "Content-Length is invalid");
    }
    if (declaredLength > limit) {
      throw new HttpProblem(413, "request-too-large", "Request body is too large");
    }
  }

  if (!request.body) {
    throw new HttpProblem(400, "invalid-json", "Request body must be a JSON object");
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let totalBytes = 0;
  let text = "";
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      totalBytes += chunk.value.byteLength;
      if (totalBytes > limit) {
        try {
          await reader.cancel();
        } catch {
          // The size violation remains authoritative even if cancellation of a
          // broken client stream also fails.
        }
        throw new HttpProblem(413, "request-too-large", "Request body is too large");
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
  } catch (error) {
    if (error instanceof HttpProblem) throw error;
    throw new HttpProblem(400, "invalid-json", "Request body must be valid JSON");
  } finally {
    reader.releaseLock();
  }

  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new HttpProblem(400, "invalid-json", "Request body must be valid JSON");
  }
  if (!isJsonRecord(value)) {
    throw new HttpProblem(400, "invalid-json", "Request body must be a JSON object");
  }
  assertSafeJsonShape(value);
  return value;
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertSafeJsonShape(root: Record<string, unknown>): void {
  const queue: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 0 }];
  let entries = 0;
  while (queue.length > 0) {
    const current = queue.pop();
    if (!current) break;
    if (current.depth > MAX_JSON_DEPTH) {
      throw new HttpProblem(400, "invalid-json", "Request JSON is too deeply nested");
    }
    if (current.value === null || typeof current.value !== "object") continue;

    const values = Array.isArray(current.value)
      ? current.value.map((value, index) => [String(index), value] as const)
      : Object.entries(current.value);
    entries += values.length;
    if (entries > MAX_JSON_ENTRIES) {
      throw new HttpProblem(400, "invalid-json", "Request JSON has too many entries");
    }
    for (const [key, value] of values) {
      if (
        current.depth === 0 &&
        !Array.isArray(current.value) &&
        RESERVED_COMMAND_FIELDS.has(key)
      ) {
        throw new HttpProblem(
          400,
          "reserved-command-field",
          "Request contains a server-owned command field"
        );
      }
      if (key === "__proto__" || key === "prototype" || key === "constructor") {
        throw new HttpProblem(400, "invalid-json", "Request JSON contains an invalid field");
      }
      queue.push({ value, depth: current.depth + 1 });
    }
  }
}

function assertHumanCommandShape(body: Record<string, unknown>): void {
  if (typeof body.type !== "string" || !Object.hasOwn(HUMAN_COMMAND_FIELDS, body.type)) {
    throw new HttpProblem(400, "unsupported-command", "Command type is not supported");
  }

  const type = body.type as HumanCommandType;
  const allowedFields = new Set<string>(["type", "occurredAtMs", ...HUMAN_COMMAND_FIELDS[type]]);
  if (type === "session.responsibility.grant") {
    if (body.responsibility === "supervisor") allowedFields.add("expectedSupervisionRevision");
    if (body.responsibility === "steerer") allowedFields.add("expectedSteeringRevision");
  }
  if (type === "session.responsibility.revoke") {
    if (body.responsibility === "supervisor") allowedFields.add("expectedSupervisionRevision");
    if (body.responsibility === "steerer") {
      allowedFields.add("expectedSteeringRevision");
      allowedFields.add("expectedControlRevision");
      allowedFields.add("expectedControlEpoch");
    }
  }

  if (Object.keys(body).some((field) => !allowedFields.has(field))) {
    throw new HttpProblem(
      400,
      "unknown-command-field",
      "Request contains an unknown command field"
    );
  }
  if (type === "session.handoff.offer" && body.briefing !== undefined) {
    assertHandoffBriefingShape(body.briefing);
  }
  if (type === "suggestion.resolve") {
    assertSuggestionResolutionShape(body);
  }
}

function assertSuggestionResolutionShape(body: Record<string, unknown>): void {
  if (body.resolution === "accept-edited") {
    if (typeof body.editedBody === "string") return;
    throw new HttpProblem(400, "invalid-request", "Invalid request");
  }
  if (body.resolution === "accept" || body.resolution === "reject") {
    if (!Object.hasOwn(body, "editedBody")) return;
    throw new HttpProblem(400, "invalid-request", "Invalid request");
  }
  throw new HttpProblem(400, "invalid-request", "Invalid request");
}

function assertHandoffBriefingShape(value: unknown): void {
  if (!isJsonRecord(value)) {
    throw new HttpProblem(400, "invalid-briefing", "Handoff briefing is invalid");
  }
  const allowedFields = new Set(["summary", "blockers", "artifactRefs"]);
  if (Object.keys(value).some((field) => !allowedFields.has(field))) {
    throw new HttpProblem(400, "unknown-briefing-field", "Handoff briefing has an unknown field");
  }
  if (typeof value.summary !== "string") {
    throw new HttpProblem(400, "invalid-briefing", "Handoff briefing is invalid");
  }
  assertOptionalStringArray(value.blockers);
  assertOptionalStringArray(value.artifactRefs);
}

function assertOptionalStringArray(value: unknown): void {
  if (value === undefined) return;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new HttpProblem(400, "invalid-briefing", "Handoff briefing is invalid");
  }
}

function requireIdentifier(value: string, label: string): string {
  if (!SAFE_IDENTIFIER_PATTERN.test(value) || value.trim() !== value) {
    throw new HttpProblem(400, "invalid-identifier", `${label} is invalid`);
  }
  return value;
}

function materializePublicCreateFields(
  body: Record<string, unknown>,
  actor: ActorContext,
  internalIdempotencyKey: string
): Record<string, unknown> {
  switch (body.type) {
    case "team.create":
      return {
        ...body,
        teamId: deriveHttpResourceId("team", actor.userId, internalIdempotencyKey),
      };
    case "project.create":
      return {
        ...body,
        projectId: deriveHttpResourceId("project", actor.userId, internalIdempotencyKey),
      };
    case "session.start": {
      const sessionId = deriveHttpResourceId("session", actor.userId, internalIdempotencyKey);
      return {
        ...body,
        sessionId,
        tmuxName: deriveHttpTmuxName(sessionId),
      };
    }
    default:
      return body;
  }
}

function singleSearchParam(request: Request, name: string): string | undefined {
  const values = new URL(request.url).searchParams.getAll(name);
  if (values.length > 1) {
    throw new HttpProblem(400, "invalid-query", `${name} may only be supplied once`);
  }
  return values[0];
}

function projectPublicCommandResultData(
  commandType: HumanCommandType,
  data: Record<string, unknown>,
  replayed: boolean
): Record<string, unknown> {
  // A replay can become invisible after access is revoked. Do not combine the
  // marker with stale identifiers or receipt data from the original response.
  if (Object.hasOwn(data, "receiptUnavailable")) {
    if (data.receiptUnavailable !== true) throw invalidPublicCommandResult();
    return { receiptUnavailable: true };
  }

  const projected: Record<string, unknown> = {};
  for (const field of PUBLIC_COMMAND_RESULT_FIELDS[commandType]) {
    // Invitation tokens are the sole secret-shaped receipt value and are only
    // returned on the successful first response. Kernel replays instead expose
    // the closed unavailable/recovery markers listed above.
    if (field === "invitationToken" && replayed) continue;
    if (!Object.hasOwn(data, field)) continue;
    const value = data[field];
    if (!isPublicCommandResultScalar(value)) throw invalidPublicCommandResult();
    projected[field] = value;
  }
  return projected;
}

function isPublicCommandResultScalar(value: unknown): value is string | number | boolean {
  return (
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  );
}

function invalidPublicCommandResult(): Error {
  // The HTTP error adapter intentionally reports only the closed InternalError
  // class, never the malformed value or any potentially sensitive nested data.
  return new Error("Team Session kernel returned invalid public receipt data");
}

function optionalNonNegativeInteger(
  request: Request,
  name: string,
  maximum = Number.MAX_SAFE_INTEGER
): number | undefined {
  const value = singleSearchParam(request, name);
  if (value === undefined) return undefined;
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new HttpProblem(400, "invalid-query", `${name} is invalid`);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number > maximum) {
    throw new HttpProblem(400, "invalid-query", `${name} is invalid`);
  }
  return number;
}

export async function handleTeamSessionCommand(
  request: Request,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    assertMutationOrigin(request);
    if ((dependencies.isReadOnly ?? isReadOnlyMode)()) {
      throw new HttpProblem(403, "read-only", "Server is read-only");
    }
    const idempotencyKey = requireIdempotencyKey(request);
    const body = await readLimitedJson(request, dependencies);
    assertHumanCommandShape(body);
    const internalIdempotencyKey = deriveHttpIdempotencyKey(idempotencyKey);
    const command = {
      ...materializePublicCreateFields(body, actor, internalIdempotencyKey),
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      idempotency: {
        scope: deriveHttpIdempotencyScope(actor.userId),
        key: internalIdempotencyKey,
      },
    } as unknown as SessionCommand;
    const result = await sessions(dependencies).dispatch(command);
    const commandType = body.type as HumanCommandType;
    if (result.commandType !== commandType) {
      throw new Error("Team Session kernel returned a mismatched command receipt");
    }
    return jsonResponse({
      result: {
        accepted: result.accepted,
        commandType,
        replayed: result.replayed,
        data: projectPublicCommandResultData(commandType, result.data, result.replayed),
        events: result.events.map(projectPublicSessionEvent),
      },
    });
  });
}

export async function handleSessionList(
  request: Request,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    const rawTeamId = singleSearchParam(request, "teamId");
    const teamId = rawTeamId === undefined ? undefined : requireIdentifier(rawTeamId, "Team id");
    const visibleSessions: SessionInboxItemView[] = await sessions(dependencies).inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.inbox",
      actor,
      teamId,
    });
    return jsonResponse({ sessions: visibleSessions });
  });
}

export async function handleSessionGet(
  request: Request,
  sessionId: string,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    const visibleSession: SessionDetailView | null = await sessions(dependencies).inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.detail",
      actor,
      sessionId: requireIdentifier(sessionId, "Session id"),
    });
    if (!visibleSession) {
      throw new HttpProblem(404, "resource-unavailable", "Resource is unavailable");
    }
    return jsonResponse({ session: visibleSession });
  });
}

export async function handleSessionRunState(
  request: Request,
  sessionId: string,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    const normalizedSessionId = requireIdentifier(sessionId, "Session id");
    const runState: PublicSessionRunStateView | null = await sessions(dependencies).inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.public-run-state",
      actor,
      sessionId: normalizedSessionId,
    });
    if (!runState) {
      throw new HttpProblem(404, "resource-unavailable", "Resource is unavailable");
    }
    return jsonResponse({ runState });
  });
}

export async function handleWorkspaceDiscovery(
  request: Request,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    const discovery: WorkspaceDiscoveryView = await sessions(dependencies).inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "workspace.discovery",
      actor,
    });
    return jsonResponse({ discovery });
  });
}

export async function handleSessionEvents(
  request: Request,
  sessionId: string,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    const afterSequence = optionalNonNegativeInteger(request, "afterSequence");
    const limit = optionalNonNegativeInteger(request, "limit", 1_000);
    if (limit === 0) {
      throw new HttpProblem(400, "invalid-query", "limit is invalid");
    }
    const events: SessionEvent[] = await sessions(dependencies).inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.events",
      actor,
      sessionId: requireIdentifier(sessionId, "Session id"),
      afterSequence,
      limit,
    });
    return jsonResponse({ events: events.map(projectPublicSessionEvent) });
  });
}

export async function handleSessionAdmission(
  request: Request,
  sessionId: string,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    const admission: SessionAdmissionView = await sessions(dependencies).inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.admission",
      actor,
      sessionId: requireIdentifier(sessionId, "Session id"),
    });
    return jsonResponse({ admission });
  });
}

export async function handleTeamAccess(
  request: Request,
  teamId: string,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    const team: TeamAccessView = await sessions(dependencies).inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "team.access",
      actor,
      teamId: requireIdentifier(teamId, "Team id"),
    });
    return jsonResponse({ team });
  });
}

export async function handleProjectAccess(
  request: Request,
  projectId: string,
  dependencies: TeamSessionHttpDependencies = {}
): Promise<Response> {
  return withHttpErrors(dependencies, async () => {
    const actor = await requireActor(request, dependencies);
    const project: ProjectAccessView = await sessions(dependencies).inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "project.access",
      actor,
      projectId: requireIdentifier(projectId, "Project id"),
    });
    return jsonResponse({ project });
  });
}
