import type { ActorContext, SessionEvent } from "./types";

const MAX_PUBLIC_EVENT_DEPTH = 16;
const MAX_PUBLIC_EVENT_ENTRIES = 1_000;
const REDACTED_VALUE = "[redacted]";
const GENERIC_ACTIVITY_TYPE = "session.activity";
const PUBLIC_SYSTEM_ACTOR: ActorContext = Object.freeze({
  kind: "system",
  userId: "session-system",
  displayName: "Session system",
});

/**
 * Activity types whose names and initiating, already-authorized Human are
 * useful to the shared conversation UI. Their kernel payloads are never
 * public: current Session detail is the authorization source of truth.
 *
 * Admission administration is deliberately absent. In particular,
 * Invitation, Team Membership, Project Access, Session Share, and revision
 * events fall through to an anonymous `session.activity` placeholder. That
 * keeps the Session sequence gap-free without disclosing pending identities
 * or administration-ledger identifiers.
 */
const PUBLIC_ACTIVITY_TYPES = new Set([
  "directive.cancelled",
  "session.control.released",
  "session.control.transferred",
  "session.ended",
  "session.handoff.accepted",
  "session.handoff.cancelled",
  "session.handoff.expired",
  "session.handoff.offered",
  "session.participant.granted",
  "session.participant.joined",
  "session.participant.revoked",
  "session.responsibility.granted",
  "session.responsibility.revoked",
  "session.runtime-authorization.advanced",
  "session.runtime-authorization.enforced",
  "session.runtime-authorization.quarantined",
  "session.started",
]);

const PUBLIC_CONVERSATION_TYPES = new Set([
  "comment.added",
  "directive.queued",
  "suggestion.added",
  "suggestion.resolved",
]);

export interface PublicSessionEvent {
  schemaVersion: SessionEvent["schemaVersion"];
  eventId: string;
  sessionId: string;
  sequence: number;
  type: string;
  occurredAtMs: number;
  actor: ActorContext;
  sourceAdapter: PublicSessionEventSourceAdapter;
  payload: Record<string, unknown>;
}

export type PublicSessionEventSourceAdapter = "web" | "slack" | "telegram" | "runtime" | "internal";

interface RedactionBudget {
  remainingEntries: number;
}

interface PublicEventContent {
  type: string;
  actor: ActorContext;
  sourceAdapter: PublicSessionEventSourceAdapter;
  payload: Record<string, unknown>;
}

/**
 * Project a kernel event into the only event shape exposed to browsers.
 *
 * This is an allowlist, not a redacted copy of the kernel payload. Conversation
 * events retain only fields consumed by the chat UI. Known collaborative
 * activity retains its safe type and actor with an empty payload. Everything
 * else becomes an anonymous, payload-free activity placeholder so a new
 * kernel event cannot silently widen the browser contract.
 */
export function projectPublicSessionEvent(event: SessionEvent): PublicSessionEvent {
  const content = projectPublicEventContent(event);
  return {
    schemaVersion: event.schemaVersion,
    eventId: event.eventId,
    sessionId: event.sessionId,
    sequence: event.sequence,
    type: content.type,
    occurredAtMs: event.occurredAtMs,
    actor: content.actor,
    sourceAdapter: content.sourceAdapter,
    payload: content.payload,
  };
}

function projectPublicEventContent(event: SessionEvent): PublicEventContent {
  const sourceAdapter = projectSourceAdapter(event.source.scope);
  if (PUBLIC_CONVERSATION_TYPES.has(event.type)) {
    return {
      type: event.type,
      actor: projectActor(event.actor),
      sourceAdapter,
      payload: projectConversationPayload(event.type, event.payload),
    };
  }

  if (PUBLIC_ACTIVITY_TYPES.has(event.type)) {
    return {
      type: event.type,
      actor: projectActor(event.actor),
      sourceAdapter,
      payload: {},
    };
  }

  // Invitation redemption and the Membership event it emits happen before a
  // Guest has a Session Share or Participant row. Keeping all non-public event
  // types anonymous also makes future admission events fail closed.
  return {
    type: GENERIC_ACTIVITY_TYPE,
    actor: { ...PUBLIC_SYSTEM_ACTOR },
    sourceAdapter: "internal",
    payload: {},
  };
}

function projectConversationPayload(
  type: string,
  sourcePayload: Record<string, unknown>
): Record<string, unknown> {
  // Defense in depth: redact a bounded copy before selecting public fields.
  // The selector below is still authoritative and rejects non-scalar values.
  const redacted = redactSensitiveEventFields(sourcePayload, 0, {
    remainingEntries: MAX_PUBLIC_EVENT_ENTRIES,
  });
  if (!isRecord(redacted)) return {};

  switch (type) {
    case "comment.added":
      return projectFields(redacted, [stringField("commentId"), stringField("body")]);
    case "suggestion.added":
      return projectFields(redacted, [
        stringField("suggestionId"),
        positiveIntegerField("suggestionVersion"),
        stringField("body"),
      ]);
    case "suggestion.resolved":
      return projectFields(redacted, [
        stringField("suggestionId"),
        positiveIntegerField("suggestionVersion"),
        enumField("resolution", ["accept", "accept-edited", "reject"]),
      ]);
    case "directive.queued":
      return projectFields(redacted, [stringField("directiveId"), stringField("body")]);
    default:
      return {};
  }
}

type PublicFieldProjector = (
  source: Record<string, unknown>,
  target: Record<string, unknown>
) => void;

function projectFields(
  source: Record<string, unknown>,
  projectors: readonly PublicFieldProjector[]
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const project of projectors) project(source, result);
  return result;
}

function stringField(key: string): PublicFieldProjector {
  return (source, target) => {
    const value = source[key];
    if (typeof value === "string") target[key] = value;
  };
}

function positiveIntegerField(key: string): PublicFieldProjector {
  return (source, target) => {
    const value = source[key];
    if (Number.isSafeInteger(value) && (value as number) >= 1) target[key] = value;
  };
}

function enumField(key: string, allowed: readonly string[]): PublicFieldProjector {
  return (source, target) => {
    const value = source[key];
    if (typeof value === "string" && allowed.includes(value)) target[key] = value;
  };
}

function projectActor(actor: ActorContext): ActorContext {
  if (actor.kind !== "human") return { ...PUBLIC_SYSTEM_ACTOR };
  if (typeof actor.userId !== "string" || typeof actor.displayName !== "string") {
    return { ...PUBLIC_SYSTEM_ACTOR };
  }
  return {
    kind: "human",
    userId: actor.userId,
    displayName: actor.displayName,
  };
}

function projectSourceAdapter(scope: string): PublicSessionEventSourceAdapter {
  if (scope.startsWith("http:")) return "web";
  if (scope.startsWith("slack:")) return "slack";
  if (scope.startsWith("telegram:")) return "telegram";
  if (scope.startsWith("runtime-worker:")) return "runtime";
  return "internal";
}

function redactSensitiveEventFields(
  value: unknown,
  depth: number,
  budget: RedactionBudget
): unknown {
  if (depth > MAX_PUBLIC_EVENT_DEPTH) return REDACTED_VALUE;

  if (Array.isArray(value)) {
    const result: unknown[] = [];
    for (const entry of value) {
      if (budget.remainingEntries === 0) break;
      budget.remainingEntries -= 1;
      result.push(redactSensitiveEventFields(entry, depth + 1, budget));
    }
    return result;
  }

  if (!isRecord(value)) return value;

  const result: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (budget.remainingEntries === 0) break;
    budget.remainingEntries -= 1;
    result[key] = isSensitiveFieldName(key)
      ? REDACTED_VALUE
      : redactSensitiveEventFields(entry, depth + 1, budget);
  }
  return result;
}

function isSensitiveFieldName(key: string): boolean {
  const normalized = key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .toLowerCase();
  return (
    normalized === "authorization" ||
    /(?:^|_)(?:token|secret|password|passphrase|private_key|api_key|access_key|encryption_key|signing_key|key_material|ssh_key|mnemonic|seed_phrase|recovery_phrase|credential|cookie|bearer|authorization_header|authorization_token)(?:_|$)/.test(
      normalized
    )
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
