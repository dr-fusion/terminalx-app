import type { ActorContext, SessionEvent } from "./types";

const MAX_PUBLIC_EVENT_DEPTH = 16;
const MAX_PUBLIC_EVENT_ENTRIES = 1_000;
const REDACTED_VALUE = "[redacted]";

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

/**
 * Project a kernel event into the only event shape exposed to browsers.
 * Adapter source/idempotency details are intentionally not part of this type.
 */
export function projectPublicSessionEvent(event: SessionEvent): PublicSessionEvent {
  return {
    schemaVersion: event.schemaVersion,
    eventId: event.eventId,
    sessionId: event.sessionId,
    sequence: event.sequence,
    type: event.type,
    occurredAtMs: event.occurredAtMs,
    actor: event.actor,
    sourceAdapter: projectSourceAdapter(event.source.scope),
    payload: redactSensitiveEventFields(event.payload, 0, {
      remainingEntries: MAX_PUBLIC_EVENT_ENTRIES,
    }) as Record<string, unknown>,
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
