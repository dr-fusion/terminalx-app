import {
  boundedIdentifier,
  digestField,
  exactRecord,
  field,
  positiveInteger,
  safeTimestamp,
  SecretBrokerProtocolError,
} from "../protocol";

/**
 * The Credential Proxy protocol is the destination-scoped effect boundary of
 * Slice 8D. Like the registration protocol it is non-exporting by construction:
 * the single {@link CREDENTIAL_PROXY_METHODS} operation performs a typed,
 * destination-scoped provider request inside the broker process and returns a
 * bounded, allowlisted result. There is deliberately no generic "HTTP request
 * with credential" operation — every operation is a named entry in the typed
 * operation registry, and {@link assertClosedProxyResponse} rejects any result
 * that introduces a field outside the closed envelope.
 */
export const CREDENTIAL_PROXY_PROTOCOL_VERSION = 1 as const;

export const CREDENTIAL_PROXY_METHODS = Object.freeze(["proxy.execute"] as const);

export type CredentialProxyMethod = (typeof CREDENTIAL_PROXY_METHODS)[number];

export function isCredentialProxyMethod(value: unknown): value is CredentialProxyMethod {
  return (
    typeof value === "string" && (CREDENTIAL_PROXY_METHODS as readonly string[]).includes(value)
  );
}

/** The bounded, provider-independent outcome classification of a proxy call. */
export type ProxyResultClass = "ok" | "retryable" | "denied" | "provider-error";

const RESULT_CLASSES: readonly ProxyResultClass[] = Object.freeze([
  "ok",
  "retryable",
  "denied",
  "provider-error",
]);

export function isProxyResultClass(value: unknown): value is ProxyResultClass {
  return typeof value === "string" && (RESULT_CLASSES as readonly string[]).includes(value);
}

/**
 * Bounded, provider-independent error classification tokens. No upstream error
 * body, provider URL (which for Telegram embeds the bot token), or raw header is
 * ever surfaced; a call resolves to exactly one of these tokens instead.
 */
export const PROXY_ERROR_CODES = Object.freeze([
  "unsupported-operation",
  "provider-mismatch",
  "destination-denied",
  "invalid-params",
  "params-too-large",
  "handle-inactive",
  "authority-mismatch",
  "unsupported-credential-kind",
  "credential-unavailable",
  "provider-declined",
  "rate-limited",
  "provider-error",
  "response-too-large",
  "timeout",
  "timeout-ambiguous",
  "transport",
] as const);

export type ProxyErrorCode = (typeof PROXY_ERROR_CODES)[number];

export function isProxyErrorCode(value: unknown): value is ProxyErrorCode {
  return typeof value === "string" && (PROXY_ERROR_CODES as readonly string[]).includes(value);
}

/**
 * The closed result envelope. `projection` is either `null` or a bounded,
 * operation-specific record validated separately by the operation's own
 * projection guard before the envelope is assembled.
 */
export const PROXY_RESULT_FIELDS = Object.freeze([
  "operation",
  "provider",
  "destinationHost",
  "resultClass",
  "ambiguous",
  "errorCode",
  "requestBytes",
  "responseBytes",
  "handleGeneration",
  "installationRevision",
  "bindingRevision",
  "startedAtMs",
  "completedAtMs",
  "accountingRowId",
  "projection",
] as const);

/**
 * Fail closed unless `response` is a plain object whose own keys are exactly the
 * proxy result envelope. This is the runtime guard that keeps the proxy
 * non-exporting: a result that tried to carry an `authorization`, `token`,
 * `url`, or `secret` field is rejected before serialization.
 */
export function assertClosedProxyResponse(response: unknown): void {
  try {
    const record = exactRecord(response, PROXY_RESULT_FIELDS);
    if (!isProxyResultClass(field(record, "resultClass"))) throw new TypeError();
    const errorCode = field(record, "errorCode");
    if (errorCode !== null && !isProxyErrorCode(errorCode)) throw new TypeError();
    if (typeof field(record, "ambiguous") !== "boolean") throw new TypeError();
  } catch {
    throw new SecretBrokerProtocolError("internal");
  }
}

export interface ProxyResult {
  readonly operation: string;
  readonly provider: string;
  readonly destinationHost: string;
  readonly resultClass: ProxyResultClass;
  readonly ambiguous: boolean;
  readonly errorCode: ProxyErrorCode | null;
  readonly requestBytes: number;
  readonly responseBytes: number;
  readonly handleGeneration: number;
  readonly installationRevision: number;
  readonly bindingRevision: number | null;
  readonly startedAtMs: number;
  readonly completedAtMs: number;
  readonly accountingRowId: number;
  readonly projection: Record<string, unknown> | null;
}

/**
 * Validate and freeze an untrusted wire result. The main-side client uses this so
 * a malformed or field-injecting result cannot escape the closed envelope even
 * across the socket boundary.
 */
export function snapshotProxyResult(value: unknown): ProxyResult {
  const record = exactRecord(value, PROXY_RESULT_FIELDS);
  const resultClass = field(record, "resultClass");
  const ambiguous = field(record, "ambiguous");
  const errorCode = field(record, "errorCode");
  const bindingRevisionRaw = field(record, "bindingRevision");
  const projectionRaw = field(record, "projection");
  if (
    !isProxyResultClass(resultClass) ||
    typeof ambiguous !== "boolean" ||
    (errorCode !== null && !isProxyErrorCode(errorCode))
  ) {
    throw new TypeError();
  }
  let projection: Record<string, unknown> | null = null;
  if (projectionRaw !== null) {
    if (
      typeof projectionRaw !== "object" ||
      Array.isArray(projectionRaw) ||
      Object.getPrototypeOf(projectionRaw) !== Object.prototype
    ) {
      throw new TypeError();
    }
    projection = projectionRaw as Record<string, unknown>;
  }
  return Object.freeze({
    operation: boundedIdentifier(field(record, "operation")),
    provider: boundedIdentifier(field(record, "provider")),
    destinationHost: boundedIdentifier(field(record, "destinationHost")),
    resultClass,
    ambiguous,
    errorCode,
    requestBytes: nonNegativeInteger(field(record, "requestBytes")),
    responseBytes: nonNegativeInteger(field(record, "responseBytes")),
    handleGeneration: positiveInteger(field(record, "handleGeneration")),
    installationRevision: positiveInteger(field(record, "installationRevision")),
    bindingRevision: bindingRevisionRaw === null ? null : positiveInteger(bindingRevisionRaw),
    startedAtMs: safeTimestamp(field(record, "startedAtMs")),
    completedAtMs: safeTimestamp(field(record, "completedAtMs")),
    accountingRowId: positiveInteger(field(record, "accountingRowId")),
    projection,
  });
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError();
  return value as number;
}

export interface ProxyAuthoritySnapshot {
  readonly provider: string;
  readonly handleId: string;
  readonly handleGeneration: number;
  readonly expectationDigest: string;
  readonly installationId: string;
  readonly installationRevision: number;
  readonly bindingId: string | null;
  readonly bindingRevision: number | null;
}

/**
 * The two explicit caller classes (Slice 8F). Local non-hosted callers — the 8E
 * HTTP flows — are `human-session`: they are human-session-fenced at the route
 * boundary and carry no assignment fence. A hosted Run is `hosted-assignment`
 * and must carry the exact Runtime Assignment identity (assignment id +
 * generation + Sandbox identity digest from the Phase 7 trust chain), which the
 * broker durably records and generation-fences.
 */
export type ProxyCallerFence =
  | {
      readonly class: "human-session";
      readonly humanSessionFenceId: string;
    }
  | {
      readonly class: "hosted-assignment";
      readonly runtimeAssignmentId: string;
      readonly runtimeAssignmentGeneration: number;
      readonly sandboxIdentityDigest: string;
    };

export interface ProxyExecuteRequest {
  /** A fresh per-call nonce; the accounting key that makes a duplicate frame converge. */
  readonly operationId: string;
  readonly operation: string;
  readonly authority: ProxyAuthoritySnapshot;
  /** Absent on legacy frames (treated as human-session, unfenced). */
  readonly caller: ProxyCallerFence | null;
  readonly params: unknown;
}

/**
 * Validate and freeze an untrusted `proxy.execute` params object. Every authority
 * identifier is bounded and typed; a malformed request throws
 * `invalid-request` before any operation, fence, or credential is touched.
 */
export function snapshotProxyExecuteRequest(params: unknown): ProxyExecuteRequest {
  try {
    const record = recordWithOptionalCaller(params);
    const caller = snapshotCallerFence("caller" in record ? record.caller : undefined);
    const authorityRecord = exactRecord(field(record, "authority"), [
      "provider",
      "handleId",
      "handleGeneration",
      "expectationDigest",
      "installationId",
      "installationRevision",
      "bindingId",
      "bindingRevision",
    ]);
    const bindingIdRaw = field(authorityRecord, "bindingId");
    const bindingRevisionRaw = field(authorityRecord, "bindingRevision");
    const bindingId = bindingIdRaw === null ? null : boundedIdentifier(bindingIdRaw);
    const bindingRevision =
      bindingRevisionRaw === null ? null : positiveInteger(bindingRevisionRaw);
    if ((bindingId === null) !== (bindingRevision === null)) throw new TypeError();
    const authority: ProxyAuthoritySnapshot = Object.freeze({
      provider: boundedIdentifier(field(authorityRecord, "provider")),
      handleId: boundedIdentifier(field(authorityRecord, "handleId")),
      handleGeneration: positiveInteger(field(authorityRecord, "handleGeneration")),
      expectationDigest: digestField(field(authorityRecord, "expectationDigest")),
      installationId: boundedIdentifier(field(authorityRecord, "installationId")),
      installationRevision: positiveInteger(field(authorityRecord, "installationRevision")),
      bindingId,
      bindingRevision,
    });
    return Object.freeze({
      operationId: boundedIdentifier(field(record, "operationId")),
      operation: boundedIdentifier(field(record, "operation")),
      authority,
      caller,
      params: field(record, "params"),
    });
  } catch (error) {
    if (error instanceof SecretBrokerProtocolError) throw error;
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

function recordWithOptionalCaller(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const record = value as Record<string, unknown>;
  const required = ["operationId", "operation", "authority", "params"];
  const allowed = new Set([...required, "caller"]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new TypeError();
  }
  for (const key of required) field(record, key);
  return record;
}

function snapshotCallerFence(value: unknown): ProxyCallerFence | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) throw new TypeError();
  const callerClass = (value as Record<string, unknown>).class;
  if (callerClass === "human-session") {
    const record = exactRecord(value, ["class", "humanSessionFenceId"]);
    return Object.freeze({
      class: "human-session",
      humanSessionFenceId: boundedIdentifier(field(record, "humanSessionFenceId")),
    });
  }
  if (callerClass === "hosted-assignment") {
    const record = exactRecord(value, [
      "class",
      "runtimeAssignmentId",
      "runtimeAssignmentGeneration",
      "sandboxIdentityDigest",
    ]);
    return Object.freeze({
      class: "hosted-assignment",
      runtimeAssignmentId: boundedIdentifier(field(record, "runtimeAssignmentId")),
      runtimeAssignmentGeneration: positiveInteger(field(record, "runtimeAssignmentGeneration")),
      sandboxIdentityDigest: digestField(field(record, "sandboxIdentityDigest")),
    });
  }
  throw new TypeError();
}

export { safeTimestamp };
