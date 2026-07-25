import { createHash, timingSafeEqual } from "node:crypto";
import { types as nodeTypes } from "node:util";

/**
 * The Secret Broker protocol is non-exporting by construction. Every operation
 * below either mutates broker-private registration state or returns bounded,
 * allowlisted metadata. There is deliberately no operation whose response can
 * carry credential material, and {@link assertClosedResponse} rejects any
 * adapter/handler return value that introduces an unexpected field.
 */
export const SECRET_BROKER_PROTOCOL_VERSION = 1 as const;

export const SECRET_BROKER_METHODS = Object.freeze([
  "registration.prepare",
  "registration.finalize",
  "registration.abort",
  "rotation.prepare",
  "rotation.finalize",
  "rotation.abort",
  "handle.revoke",
  "handle.status",
  "broker.health",
] as const);

export type SecretBrokerMethod = (typeof SECRET_BROKER_METHODS)[number];

export type SecretBrokerProtocolErrorCode =
  | "invalid-request"
  | "not-ready"
  | "unavailable"
  | "permission-denied"
  | "conflict"
  | "not-found"
  | "internal";

const SAFE_ERROR_MESSAGES: Readonly<Record<SecretBrokerProtocolErrorCode, string>> = Object.freeze({
  "invalid-request": "The Secret Broker request was malformed.",
  "not-ready": "The Secret Broker is not ready.",
  unavailable: "The Secret Broker is unavailable.",
  "permission-denied": "The Secret Broker denied the request.",
  conflict: "The Secret Broker registration state conflicts.",
  "not-found": "The Secret Broker registration was not found.",
  internal: "The Secret Broker encountered an internal error.",
});

/**
 * A protocol error whose message is fixed per code and never derived from
 * request content, adapter output, or secret material.
 */
export class SecretBrokerProtocolError extends Error {
  readonly code: SecretBrokerProtocolErrorCode;
  constructor(code: SecretBrokerProtocolErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.code = code;
    this.name = "SecretBrokerProtocolError";
  }
}

export function isSecretBrokerMethod(value: unknown): value is SecretBrokerMethod {
  return typeof value === "string" && (SECRET_BROKER_METHODS as readonly string[]).includes(value);
}

/** Deterministic, prototype-safe JSON with lexicographically sorted keys. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new TypeError();
    return value;
  }
  if (Array.isArray(value)) return value.map(sortValue);
  if (nodeTypes.isProxy(value)) throw new TypeError();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    const entry = (value as Record<string, unknown>)[key];
    if (entry === undefined) continue;
    result[key] = sortValue(entry);
  }
  return result;
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function domainSeparatedDigest(domain: string, value: string): string {
  return createHash("sha256").update(domain, "utf8").update(value, "utf8").digest("hex");
}

export function sameDigest(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

/**
 * Return `value` unchanged only if it is a plain object with exactly `names` as
 * its own enumerable string keys. Rejects proxies, exotic prototypes, and any
 * additional field so an adapter or peer cannot smuggle extra data through.
 */
export function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

export function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

export function boundedIdentifier(value: unknown, maxLength = 300): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    value !== value.trim() ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError();
  }
  return value;
}

export function digestField(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new TypeError();
  return value;
}

export function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TypeError();
  return value as number;
}

export function safeTimestamp(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError();
  return value as number;
}

/**
 * The closed-response allowlist. Every protocol response object is validated
 * against exactly one of these field sets before it is written to the wire. A
 * response type that carried credential material could not be added here
 * without an explicit, reviewable schema change.
 */
export const RESPONSE_SCHEMAS: Readonly<Record<SecretBrokerMethod, readonly string[]>> =
  Object.freeze({
    "registration.prepare": ["receipt"],
    "registration.finalize": ["handleId", "status"],
    "registration.abort": ["receiptId", "status"],
    "rotation.prepare": ["receipt"],
    "rotation.finalize": ["handleId", "status", "replacedHandleId", "replacedStatus"],
    "rotation.abort": ["receiptId", "status"],
    "handle.revoke": ["handleId", "status"],
    "handle.status": ["handleId", "status", "brokerKind", "provider", "usage", "expiresAtMs"],
    "broker.health": ["brokerInstanceId", "brokerEpoch", "signingKeyId", "pendingRegistrations"],
  });

/**
 * A registration receipt is itself a closed record. It carries only opaque
 * identifiers, a bound expectation digest, timing, and the Ed25519 signature —
 * never secret material.
 */
export const RECEIPT_FIELDS = Object.freeze(["payload", "signature"] as const);

export const RECEIPT_PAYLOAD_FIELDS = Object.freeze([
  "schema",
  "kind",
  "brokerInstanceId",
  "brokerEpoch",
  "signingKeyId",
  "operationId",
  "handleId",
  "receiptId",
  "provider",
  "brokerKind",
  "usage",
  "expectationDigest",
  "hasReplacement",
  "issuedAtMs",
  "expiresAtMs",
] as const);

/**
 * Fail closed unless `response` is a plain object whose own keys are exactly the
 * allowlist for `method`. This is the runtime guard that makes the protocol
 * non-exporting: an adapter that tried to return a `secret`, `token`, `value`,
 * or any other unlisted field is rejected before serialization.
 */
export function assertClosedResponse(method: SecretBrokerMethod, response: unknown): void {
  const allowed = RESPONSE_SCHEMAS[method];
  try {
    const record = exactRecord(response, allowed);
    if (method === "registration.prepare" || method === "rotation.prepare") {
      assertClosedReceipt(field(record, "receipt"));
    }
  } catch {
    throw new SecretBrokerProtocolError("internal");
  }
}

function assertClosedReceipt(receipt: unknown): void {
  const record = exactRecord(receipt, RECEIPT_FIELDS);
  exactRecord(field(record, "payload"), RECEIPT_PAYLOAD_FIELDS);
  if (typeof field(record, "signature") !== "string") throw new TypeError();
}
