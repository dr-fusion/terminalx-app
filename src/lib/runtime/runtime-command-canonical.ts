import { createHash } from "node:crypto";

export const RUNTIME_COMMAND_CLAIMS_DIGEST_DOMAIN =
  "terminalx/runtime-command-claims/v1\0" as const;
export const RUNTIME_COMMAND_AUTHORITY_SIGNATURE_DOMAIN =
  "terminalx/runtime-command-authority/v1\0" as const;

const MAX_DEPTH = 32;
const MAX_NODES = 20_000;
const MAX_FIELDS = 1_000;
const MAX_STRING_BYTES = 1_000_000;
const RESERVED_BYTES_FIELD = "$terminalx.runtime.bytes.v1";

export type RuntimeCommandCanonicalErrorCode = "invalid_value" | "resource_limit";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeCommandCanonicalErrorCode, string>> = {
  invalid_value: "Runtime command claims are not canonicalizable",
  resource_limit: "Runtime command claims exceed canonicalization limits",
};

/** Safe failure surface: rejected values are never interpolated into the error. */
export class RuntimeCommandCanonicalError extends Error {
  constructor(readonly code: RuntimeCommandCanonicalErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeCommandCanonicalError";
  }
}

interface CanonicalState {
  readonly ancestors: Set<object>;
  remainingNodes: number;
  remainingStringBytes: number;
}

/**
 * Deterministic, bounded JSON profile for portable Runtime data.
 *
 * Plain records, arrays, JSON primitives, and Uint8Array values are supported.
 * Byte arrays use a reserved, collision-free tagged JSON representation. Data
 * properties only are accepted, so canonicalization never invokes a getter.
 */
export function canonicalRuntimeJson(value: unknown): string {
  return canonicalValue(value, initialState(), 0);
}

/** Canonicalize the complete top-level Runtime command with `authority` omitted. */
export function canonicalRuntimeCommandClaims(command: unknown): string {
  const record = plainRecord(command);
  return canonicalRecord(record, initialState(), 0, true);
}

/** Lowercase SHA-256 over a domain separator and the canonical command claims. */
export function digestRuntimeCommandClaims(command: unknown): string {
  return createHash("sha256")
    .update(RUNTIME_COMMAND_CLAIMS_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeCommandClaims(command), "utf8")
    .digest("hex");
}

function initialState(): CanonicalState {
  return {
    ancestors: new Set<object>(),
    remainingNodes: MAX_NODES,
    remainingStringBytes: MAX_STRING_BYTES,
  };
}

function canonicalValue(value: unknown, state: CanonicalState, depth: number): string {
  consumeNode(state, depth);
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    consumeString(state, value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) invalid();
    return JSON.stringify(value);
  }
  if (typeof value !== "object") invalid();

  if (value instanceof Uint8Array) return canonicalBytes(value, state);
  if (Array.isArray(value)) return canonicalArray(value, state, depth);
  return canonicalRecord(plainRecord(value), state, depth, false, true);
}

function canonicalArray(value: unknown[], state: CanonicalState, depth: number): string {
  enter(value, state);
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes("length")) invalid();
    const entries: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid();
      entries.push(canonicalValue(descriptor.value, state, depth + 1));
    }
    return `[${entries.join(",")}]`;
  } finally {
    state.ancestors.delete(value);
  }
}

function canonicalRecord(
  value: Record<string, unknown>,
  state: CanonicalState,
  depth: number,
  omitTopLevelAuthority: boolean,
  nodeAlreadyConsumed = false
): string {
  if (!nodeAlreadyConsumed) consumeNode(state, depth);
  enter(value, state);
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.length > MAX_FIELDS) limited();
    const fields: Array<readonly [string, unknown]> = [];
    for (const key of keys) {
      if (typeof key !== "string" || key === RESERVED_BYTES_FIELD) invalid();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid();
      if (omitTopLevelAuthority && key === "authority") continue;
      consumeString(state, key);
      fields.push([key, descriptor.value]);
    }
    fields.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    return `{${fields
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalValue(entry, state, depth + 1)}`)
      .join(",")}}`;
  } finally {
    state.ancestors.delete(value);
  }
}

function canonicalBytes(value: Uint8Array, state: CanonicalState): string {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.byteLength) invalid();
  for (let index = 0; index < value.byteLength; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid();
  }
  let encoded: string;
  try {
    // Buffer.from(Uint8Array) copies the view, preventing a later mutation from
    // changing the bytes represented by this canonicalization pass.
    encoded = Buffer.from(value).toString("base64url");
  } catch {
    invalid();
  }
  consumeString(state, RESERVED_BYTES_FIELD);
  consumeString(state, encoded);
  return `{${JSON.stringify(RESERVED_BYTES_FIELD)}:${JSON.stringify(encoded)}}`;
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    invalid();
  }
  if (prototype !== Object.prototype && prototype !== null) invalid();
  return value as Record<string, unknown>;
}

function enter(value: object, state: CanonicalState): void {
  if (state.ancestors.has(value)) invalid();
  state.ancestors.add(value);
}

function consumeNode(state: CanonicalState, depth: number): void {
  if (depth > MAX_DEPTH || state.remainingNodes < 1) limited();
  state.remainingNodes -= 1;
}

function consumeString(state: CanonicalState, value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) invalid();
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      invalid();
    }
  }
  state.remainingStringBytes -= Buffer.byteLength(value, "utf8");
  if (state.remainingStringBytes < 0) limited();
}

function invalid(): never {
  throw new RuntimeCommandCanonicalError("invalid_value");
}

function limited(): never {
  throw new RuntimeCommandCanonicalError("resource_limit");
}
