import { createHash } from "node:crypto";

export const RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD = 3 as const;

const DEFAULT_TTL_MS = 60 * 60 * 1_000;
const MIN_TTL_MS = 1_000;
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
const DEFAULT_MAX_ENTRIES = 1_024;
const MAX_MAX_ENTRIES = 10_000;
const DEFAULT_MAX_FINGERPRINTS_PER_ENTRY = 64;
const MAX_MAX_FINGERPRINTS_PER_ENTRY = 256;

const MAX_SCOPE_LENGTH = 256;
const MAX_OPERATION_LENGTH = 256;
const MAX_CODE_LENGTH = 256;
const MAX_SIGNAL_LENGTH = 64;
const MAX_STRING_LENGTH = 16_384;
const MAX_KEY_LENGTH = 256;
const MAX_CANONICAL_LENGTH = 65_536;
const MAX_CANONICAL_NODES = 1_024;
const MAX_CANONICAL_DEPTH = 12;
const MAX_COLLECTION_SIZE = 128;

type FingerprintMode = "failure" | "proposal";

export interface RuntimeFailureFingerprintInput {
  /** Stable adapter operation, for example `terminal.write` or `sandbox.create`. */
  operation: string;
  /** Safe, stable failure class. Raw error text should be supplied as `message`. */
  code: string;
  message?: string;
  exitCode?: number | null;
  signal?: string | null;
  details?: unknown;
}

export interface RuntimeCircuitBreakerOptions {
  /** Maximum number of independent scope entries held in process memory. */
  maxEntries?: number;
  /** Maximum combined failure and denial fingerprints held for one scope. */
  maxFingerprintsPerEntry?: number;
  /** Inactivity lifetime for counters, open circuits, and proposal denials. */
  ttlMs?: number;
}

export type RuntimeCircuitState = "closed" | "open";

export interface RuntimeFailureDecision {
  state: RuntimeCircuitState;
  retryAllowed: boolean;
  failureFingerprint: string;
  identicalFailureCount: number;
  opened: boolean;
  expiresAtMs: number;
}

export type RuntimeProposalBlockReason = "circuit_open" | "proposal_unchanged";

export type RuntimeProposalDecision =
  | {
      allowed: true;
      fingerprint: string;
    }
  | {
      allowed: false;
      fingerprint: string;
      reason: RuntimeProposalBlockReason;
      expiresAtMs: number;
    };

export interface RuntimeCircuitBreakerStatus {
  state: RuntimeCircuitState;
  openFailureFingerprint?: string;
  openUntilMs?: number;
  trackedFailureFingerprints: number;
  deniedProposalFingerprints: number;
}

interface FailureCounter {
  count: number;
  expiresAtMs: number;
}

interface OpenCircuit {
  failureFingerprint: string;
  expiresAtMs: number;
}

interface CircuitEntry {
  failures: Map<string, FailureCounter>;
  deniedProposals: Map<string, number>;
  open?: OpenCircuit;
}

interface CanonicalBudget {
  length: number;
  nodes: number;
}

export class RuntimeCircuitBreakerInputError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeCircuitBreakerInputError";
  }
}

/**
 * Capacity exhaustion is a blocking result. Callers must not evict an existing
 * open circuit or denial in order to admit a new operation.
 */
export class RuntimeCircuitBreakerCapacityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeCircuitBreakerCapacityError";
  }
}

export class RuntimeCircuitBreakerBlockedError extends Error {
  readonly reason: RuntimeProposalBlockReason;
  readonly scope: string;
  readonly fingerprint: string;
  readonly expiresAtMs: number;

  constructor(scope: string, decision: Extract<RuntimeProposalDecision, { allowed: false }>) {
    super(
      decision.reason === "circuit_open"
        ? `Runtime circuit is open for scope ${scope}`
        : `An unchanged denied proposal cannot be submitted for scope ${scope}`
    );
    this.name = "RuntimeCircuitBreakerBlockedError";
    this.reason = decision.reason;
    this.scope = scope;
    this.fingerprint = decision.fingerprint;
    this.expiresAtMs = decision.expiresAtMs;
  }
}

/**
 * Returns an opaque, deterministic digest of the stable parts of a Runtime
 * failure. Volatile identifiers, timestamps, retry counters, and secret-bearing
 * fields do not affect the digest. Common occurrences of those values in raw
 * messages are normalized as well.
 */
export function fingerprintRuntimeFailure(input: RuntimeFailureFingerprintInput): string {
  if (!input || typeof input !== "object") {
    throw new RuntimeCircuitBreakerInputError("Runtime failure must be an object");
  }

  const operation = validateRequiredText("operation", input.operation, MAX_OPERATION_LENGTH);
  const code = validateRequiredText("code", input.code, MAX_CODE_LENGTH);
  const message =
    input.message === undefined
      ? undefined
      : validateText("message", input.message, MAX_STRING_LENGTH);
  const signal =
    input.signal === undefined || input.signal === null
      ? input.signal
      : validateText("signal", input.signal, MAX_SIGNAL_LENGTH);

  if (
    input.exitCode !== undefined &&
    input.exitCode !== null &&
    (!Number.isSafeInteger(input.exitCode) || input.exitCode < -1 || input.exitCode > 255)
  ) {
    throw new RuntimeCircuitBreakerInputError("exitCode must be null or an integer from -1 to 255");
  }

  return digestFingerprint(
    "runtime-failure:v1",
    {
      code,
      operation,
      ...(message === undefined ? {} : { message }),
      ...(input.exitCode === undefined ? {} : { exitCode: input.exitCode }),
      ...(signal === undefined ? {} : { signal }),
      ...(input.details === undefined ? {} : { details: input.details }),
    },
    "failure"
  );
}

/**
 * Fingerprints proposal semantics while omitting transport metadata and secret
 * values. Semantic target identifiers are retained; only known request/proposal
 * envelope identifiers are ignored.
 */
export function fingerprintRuntimeProposal(proposal: unknown): string {
  return digestFingerprint("runtime-proposal:v1", proposal, "proposal");
}

/**
 * A deterministic, process-local guard. It owns no timers and performs no I/O;
 * every operation receives the authoritative time from its caller.
 *
 * Three matching failure fingerprints within the TTL open a scope. Open state
 * is sticky until recordSuccess/resetFailures/reset, or until the TTL expires.
 * A success clears all failure counters but deliberately preserves proposal
 * denials. Denials require their own reset, a full reset, or TTL expiry.
 */
export class RuntimeCircuitBreaker {
  private readonly entries = new Map<string, CircuitEntry>();
  private readonly maxEntries: number;
  private readonly maxFingerprintsPerEntry: number;
  private readonly ttlMs: number;

  constructor(options: RuntimeCircuitBreakerOptions = {}) {
    validateOptionsObject(options);
    this.maxEntries = validateBoundedInteger(
      "maxEntries",
      options.maxEntries ?? DEFAULT_MAX_ENTRIES,
      1,
      MAX_MAX_ENTRIES
    );
    this.maxFingerprintsPerEntry = validateBoundedInteger(
      "maxFingerprintsPerEntry",
      options.maxFingerprintsPerEntry ?? DEFAULT_MAX_FINGERPRINTS_PER_ENTRY,
      1,
      MAX_MAX_FINGERPRINTS_PER_ENTRY
    );
    this.ttlMs = validateBoundedInteger(
      "ttlMs",
      options.ttlMs ?? DEFAULT_TTL_MS,
      MIN_TTL_MS,
      MAX_TTL_MS
    );
  }

  recordFailure(
    scope: string,
    failure: RuntimeFailureFingerprintInput,
    nowMs: number
  ): RuntimeFailureDecision {
    validateScope(scope);
    const expiresAtMs = this.validateTimeAndExpiry(nowMs);
    const failureFingerprint = fingerprintRuntimeFailure(failure);
    this.pruneExpired(nowMs);

    const entry = this.getOrCreateEntry(scope);
    if (entry.open) {
      return {
        state: "open",
        retryAllowed: false,
        failureFingerprint,
        identicalFailureCount: RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        opened: false,
        expiresAtMs: entry.open.expiresAtMs,
      };
    }

    const counter = entry.failures.get(failureFingerprint);
    if (!counter) this.assertFingerprintCapacity(scope, entry);

    const identicalFailureCount = (counter?.count ?? 0) + 1;
    if (identicalFailureCount >= RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD) {
      entry.failures.clear();
      entry.open = { failureFingerprint, expiresAtMs };
      return {
        state: "open",
        retryAllowed: false,
        failureFingerprint,
        identicalFailureCount,
        opened: true,
        expiresAtMs,
      };
    }

    entry.failures.set(failureFingerprint, { count: identicalFailureCount, expiresAtMs });
    return {
      state: "closed",
      retryAllowed: true,
      failureFingerprint,
      identicalFailureCount,
      opened: false,
      expiresAtMs,
    };
  }

  /** Clears open state and every failure counter, but not proposal denials. */
  recordSuccess(scope: string, nowMs: number): RuntimeCircuitBreakerStatus {
    validateScope(scope);
    this.validateTimeAndExpiry(nowMs);
    this.pruneExpired(nowMs);
    const entry = this.entries.get(scope);
    if (entry) {
      entry.failures.clear();
      delete entry.open;
      this.deleteEntryIfEmpty(scope, entry);
    }
    return this.status(scope, nowMs);
  }

  recordDeniedProposal(scope: string, proposal: unknown, nowMs: number): string {
    validateScope(scope);
    const expiresAtMs = this.validateTimeAndExpiry(nowMs);
    const fingerprint = fingerprintRuntimeProposal(proposal);
    this.pruneExpired(nowMs);

    const entry = this.getOrCreateEntry(scope);
    if (!entry.deniedProposals.has(fingerprint)) this.assertFingerprintCapacity(scope, entry);
    entry.deniedProposals.set(fingerprint, expiresAtMs);
    return fingerprint;
  }

  evaluateProposal(scope: string, proposal: unknown, nowMs: number): RuntimeProposalDecision {
    validateScope(scope);
    this.validateTimeAndExpiry(nowMs);
    const fingerprint = fingerprintRuntimeProposal(proposal);
    this.pruneExpired(nowMs);
    const entry = this.entries.get(scope);

    if (entry?.open) {
      return {
        allowed: false,
        fingerprint,
        reason: "circuit_open",
        expiresAtMs: entry.open.expiresAtMs,
      };
    }

    const denialExpiresAtMs = entry?.deniedProposals.get(fingerprint);
    if (denialExpiresAtMs !== undefined) {
      return {
        allowed: false,
        fingerprint,
        reason: "proposal_unchanged",
        expiresAtMs: denialExpiresAtMs,
      };
    }

    return { allowed: true, fingerprint };
  }

  assertProposalAllowed(scope: string, proposal: unknown, nowMs: number): string {
    const decision = this.evaluateProposal(scope, proposal, nowMs);
    if (!decision.allowed) throw new RuntimeCircuitBreakerBlockedError(scope, decision);
    return decision.fingerprint;
  }

  status(scope: string, nowMs: number): RuntimeCircuitBreakerStatus {
    validateScope(scope);
    this.validateTimeAndExpiry(nowMs);
    this.pruneExpired(nowMs);
    const entry = this.entries.get(scope);

    if (!entry) {
      return {
        state: "closed",
        trackedFailureFingerprints: 0,
        deniedProposalFingerprints: 0,
      };
    }

    return {
      state: entry.open ? "open" : "closed",
      ...(entry.open
        ? {
            openFailureFingerprint: entry.open.failureFingerprint,
            openUntilMs: entry.open.expiresAtMs,
          }
        : {}),
      trackedFailureFingerprints: entry.failures.size,
      deniedProposalFingerprints: entry.deniedProposals.size,
    };
  }

  resetFailures(scope: string): boolean {
    validateScope(scope);
    const entry = this.entries.get(scope);
    if (!entry) return false;
    const changed = entry.failures.size > 0 || entry.open !== undefined;
    entry.failures.clear();
    delete entry.open;
    this.deleteEntryIfEmpty(scope, entry);
    return changed;
  }

  resetDeniedProposals(scope: string): boolean {
    validateScope(scope);
    const entry = this.entries.get(scope);
    if (!entry) return false;
    const changed = entry.deniedProposals.size > 0;
    entry.deniedProposals.clear();
    this.deleteEntryIfEmpty(scope, entry);
    return changed;
  }

  reset(scope: string): boolean {
    validateScope(scope);
    return this.entries.delete(scope);
  }

  private validateTimeAndExpiry(nowMs: number): number {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > Number.MAX_SAFE_INTEGER - this.ttlMs) {
      throw new RuntimeCircuitBreakerInputError(
        "nowMs must be a non-negative safe integer that can accommodate the configured TTL"
      );
    }
    return nowMs + this.ttlMs;
  }

  private getOrCreateEntry(scope: string): CircuitEntry {
    const current = this.entries.get(scope);
    if (current) return current;
    if (this.entries.size >= this.maxEntries) {
      throw new RuntimeCircuitBreakerCapacityError(
        `Runtime circuit-breaker scope capacity (${this.maxEntries}) is exhausted`
      );
    }
    const entry: CircuitEntry = {
      failures: new Map(),
      deniedProposals: new Map(),
    };
    this.entries.set(scope, entry);
    return entry;
  }

  private assertFingerprintCapacity(scope: string, entry: CircuitEntry): void {
    if (entry.failures.size + entry.deniedProposals.size >= this.maxFingerprintsPerEntry) {
      throw new RuntimeCircuitBreakerCapacityError(
        `Runtime circuit-breaker fingerprint capacity for scope ${scope} is exhausted`
      );
    }
  }

  private pruneExpired(nowMs: number): void {
    for (const [scope, entry] of this.entries) {
      for (const [fingerprint, counter] of entry.failures) {
        if (counter.expiresAtMs <= nowMs) entry.failures.delete(fingerprint);
      }
      for (const [fingerprint, expiresAtMs] of entry.deniedProposals) {
        if (expiresAtMs <= nowMs) entry.deniedProposals.delete(fingerprint);
      }
      if (entry.open && entry.open.expiresAtMs <= nowMs) delete entry.open;
      this.deleteEntryIfEmpty(scope, entry);
    }
  }

  private deleteEntryIfEmpty(scope: string, entry: CircuitEntry): void {
    if (!entry.open && entry.failures.size === 0 && entry.deniedProposals.size === 0) {
      this.entries.delete(scope);
    }
  }
}

export function createRuntimeCircuitBreaker(
  options?: RuntimeCircuitBreakerOptions
): RuntimeCircuitBreaker {
  return new RuntimeCircuitBreaker(options);
}

function digestFingerprint(prefix: string, value: unknown, mode: FingerprintMode): string {
  const canonical = canonicalize(value, mode);
  return `${prefix}:${createHash("sha256").update(canonical).digest("hex")}`;
}

function canonicalize(value: unknown, mode: FingerprintMode): string {
  const chunks: string[] = [];
  const budget: CanonicalBudget = { length: 0, nodes: 0 };
  appendCanonicalValue(chunks, value, mode, budget, 0);
  return chunks.join("");
}

function appendCanonicalValue(
  chunks: string[],
  value: unknown,
  mode: FingerprintMode,
  budget: CanonicalBudget,
  depth: number
): void {
  budget.nodes += 1;
  if (budget.nodes > MAX_CANONICAL_NODES || depth > MAX_CANONICAL_DEPTH) {
    throw new RuntimeCircuitBreakerInputError("Fingerprint input exceeds structural limits");
  }

  if (value === null) {
    appendChunk(chunks, "null", budget);
    return;
  }
  if (typeof value === "boolean") {
    appendChunk(chunks, value ? "true" : "false", budget);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new RuntimeCircuitBreakerInputError("Fingerprint numbers must be finite");
    }
    const normalized =
      mode === "failure" && looksLikeEpochTimestamp(value)
        ? "<timestamp>"
        : Object.is(value, -0)
          ? 0
          : value;
    appendChunk(chunks, JSON.stringify(normalized), budget);
    return;
  }
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      throw new RuntimeCircuitBreakerInputError("Fingerprint string exceeds its size limit");
    }
    appendChunk(
      chunks,
      JSON.stringify(mode === "failure" ? normalizeFailureText(value) : normalizeSecretText(value)),
      budget
    );
    return;
  }
  if (typeof value !== "object") {
    throw new RuntimeCircuitBreakerInputError(
      `Unsupported fingerprint value type: ${typeof value}`
    );
  }

  if (Array.isArray(value)) {
    if (value.length > MAX_COLLECTION_SIZE) {
      throw new RuntimeCircuitBreakerInputError("Fingerprint array exceeds its item limit");
    }
    const enumerableKeys = Object.keys(value);
    if (
      enumerableKeys.length !== value.length ||
      enumerableKeys.some((key, index) => key !== String(index))
    ) {
      throw new RuntimeCircuitBreakerInputError("Fingerprint arrays must be dense and unadorned");
    }
    appendChunk(chunks, "[", budget);
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) appendChunk(chunks, ",", budget);
      appendCanonicalValue(chunks, value[index], mode, budget, depth + 1);
    }
    appendChunk(chunks, "]", budget);
    return;
  }

  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    throw new RuntimeCircuitBreakerInputError("Fingerprint objects must be inspectable");
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new RuntimeCircuitBreakerInputError("Fingerprint objects must be plain records");
  }

  const symbolKeys = Object.getOwnPropertySymbols(value);
  if (symbolKeys.some((key) => Object.prototype.propertyIsEnumerable.call(value, key))) {
    throw new RuntimeCircuitBreakerInputError("Fingerprint objects cannot contain symbol keys");
  }

  const keys = Object.keys(value).sort();
  if (keys.length > MAX_COLLECTION_SIZE) {
    throw new RuntimeCircuitBreakerInputError("Fingerprint object exceeds its field limit");
  }

  appendChunk(chunks, "{", budget);
  let wroteField = false;
  for (const key of keys) {
    if (key.length > MAX_KEY_LENGTH) {
      throw new RuntimeCircuitBreakerInputError("Fingerprint field name exceeds its size limit");
    }
    if (isForbiddenObjectKey(key)) {
      throw new RuntimeCircuitBreakerInputError(`Forbidden fingerprint field: ${key}`);
    }
    if (shouldOmitKey(key, mode, depth)) continue;

    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) {
      throw new RuntimeCircuitBreakerInputError("Fingerprint objects cannot contain accessors");
    }
    if (wroteField) appendChunk(chunks, ",", budget);
    appendChunk(chunks, JSON.stringify(key), budget);
    appendChunk(chunks, ":", budget);
    appendCanonicalValue(chunks, descriptor.value, mode, budget, depth + 1);
    wroteField = true;
  }
  appendChunk(chunks, "}", budget);
}

function appendChunk(chunks: string[], chunk: string | undefined, budget: CanonicalBudget): void {
  if (chunk === undefined) {
    throw new RuntimeCircuitBreakerInputError("Fingerprint value cannot be represented");
  }
  budget.length += chunk.length;
  if (budget.length > MAX_CANONICAL_LENGTH) {
    throw new RuntimeCircuitBreakerInputError("Fingerprint input exceeds its canonical size limit");
  }
  chunks.push(chunk);
}

function shouldOmitKey(key: string, mode: FingerprintMode, depth: number): boolean {
  const words = splitKeyWords(key);
  const normalized = words.join("");
  if (isSensitiveKey(normalized)) return true;

  if (mode === "failure") {
    return (
      words.at(-1) === "id" ||
      words.at(-1) === "ids" ||
      isTimestampKey(words, normalized) ||
      normalized === "attempt" ||
      normalized === "attemptnumber" ||
      normalized === "retry" ||
      normalized === "retrycount" ||
      normalized === "nonce" ||
      normalized === "sequence"
    );
  }

  return (depth === 0 && normalized === "id") || PROPOSAL_TRANSPORT_KEYS.has(normalized);
}

const PROPOSAL_TRANSPORT_KEYS = new Set([
  "proposalid",
  "requestid",
  "eventid",
  "correlationid",
  "traceid",
  "spanid",
  "invocationid",
  "commandid",
  "idempotencykey",
  "createdat",
  "createdatms",
  "updatedat",
  "updatedatms",
  "occurredat",
  "occurredatms",
  "receivedat",
  "receivedatms",
  "timestamp",
  "timestampms",
  "requesttimestamp",
  "idempotency",
]);

function isTimestampKey(words: string[], normalized: string): boolean {
  const finalWord = words.at(-1);
  return (
    finalWord === "timestamp" ||
    finalWord === "timestamps" ||
    finalWord === "time" ||
    finalWord === "date" ||
    normalized === "at" ||
    normalized.endsWith("atms") ||
    /^(created|updated|occurred|received|started|finished|failed|requested|completed)at$/.test(
      normalized
    )
  );
}

function isSensitiveKey(normalized: string): boolean {
  return (
    normalized === "key" ||
    normalized.includes("secret") ||
    normalized.includes("password") ||
    normalized.includes("passwd") ||
    normalized.includes("passphrase") ||
    normalized.includes("token") ||
    normalized.includes("credential") ||
    normalized.includes("authorization") ||
    normalized === "auth" ||
    normalized === "authheader" ||
    normalized.includes("cookie") ||
    normalized.includes("privatekey") ||
    normalized.includes("apikey") ||
    normalized.includes("accesskey") ||
    normalized.includes("signingkey") ||
    normalized.includes("encryptionkey") ||
    normalized.includes("sshkey") ||
    normalized.includes("mnemonic") ||
    normalized.includes("seedphrase")
  );
}

function splitKeyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());
}

function normalizeFailureText(value: string): string {
  return normalizeSecretText(value)
    .replace(
      /(\b(?:request|trace|span|session|run|event|proposal|invocation|command|correlation)[ _-]?id\b\s*(?:[:=#]|is)?\s*)["']?[a-z0-9._:/-]+["']?/gi,
      "$1<id>"
    )
    .replace(
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
      "<id>"
    )
    .replace(/\b[0-9a-hjkmnp-tv-z]{26}\b/gi, "<id>")
    .replace(/\b[0-9a-f]{24}\b/gi, "<id>")
    .replace(/\b[0-9a-f]{32,}\b/gi, "<opaque>")
    .replace(/\b\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?z\b/gi, "<timestamp>")
    .replace(/\b(?:1\d{9}|[1-4]\d{12})\b/g, "<timestamp>")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function normalizeSecretText(value: string): string {
  return value
    .replace(
      /-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/gi,
      "<private-key>"
    )
    .replace(/\b(?:bearer|basic)\s+[a-z0-9._~+/=-]+/gi, (match) => {
      const scheme = match.slice(0, match.indexOf(" "));
      return `${scheme} <secret>`;
    })
    .replace(
      /(["']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|passphrase|secret|authorization|cookie|private[_-]?key)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,
      "$1<secret>"
    )
    .replace(/\b[a-z0-9_-]{40,}\b/gi, "<opaque>");
}

function looksLikeEpochTimestamp(value: number): boolean {
  return (
    (Number.isInteger(value) && value >= 1_000_000_000 && value <= 4_999_999_999) ||
    (Number.isInteger(value) && value >= 1_000_000_000_000 && value <= 4_999_999_999_999)
  );
}

function isForbiddenObjectKey(key: string): boolean {
  return key === "__proto__" || key === "prototype" || key === "constructor";
}

function validateRequiredText(name: string, value: unknown, maxLength: number): string {
  const text = validateText(name, value, maxLength).trim();
  if (!text) throw new RuntimeCircuitBreakerInputError(`${name} cannot be empty`);
  return text;
}

function validateText(name: string, value: unknown, maxLength: number): string {
  if (typeof value !== "string" || value.length > maxLength || /[\0]/.test(value)) {
    throw new RuntimeCircuitBreakerInputError(`${name} must be a bounded string without NUL bytes`);
  }
  return value;
}

function validateScope(scope: unknown): asserts scope is string {
  if (
    typeof scope !== "string" ||
    !scope ||
    scope.length > MAX_SCOPE_LENGTH ||
    scope.trim() !== scope ||
    /[\0\r\n\t]/.test(scope)
  ) {
    throw new RuntimeCircuitBreakerInputError("scope must be a bounded, canonical string");
  }
}

function validateOptionsObject(options: RuntimeCircuitBreakerOptions): void {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new RuntimeCircuitBreakerInputError("Circuit-breaker options must be an object");
  }
  const allowed = new Set(["maxEntries", "maxFingerprintsPerEntry", "ttlMs"]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      throw new RuntimeCircuitBreakerInputError(`Unknown circuit-breaker option: ${key}`);
    }
  }
}

function validateBoundedInteger(
  name: string,
  value: number,
  minimum: number,
  maximum: number
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RuntimeCircuitBreakerInputError(
      `${name} must be a safe integer from ${minimum} to ${maximum}`
    );
  }
  return value;
}
