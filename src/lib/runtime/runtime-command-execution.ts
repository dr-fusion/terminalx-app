import { createHash, timingSafeEqual } from "node:crypto";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type {
  AggregateEnforcementProof,
  NonDuplicateRuntimeReceipt,
  Runtime,
  RuntimeHandle,
  RuntimePostStartLifecycleCommand,
  RuntimeReceipt,
} from "./contracts";
import { assertRuntimeCommandAuthorityBinding } from "./runtime-authority";

const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REF = /^[^\u0000-\u001f\u007f]{1,300}$/;
const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_NODES = 20_000;
const MAX_SNAPSHOT_FIELDS = 1_000;
const MAX_SNAPSHOT_STRING_BYTES = 1_000_000;
const AGGREGATE_PROOF_DIGEST_DOMAIN = "terminalx/runtime-aggregate-enforcement-proof/v1\0";

const LIFECYCLE_KINDS = new Set<RuntimePostStartLifecycleCommand["kind"]>([
  "run.pause",
  "run.resume",
  "run.stop",
]);

const COMMAND_BASE_FIELDS = [
  "kind",
  "commandId",
  "binding",
  "projectCeilingRevision",
  "runtimeAuthorizationGeneration",
  "causationId",
  "actor",
  "issuedAtMs",
  "deadlineAtMs",
  "authority",
] as const;

const LIFECYCLE_FIELDS = [
  "agentRunId",
  "runPolicyRevision",
  "fromRunStateVersion",
  "toRunStateVersion",
] as const;

const BINDING_FIELDS = [
  "teamId",
  "projectId",
  "sessionId",
  "runtimeAssignmentId",
  "runtimeAssignmentGeneration",
  "sandboxId",
  "sandboxGeneration",
  "runtimePrincipalId",
] as const;

const REJECTION_CODES = new Set([
  "invalid_authority",
  "expired",
  "stale_binding",
  "stale_fence",
  "conflicting_duplicate",
  "policy_exceeds_ceiling",
  "policy_revision_conflict",
  "second_active_run",
  "awaiting_assignee",
  "invalid_manifest",
  "invalid_grant",
  "grant_consumed",
  "action_already_resolved",
  "forbidden",
  "not_ready",
]);

const QUARANTINE_REASONS = new Set([
  "authorization_ack_failed",
  "effect_enforcer_set_mismatch",
  "isolation_failure",
  "kill_failure",
]);

const ENFORCER_KINDS = new Set([
  "runtime",
  "credential-proxy",
  "source-control",
  "deployment",
  "signer",
  "other-effect-enforcer",
]);

export type RuntimeCommandExecutionErrorCode =
  | "invalid_input"
  | "invalid_authority"
  | "authority_verification_failed"
  | "binding_mismatch"
  | "deadline_expired"
  | "runtime_command_failed"
  | "invalid_receipt";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeCommandExecutionErrorCode, string>> = {
  invalid_input: "Runtime command input is invalid",
  invalid_authority: "Runtime command authority is invalid",
  authority_verification_failed: "Runtime command authority could not be verified",
  binding_mismatch: "Runtime command binding does not match its handle",
  deadline_expired: "Runtime command deadline has expired",
  runtime_command_failed: "Runtime command execution failed",
  invalid_receipt: "Runtime returned an invalid receipt",
};

/** Safe error surface: provider and verifier failures are never attached as causes. */
export class RuntimeCommandExecutionError extends Error {
  constructor(readonly code: RuntimeCommandExecutionErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeCommandExecutionError";
  }
}

export interface RuntimeAuthorityVerificationInput {
  readonly handle: RuntimeHandle;
  readonly command: RuntimePostStartLifecycleCommand;
  readonly nowMs: number;
}

/** A verifier must return literal true only after signature and claims verification. */
export type RuntimeAuthorityVerifier = (
  input: RuntimeAuthorityVerificationInput
) => boolean | Promise<boolean>;

export type RuntimeCommandClock = () => number;

type AggregateEnforcementProofDigestInput = Omit<AggregateEnforcementProof, "aggregateProofDigest">;

type RuntimeDispatch = (
  handle: RuntimeHandle,
  command: RuntimePostStartLifecycleCommand
) => Promise<RuntimeReceipt>;

/**
 * Deep execution Module for existing-Run lifecycle transitions at the
 * untrusted Runtime adapter seam. Durable `run.start` execution remains closed
 * until its complete policy, YOLO, and persistence invariants are implemented.
 * The verifier and adapter receive frozen snapshots, never caller-owned objects,
 * and the returned receipt is an independently validated snapshot.
 */
export async function executeRuntimeCommand(
  runtime: Runtime,
  handle: RuntimeHandle,
  command: RuntimePostStartLifecycleCommand,
  verifyAuthority: RuntimeAuthorityVerifier,
  clock: RuntimeCommandClock
): Promise<RuntimeReceipt> {
  if (typeof verifyAuthority !== "function" || typeof clock !== "function") {
    fail("invalid_input");
  }

  const handleSnapshot = snapshotPortable(handle, "invalid_input");
  const commandSnapshot = snapshotPortable(command, "invalid_input");
  const dispatch = captureRuntimeDispatch(runtime);
  const initialNowMs = sampleClock(clock);
  const preflight = preflightCommand(handleSnapshot, commandSnapshot, initialNowMs);
  const verificationInput = Object.freeze({
    handle: handleSnapshot,
    command: commandSnapshot,
    nowMs: initialNowMs,
  });

  let verified: boolean;
  try {
    verified = (await verifyAuthority(verificationInput)) === true;
  } catch {
    fail("authority_verification_failed");
  }
  if (!verified) fail("authority_verification_failed");

  const dispatchNowMs = sampleClock(clock);
  if (dispatchNowMs < initialNowMs) fail("invalid_input");
  validateTemporalWindow(preflight.temporal, dispatchNowMs);

  let providerReceipt: RuntimeReceipt;
  try {
    providerReceipt = await dispatch(handleSnapshot, commandSnapshot);
  } catch {
    fail("runtime_command_failed");
  }

  const receiptSnapshot = snapshotPortable(providerReceipt, "invalid_receipt");
  validateReceipt(receiptSnapshot, {
    commandId: preflight.commandId,
    binding: preflight.binding,
    authorizationGeneration: preflight.authorizationGeneration,
    lifecycleFence: preflight.lifecycleFence,
  });
  return receiptSnapshot;
}

/** Digest profile providers use when returning a duplicate receipt. */
export function digestNonDuplicateRuntimeReceipt(receipt: NonDuplicateRuntimeReceipt): string {
  const snapshot = snapshotPortable(receipt, "invalid_receipt");
  validateNonDuplicateReceipt(snapshot);
  return sha256Canonical(snapshot);
}

/** Canonical internal-integrity digest for an aggregate proof's exact contents. */
export function digestAggregateEnforcementProof(
  proof: AggregateEnforcementProofDigestInput
): string {
  const snapshot = snapshotPortable(proof, "invalid_receipt");
  validateAggregateProofPayload(snapshot);
  return createHash("sha256")
    .update(AGGREGATE_PROOF_DIGEST_DOMAIN, "utf8")
    .update(canonicalJson(snapshot), "utf8")
    .digest("hex");
}

interface TemporalWindow {
  readonly commandIssuedAtMs: number;
  readonly commandDeadlineAtMs: number;
  readonly authorityIssuedAtMs: number;
  readonly authorityExpiresAtMs: number;
}

interface CommandPreflight {
  readonly commandId: string;
  readonly binding: RuntimeBinding;
  readonly authorizationGeneration: number;
  readonly lifecycleFence: number;
  readonly temporal: TemporalWindow;
}

function preflightCommand(
  handle: RuntimeHandle,
  command: RuntimePostStartLifecycleCommand,
  nowMs: number
): CommandPreflight {
  const handleRecord = validateHandle(handle);
  const commandRecord = plainRecord(command, "invalid_input");
  const kind = dataField(commandRecord, "kind", "invalid_input");
  if (
    typeof kind !== "string" ||
    !LIFECYCLE_KINDS.has(kind as RuntimePostStartLifecycleCommand["kind"])
  ) {
    fail("invalid_input");
  }

  validateLifecycleCommandShape(commandRecord, kind as RuntimePostStartLifecycleCommand["kind"]);
  try {
    assertRuntimeCommandAuthorityBinding(command);
  } catch {
    fail("invalid_authority");
  }

  const commandId = safeRef(
    dataField(commandRecord, "commandId", "invalid_input"),
    "invalid_input"
  );
  safeRef(dataField(commandRecord, "projectCeilingRevision", "invalid_input"), "invalid_input");
  safeRef(dataField(commandRecord, "causationId", "invalid_input"), "invalid_input");
  validateActor(dataField(commandRecord, "actor", "invalid_input"));

  const commandBinding = validateBinding(
    dataField(commandRecord, "binding", "invalid_input"),
    "invalid_input"
  );
  const handleBinding = validateBinding(
    dataField(handleRecord, "binding", "invalid_input"),
    "invalid_input"
  );
  if (!sameBinding(commandBinding, handleBinding)) fail("binding_mismatch");

  const authorizationGeneration = positiveInteger(
    dataField(commandRecord, "runtimeAuthorizationGeneration", "invalid_input"),
    "invalid_input"
  );
  safeRef(dataField(commandRecord, "agentRunId", "invalid_input"), "invalid_input");
  positiveInteger(dataField(commandRecord, "runPolicyRevision", "invalid_input"), "invalid_input");
  const fromRunStateVersion = positiveInteger(
    dataField(commandRecord, "fromRunStateVersion", "invalid_input"),
    "invalid_input"
  );
  const toRunStateVersion = positiveInteger(
    dataField(commandRecord, "toRunStateVersion", "invalid_input"),
    "invalid_input"
  );
  if (toRunStateVersion !== fromRunStateVersion + 1) fail("invalid_input");

  const commandIssuedAtMs = nonNegativeInteger(
    dataField(commandRecord, "issuedAtMs", "invalid_input"),
    "invalid_input"
  );
  const commandDeadlineAtMs = nonNegativeInteger(
    dataField(commandRecord, "deadlineAtMs", "invalid_input"),
    "invalid_input"
  );
  if (commandDeadlineAtMs <= commandIssuedAtMs) fail("invalid_input");

  const authority = plainRecord(
    dataField(commandRecord, "authority", "invalid_authority"),
    "invalid_authority"
  );
  const temporal = {
    commandIssuedAtMs,
    commandDeadlineAtMs,
    authorityIssuedAtMs: nonNegativeInteger(
      dataField(authority, "issuedAtMs", "invalid_authority"),
      "invalid_authority"
    ),
    authorityExpiresAtMs: nonNegativeInteger(
      dataField(authority, "expiresAtMs", "invalid_authority"),
      "invalid_authority"
    ),
  };
  validateTemporalWindow(temporal, nowMs);

  return {
    commandId,
    binding: commandBinding,
    authorizationGeneration,
    lifecycleFence: toRunStateVersion,
    temporal,
  };
}

function validateHandle(handle: RuntimeHandle): Record<string, unknown> {
  const record = plainRecord(handle, "invalid_input");
  exactFields(record, ["binding", "opaqueHandleRef", "capabilities"], [], "invalid_input");
  safeRef(dataField(record, "opaqueHandleRef", "invalid_input"), "invalid_input");
  const capabilities = plainRecord(
    dataField(record, "capabilities", "invalid_input"),
    "invalid_input"
  );
  exactFields(
    capabilities,
    ["isolatedExecution", "brokeredCredentials", "proxyOnlyEgress", "checkpoints", "yoloEligible"],
    [],
    "invalid_input"
  );
  for (const field of [
    "isolatedExecution",
    "brokeredCredentials",
    "proxyOnlyEgress",
    "checkpoints",
    "yoloEligible",
  ]) {
    if (typeof dataField(capabilities, field, "invalid_input") !== "boolean") {
      fail("invalid_input");
    }
  }
  return record;
}

function validateLifecycleCommandShape(
  command: Record<string, unknown>,
  kind: RuntimePostStartLifecycleCommand["kind"]
): void {
  if (kind === "run.pause") {
    exactFields(
      command,
      [...COMMAND_BASE_FIELDS, ...LIFECYCLE_FIELDS, "reason"],
      [],
      "invalid_input"
    );
    if (
      !new Set(["human", "attention_timeout", "limit", "safety"]).has(
        dataField(command, "reason", "invalid_input") as string
      )
    ) {
      fail("invalid_input");
    }
    return;
  }
  if (kind === "run.resume") {
    exactFields(
      command,
      [...COMMAND_BASE_FIELDS, ...LIFECYCLE_FIELDS, "accountableAssigneePresent"],
      [],
      "invalid_input"
    );
    if (dataField(command, "accountableAssigneePresent", "invalid_input") !== true) {
      fail("invalid_input");
    }
    return;
  }
  exactFields(
    command,
    [...COMMAND_BASE_FIELDS, ...LIFECYCLE_FIELDS, "reason"],
    [],
    "invalid_input"
  );
  if (
    !new Set(["human", "final_review_closed", "superseded"]).has(
      dataField(command, "reason", "invalid_input") as string
    )
  ) {
    fail("invalid_input");
  }
}

function validateActor(value: unknown): void {
  const actor = plainRecord(value, "invalid_input");
  exactFields(actor, ["kind", "actorRef"], [], "invalid_input");
  const kind = dataField(actor, "kind", "invalid_input");
  if (kind !== "human" && kind !== "system") fail("invalid_input");
  safeRef(dataField(actor, "actorRef", "invalid_input"), "invalid_input");
}

function validateTemporalWindow(window: TemporalWindow, nowMs: number): void {
  if (nowMs < window.commandIssuedAtMs) fail("invalid_input");
  if (nowMs >= window.commandDeadlineAtMs) fail("deadline_expired");
  if (nowMs < window.authorityIssuedAtMs || nowMs >= window.authorityExpiresAtMs) {
    fail("invalid_authority");
  }
}

interface ExpectedReceiptBinding {
  readonly commandId: string;
  readonly binding: RuntimeBinding;
  readonly authorizationGeneration: number;
  readonly lifecycleFence: number;
}

function validateReceipt(receipt: RuntimeReceipt, expected: ExpectedReceiptBinding): void {
  const record = plainRecord(receipt, "invalid_receipt");
  if (dataField(record, "outcome", "invalid_receipt") === "duplicate") {
    exactFields(record, [
      "commandId",
      "binding",
      "runtimeAuthorizationGeneration",
      "outcome",
      "originalReceipt",
      "originalReceiptDigest",
    ]);
    validateReceiptBase(record, expected);
    const original = dataField(
      record,
      "originalReceipt",
      "invalid_receipt"
    ) as NonDuplicateRuntimeReceipt;
    validateNonDuplicateReceipt(original, expected);
    const claimedDigest = dataField(record, "originalReceiptDigest", "invalid_receipt");
    if (typeof claimedDigest !== "string" || !SHA256.test(claimedDigest)) {
      fail("invalid_receipt");
    }
    const actualDigest = sha256Canonical(original);
    if (!sameDigest(claimedDigest, actualDigest)) fail("invalid_receipt");
    return;
  }
  validateNonDuplicateReceipt(receipt as NonDuplicateRuntimeReceipt, expected);
}

function validateNonDuplicateReceipt(
  receipt: NonDuplicateRuntimeReceipt,
  expected?: ExpectedReceiptBinding
): void {
  const record = plainRecord(receipt, "invalid_receipt");
  const outcome = dataField(record, "outcome", "invalid_receipt");

  if (outcome === "accepted") {
    exactFields(record, [
      "commandId",
      "binding",
      "runtimeAuthorizationGeneration",
      "outcome",
      "effectRef",
    ]);
    safeRef(dataField(record, "effectRef", "invalid_receipt"), "invalid_receipt");
  } else if (outcome === "enforced") {
    exactFields(
      record,
      [
        "commandId",
        "binding",
        "runtimeAuthorizationGeneration",
        "outcome",
        "effectRef",
        "enforcedFence",
      ],
      ["aggregateEnforcementProof"]
    );
    safeRef(dataField(record, "effectRef", "invalid_receipt"), "invalid_receipt");
    const enforcedFence = positiveInteger(
      dataField(record, "enforcedFence", "invalid_receipt"),
      "invalid_receipt"
    );
    if (expected && enforcedFence !== expected.lifecycleFence) fail("invalid_receipt");
    const proof = optionalDataField(record, "aggregateEnforcementProof", "invalid_receipt");
    if (proof !== undefined) {
      validateAggregateProof(
        proof,
        positiveInteger(
          dataField(record, "runtimeAuthorizationGeneration", "invalid_receipt"),
          "invalid_receipt"
        )
      );
    }
  } else if (outcome === "rejected") {
    exactFields(record, [
      "commandId",
      "binding",
      "runtimeAuthorizationGeneration",
      "outcome",
      "code",
      "safeDetail",
    ]);
    if (!REJECTION_CODES.has(dataField(record, "code", "invalid_receipt") as string)) {
      fail("invalid_receipt");
    }
    safeText(dataField(record, "safeDetail", "invalid_receipt"), 500, "invalid_receipt", true);
  } else if (outcome === "quarantined") {
    exactFields(record, [
      "commandId",
      "binding",
      "runtimeAuthorizationGeneration",
      "outcome",
      "reason",
      "effectRef",
    ]);
    if (!QUARANTINE_REASONS.has(dataField(record, "reason", "invalid_receipt") as string)) {
      fail("invalid_receipt");
    }
    safeRef(dataField(record, "effectRef", "invalid_receipt"), "invalid_receipt");
  } else {
    fail("invalid_receipt");
  }

  positiveInteger(
    dataField(record, "runtimeAuthorizationGeneration", "invalid_receipt"),
    "invalid_receipt"
  );
  validateBinding(dataField(record, "binding", "invalid_receipt"), "invalid_receipt");
  safeRef(dataField(record, "commandId", "invalid_receipt"), "invalid_receipt");
  if (expected) validateReceiptBase(record, expected);
}

function validateReceiptBase(
  record: Record<string, unknown>,
  expected: ExpectedReceiptBinding
): void {
  if (
    dataField(record, "commandId", "invalid_receipt") !== expected.commandId ||
    dataField(record, "runtimeAuthorizationGeneration", "invalid_receipt") !==
      expected.authorizationGeneration
  ) {
    fail("invalid_receipt");
  }
  const binding = validateBinding(
    dataField(record, "binding", "invalid_receipt"),
    "invalid_receipt"
  );
  if (!sameBinding(binding, expected.binding)) fail("invalid_receipt");
}

function validateAggregateProof(value: unknown, expectedGeneration: number): void {
  const proof = plainRecord(value, "invalid_receipt");
  exactFields(proof, [
    "generation",
    "requiredEffectEnforcerSetDigest",
    "acknowledgements",
    "aggregateProofDigest",
  ]);
  if (
    positiveInteger(dataField(proof, "generation", "invalid_receipt"), "invalid_receipt") !==
    expectedGeneration
  ) {
    fail("invalid_receipt");
  }
  const claimedDigest = sha256(
    dataField(proof, "aggregateProofDigest", "invalid_receipt"),
    "invalid_receipt"
  );
  const payload = Object.freeze({
    generation: dataField(proof, "generation", "invalid_receipt"),
    requiredEffectEnforcerSetDigest: dataField(
      proof,
      "requiredEffectEnforcerSetDigest",
      "invalid_receipt"
    ),
    acknowledgements: dataField(proof, "acknowledgements", "invalid_receipt"),
  }) as AggregateEnforcementProofDigestInput;
  validateAggregateProofPayload(payload);
  const actualDigest = createHash("sha256")
    .update(AGGREGATE_PROOF_DIGEST_DOMAIN, "utf8")
    .update(canonicalJson(payload), "utf8")
    .digest("hex");
  if (!sameDigest(claimedDigest, actualDigest)) fail("invalid_receipt");
}

function validateAggregateProofPayload(value: unknown): void {
  const proof = plainRecord(value, "invalid_receipt");
  exactFields(proof, ["generation", "requiredEffectEnforcerSetDigest", "acknowledgements"]);
  positiveInteger(dataField(proof, "generation", "invalid_receipt"), "invalid_receipt");
  sha256(dataField(proof, "requiredEffectEnforcerSetDigest", "invalid_receipt"), "invalid_receipt");
  const acknowledgements = dataField(proof, "acknowledgements", "invalid_receipt");
  if (
    !Array.isArray(acknowledgements) ||
    acknowledgements.length < 1 ||
    acknowledgements.length > 64
  ) {
    fail("invalid_receipt");
  }
  const enforcerRefs = new Set<string>();
  for (const acknowledgement of acknowledgements) {
    const record = plainRecord(acknowledgement, "invalid_receipt");
    exactFields(record, ["enforcerRef", "enforcerKind", "acknowledgementDigest"]);
    const enforcerRef = safeRef(
      dataField(record, "enforcerRef", "invalid_receipt"),
      "invalid_receipt"
    );
    if (
      enforcerRefs.has(enforcerRef) ||
      !ENFORCER_KINDS.has(dataField(record, "enforcerKind", "invalid_receipt") as string)
    ) {
      fail("invalid_receipt");
    }
    enforcerRefs.add(enforcerRef);
    sha256(dataField(record, "acknowledgementDigest", "invalid_receipt"), "invalid_receipt");
  }
}

function validateBinding(value: unknown, code: RuntimeCommandExecutionErrorCode): RuntimeBinding {
  const binding = plainRecord(value, code);
  exactFields(binding, BINDING_FIELDS, [], code);
  safeRef(dataField(binding, "teamId", code), code);
  safeRef(dataField(binding, "projectId", code), code);
  safeRef(dataField(binding, "sessionId", code), code);
  safeRef(dataField(binding, "runtimeAssignmentId", code), code);
  positiveInteger(dataField(binding, "runtimeAssignmentGeneration", code), code);
  safeRef(dataField(binding, "sandboxId", code), code);
  positiveInteger(dataField(binding, "sandboxGeneration", code), code);
  safeRef(dataField(binding, "runtimePrincipalId", code), code);
  return binding as unknown as RuntimeBinding;
}

function sameBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
  return BINDING_FIELDS.every((field) => left[field] === right[field]);
}

function captureRuntimeDispatch(runtime: Runtime): RuntimeDispatch {
  try {
    if ((typeof runtime !== "object" && typeof runtime !== "function") || runtime === null) {
      fail("invalid_input");
    }
    const method = Reflect.get(runtime as object, "command");
    if (typeof method !== "function") fail("invalid_input");
    return (handle, command) =>
      Reflect.apply(method, runtime, [handle, command]) as Promise<RuntimeReceipt>;
  } catch {
    fail("invalid_input");
  }
}

function sampleClock(clock: RuntimeCommandClock): number {
  try {
    const nowMs = clock();
    if (!isNonNegativeSafeInteger(nowMs)) fail("invalid_input");
    return nowMs;
  } catch {
    fail("invalid_input");
  }
}

function snapshotPortable<T>(value: T, code: RuntimeCommandExecutionErrorCode): T {
  try {
    const state: SnapshotState = {
      ancestors: new Set<object>(),
      remainingNodes: MAX_SNAPSHOT_NODES,
      remainingStringBytes: MAX_SNAPSHOT_STRING_BYTES,
    };
    return clonePortable(value, state, 0) as T;
  } catch {
    fail(code);
  }
}

interface SnapshotState {
  readonly ancestors: Set<object>;
  remainingNodes: number;
  remainingStringBytes: number;
}

function clonePortable(value: unknown, state: SnapshotState, depth: number): unknown {
  if (depth > MAX_SNAPSHOT_DEPTH || state.remainingNodes-- < 1) throw new TypeError();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    state.remainingStringBytes -= Buffer.byteLength(value, "utf8");
    if (state.remainingStringBytes < 0) throw new TypeError();
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new TypeError();
    return value;
  }
  if (typeof value !== "object") throw new TypeError();
  if (state.ancestors.has(value)) throw new TypeError();
  state.ancestors.add(value);

  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes("length")) throw new TypeError();
    const clone: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new TypeError();
      }
      clone.push(clonePortable(descriptor.value, state, depth + 1));
    }
    state.ancestors.delete(value);
    return Object.freeze(clone);
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_SNAPSHOT_FIELDS) throw new TypeError();
  const clone = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new TypeError();
    }
    if (descriptor.value === undefined) throw new TypeError();
    Object.defineProperty(clone, key, {
      value: clonePortable(descriptor.value, state, depth + 1),
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  state.ancestors.delete(value);
  return Object.freeze(clone);
}

function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail("invalid_receipt");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = plainRecord(value, "invalid_receipt");
  return `{${Reflect.ownKeys(record)
    .map((key) => {
      if (typeof key !== "string") fail("invalid_receipt");
      return key;
    })
    .sort()
    .map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(dataField(record, key, "invalid_receipt"))}`
    )
    .join(",")}}`;
}

function exactFields(
  record: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
  code: RuntimeCommandExecutionErrorCode = "invalid_receipt"
): void {
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(record);
  if (
    keys.length < required.length ||
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    required.some((key) => !keys.includes(key))
  ) {
    fail(code);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  }
}

function plainRecord(
  value: unknown,
  code: RuntimeCommandExecutionErrorCode
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(code);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(code);
  return value as Record<string, unknown>;
}

function dataField(
  record: Record<string, unknown>,
  key: string,
  code: RuntimeCommandExecutionErrorCode
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  return descriptor.value;
}

function optionalDataField(
  record: Record<string, unknown>,
  key: string,
  code: RuntimeCommandExecutionErrorCode
): unknown {
  if (!Object.hasOwn(record, key)) return undefined;
  const value = dataField(record, key, code);
  if (value === undefined) fail(code);
  return value;
}

function safeRef(value: unknown, code: RuntimeCommandExecutionErrorCode): string {
  if (typeof value !== "string" || value.trim() !== value || !SAFE_REF.test(value)) fail(code);
  return value;
}

function safeText(
  value: unknown,
  maximumLength: number,
  code: RuntimeCommandExecutionErrorCode,
  emptyAllowed = false
): string {
  if (
    typeof value !== "string" ||
    (!emptyAllowed && value.length < 1) ||
    value.length > maximumLength ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)
  ) {
    fail(code);
  }
  return value;
}

function nonNegativeInteger(value: unknown, code: RuntimeCommandExecutionErrorCode): number {
  if (!isNonNegativeSafeInteger(value)) fail(code);
  return value;
}

function positiveInteger(value: unknown, code: RuntimeCommandExecutionErrorCode): number {
  const result = nonNegativeInteger(value, code);
  if (result < 1) fail(code);
  return result;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && !Object.is(value, -0);
}

function sha256(value: unknown, code: RuntimeCommandExecutionErrorCode): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(code);
  return value;
}

function sameDigest(left: string, right: string): boolean {
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function fail(code: RuntimeCommandExecutionErrorCode): never {
  throw new RuntimeCommandExecutionError(code);
}
