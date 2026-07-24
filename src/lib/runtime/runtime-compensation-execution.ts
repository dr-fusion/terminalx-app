import { createHash, timingSafeEqual } from "node:crypto";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type {
  AggregateEnforcementProof,
  NonDuplicateRuntimeCompensationReceipt,
  RuntimeCompensationCommand,
  RuntimeCompensationReceipt,
  RuntimeHandle,
} from "./contracts";
import { assertRuntimeCommandAuthorityBinding } from "./runtime-authority";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import {
  captureRuntimeCommandDataFunction,
  type RuntimeCommandCapability,
  type RuntimeCommandDataFunction,
} from "./runtime-command-dispatch";
import {
  RuntimeCompensationEnforcementProofError,
  verifyRuntimeCompensationEnforcementProof,
  verifyRuntimeCompensationEnforcementProofSynchronously,
  type RuntimeCompensationEnforcementProofVerifier,
  type RuntimeCompensationEnforcementSubject,
  type SynchronousRuntimeCompensationEnforcementProofVerifier,
} from "./runtime-compensation-enforcement-proof";
import {
  commitRuntimeEffectRef,
  snapshotAggregateEnforcementProof,
  snapshotPersistedRuntimeEffectRefCommitment,
} from "./runtime-enforcement-proof";

export const RUNTIME_COMPENSATION_RECEIPT_DIGEST_DOMAIN =
  "terminalx/runtime-compensation-receipt/v1\0" as const;

const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REF = /^[^\u0000-\u001f\u007f]{1,300}$/;
const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_NODES = 20_000;
const MAX_SNAPSHOT_FIELDS = 1_000;
const MAX_SNAPSHOT_STRING_BYTES = 1_000_000;
const COMMAND_FIELDS = [
  "kind",
  "commandId",
  "compensationId",
  "binding",
  "observedRuntimeAuthorizationGeneration",
  "source",
  "platformSecurityPolicyRevision",
  "requiredContainmentEnforcerSetDigest",
  "containment",
  "safetyFence",
  "exactBindingOnly",
  "advanceBeyondCurrentFences",
  "reasonRef",
  "causationId",
  "actor",
  "issuedAtMs",
  "deadlineAtMs",
  "authority",
] as const;
const SOURCE_FIELDS = [
  "lifecycleCommandId",
  "lifecycleCommandClaimsDigest",
  "lifecycleReceiptDigest",
  "lifecycleEnforcementSubjectDigest",
  "lifecycleAggregateProofDigest",
  "sourceRequiredEffectEnforcerSetDigest",
] as const;
const COMMAND_CONTAINMENT_FIELDS = [
  "revokeTerminalWrites",
  "stopProcessExecution",
  "quarantineRuntime",
] as const;
const RECEIPT_CONTAINMENT_FIELDS = [
  "terminalWritesRevoked",
  "processExecutionStopped",
  "runtimeQuarantined",
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
  "forbidden",
  "not_ready",
]);
const QUARANTINE_REASONS = new Set([
  "authorization_ack_failed",
  "effect_enforcer_set_mismatch",
  "isolation_failure",
  "kill_failure",
]);

export type RuntimeCompensationExecutionErrorCode =
  | "invalid_input"
  | "invalid_authority"
  | "authority_verification_failed"
  | "binding_mismatch"
  | "deadline_expired"
  | "runtime_command_failed"
  | "invalid_receipt"
  | "enforcement_proof_verification_failed";

export type RuntimeCompensationDispatchCertainty = "not-dispatched" | "dispatch-uncertain";

const DISPATCH_CERTAINTY: Readonly<
  Record<RuntimeCompensationExecutionErrorCode, RuntimeCompensationDispatchCertainty>
> = {
  invalid_input: "not-dispatched",
  invalid_authority: "not-dispatched",
  authority_verification_failed: "not-dispatched",
  binding_mismatch: "not-dispatched",
  deadline_expired: "not-dispatched",
  runtime_command_failed: "dispatch-uncertain",
  invalid_receipt: "dispatch-uncertain",
  enforcement_proof_verification_failed: "dispatch-uncertain",
};

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeCompensationExecutionErrorCode, string>> = {
  invalid_input: "Runtime compensation command input is invalid",
  invalid_authority: "Runtime compensation command authority is invalid",
  authority_verification_failed: "Runtime compensation authority could not be verified",
  binding_mismatch: "Runtime compensation binding does not match its historical handle",
  deadline_expired: "Runtime compensation command deadline has expired",
  runtime_command_failed: "Runtime compensation command execution failed",
  invalid_receipt: "Runtime returned an invalid compensation receipt",
  enforcement_proof_verification_failed:
    "Runtime compensation enforcement proof could not be verified",
};

/** Safe failure surface: no provider, transport, signer, or verifier detail is attached. */
export class RuntimeCompensationExecutionError extends Error {
  readonly dispatchCertainty: RuntimeCompensationDispatchCertainty;

  constructor(readonly code: RuntimeCompensationExecutionErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeCompensationExecutionError";
    this.dispatchCertainty = DISPATCH_CERTAINTY[code];
  }
}

export interface RuntimeCompensationAuthorityVerificationInput {
  readonly handle: RuntimeHandle;
  readonly command: RuntimeCompensationCommand;
  readonly nowMs: number;
}

export type RuntimeCompensationAuthorityVerifier = (
  input: RuntimeCompensationAuthorityVerificationInput
) => boolean | Promise<boolean>;

export type RuntimeCompensationClock = () => number;

export type RuntimeCompensationDispatch = (
  handle: RuntimeHandle,
  command: RuntimeCompensationCommand,
  signal: AbortSignal
) => Promise<unknown>;

/**
 * Execute one platform-security containment command against an exact historical
 * binding. Current Session/Run state is deliberately absent from this module.
 */
export async function executeRuntimeCompensationCommand(
  runtime: RuntimeCommandCapability,
  handle: RuntimeHandle,
  command: RuntimeCompensationCommand,
  verifyAuthority: RuntimeCompensationAuthorityVerifier,
  clock: RuntimeCompensationClock,
  verifyEnforcementProof: RuntimeCompensationEnforcementProofVerifier,
  runtimeCommandSignal: AbortSignal = new AbortController().signal
): Promise<RuntimeCompensationReceipt> {
  const dispatch = captureRuntimeCompensationDispatch(runtime);
  return executeCapturedRuntimeCompensationCommand(
    dispatch,
    handle,
    command,
    verifyAuthority,
    clock,
    verifyEnforcementProof,
    runtimeCommandSignal
  );
}

/**
 * Execute through a Runtime command data-function captured by the composition
 * root. Compensation supervisors use this path so provider property lookup
 * cannot occur after their durable dispatch marker is renewed.
 */
export async function executeCapturedRuntimeCompensationCommand(
  dispatch: RuntimeCompensationDispatch,
  handle: RuntimeHandle,
  command: RuntimeCompensationCommand,
  verifyAuthority: RuntimeCompensationAuthorityVerifier,
  clock: RuntimeCompensationClock,
  verifyEnforcementProof: RuntimeCompensationEnforcementProofVerifier,
  runtimeCommandSignal: AbortSignal = new AbortController().signal
): Promise<RuntimeCompensationReceipt> {
  if (
    typeof dispatch !== "function" ||
    typeof verifyAuthority !== "function" ||
    typeof clock !== "function" ||
    typeof verifyEnforcementProof !== "function" ||
    !isNativeAbortSignal(runtimeCommandSignal)
  ) {
    fail("invalid_input");
  }
  if (runtimeCommandSignal.aborted) fail("runtime_command_failed");

  const handleSnapshot = snapshotPortable(handle, "invalid_input");
  const commandSnapshot = snapshotPortable(command, "invalid_input");
  const initialNowMs = sampleClock(clock);
  const temporal = preflightCommand(handleSnapshot, commandSnapshot, initialNowMs);

  await requireAuthority(
    verifyAuthority,
    Object.freeze({ handle: handleSnapshot, command: commandSnapshot, nowMs: initialNowMs })
  );
  const dispatchNowMs = sampleClock(clock);
  if (dispatchNowMs < initialNowMs) fail("invalid_input");
  validateTemporalWindow(temporal, dispatchNowMs);
  if (runtimeCommandSignal.aborted) fail("runtime_command_failed");

  // Recheck the exact signed command at the last in-process boundary before
  // Runtime dispatch. A stale or stateful verifier cannot reuse the first pass.
  await requireAuthority(
    verifyAuthority,
    Object.freeze({ handle: handleSnapshot, command: commandSnapshot, nowMs: dispatchNowMs })
  );
  const authorityConfirmedAtMs = sampleClock(clock);
  if (authorityConfirmedAtMs < dispatchNowMs) fail("invalid_input");
  validateTemporalWindow(temporal, authorityConfirmedAtMs);
  if (runtimeCommandSignal.aborted) fail("runtime_command_failed");

  let providerReceipt: unknown;
  try {
    providerReceipt = await dispatch(handleSnapshot, commandSnapshot, runtimeCommandSignal);
  } catch {
    fail("runtime_command_failed");
  }
  if (runtimeCommandSignal.aborted) fail("runtime_command_failed");

  const receipt = snapshotRuntimeCompensationReceiptForCommand(providerReceipt, commandSnapshot);
  await verifyRuntimeCompensationReceiptEnforcementProof(
    commandSnapshot,
    receipt,
    verifyEnforcementProof
  );
  return receipt;
}

export function snapshotRuntimeCompensationReceiptForCommand(
  receipt: unknown,
  command: RuntimeCompensationCommand
): RuntimeCompensationReceipt {
  return snapshotCompensationReceiptForCommand(receipt, command, "raw-provider");
}

/** Explicit trusted-persistence path; provider values must never call this. */
export function snapshotPersistedRuntimeCompensationReceiptForCommand(
  receipt: unknown,
  command: RuntimeCompensationCommand
): RuntimeCompensationReceipt {
  return snapshotCompensationReceiptForCommand(receipt, command, "persisted-commitment");
}

export function digestNonDuplicateRuntimeCompensationReceipt(
  receipt: NonDuplicateRuntimeCompensationReceipt
): string {
  const snapshot = snapshotPortable(receipt, "invalid_receipt");
  validateNonDuplicateReceipt(snapshot, undefined, "raw-provider");
  return digestReceipt(snapshot);
}

export async function verifyRuntimeCompensationReceiptEnforcementProof(
  command: RuntimeCompensationCommand,
  receipt: RuntimeCompensationReceipt,
  verifier: RuntimeCompensationEnforcementProofVerifier
): Promise<void> {
  const effective = enforcedReceipt(receipt);
  if (!effective) return;
  if (!effective.aggregateEnforcementProof) fail("invalid_receipt");
  try {
    await verifyRuntimeCompensationEnforcementProof(
      compensationSubject(command, effective, "raw-provider"),
      effective.aggregateEnforcementProof,
      verifier
    );
  } catch (error) {
    mapProofError(error);
  }
}

export function verifyRuntimeCompensationReceiptEnforcementProofSynchronously(
  command: RuntimeCompensationCommand,
  receipt: RuntimeCompensationReceipt,
  verifier: SynchronousRuntimeCompensationEnforcementProofVerifier
): void {
  verifyCompensationReceiptProofSynchronously(command, receipt, verifier, "raw-provider");
}

export function verifyPersistedRuntimeCompensationReceiptEnforcementProofSynchronously(
  command: RuntimeCompensationCommand,
  receipt: RuntimeCompensationReceipt,
  verifier: SynchronousRuntimeCompensationEnforcementProofVerifier
): void {
  verifyCompensationReceiptProofSynchronously(
    command,
    snapshotPersistedRuntimeCompensationReceiptForCommand(receipt, command),
    verifier,
    "persisted-commitment"
  );
}

function verifyCompensationReceiptProofSynchronously(
  command: RuntimeCompensationCommand,
  receipt: RuntimeCompensationReceipt,
  verifier: SynchronousRuntimeCompensationEnforcementProofVerifier,
  effectRefForm: EffectRefForm
): void {
  const effective = enforcedReceipt(receipt);
  if (!effective) return;
  if (!effective.aggregateEnforcementProof) fail("invalid_receipt");
  try {
    verifyRuntimeCompensationEnforcementProofSynchronously(
      compensationSubject(command, effective, effectRefForm),
      effective.aggregateEnforcementProof,
      verifier
    );
  } catch (error) {
    mapProofError(error);
  }
}

function mapProofError(error: unknown): never {
  if (
    error instanceof RuntimeCompensationEnforcementProofError &&
    (error.code === "invalid_subject" || error.code === "invalid_proof")
  ) {
    fail("invalid_receipt");
  }
  fail("enforcement_proof_verification_failed");
}

type EnforcedCompensationReceipt = Extract<
  NonDuplicateRuntimeCompensationReceipt,
  { outcome: "enforced" }
>;
type EffectRefForm = "raw-provider" | "persisted-commitment";

function enforcedReceipt(
  receipt: RuntimeCompensationReceipt
): EnforcedCompensationReceipt | undefined {
  if (receipt.outcome === "enforced") return receipt;
  if (receipt.outcome === "duplicate" && receipt.originalReceipt.outcome === "enforced") {
    return receipt.originalReceipt;
  }
  return undefined;
}

function compensationSubject(
  command: RuntimeCompensationCommand,
  receipt: EnforcedCompensationReceipt,
  effectRefForm: EffectRefForm
): RuntimeCompensationEnforcementSubject {
  return {
    version: 1,
    purpose: "stale-lifecycle-effect-containment",
    compensationId: command.compensationId,
    commandId: command.commandId,
    commandClaimsDigest: command.authority.claimsDigest,
    binding: command.binding,
    observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
    safetyFence: command.safetyFence,
    enforcedSafetyFence: receipt.enforcedSafetyFence,
    sourceReceiptDigest: command.source.lifecycleReceiptDigest,
    sourceEnforcementSubjectDigest: command.source.lifecycleEnforcementSubjectDigest,
    sourceAggregateProofDigest: command.source.lifecycleAggregateProofDigest,
    requiredContainmentEnforcerSetDigest: command.requiredContainmentEnforcerSetDigest,
    effectRefCommitment:
      effectRefForm === "raw-provider"
        ? commitRuntimeEffectRef(receipt.effectRef)
        : snapshotPersistedRuntimeEffectRefCommitment(receipt.effectRef),
    containment: receipt.containment,
  };
}

interface TemporalWindow {
  readonly commandIssuedAtMs: number;
  readonly commandDeadlineAtMs: number;
  readonly authorityIssuedAtMs: number;
  readonly authorityExpiresAtMs: number;
}

function preflightCommand(
  handle: RuntimeHandle,
  command: RuntimeCompensationCommand,
  nowMs: number
): TemporalWindow {
  const handleRecord = exactRecord(handle, ["binding", "opaqueHandleRef", "capabilities"]);
  safeRef(field(handleRecord, "opaqueHandleRef"), "invalid_input");
  validateCapabilities(field(handleRecord, "capabilities"));

  const record = exactRecord(command, COMMAND_FIELDS);
  if (field(record, "kind") !== "safety.quarantine") fail("invalid_input");
  try {
    assertRuntimeCommandAuthorityBinding(command);
  } catch {
    fail("invalid_authority");
  }

  safeRef(field(record, "commandId"), "invalid_input");
  safeRef(field(record, "compensationId"), "invalid_input");
  const commandBinding = validateBinding(field(record, "binding"), "invalid_input");
  const handleBinding = validateBinding(field(handleRecord, "binding"), "invalid_input");
  if (!sameBinding(commandBinding, handleBinding)) fail("binding_mismatch");
  positiveInteger(field(record, "observedRuntimeAuthorizationGeneration"), "invalid_input");

  const source = exactRecord(field(record, "source"), SOURCE_FIELDS);
  const lifecycleCommandId = safeRef(field(source, "lifecycleCommandId"), "invalid_input");
  for (const digestField of SOURCE_FIELDS.slice(1)) {
    sha256(field(source, digestField), "invalid_input");
  }
  safeRef(field(record, "platformSecurityPolicyRevision"), "invalid_input");
  sha256(field(record, "requiredContainmentEnforcerSetDigest"), "invalid_input");
  validateCommandContainment(field(record, "containment"));
  positiveInteger(field(record, "safetyFence"), "invalid_input");
  if (
    field(record, "exactBindingOnly") !== true ||
    field(record, "advanceBeyondCurrentFences") !== true
  ) {
    fail("invalid_input");
  }
  safeRef(field(record, "reasonRef"), "invalid_input");
  if (safeRef(field(record, "causationId"), "invalid_input") !== lifecycleCommandId) {
    fail("invalid_input");
  }
  const actor = exactRecord(field(record, "actor"), ["kind", "actorRef"]);
  if (field(actor, "kind") !== "system" || field(actor, "actorRef") !== "platform-security") {
    fail("invalid_input");
  }

  const commandIssuedAtMs = nonNegativeInteger(field(record, "issuedAtMs"), "invalid_input");
  const commandDeadlineAtMs = nonNegativeInteger(field(record, "deadlineAtMs"), "invalid_input");
  if (commandDeadlineAtMs <= commandIssuedAtMs) fail("invalid_input");
  const authority = plainRecord(field(record, "authority"), "invalid_authority");
  if (
    field(authority, "issuer") !== "platform-security" ||
    field(authority, "capability") !== "safety.quarantine"
  ) {
    fail("invalid_authority");
  }
  const temporal = {
    commandIssuedAtMs,
    commandDeadlineAtMs,
    authorityIssuedAtMs: nonNegativeInteger(field(authority, "issuedAtMs"), "invalid_authority"),
    authorityExpiresAtMs: nonNegativeInteger(field(authority, "expiresAtMs"), "invalid_authority"),
  };
  validateTemporalWindow(temporal, nowMs);
  return temporal;
}

function validateCapabilities(value: unknown): void {
  const capabilities = exactRecord(value, [
    "isolatedExecution",
    "brokeredCredentials",
    "proxyOnlyEgress",
    "checkpoints",
    "yoloEligible",
  ]);
  for (const name of Reflect.ownKeys(capabilities)) {
    if (typeof name !== "string" || typeof field(capabilities, name) !== "boolean") {
      fail("invalid_input");
    }
  }
}

function validateCommandContainment(value: unknown): void {
  const containment = exactRecord(value, COMMAND_CONTAINMENT_FIELDS);
  if (
    field(containment, "revokeTerminalWrites") !== true ||
    field(containment, "stopProcessExecution") !== true ||
    field(containment, "quarantineRuntime") !== true
  ) {
    fail("invalid_input");
  }
}

function validateReceiptContainment(value: unknown): void {
  const containment = exactRecord(value, RECEIPT_CONTAINMENT_FIELDS, "invalid_receipt");
  if (
    field(containment, "terminalWritesRevoked", "invalid_receipt") !== true ||
    field(containment, "processExecutionStopped", "invalid_receipt") !== true ||
    field(containment, "runtimeQuarantined", "invalid_receipt") !== true
  ) {
    fail("invalid_receipt");
  }
}

async function requireAuthority(
  verifier: RuntimeCompensationAuthorityVerifier,
  input: RuntimeCompensationAuthorityVerificationInput
): Promise<void> {
  let verified: unknown;
  try {
    verified = await verifier(input);
  } catch {
    fail("authority_verification_failed");
  }
  if (verified !== true) fail("authority_verification_failed");
}

function validateTemporalWindow(window: TemporalWindow, nowMs: number): void {
  if (nowMs < window.commandIssuedAtMs) fail("invalid_input");
  if (nowMs >= window.commandDeadlineAtMs) fail("deadline_expired");
  if (nowMs < window.authorityIssuedAtMs || nowMs >= window.authorityExpiresAtMs) {
    fail("invalid_authority");
  }
}

function snapshotCompensationReceiptForCommand(
  value: unknown,
  command: RuntimeCompensationCommand,
  effectRefForm: EffectRefForm
): RuntimeCompensationReceipt {
  const receipt = snapshotPortable(value, "invalid_receipt") as RuntimeCompensationReceipt;
  validateReceipt(receipt, command, effectRefForm);
  return receipt;
}

function validateReceipt(
  receipt: RuntimeCompensationReceipt,
  command: RuntimeCompensationCommand,
  effectRefForm: EffectRefForm
): void {
  const record = plainRecord(receipt, "invalid_receipt");
  if (field(record, "outcome", "invalid_receipt") === "duplicate") {
    exactFields(
      record,
      [
        "receiptKind",
        "compensationId",
        "commandId",
        "binding",
        "observedRuntimeAuthorizationGeneration",
        "outcome",
        "originalReceipt",
        "originalReceiptDigest",
      ],
      "invalid_receipt"
    );
    validateReceiptBase(record, command);
    const original = field(record, "originalReceipt", "invalid_receipt");
    validateNonDuplicateReceipt(
      original as NonDuplicateRuntimeCompensationReceipt,
      command,
      effectRefForm
    );
    const claimedDigest = sha256(
      field(record, "originalReceiptDigest", "invalid_receipt"),
      "invalid_receipt"
    );
    if (!sameDigest(claimedDigest, digestReceipt(original))) fail("invalid_receipt");
    return;
  }
  validateNonDuplicateReceipt(
    receipt as NonDuplicateRuntimeCompensationReceipt,
    command,
    effectRefForm
  );
}

function validateNonDuplicateReceipt(
  receipt: NonDuplicateRuntimeCompensationReceipt,
  command?: RuntimeCompensationCommand,
  effectRefForm: EffectRefForm = "raw-provider"
): void {
  const record = plainRecord(receipt, "invalid_receipt");
  const outcome = field(record, "outcome", "invalid_receipt");
  const base = [
    "receiptKind",
    "compensationId",
    "commandId",
    "binding",
    "observedRuntimeAuthorizationGeneration",
    "outcome",
  ] as const;
  if (outcome === "accepted") {
    exactFields(record, [...base, "effectRef"], "invalid_receipt");
    validateEffectRef(field(record, "effectRef", "invalid_receipt"), effectRefForm);
  } else if (outcome === "enforced") {
    exactFields(
      record,
      [...base, "effectRef", "enforcedSafetyFence", "containment", "aggregateEnforcementProof"],
      "invalid_receipt"
    );
    validateEffectRef(field(record, "effectRef", "invalid_receipt"), effectRefForm);
    const enforcedSafetyFence = positiveInteger(
      field(record, "enforcedSafetyFence", "invalid_receipt"),
      "invalid_receipt"
    );
    if (command && enforcedSafetyFence < command.safetyFence) fail("invalid_receipt");
    validateReceiptContainment(field(record, "containment", "invalid_receipt"));
    const proof = field(record, "aggregateEnforcementProof", "invalid_receipt");
    let proofSnapshot: AggregateEnforcementProof;
    try {
      proofSnapshot = snapshotAggregateEnforcementProof(proof as AggregateEnforcementProof);
    } catch {
      fail("invalid_receipt");
    }
    if (
      command &&
      (proofSnapshot.generation !== command.observedRuntimeAuthorizationGeneration ||
        !sameDigest(
          proofSnapshot.requiredEffectEnforcerSetDigest,
          command.requiredContainmentEnforcerSetDigest
        ))
    ) {
      fail("invalid_receipt");
    }
  } else if (outcome === "rejected") {
    exactFields(record, [...base, "code", "safeDetail"], "invalid_receipt");
    if (!REJECTION_CODES.has(field(record, "code", "invalid_receipt") as string)) {
      fail("invalid_receipt");
    }
    safeText(field(record, "safeDetail", "invalid_receipt"), 500, true);
  } else if (outcome === "quarantined") {
    exactFields(record, [...base, "reason", "effectRef"], "invalid_receipt");
    if (!QUARANTINE_REASONS.has(field(record, "reason", "invalid_receipt") as string)) {
      fail("invalid_receipt");
    }
    validateEffectRef(field(record, "effectRef", "invalid_receipt"), effectRefForm);
  } else {
    fail("invalid_receipt");
  }
  if (field(record, "receiptKind", "invalid_receipt") !== "runtime.compensation") {
    fail("invalid_receipt");
  }
  validateBinding(field(record, "binding", "invalid_receipt"), "invalid_receipt");
  safeRef(field(record, "compensationId", "invalid_receipt"), "invalid_receipt");
  safeRef(field(record, "commandId", "invalid_receipt"), "invalid_receipt");
  positiveInteger(
    field(record, "observedRuntimeAuthorizationGeneration", "invalid_receipt"),
    "invalid_receipt"
  );
  if (command) validateReceiptBase(record, command);
}

function validateReceiptBase(
  record: Record<string, unknown>,
  command: RuntimeCompensationCommand
): void {
  if (
    field(record, "receiptKind", "invalid_receipt") !== "runtime.compensation" ||
    field(record, "compensationId", "invalid_receipt") !== command.compensationId ||
    field(record, "commandId", "invalid_receipt") !== command.commandId ||
    field(record, "observedRuntimeAuthorizationGeneration", "invalid_receipt") !==
      command.observedRuntimeAuthorizationGeneration
  ) {
    fail("invalid_receipt");
  }
  const receiptBinding = validateBinding(
    field(record, "binding", "invalid_receipt"),
    "invalid_receipt"
  );
  if (!sameBinding(receiptBinding, command.binding)) fail("invalid_receipt");
}

function validateEffectRef(value: unknown, form: EffectRefForm): void {
  const effectRef = safeRef(value, "invalid_receipt");
  if (form === "persisted-commitment") {
    try {
      snapshotPersistedRuntimeEffectRefCommitment(effectRef);
    } catch {
      fail("invalid_receipt");
    }
  }
}

function digestReceipt(value: unknown): string {
  try {
    return createHash("sha256")
      .update(RUNTIME_COMPENSATION_RECEIPT_DIGEST_DOMAIN, "utf8")
      .update(canonicalRuntimeJson(value), "utf8")
      .digest("hex");
  } catch {
    fail("invalid_receipt");
  }
}

export function captureRuntimeCompensationDispatch(
  runtime: RuntimeCommandCapability
): RuntimeCompensationDispatch {
  try {
    const dispatch = captureRuntimeCommandDataFunction(runtime);
    return (handle, command, signal) =>
      compensationCommandResult(dispatch, handle, command, signal);
  } catch {
    fail("invalid_input");
  }
}

function compensationCommandResult(
  dispatch: RuntimeCommandDataFunction,
  handle: RuntimeHandle,
  command: RuntimeCompensationCommand,
  signal: AbortSignal
): Promise<unknown> {
  return dispatch(handle, command, signal);
}

function validateBinding(
  value: unknown,
  code: RuntimeCompensationExecutionErrorCode
): RuntimeBinding {
  const binding = exactRecord(value, BINDING_FIELDS, code);
  return Object.freeze({
    teamId: safeRef(field(binding, "teamId", code), code),
    projectId: safeRef(field(binding, "projectId", code), code),
    sessionId: safeRef(field(binding, "sessionId", code), code),
    runtimeAssignmentId: safeRef(field(binding, "runtimeAssignmentId", code), code),
    runtimeAssignmentGeneration: positiveInteger(
      field(binding, "runtimeAssignmentGeneration", code),
      code
    ),
    sandboxId: safeRef(field(binding, "sandboxId", code), code),
    sandboxGeneration: positiveInteger(field(binding, "sandboxGeneration", code), code),
    runtimePrincipalId: safeRef(field(binding, "runtimePrincipalId", code), code),
  });
}

function sameBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
  return BINDING_FIELDS.every((name) => left[name] === right[name]);
}

function sampleClock(clock: RuntimeCompensationClock): number {
  try {
    return nonNegativeInteger(clock(), "invalid_input");
  } catch {
    fail("invalid_input");
  }
}

function isNativeAbortSignal(value: unknown): value is AbortSignal {
  try {
    const getter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
    return (
      typeof getter === "function" &&
      typeof Reflect.apply(getter, value, []) === "boolean" &&
      typeof (value as AbortSignal).addEventListener === "function" &&
      typeof (value as AbortSignal).removeEventListener === "function"
    );
  } catch {
    return false;
  }
}

interface SnapshotState {
  readonly ancestors: Set<object>;
  remainingNodes: number;
  remainingStringBytes: number;
}

function snapshotPortable<T>(value: T, code: RuntimeCompensationExecutionErrorCode): T {
  try {
    return clonePortable(
      value,
      {
        ancestors: new Set<object>(),
        remainingNodes: MAX_SNAPSHOT_NODES,
        remainingStringBytes: MAX_SNAPSHOT_STRING_BYTES,
      },
      0
    ) as T;
  } catch {
    fail(code);
  }
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
  if (typeof value !== "object" || state.ancestors.has(value)) throw new TypeError();
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
  const keys = Reflect.ownKeys(value);
  if ((prototype !== Object.prototype && prototype !== null) || keys.length > MAX_SNAPSHOT_FIELDS) {
    throw new TypeError();
  }
  const clone = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new TypeError();
    }
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

function exactRecord(
  value: unknown,
  fields: readonly string[],
  code: RuntimeCompensationExecutionErrorCode = "invalid_input"
): Record<string, unknown> {
  const record = plainRecord(value, code);
  exactFields(record, fields, code);
  return record;
}

function plainRecord(
  value: unknown,
  code: RuntimeCompensationExecutionErrorCode
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(code);
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    fail(code);
  }
  if (prototype !== Object.prototype && prototype !== null) fail(code);
  return value as Record<string, unknown>;
}

function exactFields(
  record: Record<string, unknown>,
  fields: readonly string[],
  code: RuntimeCompensationExecutionErrorCode
): void {
  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(record);
  } catch {
    fail(code);
  }
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    fail(code);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  }
}

function field(
  record: Record<string, unknown>,
  name: string,
  code: RuntimeCompensationExecutionErrorCode = "invalid_input"
): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, name);
  } catch {
    fail(code);
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  return descriptor.value;
}

function safeRef(value: unknown, code: RuntimeCompensationExecutionErrorCode): string {
  if (typeof value !== "string" || !SAFE_REF.test(value)) fail(code);
  return value;
}

function safeText(value: unknown, maximumBytes: number, allowEmpty: boolean): string {
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length < 1) ||
    Buffer.byteLength(value, "utf8") > maximumBytes ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    fail("invalid_receipt");
  }
  return value;
}

function sha256(value: unknown, code: RuntimeCompensationExecutionErrorCode): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(code);
  return value;
}

function nonNegativeInteger(value: unknown, code: RuntimeCompensationExecutionErrorCode): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) fail(code);
  return value as number;
}

function positiveInteger(value: unknown, code: RuntimeCompensationExecutionErrorCode): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail(code);
  return value as number;
}

function sameDigest(left: string, right: string): boolean {
  try {
    return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
  } catch {
    return false;
  }
}

function fail(code: RuntimeCompensationExecutionErrorCode): never {
  throw new RuntimeCompensationExecutionError(code);
}
