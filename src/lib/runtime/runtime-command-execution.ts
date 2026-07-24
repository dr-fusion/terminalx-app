import { createHash, timingSafeEqual } from "node:crypto";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type {
  AggregateEnforcementProof,
  NonDuplicateRuntimeReceipt,
  RuntimeHandle,
  RuntimeLifecycleCommand,
  RuntimeReceipt,
} from "./contracts";
import {
  verifyActionManifestDigest,
  type ActionManifest as DigestibleActionManifest,
} from "./action-policy";
import { assertRuntimeCommandAuthorityBinding } from "./runtime-authority";
import {
  captureRuntimeCommandDataFunction,
  type RuntimeCommandCapability,
  type RuntimeCommandDataFunction,
} from "./runtime-command-dispatch";
import {
  commitRuntimeEffectRef,
  RuntimeEnforcementProofError,
  snapshotAggregateEnforcementProof,
  snapshotPersistedRuntimeEffectRefCommitment,
  snapshotRuntimeEnforcementProofVerificationInput,
  verifyRuntimeEnforcementProof,
  type RuntimeEnforcementProofVerifier,
  type RuntimeEnforcementSubject,
  type SynchronousRuntimeEnforcementProofVerifier,
} from "./runtime-enforcement-proof";
import { suppressNativePromiseRejection } from "./runtime-native-promise";

export { digestAggregateEnforcementProof } from "./runtime-enforcement-proof";

const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REF = /^[^\u0000-\u001f\u007f]{1,300}$/;
const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_NODES = 20_000;
const MAX_SNAPSHOT_FIELDS = 1_000;
const MAX_SNAPSHOT_STRING_BYTES = 1_000_000;

const LIFECYCLE_KINDS = new Set<RuntimeLifecycleCommand["kind"]>([
  "run.start",
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
  "requiredEffectEnforcerSetDigest",
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

export type RuntimeCommandExecutionErrorCode =
  | "invalid_input"
  | "invalid_authority"
  | "authority_verification_failed"
  | "binding_mismatch"
  | "deadline_expired"
  | "runtime_command_failed"
  | "invalid_receipt"
  | "enforcement_proof_verification_failed";

/**
 * Whether the control plane can prove that the portable Runtime command did
 * not cross the adapter seam. Unknown must be handled as potentially enforced;
 * it can never be compensated as a simple rejection.
 */
export type RuntimeCommandDispatchCertainty = "not-dispatched" | "dispatch-uncertain";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeCommandExecutionErrorCode, string>> = {
  invalid_input: "Runtime command input is invalid",
  invalid_authority: "Runtime command authority is invalid",
  authority_verification_failed: "Runtime command authority could not be verified",
  binding_mismatch: "Runtime command binding does not match its handle",
  deadline_expired: "Runtime command deadline has expired",
  runtime_command_failed: "Runtime command execution failed",
  invalid_receipt: "Runtime returned an invalid receipt",
  enforcement_proof_verification_failed: "Runtime enforcement proof could not be verified",
};

const DISPATCH_CERTAINTY: Readonly<
  Record<RuntimeCommandExecutionErrorCode, RuntimeCommandDispatchCertainty>
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

/** Safe error surface: provider and verifier failures are never attached as causes. */
export class RuntimeCommandExecutionError extends Error {
  readonly dispatchCertainty: RuntimeCommandDispatchCertainty;

  constructor(readonly code: RuntimeCommandExecutionErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeCommandExecutionError";
    this.dispatchCertainty = DISPATCH_CERTAINTY[code];
  }
}

export interface RuntimeAuthorityVerificationInput {
  readonly handle: RuntimeHandle;
  readonly command: RuntimeLifecycleCommand;
  readonly nowMs: number;
}

/** A verifier must return literal true only after signature and claims verification. */
export type RuntimeAuthorityVerifier = (
  input: RuntimeAuthorityVerificationInput
) => boolean | Promise<boolean>;

export type RuntimeCommandClock = () => number;

export type RuntimeLifecycleDispatch = (
  handle: RuntimeHandle,
  command: RuntimeLifecycleCommand,
  signal: AbortSignal
) => Promise<RuntimeReceipt>;

/**
 * Deep execution Module for exact-bound lifecycle transitions at the untrusted
 * Runtime adapter seam. The verifier and adapter receive frozen snapshots,
 * never caller-owned objects, and the returned receipt is an independently
 * validated snapshot. Persistence remains a separate journal responsibility.
 */
export async function executeRuntimeCommand(
  runtime: RuntimeCommandCapability,
  handle: RuntimeHandle,
  command: RuntimeLifecycleCommand,
  verifyAuthority: RuntimeAuthorityVerifier,
  clock: RuntimeCommandClock,
  verifyEnforcementProof?: RuntimeEnforcementProofVerifier,
  runtimeCommandSignal?: AbortSignal
): Promise<RuntimeReceipt> {
  const dispatch = captureRuntimeLifecycleDispatch(runtime);
  return executeCapturedRuntimeCommand(
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
 * root. Supervisors use this entrypoint so no provider property lookup can
 * occur after their durable final pre-dispatch interlock.
 */
export async function executeCapturedRuntimeCommand(
  dispatch: RuntimeLifecycleDispatch,
  handle: RuntimeHandle,
  command: RuntimeLifecycleCommand,
  verifyAuthority: RuntimeAuthorityVerifier,
  clock: RuntimeCommandClock,
  verifyEnforcementProof?: RuntimeEnforcementProofVerifier,
  runtimeCommandSignal?: AbortSignal
): Promise<RuntimeReceipt> {
  if (typeof verifyAuthority !== "function" || typeof clock !== "function") {
    fail("invalid_input");
  }
  if (typeof dispatch !== "function") fail("invalid_input");
  const dispatchSignal = runtimeCommandSignal ?? new AbortController().signal;
  if (!isNativeAbortSignal(dispatchSignal)) fail("invalid_input");
  if (dispatchSignal.aborted) fail("runtime_command_failed");

  const handleSnapshot = snapshotPortable(handle, "invalid_input");
  const commandSnapshot = snapshotPortable(command, "invalid_input");
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
  // A timed-out authority verifier must never resume later and dispatch.
  if (dispatchSignal.aborted) fail("runtime_command_failed");

  let providerReceipt: RuntimeReceipt;
  try {
    providerReceipt = await dispatch(handleSnapshot, commandSnapshot, dispatchSignal);
  } catch {
    fail("runtime_command_failed");
  }
  // A response racing the deadline cannot restore certainty after cancellation.
  if (dispatchSignal.aborted) fail("runtime_command_failed");

  const receipt = snapshotRuntimeReceiptForCommand(providerReceipt, commandSnapshot);
  await verifyRuntimeReceiptEnforcementProof(commandSnapshot, receipt, verifyEnforcementProof);
  return receipt;
}

/**
 * Authenticate any enforced effective receipt against the exact signed command.
 * Journals and late-receipt reconcilers reuse this boundary so direct settlement
 * cannot bypass the executor's trust decision.
 */
export async function verifyRuntimeReceiptEnforcementProof(
  command: RuntimeLifecycleCommand,
  receipt: RuntimeReceipt,
  verifyEnforcementProof?: RuntimeEnforcementProofVerifier
): Promise<void> {
  const enforcedReceipt = unwrapEnforcedReceipt(receipt);
  if (!enforcedReceipt) return;
  const aggregateEnforcementProof = enforcedReceipt.aggregateEnforcementProof;
  if (!aggregateEnforcementProof) fail("invalid_receipt");
  if (typeof verifyEnforcementProof !== "function") {
    fail("enforcement_proof_verification_failed");
  }
  try {
    await verifyRuntimeEnforcementProof(
      runtimeEnforcementSubject(command, enforcedReceipt),
      aggregateEnforcementProof,
      verifyEnforcementProof
    );
  } catch (error) {
    if (
      error instanceof RuntimeEnforcementProofError &&
      (error.code === "invalid_subject" || error.code === "invalid_proof")
    ) {
      fail("invalid_receipt");
    }
    fail("enforcement_proof_verification_failed");
  }
}

/**
 * Synchronous variant for an already-open SQLite settlement transaction.
 * Asynchronous verifiers fail closed; production follow composition must keep
 * its authenticated enforcer manifest and attestation ledger locally available.
 */
export function verifyRuntimeReceiptEnforcementProofSynchronously(
  command: RuntimeLifecycleCommand,
  receipt: RuntimeReceipt,
  verifyEnforcementProof?: SynchronousRuntimeEnforcementProofVerifier
): void {
  verifyRuntimeReceiptEnforcementProofSynchronouslyByEffectRefForm(
    command,
    receipt,
    verifyEnforcementProof,
    "raw-provider"
  );
}

/**
 * Re-authenticate a durable receipt whose effect references were already
 * committed by this journal. This explicit interface is the only path that
 * treats an effectRef as a commitment; provider receipts must use the raw path.
 */
export function verifyPersistedRuntimeReceiptEnforcementProofSynchronously(
  command: RuntimeLifecycleCommand,
  persistedReceipt: RuntimeReceipt,
  verifyEnforcementProof?: SynchronousRuntimeEnforcementProofVerifier
): void {
  const receiptSnapshot = snapshotRuntimeReceiptForCommandByEffectRefForm(
    persistedReceipt,
    command,
    "persisted-commitment"
  );
  verifyRuntimeReceiptEnforcementProofSynchronouslyByEffectRefForm(
    command,
    receiptSnapshot,
    verifyEnforcementProof,
    "persisted-commitment"
  );
}

function verifyRuntimeReceiptEnforcementProofSynchronouslyByEffectRefForm(
  command: RuntimeLifecycleCommand,
  receipt: RuntimeReceipt,
  verifyEnforcementProof: SynchronousRuntimeEnforcementProofVerifier | undefined,
  effectRefForm: RuntimeReceiptEffectRefForm
): void {
  const enforcedReceipt = unwrapEnforcedReceipt(receipt);
  if (!enforcedReceipt) return;
  const aggregateEnforcementProof = enforcedReceipt.aggregateEnforcementProof;
  if (!aggregateEnforcementProof) fail("invalid_receipt");
  if (typeof verifyEnforcementProof !== "function") {
    fail("enforcement_proof_verification_failed");
  }
  let input: ReturnType<typeof snapshotRuntimeEnforcementProofVerificationInput>;
  try {
    input = snapshotRuntimeEnforcementProofVerificationInput(
      runtimeEnforcementSubject(command, enforcedReceipt, effectRefForm),
      aggregateEnforcementProof
    );
  } catch {
    fail("invalid_receipt");
  }
  let verified: unknown;
  try {
    verified = verifyEnforcementProof(input);
  } catch {
    fail("enforcement_proof_verification_failed");
  }
  if (verified !== true) {
    // The SQLite follow boundary cannot suspend its transaction. Fail closed,
    // but observe a genuine Promise rejection without assimilating a custom
    // thenable or invoking provider-controlled code after rollback.
    suppressNativePromiseRejection(verified);
    fail("enforcement_proof_verification_failed");
  }
}

/**
 * Capture and strictly validate a provider receipt against one exact lifecycle
 * command. The journal reuses this boundary so duplicate originals cannot
 * substitute another command, tenant, binding, authorization generation, or
 * lifecycle fence.
 */
export function snapshotRuntimeReceiptForCommand(
  receipt: RuntimeReceipt,
  expected: Pick<
    RuntimeLifecycleCommand,
    | "commandId"
    | "binding"
    | "runtimeAuthorizationGeneration"
    | "requiredEffectEnforcerSetDigest"
    | "toRunStateVersion"
    | "authority"
  >
): RuntimeReceipt {
  return snapshotRuntimeReceiptForCommandByEffectRefForm(receipt, expected, "raw-provider");
}

function snapshotRuntimeReceiptForCommandByEffectRefForm(
  receipt: RuntimeReceipt,
  expected: Pick<
    RuntimeLifecycleCommand,
    | "commandId"
    | "binding"
    | "runtimeAuthorizationGeneration"
    | "requiredEffectEnforcerSetDigest"
    | "toRunStateVersion"
    | "authority"
  >,
  effectRefForm: RuntimeReceiptEffectRefForm
): RuntimeReceipt {
  const receiptSnapshot = snapshotPortable(receipt, "invalid_receipt");
  validateReceipt(
    receiptSnapshot,
    {
      commandId: expected.commandId,
      binding: expected.binding,
      authorizationGeneration: expected.runtimeAuthorizationGeneration,
      lifecycleFence: expected.toRunStateVersion,
      requiredEffectEnforcerSetDigest: sha256(
        expected.requiredEffectEnforcerSetDigest,
        "invalid_receipt"
      ),
      commandClaimsDigest: sha256(expected.authority.claimsDigest, "invalid_receipt"),
    },
    effectRefForm
  );
  return receiptSnapshot;
}

/** Digest profile providers use when returning a duplicate receipt. */
export function digestNonDuplicateRuntimeReceipt(receipt: NonDuplicateRuntimeReceipt): string {
  const snapshot = snapshotPortable(receipt, "invalid_receipt");
  validateNonDuplicateReceipt(snapshot);
  return sha256Canonical(snapshot);
}

type EnforcedRuntimeReceipt = Extract<NonDuplicateRuntimeReceipt, { outcome: "enforced" }>;
type RuntimeReceiptEffectRefForm = "raw-provider" | "persisted-commitment";

function unwrapEnforcedReceipt(receipt: RuntimeReceipt): EnforcedRuntimeReceipt | undefined {
  if (receipt.outcome === "enforced") return receipt;
  if (receipt.outcome === "duplicate" && receipt.originalReceipt.outcome === "enforced") {
    return receipt.originalReceipt;
  }
  return undefined;
}

function runtimeEnforcementSubject(
  command: RuntimeLifecycleCommand,
  receipt: EnforcedRuntimeReceipt,
  effectRefForm: RuntimeReceiptEffectRefForm = "raw-provider"
): RuntimeEnforcementSubject {
  return {
    version: 1,
    commandId: command.commandId,
    commandClaimsDigest: sha256(command.authority.claimsDigest, "invalid_receipt"),
    binding: command.binding,
    runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest: sha256(
      command.requiredEffectEnforcerSetDigest,
      "invalid_receipt"
    ),
    effectRefCommitment:
      effectRefForm === "raw-provider"
        ? commitRuntimeEffectRef(receipt.effectRef)
        : snapshotPersistedRuntimeEffectRefCommitment(receipt.effectRef),
    enforcedFence: receipt.enforcedFence,
  };
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
  command: RuntimeLifecycleCommand,
  nowMs: number
): CommandPreflight {
  const handleRecord = validateHandle(handle);
  const commandRecord = plainRecord(command, "invalid_input");
  const kind = dataField(commandRecord, "kind", "invalid_input");
  if (typeof kind !== "string" || !LIFECYCLE_KINDS.has(kind as RuntimeLifecycleCommand["kind"])) {
    fail("invalid_input");
  }

  validateLifecycleCommandShape(commandRecord, kind as RuntimeLifecycleCommand["kind"]);
  try {
    assertRuntimeCommandAuthorityBinding(command);
  } catch {
    fail("invalid_authority");
  }

  const commandId = safeRef(
    dataField(commandRecord, "commandId", "invalid_input"),
    "invalid_input"
  );
  const projectCeilingRevision = safeRef(
    dataField(commandRecord, "projectCeilingRevision", "invalid_input"),
    "invalid_input"
  );
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
  const requiredEffectEnforcerSetDigest = sha256(
    dataField(commandRecord, "requiredEffectEnforcerSetDigest", "invalid_input"),
    "invalid_input"
  );
  const agentRunId = safeRef(
    dataField(commandRecord, "agentRunId", "invalid_input"),
    "invalid_input"
  );
  const runPolicyRevision = positiveInteger(
    dataField(commandRecord, "runPolicyRevision", "invalid_input"),
    "invalid_input"
  );
  const fromRunStateVersion = positiveInteger(
    dataField(commandRecord, "fromRunStateVersion", "invalid_input"),
    "invalid_input"
  );
  const toRunStateVersion = positiveInteger(
    dataField(commandRecord, "toRunStateVersion", "invalid_input"),
    "invalid_input"
  );
  if (toRunStateVersion !== fromRunStateVersion + 1) fail("invalid_input");

  if (kind === "run.start") {
    if (runPolicyRevision !== 1 || fromRunStateVersion !== 1 || toRunStateVersion !== 2) {
      fail("invalid_input");
    }
    validateStartCommandPayload(commandRecord, handleRecord, {
      commandBinding,
      authorizationGeneration,
      agentRunId,
      runPolicyRevision,
      projectCeilingRevision,
      requiredEffectEnforcerSetDigest,
    });
  }

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
  kind: RuntimeLifecycleCommand["kind"]
): void {
  if (kind === "run.start") {
    exactFields(
      command,
      [...COMMAND_BASE_FIELDS, ...LIFECYCLE_FIELDS, "policy"],
      ["yoloAuthorization"],
      "invalid_input"
    );
    return;
  }
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

interface StartCommandValidationContext {
  readonly commandBinding: RuntimeBinding;
  readonly authorizationGeneration: number;
  readonly agentRunId: string;
  readonly runPolicyRevision: number;
  readonly projectCeilingRevision: string;
  readonly requiredEffectEnforcerSetDigest: string;
}

function validateStartCommandPayload(
  command: Record<string, unknown>,
  handle: Record<string, unknown>,
  context: StartCommandValidationContext
): void {
  const policy = exactRecord(
    dataField(command, "policy", "invalid_input"),
    [
      "agentRunId",
      "revision",
      "digest",
      "policyBodyDigest",
      "mode",
      "completionPolicy",
      "scopedExternalPolicyRef",
      "limits",
      "initialGoalSet",
      "scopedExternalRules",
      "projectCeilingRevision",
      "projectCeilingDigest",
      "binding",
      "runtimeAuthorizationGeneration",
      "requiredEffectEnforcerSetDigest",
      "createdAtMs",
    ],
    ["previousRevision", "yoloConfirmationRef"]
  );

  if (
    safeRef(dataField(policy, "agentRunId", "invalid_input"), "invalid_input") !==
      context.agentRunId ||
    positiveInteger(dataField(policy, "revision", "invalid_input"), "invalid_input") !==
      context.runPolicyRevision ||
    safeRef(dataField(policy, "projectCeilingRevision", "invalid_input"), "invalid_input") !==
      context.projectCeilingRevision ||
    positiveInteger(
      dataField(policy, "runtimeAuthorizationGeneration", "invalid_input"),
      "invalid_input"
    ) !== context.authorizationGeneration ||
    sha256(
      dataField(policy, "requiredEffectEnforcerSetDigest", "invalid_input"),
      "invalid_input"
    ) !== context.requiredEffectEnforcerSetDigest
  ) {
    fail("invalid_input");
  }
  sha256(dataField(policy, "digest", "invalid_input"), "invalid_input");
  sha256(dataField(policy, "policyBodyDigest", "invalid_input"), "invalid_input");
  sha256(dataField(policy, "projectCeilingDigest", "invalid_input"), "invalid_input");
  const policyBinding = validateBinding(
    dataField(policy, "binding", "invalid_input"),
    "invalid_input"
  );
  if (!sameBinding(policyBinding, context.commandBinding)) fail("invalid_input");

  const previousRevision = optionalDataField(policy, "previousRevision", "invalid_input");
  if (
    previousRevision !== undefined &&
    positiveInteger(previousRevision, "invalid_input") >= context.runPolicyRevision
  ) {
    fail("invalid_input");
  }
  const yoloConfirmationRef = optionalDataField(policy, "yoloConfirmationRef", "invalid_input");
  if (yoloConfirmationRef !== undefined) safeRef(yoloConfirmationRef, "invalid_input");

  const createdAtMs = nonNegativeInteger(
    dataField(policy, "createdAtMs", "invalid_input"),
    "invalid_input"
  );
  const issuedAtMs = nonNegativeInteger(
    dataField(command, "issuedAtMs", "invalid_input"),
    "invalid_input"
  );
  if (createdAtMs > issuedAtMs) fail("invalid_input");

  const mode = dataField(policy, "mode", "invalid_input");
  if (mode !== "supervised" && mode !== "autonomous" && mode !== "yolo") {
    fail("invalid_input");
  }
  const completionPolicy = exactRecord(dataField(policy, "completionPolicy", "invalid_input"), [
    "kind",
  ]);
  const completionKind = dataField(completionPolicy, "kind", "invalid_input");
  if (
    completionKind !== "stop-after-directed-work" &&
    completionKind !== "continue-until-all-goals-achieved"
  ) {
    fail("invalid_input");
  }
  if (mode === "supervised" && completionKind === "continue-until-all-goals-achieved") {
    fail("invalid_input");
  }
  safeRef(dataField(policy, "scopedExternalPolicyRef", "invalid_input"), "invalid_input");
  const limits = validateRunLimits(dataField(policy, "limits", "invalid_input"));
  validateInitialGoalSet(dataField(policy, "initialGoalSet", "invalid_input"), context.agentRunId);
  validateScopedExternalRules(dataField(policy, "scopedExternalRules", "invalid_input"));

  const capabilities = plainRecord(
    dataField(handle, "capabilities", "invalid_input"),
    "invalid_input"
  );
  if (dataField(capabilities, "isolatedExecution", "invalid_input") !== true) {
    fail("invalid_input");
  }

  if (mode === "yolo") {
    if (
      yoloConfirmationRef === undefined ||
      dataField(capabilities, "yoloEligible", "invalid_input") !== true ||
      dataField(capabilities, "brokeredCredentials", "invalid_input") !== true ||
      dataField(capabilities, "proxyOnlyEgress", "invalid_input") !== true
    ) {
      fail("invalid_input");
    }
  } else if (yoloConfirmationRef !== undefined) {
    fail("invalid_input");
  }

  const yoloAuthorization = optionalDataField(command, "yoloAuthorization", "invalid_input");
  if (mode === "yolo") {
    if (yoloAuthorization === undefined) fail("invalid_input");
    validateYoloAuthorization(yoloAuthorization, context, issuedAtMs, limits);
  } else if (yoloAuthorization !== undefined) {
    fail("invalid_input");
  }
}

interface ValidatedMoney {
  readonly currency: string;
  readonly minorUnits: number;
}

interface ValidatedRunLimits {
  readonly wallClock?: number;
  readonly modelTokens?: number;
  readonly modelSpend?: ValidatedMoney;
  readonly outboundBytes?: number;
  readonly actionCounts: Readonly<
    Record<"local" | "scoped-external" | "protected" | "forbidden", number | undefined>
  >;
}

interface ValidatedResourceEffect {
  readonly wallClock: number;
  readonly modelTokens: number;
  readonly modelSpend: ValidatedMoney;
  readonly outboundBytes: number;
  readonly actionCounts: Readonly<
    Record<"local" | "scoped-external" | "protected" | "forbidden", number>
  >;
}

function validateRunLimits(value: unknown): ValidatedRunLimits {
  const limits = exactRecord(value, [
    "wallClock",
    "modelTokens",
    "modelSpend",
    "outboundBytes",
    "actionCounts",
  ]);
  const wallClock = validateRunLimit(
    dataField(limits, "wallClock", "invalid_input"),
    (duration) => {
      const record = exactRecord(duration, ["milliseconds"]);
      return nonNegativeInteger(
        dataField(record, "milliseconds", "invalid_input"),
        "invalid_input"
      );
    }
  );
  const modelTokens = validateRunLimit(
    dataField(limits, "modelTokens", "invalid_input"),
    (tokens) => nonNegativeInteger(tokens, "invalid_input")
  );
  const modelSpend = validateRunLimit(
    dataField(limits, "modelSpend", "invalid_input"),
    validateMoney
  );
  const outboundBytes = validateRunLimit(
    dataField(limits, "outboundBytes", "invalid_input"),
    (bytes) => nonNegativeInteger(bytes, "invalid_input")
  );
  const actionCounts = exactRecord(dataField(limits, "actionCounts", "invalid_input"), [
    "local",
    "scoped-external",
    "protected",
    "forbidden",
  ]);
  const validatedActionCounts = {
    local: validateRunLimit(dataField(actionCounts, "local", "invalid_input"), (count) =>
      nonNegativeInteger(count, "invalid_input")
    ),
    "scoped-external": validateRunLimit(
      dataField(actionCounts, "scoped-external", "invalid_input"),
      (count) => nonNegativeInteger(count, "invalid_input")
    ),
    protected: validateRunLimit(dataField(actionCounts, "protected", "invalid_input"), (count) =>
      nonNegativeInteger(count, "invalid_input")
    ),
    forbidden: validateRunLimit(dataField(actionCounts, "forbidden", "invalid_input"), (count) =>
      nonNegativeInteger(count, "invalid_input")
    ),
  };
  return { wallClock, modelTokens, modelSpend, outboundBytes, actionCounts: validatedActionCounts };
}

function validateRunLimit<T>(value: unknown, validateValue: (value: unknown) => T): T | undefined {
  const limit = plainRecord(value, "invalid_input");
  const kind = dataField(limit, "kind", "invalid_input");
  if (kind === "unconfigured") {
    exactFields(limit, ["kind"], [], "invalid_input");
    return undefined;
  }
  if (kind !== "capped") fail("invalid_input");
  exactFields(limit, ["kind", "value"], [], "invalid_input");
  return validateValue(dataField(limit, "value", "invalid_input"));
}

function validateMoney(value: unknown): ValidatedMoney {
  const money = exactRecord(value, ["currency", "minorUnits"]);
  const currency = dataField(money, "currency", "invalid_input");
  if (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)) fail("invalid_input");
  return {
    currency,
    minorUnits: nonNegativeInteger(
      dataField(money, "minorUnits", "invalid_input"),
      "invalid_input"
    ),
  };
}

function validateInitialGoalSet(value: unknown, agentRunId: string): void {
  const goalSet = exactRecord(
    value,
    ["goalSetId", "agentRunId", "revision", "digest", "goals"],
    ["previousRevision"]
  );
  safeRef(dataField(goalSet, "goalSetId", "invalid_input"), "invalid_input");
  if (dataField(goalSet, "agentRunId", "invalid_input") !== agentRunId) fail("invalid_input");
  const revision = positiveInteger(
    dataField(goalSet, "revision", "invalid_input"),
    "invalid_input"
  );
  if (revision !== 1) fail("invalid_input");
  sha256(dataField(goalSet, "digest", "invalid_input"), "invalid_input");
  const previousRevision = optionalDataField(goalSet, "previousRevision", "invalid_input");
  if (
    previousRevision !== undefined &&
    positiveInteger(previousRevision, "invalid_input") >= revision
  ) {
    fail("invalid_input");
  }
  const goals = dataField(goalSet, "goals", "invalid_input");
  if (!Array.isArray(goals) || goals.length < 1 || goals.length > 100) fail("invalid_input");
  const ids = new Set<string>();
  const dependencies = new Map<string, readonly string[]>();
  for (const [index, goalValue] of goals.entries()) {
    const goal = exactRecord(goalValue, [
      "goalId",
      "position",
      "title",
      "acceptanceCriteria",
      "dependencyGoalIds",
      "version",
      "status",
    ]);
    const goalId = safeRef(dataField(goal, "goalId", "invalid_input"), "invalid_input");
    if (ids.has(goalId) || dataField(goal, "position", "invalid_input") !== index + 1) {
      fail("invalid_input");
    }
    ids.add(goalId);
    safeText(dataField(goal, "title", "invalid_input"), 1_000, "invalid_input");
    if (positiveInteger(dataField(goal, "version", "invalid_input"), "invalid_input") !== 1) {
      fail("invalid_input");
    }
    const status = dataField(goal, "status", "invalid_input");
    if (status !== "pending") fail("invalid_input");
    const criteria = dataField(goal, "acceptanceCriteria", "invalid_input");
    if (!Array.isArray(criteria) || criteria.length < 1 || criteria.length > 32) {
      fail("invalid_input");
    }
    for (const criterion of criteria) safeText(criterion, 1_000, "invalid_input");
    const dependencyIds = dataField(goal, "dependencyGoalIds", "invalid_input");
    if (
      !Array.isArray(dependencyIds) ||
      dependencyIds.length > 99 ||
      dependencyIds.some((dependency) => typeof dependency !== "string")
    ) {
      fail("invalid_input");
    }
    const normalized = dependencyIds.map((dependency) => safeRef(dependency, "invalid_input"));
    if (new Set(normalized).size !== normalized.length) fail("invalid_input");
    dependencies.set(goalId, normalized);
  }
  for (const [goalId, dependencyIds] of dependencies) {
    if (dependencyIds.some((dependency) => dependency === goalId || !ids.has(dependency))) {
      fail("invalid_input");
    }
  }
  assertAcyclicGoals(dependencies);
}

function assertAcyclicGoals(dependencies: ReadonlyMap<string, readonly string[]>): void {
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (goalId: string): void => {
    if (visiting.has(goalId)) fail("invalid_input");
    if (visited.has(goalId)) return;
    visiting.add(goalId);
    for (const dependency of dependencies.get(goalId) ?? []) visit(dependency);
    visiting.delete(goalId);
    visited.add(goalId);
  };
  for (const goalId of dependencies.keys()) visit(goalId);
}

function validateScopedExternalRules(value: unknown): void {
  if (!Array.isArray(value) || value.length > 256) fail("invalid_input");
  const identities = new Set<string>();
  for (const ruleValue of value) {
    const rule = exactRecord(
      ruleValue,
      ["actionClass", "provider", "operation", "targetPattern"],
      ["credentialRef"]
    );
    const actionClass = dataField(rule, "actionClass", "invalid_input");
    if (
      actionClass !== "local" &&
      actionClass !== "scoped-external" &&
      actionClass !== "protected" &&
      actionClass !== "forbidden"
    ) {
      fail("invalid_input");
    }
    const provider = safeRef(dataField(rule, "provider", "invalid_input"), "invalid_input");
    const operation = safeRef(dataField(rule, "operation", "invalid_input"), "invalid_input");
    const targetPattern = safeText(
      dataField(rule, "targetPattern", "invalid_input"),
      4_000,
      "invalid_input"
    );
    const credentialRef = optionalDataField(rule, "credentialRef", "invalid_input");
    if (credentialRef !== undefined) safeRef(credentialRef, "invalid_input");
    const identity = `${actionClass}\0${provider}\0${operation}\0${targetPattern}\0${String(
      credentialRef ?? ""
    )}`;
    if (identities.has(identity)) fail("invalid_input");
    identities.add(identity);
  }
}

function validateYoloAuthorization(
  value: unknown,
  context: StartCommandValidationContext,
  commandIssuedAtMs: number,
  runLimits: ValidatedRunLimits
): void {
  const authorization = exactRecord(value, ["manifest", "grant"]);
  const manifest = exactRecord(
    dataField(authorization, "manifest", "invalid_input"),
    [
      "version",
      "manifestId",
      "digest",
      "actionClass",
      "provider",
      "operation",
      "exactTarget",
      "actionSchema",
      "canonicalEffectInputDigest",
      "effectIdempotencyKey",
      "expectedEffect",
      "expiresAtMs",
    ],
    ["commitSha", "artifactDigest", "credentialRef"]
  );
  if (!verifyActionManifestDigest(manifest as unknown as DigestibleActionManifest)) {
    fail("invalid_input");
  }
  if (typeof dataField(manifest, "exactTarget", "invalid_input") !== "string") {
    fail("invalid_input");
  }
  const expectedEffect = validateResourceEffect(
    dataField(manifest, "expectedEffect", "invalid_input")
  );
  assertEffectWithinRunLimits(expectedEffect, runLimits);
  const manifestDigest = sha256(dataField(manifest, "digest", "invalid_input"), "invalid_input");
  const manifestClass = dataField(manifest, "actionClass", "invalid_input");
  if (manifestClass !== "scoped-external" && manifestClass !== "protected") {
    fail("invalid_input");
  }
  if (
    positiveInteger(dataField(manifest, "expiresAtMs", "invalid_input"), "invalid_input") <=
    commandIssuedAtMs
  ) {
    fail("invalid_input");
  }

  const grant = exactRecord(
    dataField(authorization, "grant", "invalid_input"),
    [
      "grantId",
      "teamId",
      "projectId",
      "sessionId",
      "agentRunId",
      "runPolicyRevision",
      "runtimeAssignmentId",
      "runtimeAssignmentGeneration",
      "sandboxId",
      "sandboxGeneration",
      "runtimePrincipalId",
      "runtimeAuthorizationGeneration",
      "approvalRequestId",
      "approvalRequestVersion",
      "provider",
      "operation",
      "target",
      "budget",
      "usageLedgerRef",
      "issuerActorRef",
      "issuerApprovalAuthorityRevision",
      "expiresAtMs",
      "signature",
      "createdAtMs",
      "actionClass",
      "scope",
    ],
    ["credentialRef"]
  );
  for (const field of [
    "grantId",
    "approvalRequestId",
    "usageLedgerRef",
    "issuerActorRef",
    "issuerApprovalAuthorityRevision",
  ]) {
    safeRef(dataField(grant, field, "invalid_input"), "invalid_input");
  }
  const bindingFields = [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "sandboxId",
    "runtimePrincipalId",
  ] as const;
  for (const field of bindingFields) {
    if (
      safeRef(dataField(grant, field, "invalid_input"), "invalid_input") !==
      context.commandBinding[field]
    ) {
      fail("invalid_input");
    }
  }
  for (const [field, expected] of [
    ["runtimeAssignmentGeneration", context.commandBinding.runtimeAssignmentGeneration],
    ["sandboxGeneration", context.commandBinding.sandboxGeneration],
    ["runtimeAuthorizationGeneration", context.authorizationGeneration],
    ["runPolicyRevision", context.runPolicyRevision],
  ] as const) {
    if (positiveInteger(dataField(grant, field, "invalid_input"), "invalid_input") !== expected) {
      fail("invalid_input");
    }
  }
  if (dataField(grant, "agentRunId", "invalid_input") !== context.agentRunId) {
    fail("invalid_input");
  }
  if (
    dataField(grant, "actionClass", "invalid_input") !== manifestClass ||
    dataField(grant, "provider", "invalid_input") !==
      dataField(manifest, "provider", "invalid_input") ||
    dataField(grant, "operation", "invalid_input") !==
      dataField(manifest, "operation", "invalid_input") ||
    dataField(grant, "target", "invalid_input") !==
      dataField(manifest, "exactTarget", "invalid_input")
  ) {
    fail("invalid_input");
  }
  const manifestCredential = optionalDataField(manifest, "credentialRef", "invalid_input");
  const grantCredential = optionalDataField(grant, "credentialRef", "invalid_input");
  if (manifestCredential !== grantCredential) fail("invalid_input");
  if (grantCredential !== undefined) safeRef(grantCredential, "invalid_input");
  positiveInteger(dataField(grant, "approvalRequestVersion", "invalid_input"), "invalid_input");
  const grantCreatedAtMs = nonNegativeInteger(
    dataField(grant, "createdAtMs", "invalid_input"),
    "invalid_input"
  );
  const grantExpiresAtMs = positiveInteger(
    dataField(grant, "expiresAtMs", "invalid_input"),
    "invalid_input"
  );
  if (grantCreatedAtMs > commandIssuedAtMs || grantExpiresAtMs <= commandIssuedAtMs) {
    fail("invalid_input");
  }
  safeText(dataField(grant, "signature", "invalid_input"), 4_000, "invalid_input");
  validateActionGrantBudget(dataField(grant, "budget", "invalid_input"), expectedEffect);
  validateActionGrantScope(
    dataField(grant, "scope", "invalid_input"),
    manifest,
    manifestDigest,
    manifestClass,
    grantCredential
  );
}

function validateActionGrantScope(
  value: unknown,
  manifest: Record<string, unknown>,
  manifestDigest: string,
  manifestClass: "scoped-external" | "protected",
  grantCredential: unknown
): void {
  const scope = plainRecord(value, "invalid_input");
  const kind = dataField(scope, "kind", "invalid_input");
  if (kind === "once") {
    exactFields(scope, ["kind", "manifestDigest", "effectIdempotencyKey"], [], "invalid_input");
    if (
      dataField(scope, "manifestDigest", "invalid_input") !== manifestDigest ||
      dataField(scope, "effectIdempotencyKey", "invalid_input") !==
        dataField(manifest, "effectIdempotencyKey", "invalid_input")
    ) {
      fail("invalid_input");
    }
    return;
  }
  if (kind !== "run" || manifestClass !== "scoped-external") fail("invalid_input");
  exactFields(
    scope,
    ["kind", "actionClass", "provider", "operation", "targetPattern", "eligibleUse", "digest"],
    ["credentialRef"],
    "invalid_input"
  );
  if (
    dataField(scope, "actionClass", "invalid_input") !== "scoped-external" ||
    dataField(scope, "provider", "invalid_input") !==
      dataField(manifest, "provider", "invalid_input") ||
    dataField(scope, "operation", "invalid_input") !==
      dataField(manifest, "operation", "invalid_input")
  ) {
    fail("invalid_input");
  }
  safeText(dataField(scope, "targetPattern", "invalid_input"), 4_000, "invalid_input");
  sha256(dataField(scope, "digest", "invalid_input"), "invalid_input");
  const eligibleUse = dataField(scope, "eligibleUse", "invalid_input");
  if (
    eligibleUse !== "session_branch_push" &&
    eligibleUse !== "draft_pull_request_update" &&
    eligibleUse !== "ephemeral_preview_update" &&
    eligibleUse !== "same_credential_nonproduction_target"
  ) {
    fail("invalid_input");
  }
  const scopeCredential = optionalDataField(scope, "credentialRef", "invalid_input");
  if (scopeCredential !== grantCredential) fail("invalid_input");
  if (scopeCredential !== undefined) safeRef(scopeCredential, "invalid_input");
  if (eligibleUse === "same_credential_nonproduction_target" && scopeCredential === undefined) {
    fail("invalid_input");
  }
}

function validateActionGrantBudget(value: unknown, expectedEffect: ValidatedResourceEffect): void {
  const budget = exactRecord(value, ["perEffectLimit", "cumulativeLimit"]);
  const perEffectLimit = validateResourceEffect(
    dataField(budget, "perEffectLimit", "invalid_input")
  );
  const cumulativeLimit = validateResourceEffect(
    dataField(budget, "cumulativeLimit", "invalid_input")
  );
  if (
    !effectFitsWithin(expectedEffect, perEffectLimit) ||
    !effectFitsWithin(perEffectLimit, cumulativeLimit)
  ) {
    fail("invalid_input");
  }
}

function validateResourceEffect(value: unknown): ValidatedResourceEffect {
  const effect = exactRecord(value, [
    "wallClock",
    "modelTokens",
    "modelSpend",
    "outboundBytes",
    "actionCounts",
  ]);
  const duration = exactRecord(dataField(effect, "wallClock", "invalid_input"), ["milliseconds"]);
  const wallClock = nonNegativeInteger(
    dataField(duration, "milliseconds", "invalid_input"),
    "invalid_input"
  );
  const modelTokens = nonNegativeInteger(
    dataField(effect, "modelTokens", "invalid_input"),
    "invalid_input"
  );
  const modelSpend = validateMoney(dataField(effect, "modelSpend", "invalid_input"));
  const outboundBytes = nonNegativeInteger(
    dataField(effect, "outboundBytes", "invalid_input"),
    "invalid_input"
  );
  const actionCounts = exactRecord(dataField(effect, "actionCounts", "invalid_input"), [
    "local",
    "scoped-external",
    "protected",
    "forbidden",
  ]);
  return {
    wallClock,
    modelTokens,
    modelSpend,
    outboundBytes,
    actionCounts: {
      local: nonNegativeInteger(dataField(actionCounts, "local", "invalid_input"), "invalid_input"),
      "scoped-external": nonNegativeInteger(
        dataField(actionCounts, "scoped-external", "invalid_input"),
        "invalid_input"
      ),
      protected: nonNegativeInteger(
        dataField(actionCounts, "protected", "invalid_input"),
        "invalid_input"
      ),
      forbidden: nonNegativeInteger(
        dataField(actionCounts, "forbidden", "invalid_input"),
        "invalid_input"
      ),
    },
  };
}

function assertEffectWithinRunLimits(
  effect: ValidatedResourceEffect,
  limits: ValidatedRunLimits
): void {
  if (
    (limits.wallClock !== undefined && effect.wallClock > limits.wallClock) ||
    (limits.modelTokens !== undefined && effect.modelTokens > limits.modelTokens) ||
    (limits.outboundBytes !== undefined && effect.outboundBytes > limits.outboundBytes) ||
    (limits.modelSpend !== undefined &&
      (effect.modelSpend.currency !== limits.modelSpend.currency ||
        effect.modelSpend.minorUnits > limits.modelSpend.minorUnits))
  ) {
    fail("invalid_input");
  }
  for (const actionClass of ["local", "scoped-external", "protected", "forbidden"] as const) {
    const cap = limits.actionCounts[actionClass];
    if (cap !== undefined && effect.actionCounts[actionClass] > cap) fail("invalid_input");
  }
}

function effectFitsWithin(
  effect: ValidatedResourceEffect,
  limit: ValidatedResourceEffect
): boolean {
  return (
    effect.wallClock <= limit.wallClock &&
    effect.modelTokens <= limit.modelTokens &&
    effect.outboundBytes <= limit.outboundBytes &&
    effect.modelSpend.currency === limit.modelSpend.currency &&
    effect.modelSpend.minorUnits <= limit.modelSpend.minorUnits &&
    effect.actionCounts.local <= limit.actionCounts.local &&
    effect.actionCounts["scoped-external"] <= limit.actionCounts["scoped-external"] &&
    effect.actionCounts.protected <= limit.actionCounts.protected &&
    effect.actionCounts.forbidden <= limit.actionCounts.forbidden
  );
}

function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = []
): Record<string, unknown> {
  const record = plainRecord(value, "invalid_input");
  exactFields(record, required, optional, "invalid_input");
  return record;
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
  readonly requiredEffectEnforcerSetDigest: string;
  readonly commandClaimsDigest: string;
}

function validateReceipt(
  receipt: RuntimeReceipt,
  expected: ExpectedReceiptBinding,
  effectRefForm: RuntimeReceiptEffectRefForm
): void {
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
    validateNonDuplicateReceipt(original, expected, effectRefForm);
    const claimedDigest = dataField(record, "originalReceiptDigest", "invalid_receipt");
    if (typeof claimedDigest !== "string" || !SHA256.test(claimedDigest)) {
      fail("invalid_receipt");
    }
    const actualDigest = sha256Canonical(original);
    if (!sameDigest(claimedDigest, actualDigest)) fail("invalid_receipt");
    return;
  }
  validateNonDuplicateReceipt(receipt as NonDuplicateRuntimeReceipt, expected, effectRefForm);
}

function validateNonDuplicateReceipt(
  receipt: NonDuplicateRuntimeReceipt,
  expected?: ExpectedReceiptBinding,
  effectRefForm: RuntimeReceiptEffectRefForm = "raw-provider"
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
    const effectRef = safeRef(dataField(record, "effectRef", "invalid_receipt"), "invalid_receipt");
    if (effectRefForm === "persisted-commitment") {
      try {
        snapshotPersistedRuntimeEffectRefCommitment(effectRef);
      } catch {
        fail("invalid_receipt");
      }
    }
  } else if (outcome === "enforced") {
    exactFields(record, [
      "commandId",
      "binding",
      "runtimeAuthorizationGeneration",
      "outcome",
      "effectRef",
      "enforcedFence",
      "aggregateEnforcementProof",
    ]);
    const effectRef = safeRef(dataField(record, "effectRef", "invalid_receipt"), "invalid_receipt");
    const enforcedFence = positiveInteger(
      dataField(record, "enforcedFence", "invalid_receipt"),
      "invalid_receipt"
    );
    if (expected && enforcedFence !== expected.lifecycleFence) fail("invalid_receipt");
    const proof = dataField(record, "aggregateEnforcementProof", "invalid_receipt");
    const generation = positiveInteger(
      dataField(record, "runtimeAuthorizationGeneration", "invalid_receipt"),
      "invalid_receipt"
    );
    validateAggregateProof(proof, generation);
    if (expected) {
      try {
        snapshotRuntimeEnforcementProofVerificationInput(
          {
            version: 1,
            commandId: expected.commandId,
            commandClaimsDigest: expected.commandClaimsDigest,
            binding: expected.binding,
            runtimeAuthorizationGeneration: expected.authorizationGeneration,
            requiredEffectEnforcerSetDigest: expected.requiredEffectEnforcerSetDigest,
            effectRefCommitment:
              effectRefForm === "raw-provider"
                ? commitRuntimeEffectRef(effectRef)
                : snapshotPersistedRuntimeEffectRefCommitment(effectRef),
            enforcedFence,
          },
          proof as AggregateEnforcementProof
        );
      } catch {
        fail("invalid_receipt");
      }
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
    const effectRef = safeRef(dataField(record, "effectRef", "invalid_receipt"), "invalid_receipt");
    if (effectRefForm === "persisted-commitment") {
      try {
        snapshotPersistedRuntimeEffectRefCommitment(effectRef);
      } catch {
        fail("invalid_receipt");
      }
    }
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
  try {
    const proof = snapshotAggregateEnforcementProof(value as AggregateEnforcementProof);
    if (proof.generation !== expectedGeneration) fail("invalid_receipt");
  } catch {
    fail("invalid_receipt");
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

export function captureRuntimeLifecycleDispatch(
  runtime: RuntimeCommandCapability
): RuntimeLifecycleDispatch {
  try {
    const dispatch = captureRuntimeCommandDataFunction(runtime);
    return (handle, command, signal) => commandResult(dispatch, handle, command, signal);
  } catch {
    fail("invalid_input");
  }
}

function commandResult(
  dispatch: RuntimeCommandDataFunction,
  handle: RuntimeHandle,
  command: RuntimeLifecycleCommand,
  signal: AbortSignal
): Promise<RuntimeReceipt> {
  return dispatch(handle, command, signal) as Promise<RuntimeReceipt>;
}

function isNativeAbortSignal(value: unknown): value is AbortSignal {
  try {
    const abortedGetter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;
    return (
      typeof abortedGetter === "function" &&
      typeof Reflect.apply(abortedGetter, value, []) === "boolean" &&
      typeof (value as AbortSignal).addEventListener === "function" &&
      typeof (value as AbortSignal).removeEventListener === "function"
    );
  } catch {
    return false;
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
