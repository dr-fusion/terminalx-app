import { createHash, timingSafeEqual } from "node:crypto";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { AggregateEnforcementProof } from "./contracts";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import {
  snapshotAggregateEnforcementProof,
  snapshotPersistedRuntimeEffectRefCommitment,
  type RuntimeEffectRefCommitment,
} from "./runtime-enforcement-proof";

export const RUNTIME_COMPENSATION_ENFORCEMENT_SUBJECT_DIGEST_DOMAIN =
  "terminalx/runtime-compensation-enforcement-subject/v1\0" as const;

const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REF = /^[^\u0000-\u001f\u007f]{1,300}$/;
const SUBJECT_FIELDS = [
  "version",
  "purpose",
  "compensationId",
  "commandId",
  "commandClaimsDigest",
  "binding",
  "observedRuntimeAuthorizationGeneration",
  "safetyFence",
  "enforcedSafetyFence",
  "sourceReceiptDigest",
  "sourceEnforcementSubjectDigest",
  "sourceAggregateProofDigest",
  "requiredContainmentEnforcerSetDigest",
  "effectRefCommitment",
  "containment",
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
const CONTAINMENT_FIELDS = [
  "terminalWritesRevoked",
  "processExecutionStopped",
  "runtimeQuarantined",
] as const;

export type RuntimeCompensationEnforcementProofErrorCode =
  | "invalid_subject"
  | "invalid_proof"
  | "verification_failed";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeCompensationEnforcementProofErrorCode, string>> =
  {
    invalid_subject: "Runtime compensation enforcement subject is invalid",
    invalid_proof: "Runtime compensation aggregate enforcement proof is invalid",
    verification_failed: "Runtime compensation enforcement proof could not be verified",
  };

/** Safe failure surface: verifier errors and provider data are never retained. */
export class RuntimeCompensationEnforcementProofError extends Error {
  constructor(readonly code: RuntimeCompensationEnforcementProofErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeCompensationEnforcementProofError";
  }
}

export interface RuntimeCompensationEnforcementSubject {
  readonly version: 1;
  readonly purpose: "stale-lifecycle-effect-containment";
  readonly compensationId: string;
  readonly commandId: string;
  readonly commandClaimsDigest: string;
  readonly binding: RuntimeBinding;
  readonly observedRuntimeAuthorizationGeneration: number;
  readonly safetyFence: number;
  readonly enforcedSafetyFence: number;
  readonly sourceReceiptDigest: string;
  readonly sourceEnforcementSubjectDigest: string;
  readonly sourceAggregateProofDigest: string;
  readonly requiredContainmentEnforcerSetDigest: string;
  readonly effectRefCommitment: RuntimeEffectRefCommitment;
  readonly containment: {
    readonly terminalWritesRevoked: true;
    readonly processExecutionStopped: true;
    readonly runtimeQuarantined: true;
  };
}

export interface RuntimeCompensationEnforcementProofVerificationInput {
  readonly subject: RuntimeCompensationEnforcementSubject;
  readonly subjectDigest: string;
  readonly proof: AggregateEnforcementProof;
}

/** Return literal true only after authenticating every containment acknowledgement. */
export type RuntimeCompensationEnforcementProofVerifier = (
  input: RuntimeCompensationEnforcementProofVerificationInput
) => boolean | Promise<boolean>;

/** SQLite-safe verifier whose complete trust decision is locally available. */
export type SynchronousRuntimeCompensationEnforcementProofVerifier = (
  input: RuntimeCompensationEnforcementProofVerificationInput
) => boolean;

export function digestRuntimeCompensationEnforcementSubject(
  subject: RuntimeCompensationEnforcementSubject
): string {
  const snapshot = snapshotSubject(subject);
  return digestSubjectSnapshot(snapshot);
}

export function snapshotRuntimeCompensationEnforcementProofVerificationInput(
  subject: RuntimeCompensationEnforcementSubject,
  proof: AggregateEnforcementProof
): RuntimeCompensationEnforcementProofVerificationInput {
  const subjectSnapshot = snapshotSubject(subject);
  let proofSnapshot: AggregateEnforcementProof;
  try {
    proofSnapshot = snapshotAggregateEnforcementProof(proof);
  } catch {
    fail("invalid_proof");
  }
  const subjectDigest = digestSubjectSnapshot(subjectSnapshot);
  if (
    proofSnapshot.generation !== subjectSnapshot.observedRuntimeAuthorizationGeneration ||
    !sameDigest(
      proofSnapshot.requiredEffectEnforcerSetDigest,
      subjectSnapshot.requiredContainmentEnforcerSetDigest
    ) ||
    !sameDigest(proofSnapshot.enforcementSubjectDigest, subjectDigest)
  ) {
    fail("invalid_proof");
  }
  return Object.freeze({ subject: subjectSnapshot, subjectDigest, proof: proofSnapshot });
}

export async function verifyRuntimeCompensationEnforcementProof(
  subject: RuntimeCompensationEnforcementSubject,
  proof: AggregateEnforcementProof,
  verifier: RuntimeCompensationEnforcementProofVerifier
): Promise<void> {
  if (typeof verifier !== "function") fail("verification_failed");
  const input = snapshotRuntimeCompensationEnforcementProofVerificationInput(subject, proof);
  let verified: unknown;
  try {
    verified = await verifier(input);
  } catch {
    fail("verification_failed");
  }
  if (verified !== true) fail("verification_failed");
}

export function verifyRuntimeCompensationEnforcementProofSynchronously(
  subject: RuntimeCompensationEnforcementSubject,
  proof: AggregateEnforcementProof,
  verifier: SynchronousRuntimeCompensationEnforcementProofVerifier
): void {
  if (typeof verifier !== "function") fail("verification_failed");
  const input = snapshotRuntimeCompensationEnforcementProofVerificationInput(subject, proof);
  let verified: unknown;
  try {
    verified = verifier(input);
  } catch {
    fail("verification_failed");
  }
  if (verified !== true) {
    // A thenable cannot hold an SQLite transaction open or settle after lease expiry.
    void Promise.resolve(verified).catch(() => undefined);
    fail("verification_failed");
  }
}

function snapshotSubject(value: unknown): RuntimeCompensationEnforcementSubject {
  let subject: Record<string, unknown>;
  try {
    subject = exactRecord(value, SUBJECT_FIELDS);
  } catch {
    fail("invalid_subject");
  }
  if (
    field(subject, "version") !== 1 ||
    field(subject, "purpose") !== "stale-lifecycle-effect-containment"
  ) {
    fail("invalid_subject");
  }
  const containment = exactRecord(field(subject, "containment"), CONTAINMENT_FIELDS);
  const safetyFence = positiveInteger(field(subject, "safetyFence"));
  const enforcedSafetyFence = positiveInteger(field(subject, "enforcedSafetyFence"));
  if (
    enforcedSafetyFence < safetyFence ||
    field(containment, "terminalWritesRevoked") !== true ||
    field(containment, "processExecutionStopped") !== true ||
    field(containment, "runtimeQuarantined") !== true
  ) {
    fail("invalid_subject");
  }
  return Object.freeze({
    version: 1,
    purpose: "stale-lifecycle-effect-containment",
    compensationId: safeRef(field(subject, "compensationId")),
    commandId: safeRef(field(subject, "commandId")),
    commandClaimsDigest: sha256(field(subject, "commandClaimsDigest")),
    binding: snapshotBinding(field(subject, "binding")),
    observedRuntimeAuthorizationGeneration: positiveInteger(
      field(subject, "observedRuntimeAuthorizationGeneration")
    ),
    safetyFence,
    enforcedSafetyFence,
    sourceReceiptDigest: sha256(field(subject, "sourceReceiptDigest")),
    sourceEnforcementSubjectDigest: sha256(field(subject, "sourceEnforcementSubjectDigest")),
    sourceAggregateProofDigest: sha256(field(subject, "sourceAggregateProofDigest")),
    requiredContainmentEnforcerSetDigest: sha256(
      field(subject, "requiredContainmentEnforcerSetDigest")
    ),
    effectRefCommitment: snapshotPersistedRuntimeEffectRefCommitment(
      field(subject, "effectRefCommitment")
    ),
    containment: Object.freeze({
      terminalWritesRevoked: true,
      processExecutionStopped: true,
      runtimeQuarantined: true,
    }),
  });
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const binding = exactRecord(value, BINDING_FIELDS);
  return Object.freeze({
    teamId: safeRef(field(binding, "teamId")),
    projectId: safeRef(field(binding, "projectId")),
    sessionId: safeRef(field(binding, "sessionId")),
    runtimeAssignmentId: safeRef(field(binding, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(binding, "runtimeAssignmentGeneration")),
    sandboxId: safeRef(field(binding, "sandboxId")),
    sandboxGeneration: positiveInteger(field(binding, "sandboxGeneration")),
    runtimePrincipalId: safeRef(field(binding, "runtimePrincipalId")),
  });
}

function digestSubjectSnapshot(subject: RuntimeCompensationEnforcementSubject): string {
  try {
    return createHash("sha256")
      .update(RUNTIME_COMPENSATION_ENFORCEMENT_SUBJECT_DIGEST_DOMAIN, "utf8")
      .update(canonicalRuntimeJson(subject), "utf8")
      .digest("hex");
  } catch {
    fail("invalid_subject");
  }
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("invalid_subject");
  }
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch {
    fail("invalid_subject");
  }
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    fail("invalid_subject");
  }
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, name);
  } catch {
    fail("invalid_subject");
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    fail("invalid_subject");
  }
  return descriptor.value;
}

function safeRef(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REF.test(value)) fail("invalid_subject");
  return value;
}

function sha256(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail("invalid_subject");
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail("invalid_subject");
  return value as number;
}

function sameDigest(left: string, right: string): boolean {
  try {
    return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
  } catch {
    return false;
  }
}

function fail(code: RuntimeCompensationEnforcementProofErrorCode): never {
  throw new RuntimeCompensationEnforcementProofError(code);
}
