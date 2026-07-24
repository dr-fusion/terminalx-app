import { createHash, timingSafeEqual } from "node:crypto";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { AggregateEnforcementProof } from "./contracts";
import { canonicalRuntimeJson } from "./runtime-command-canonical";

export const RUNTIME_ENFORCEMENT_SUBJECT_DIGEST_DOMAIN =
  "terminalx/runtime-enforcement-subject/v1\0" as const;
export const RUNTIME_AGGREGATE_ENFORCEMENT_PROOF_DIGEST_DOMAIN =
  "terminalx/runtime-aggregate-enforcement-proof/v1\0" as const;

const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REF = /^[^\u0000-\u001f\u007f]{1,300}$/;
const SUBJECT_FIELDS = [
  "version",
  "commandId",
  "commandClaimsDigest",
  "binding",
  "runtimeAuthorizationGeneration",
  "requiredEffectEnforcerSetDigest",
  "effectRefCommitment",
  "enforcedFence",
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
const PROOF_FIELDS = [
  "generation",
  "requiredEffectEnforcerSetDigest",
  "enforcementSubjectDigest",
  "acknowledgements",
  "aggregateProofDigest",
] as const;
const PROOF_PAYLOAD_FIELDS = PROOF_FIELDS.filter((field) => field !== "aggregateProofDigest");
const ACKNOWLEDGEMENT_FIELDS = ["enforcerRef", "enforcerKind", "acknowledgementDigest"] as const;
const ENFORCER_KINDS = new Set([
  "runtime",
  "credential-proxy",
  "source-control",
  "deployment",
  "signer",
  "other-effect-enforcer",
]);
const MAX_ACKNOWLEDGEMENTS = 64;
const EFFECT_REF_COMMITMENT = /^effect:v1:[0-9a-f]{64}$/;
const EFFECT_REF_COMMITMENT_DOMAIN = "terminalx/runtime-effect-ref-commitment/v1\0" as const;

declare const runtimeEffectRefCommitmentBrand: unique symbol;

/** A validated domain-separated commitment, never a raw Runtime/provider reference. */
export type RuntimeEffectRefCommitment = string & {
  readonly [runtimeEffectRefCommitmentBrand]: true;
};

export type RuntimeEnforcementProofErrorCode =
  | "invalid_subject"
  | "invalid_proof"
  | "verification_failed";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeEnforcementProofErrorCode, string>> = {
  invalid_subject: "Runtime enforcement subject is invalid",
  invalid_proof: "Runtime aggregate enforcement proof is invalid",
  verification_failed: "Runtime aggregate enforcement proof could not be verified",
};

/** Safe failure surface: provider values and verifier errors are never retained. */
export class RuntimeEnforcementProofError extends Error {
  constructor(readonly code: RuntimeEnforcementProofErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeEnforcementProofError";
  }
}

export interface RuntimeEnforcementSubject {
  readonly version: 1;
  readonly commandId: string;
  /** Digest from the command's signed authority envelope. */
  readonly commandClaimsDigest: string;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly requiredEffectEnforcerSetDigest: string;
  /** Durable nonsecret commitment; raw provider effect references are never proof inputs. */
  readonly effectRefCommitment: RuntimeEffectRefCommitment;
  readonly enforcedFence: number;
}

/**
 * Convert one raw provider effect reference into its durable, domain-separated
 * commitment. Every input is hashed, including text that happens to have the
 * commitment syntax; raw provider syntax can never select the persisted path.
 */
export function commitRuntimeEffectRef(effectRef: string): RuntimeEffectRefCommitment {
  if (typeof effectRef !== "string") invalid("invalid_subject");
  const snapshot = safeRef(effectRef, "invalid_subject");
  return `effect:v1:${createHash("sha256")
    .update(EFFECT_REF_COMMITMENT_DOMAIN, "utf8")
    .update(snapshot, "utf8")
    .digest("hex")}` as RuntimeEffectRefCommitment;
}

/**
 * Validate an already-committed reference read through a trusted persistence
 * seam. Format validation does not establish provenance: callers must never
 * use this function for Runtime/provider input.
 */
export function snapshotPersistedRuntimeEffectRefCommitment(
  value: unknown
): RuntimeEffectRefCommitment {
  if (typeof value !== "string" || !EFFECT_REF_COMMITMENT.test(value)) {
    invalid("invalid_subject");
  }
  return value as RuntimeEffectRefCommitment;
}

export type AggregateEnforcementProofDigestInput = Omit<
  AggregateEnforcementProof,
  "aggregateProofDigest"
>;

export interface RuntimeEnforcementProofVerificationInput {
  readonly subject: RuntimeEnforcementSubject;
  readonly subjectDigest: string;
  readonly proof: AggregateEnforcementProof;
}

/** Return literal true only after authenticating every required acknowledgement. */
export type RuntimeEnforcementProofVerifier = (
  input: RuntimeEnforcementProofVerificationInput
) => boolean | Promise<boolean>;

/** Journal-safe verifier: the trust decision must be locally available now. */
export type SynchronousRuntimeEnforcementProofVerifier = (
  input: RuntimeEnforcementProofVerificationInput
) => boolean;

/** Lowercase SHA-256 over one exact, domain-separated enforcement subject. */
export function digestRuntimeEnforcementSubject(subject: RuntimeEnforcementSubject): string {
  try {
    const snapshot = snapshotSubject(subject);
    return digestSubjectSnapshot(snapshot);
  } catch (error) {
    if (error instanceof RuntimeEnforcementProofError) throw error;
    invalid("invalid_subject");
  }
}

/** Canonical internal-integrity digest for one exact aggregate proof payload. */
export function digestAggregateEnforcementProof(
  proof: AggregateEnforcementProofDigestInput
): string {
  try {
    return digestProofPayloadSnapshot(snapshotProofPayload(proof));
  } catch (error) {
    if (error instanceof RuntimeEnforcementProofError) throw error;
    invalid("invalid_proof");
  }
}

/** Validate and detach an aggregate proof without yet granting it trust. */
export function snapshotAggregateEnforcementProof(
  proof: AggregateEnforcementProof
): AggregateEnforcementProof {
  try {
    return snapshotProof(proof);
  } catch (error) {
    if (error instanceof RuntimeEnforcementProofError) throw error;
    invalid("invalid_proof");
  }
}

/** Structurally bind an aggregate proof to one exact enforcement subject. */
export function snapshotRuntimeEnforcementProofVerificationInput(
  subject: RuntimeEnforcementSubject,
  proof: AggregateEnforcementProof
): RuntimeEnforcementProofVerificationInput {
  try {
    const subjectSnapshot = snapshotSubject(subject);
    const subjectDigest = digestSubjectSnapshot(subjectSnapshot);
    const proofSnapshot = snapshotProof(proof);
    if (
      proofSnapshot.generation !== subjectSnapshot.runtimeAuthorizationGeneration ||
      !sameDigest(
        proofSnapshot.requiredEffectEnforcerSetDigest,
        subjectSnapshot.requiredEffectEnforcerSetDigest
      ) ||
      !sameDigest(proofSnapshot.enforcementSubjectDigest, subjectDigest)
    ) {
      invalid("invalid_proof");
    }
    return Object.freeze({
      subject: subjectSnapshot,
      subjectDigest,
      proof: proofSnapshot,
    });
  } catch (error) {
    if (error instanceof RuntimeEnforcementProofError) throw error;
    invalid("invalid_proof");
  }
}

/**
 * Bind an aggregate proof to one exact subject, then require an injected trust
 * decision. There is intentionally no built-in or permissive verifier.
 */
export async function verifyRuntimeEnforcementProof(
  subject: RuntimeEnforcementSubject,
  proof: AggregateEnforcementProof,
  verifier: RuntimeEnforcementProofVerifier
): Promise<void> {
  if (typeof verifier !== "function") invalid("verification_failed");
  const input = snapshotRuntimeEnforcementProofVerificationInput(subject, proof);

  let verified: boolean;
  try {
    verified = (await verifier(input)) === true;
  } catch {
    invalid("verification_failed");
  }
  if (!verified) invalid("verification_failed");
}

function digestSubjectSnapshot(subject: RuntimeEnforcementSubject): string {
  return createHash("sha256")
    .update(RUNTIME_ENFORCEMENT_SUBJECT_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(subject), "utf8")
    .digest("hex");
}

function digestProofPayloadSnapshot(proof: AggregateEnforcementProofDigestInput): string {
  return createHash("sha256")
    .update(RUNTIME_AGGREGATE_ENFORCEMENT_PROOF_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(proof), "utf8")
    .digest("hex");
}

function snapshotProof(value: unknown): AggregateEnforcementProof {
  const proof = exactRecord(value, PROOF_FIELDS, "invalid_proof");
  const payload = snapshotProofPayload({
    generation: field(proof, "generation", "invalid_proof"),
    requiredEffectEnforcerSetDigest: field(
      proof,
      "requiredEffectEnforcerSetDigest",
      "invalid_proof"
    ),
    enforcementSubjectDigest: field(proof, "enforcementSubjectDigest", "invalid_proof"),
    acknowledgements: field(proof, "acknowledgements", "invalid_proof"),
  });
  const aggregateProofDigest = sha256(
    field(proof, "aggregateProofDigest", "invalid_proof"),
    "invalid_proof"
  );
  if (!sameDigest(aggregateProofDigest, digestProofPayloadSnapshot(payload))) {
    invalid("invalid_proof");
  }
  return Object.freeze({ ...payload, aggregateProofDigest });
}

function snapshotProofPayload(value: unknown): AggregateEnforcementProofDigestInput {
  const proof = exactRecord(value, PROOF_PAYLOAD_FIELDS, "invalid_proof");
  return Object.freeze({
    generation: positiveInteger(field(proof, "generation", "invalid_proof"), "invalid_proof"),
    requiredEffectEnforcerSetDigest: sha256(
      field(proof, "requiredEffectEnforcerSetDigest", "invalid_proof"),
      "invalid_proof"
    ),
    enforcementSubjectDigest: sha256(
      field(proof, "enforcementSubjectDigest", "invalid_proof"),
      "invalid_proof"
    ),
    acknowledgements: snapshotAcknowledgements(field(proof, "acknowledgements", "invalid_proof")),
  });
}

function snapshotAcknowledgements(value: unknown): AggregateEnforcementProof["acknowledgements"] {
  let keys: PropertyKey[];
  let length: number;
  try {
    if (!Array.isArray(value)) invalid("invalid_proof");
    if (Object.getPrototypeOf(value) !== Array.prototype) invalid("invalid_proof");
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      !lengthDescriptor ||
      lengthDescriptor.enumerable ||
      !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 1 ||
      lengthDescriptor.value > MAX_ACKNOWLEDGEMENTS
    ) {
      invalid("invalid_proof");
    }
    length = lengthDescriptor.value;
    keys = Reflect.ownKeys(value);
  } catch {
    invalid("invalid_proof");
  }
  if (
    keys.length !== length + 1 ||
    !keys.includes("length") ||
    keys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= length)
    )
  ) {
    invalid("invalid_proof");
  }

  const enforcerRefs = new Set<string>();
  const acknowledgementDigests = new Set<string>();
  const snapshots: Array<AggregateEnforcementProof["acknowledgements"][number]> = [];
  let priorEnforcerRef: string | undefined;
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      invalid("invalid_proof");
    }
    const acknowledgement = exactRecord(descriptor.value, ACKNOWLEDGEMENT_FIELDS, "invalid_proof");
    const enforcerRef = safeRef(
      field(acknowledgement, "enforcerRef", "invalid_proof"),
      "invalid_proof"
    );
    const enforcerKind = field(acknowledgement, "enforcerKind", "invalid_proof");
    const acknowledgementDigest = sha256(
      field(acknowledgement, "acknowledgementDigest", "invalid_proof"),
      "invalid_proof"
    );
    if (
      typeof enforcerKind !== "string" ||
      !ENFORCER_KINDS.has(enforcerKind) ||
      enforcerRefs.has(enforcerRef) ||
      acknowledgementDigests.has(acknowledgementDigest) ||
      (priorEnforcerRef !== undefined && enforcerRef <= priorEnforcerRef)
    ) {
      invalid("invalid_proof");
    }
    enforcerRefs.add(enforcerRef);
    acknowledgementDigests.add(acknowledgementDigest);
    priorEnforcerRef = enforcerRef;
    snapshots.push(
      Object.freeze({
        enforcerRef,
        enforcerKind:
          enforcerKind as AggregateEnforcementProof["acknowledgements"][number]["enforcerKind"],
        acknowledgementDigest,
      })
    );
  }
  return Object.freeze(snapshots);
}

function snapshotSubject(value: unknown): RuntimeEnforcementSubject {
  const subject = exactRecord(value, SUBJECT_FIELDS, "invalid_subject");
  if (field(subject, "version", "invalid_subject") !== 1) invalid("invalid_subject");
  const binding = snapshotBinding(field(subject, "binding", "invalid_subject"));
  const snapshot: RuntimeEnforcementSubject = {
    version: 1,
    commandId: safeRef(field(subject, "commandId", "invalid_subject"), "invalid_subject"),
    commandClaimsDigest: sha256(
      field(subject, "commandClaimsDigest", "invalid_subject"),
      "invalid_subject"
    ),
    binding,
    runtimeAuthorizationGeneration: positiveInteger(
      field(subject, "runtimeAuthorizationGeneration", "invalid_subject"),
      "invalid_subject"
    ),
    requiredEffectEnforcerSetDigest: sha256(
      field(subject, "requiredEffectEnforcerSetDigest", "invalid_subject"),
      "invalid_subject"
    ),
    effectRefCommitment: effectRefCommitment(
      field(subject, "effectRefCommitment", "invalid_subject")
    ),
    enforcedFence: positiveInteger(
      field(subject, "enforcedFence", "invalid_subject"),
      "invalid_subject"
    ),
  };
  return Object.freeze(snapshot);
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const binding = exactRecord(value, BINDING_FIELDS, "invalid_subject");
  return Object.freeze({
    teamId: safeRef(field(binding, "teamId", "invalid_subject"), "invalid_subject"),
    projectId: safeRef(field(binding, "projectId", "invalid_subject"), "invalid_subject"),
    sessionId: safeRef(field(binding, "sessionId", "invalid_subject"), "invalid_subject"),
    runtimeAssignmentId: safeRef(
      field(binding, "runtimeAssignmentId", "invalid_subject"),
      "invalid_subject"
    ),
    runtimeAssignmentGeneration: positiveInteger(
      field(binding, "runtimeAssignmentGeneration", "invalid_subject"),
      "invalid_subject"
    ),
    sandboxId: safeRef(field(binding, "sandboxId", "invalid_subject"), "invalid_subject"),
    sandboxGeneration: positiveInteger(
      field(binding, "sandboxGeneration", "invalid_subject"),
      "invalid_subject"
    ),
    runtimePrincipalId: safeRef(
      field(binding, "runtimePrincipalId", "invalid_subject"),
      "invalid_subject"
    ),
  });
}

function exactRecord(
  value: unknown,
  expectedFields: readonly string[],
  code: RuntimeEnforcementProofErrorCode
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(code);
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch {
    invalid(code);
  }
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== expectedFields.length ||
    keys.some((key) => typeof key !== "string" || !expectedFields.includes(key))
  ) {
    invalid(code);
  }
  return value as Record<string, unknown>;
}

function field(
  record: Record<string, unknown>,
  name: string,
  code: RuntimeEnforcementProofErrorCode
): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, name);
  } catch {
    invalid(code);
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid(code);
  return descriptor.value;
}

function safeRef(value: unknown, code: RuntimeEnforcementProofErrorCode): string {
  if (typeof value !== "string" || !SAFE_REF.test(value)) invalid(code);
  return value;
}

function effectRefCommitment(value: unknown): RuntimeEffectRefCommitment {
  return snapshotPersistedRuntimeEffectRefCommitment(value);
}

function sha256(value: unknown, code: RuntimeEnforcementProofErrorCode): string {
  if (typeof value !== "string" || !SHA256.test(value)) invalid(code);
  return value;
}

function positiveInteger(value: unknown, code: RuntimeEnforcementProofErrorCode): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) invalid(code);
  return value as number;
}

function sameDigest(left: string, right: string): boolean {
  try {
    return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
  } catch {
    return false;
  }
}

function invalid(code: RuntimeEnforcementProofErrorCode): never {
  throw new RuntimeEnforcementProofError(code);
}
