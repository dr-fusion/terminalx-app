import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
  timingSafeEqual,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { constants as fsConstants, closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { RuntimeCompensationCommand, RuntimeCompensationReceipt } from "./contracts";
import { canonicalRuntimeJson, digestRuntimeCommandClaims } from "./runtime-command-canonical";
import { snapshotRuntimeCompensationReceiptForCommand } from "./runtime-compensation-execution";
import {
  RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS,
  runtimeReceiptObservationCursorCodePoints,
} from "./runtime-receipt-observation-contract";

export { RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS } from "./runtime-receipt-observation-contract";

export const RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN =
  "terminalx/runtime-compensation-receipt-observation-claims/v1\0" as const;
export const RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN =
  "terminalx/runtime-compensation-receipt-observation-signature/v1\0" as const;
export const RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN =
  "terminalx/runtime-compensation-receipt-observation-receipt/v1\0" as const;

const OBSERVATION_KIND = "runtime.compensation-receipt-observed" as const;
const OBSERVATION_ISSUER = "runtime" as const;
const OBSERVATION_AUDIENCE = "terminalx-control-plane" as const;
const OBSERVATION_CAPABILITY = "runtime.compensation-receipt.observe" as const;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/;
const SAFE_CURSOR_CHARACTERS = /^[^\u0000-\u001f\u007f]+$/u;
const MAX_KEY_FILE_BYTES = 64 * 1024;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const MAX_PINNED_KEYS = 64;
const DEFAULT_OBSERVATION_TTL_MS = 60_000;
const MAX_OBSERVATION_TTL_MS = 5 * 60_000;
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
const COMMAND_REFERENCE_FIELDS = [
  "kind",
  "commandId",
  "compensationId",
  "claimsDigest",
  "binding",
  "observedRuntimeAuthorizationGeneration",
  "safetyFence",
  "source",
  "requiredContainmentEnforcerSetDigest",
] as const;
const OBSERVATION_FIELDS = [
  "version",
  "kind",
  "observationId",
  "cursor",
  "previous",
  "observedAtMs",
  "command",
  "receipt",
  "receiptDigest",
  "authority",
] as const;
const AUTHORITY_FIELDS = [
  "issuer",
  "issuerKeyId",
  "audience",
  "capability",
  "claimsDigest",
  "issuedAtMs",
  "expiresAtMs",
  "signature",
] as const;
const COMMAND_AUTHORITY_FIELDS = [
  "issuerKeyId",
  "audience",
  "claimsDigest",
  "issuedAtMs",
  "expiresAtMs",
  "signature",
  "issuer",
  "capability",
] as const;
const VERIFIED_RUNTIME_COMPENSATION_RECEIPT_OBSERVATION = Symbol(
  "terminalx.verified-runtime-compensation-receipt-observation"
);

export type RuntimeCompensationReceiptObservationErrorCode =
  | "invalid_configuration"
  | "private_key_unavailable"
  | "invalid_private_key"
  | "invalid_public_key"
  | "invalid_input"
  | "invalid_command"
  | "invalid_receipt"
  | "invalid_observation"
  | "command_mismatch"
  | "chain_mismatch"
  | "untrusted_issuer"
  | "invalid_signature"
  | "expired"
  | "signing_failed";

const SAFE_ERROR_MESSAGES: Readonly<
  Record<RuntimeCompensationReceiptObservationErrorCode, string>
> = {
  invalid_configuration: "Runtime compensation receipt observation configuration is invalid",
  private_key_unavailable: "Runtime compensation receipt observation private key is unavailable",
  invalid_private_key: "Runtime compensation receipt observation private key is invalid",
  invalid_public_key: "Runtime compensation receipt observation public key is invalid",
  invalid_input: "Runtime compensation receipt observation input is invalid",
  invalid_command: "Runtime compensation receipt observation command is invalid",
  invalid_receipt: "Runtime compensation receipt observation receipt is invalid",
  invalid_observation: "Runtime compensation receipt observation is invalid",
  command_mismatch: "Runtime compensation receipt observation does not match the expected command",
  chain_mismatch: "Runtime compensation receipt observation cursor chain does not match",
  untrusted_issuer: "Runtime compensation receipt observation issuer is not trusted",
  invalid_signature: "Runtime compensation receipt observation signature is invalid",
  expired: "Runtime compensation receipt observation has expired",
  signing_failed: "Runtime compensation receipt observation could not be signed",
};

/** Safe failure surface: provider values, key material, and crypto errors are never attached. */
export class RuntimeCompensationReceiptObservationError extends Error {
  constructor(readonly code: RuntimeCompensationReceiptObservationErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeCompensationReceiptObservationError";
  }
}

export interface RuntimeCompensationReceiptObservationCheckpoint {
  readonly cursor: string;
  readonly observationDigest: string;
}

export interface RuntimeCompensationReceiptSourceReference {
  readonly lifecycleCommandId: string;
  readonly lifecycleCommandClaimsDigest: string;
  readonly lifecycleReceiptDigest: string;
  readonly lifecycleEnforcementSubjectDigest: string;
  readonly lifecycleAggregateProofDigest: string;
  readonly sourceRequiredEffectEnforcerSetDigest: string;
}

export interface RuntimeCompensationReceiptCommandReference {
  readonly kind: "safety.quarantine";
  readonly commandId: string;
  readonly compensationId: string;
  readonly claimsDigest: string;
  readonly binding: RuntimeBinding;
  readonly observedRuntimeAuthorizationGeneration: number;
  readonly safetyFence: number;
  readonly source: RuntimeCompensationReceiptSourceReference;
  readonly requiredContainmentEnforcerSetDigest: string;
}

export interface RuntimeCompensationReceiptObservationAuthority {
  readonly issuer: "runtime";
  readonly issuerKeyId: string;
  readonly audience: "terminalx-control-plane";
  readonly capability: "runtime.compensation-receipt.observe";
  readonly claimsDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly signature: string;
}

/** Private-channel observation of one exact compensation receipt. */
export interface RuntimeCompensationReceiptObservation {
  readonly version: 1;
  readonly kind: "runtime.compensation-receipt-observed";
  readonly observationId: string;
  readonly cursor: string;
  readonly previous: RuntimeCompensationReceiptObservationCheckpoint | null;
  readonly observedAtMs: number;
  readonly command: RuntimeCompensationReceiptCommandReference;
  readonly receipt: RuntimeCompensationReceipt;
  readonly receiptDigest: string;
  readonly authority: RuntimeCompensationReceiptObservationAuthority;
}

/** Only this module can construct the brand after all checks succeed. */
export type VerifiedRuntimeCompensationReceiptObservation =
  RuntimeCompensationReceiptObservation & {
    readonly observationDigest: string;
    readonly [VERIFIED_RUNTIME_COMPENSATION_RECEIPT_OBSERVATION]: true;
  };

export function isVerifiedRuntimeCompensationReceiptObservation(
  value: unknown
): value is VerifiedRuntimeCompensationReceiptObservation {
  if (typeof value !== "object" || value === null) return false;
  try {
    const brand = Object.getOwnPropertyDescriptor(
      value,
      VERIFIED_RUNTIME_COMPENSATION_RECEIPT_OBSERVATION
    );
    const digest = Object.getOwnPropertyDescriptor(value, "observationDigest");
    return (
      Object.isFrozen(value) &&
      brand?.value === true &&
      brand.enumerable === false &&
      brand.writable === false &&
      brand.configurable === false &&
      typeof digest?.value === "string" &&
      SHA256.test(digest.value) &&
      digest.enumerable === false &&
      digest.writable === false &&
      digest.configurable === false
    );
  } catch {
    return false;
  }
}

export interface RuntimeCompensationReceiptObservationIssueInput {
  readonly observationId: string;
  readonly cursor: string;
  readonly previous: RuntimeCompensationReceiptObservationCheckpoint | null;
  readonly command: RuntimeCompensationCommand;
  readonly receipt: RuntimeCompensationReceipt;
}

export interface CreateRuntimeCompensationReceiptObservationIssuerOptions {
  readonly issuerKeyId: string;
  readonly binding: RuntimeBinding;
  readonly privateKeyFile: string;
  readonly clock?: () => number;
  readonly observationTtlMs?: number;
}

export interface RuntimeCompensationReceiptObservationIssuer {
  issue(
    input: RuntimeCompensationReceiptObservationIssueInput
  ): RuntimeCompensationReceiptObservation;
}

export interface PinnedRuntimeCompensationReceiptObservationPublicKey {
  readonly issuerKeyId: string;
  readonly binding: RuntimeBinding;
  readonly publicKeyPem: string;
}

export interface CreateRuntimeCompensationReceiptObservationVerifierOptions {
  readonly pinnedPublicKeys: readonly PinnedRuntimeCompensationReceiptObservationPublicKey[];
  readonly maximumObservationTtlMs?: number;
}

export interface RuntimeCompensationReceiptObservationVerificationInput {
  readonly observation: unknown;
  readonly command: RuntimeCompensationCommand;
  readonly expectedPrevious: RuntimeCompensationReceiptObservationCheckpoint | null;
  readonly nowMs: number;
}

export interface RuntimeCompensationReceiptObservationVerifier {
  verify(
    input: RuntimeCompensationReceiptObservationVerificationInput
  ): VerifiedRuntimeCompensationReceiptObservation;
}

interface ObservationAuthorityStatement {
  readonly version: 1;
  readonly issuer: "runtime";
  readonly issuerKeyId: string;
  readonly audience: "terminalx-control-plane";
  readonly capability: "runtime.compensation-receipt.observe";
  readonly claimsDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

interface PinnedKey {
  readonly key: KeyObject;
  readonly binding: RuntimeBinding;
}

export function createRuntimeCompensationReceiptObservationIssuer(
  unsafeOptions: CreateRuntimeCompensationReceiptObservationIssuerOptions
): RuntimeCompensationReceiptObservationIssuer {
  const options = dataRecord(unsafeOptions, "invalid_configuration");
  exactFields(
    options,
    ["issuerKeyId", "binding", "privateKeyFile"],
    ["clock", "observationTtlMs"],
    "invalid_configuration"
  );
  const issuerKeyId = requiredKeyId(
    dataField(options, "issuerKeyId", "invalid_configuration"),
    "invalid_configuration"
  );
  const binding = snapshotBinding(
    dataField(options, "binding", "invalid_configuration"),
    "invalid_configuration"
  );
  const privateKey = loadPrivateKey(
    dataField(options, "privateKeyFile", "private_key_unavailable")
  );
  const clockValue = optionalDataField(options, "clock", "invalid_configuration");
  const clock = clockValue ?? Date.now;
  if (typeof clock !== "function") fail("invalid_configuration");
  const ttl = boundedInteger(
    optionalDataField(options, "observationTtlMs", "invalid_configuration") ??
      DEFAULT_OBSERVATION_TTL_MS,
    1,
    MAX_OBSERVATION_TTL_MS,
    "invalid_configuration"
  );

  return Object.freeze({
    issue(
      unsafeInput: RuntimeCompensationReceiptObservationIssueInput
    ): RuntimeCompensationReceiptObservation {
      const input = dataRecord(unsafeInput, "invalid_input");
      exactFields(
        input,
        ["observationId", "cursor", "previous", "command", "receipt"],
        [],
        "invalid_input"
      );
      const observationId = safeReference(
        dataField(input, "observationId", "invalid_input"),
        "invalid_input"
      );
      const cursor = safeCursor(dataField(input, "cursor", "invalid_input"), "invalid_input");
      const previous = snapshotCheckpoint(
        dataField(input, "previous", "invalid_input"),
        "invalid_input"
      );
      if (previous?.cursor === cursor) fail("invalid_input");

      const command = snapshotCompensationCommand(
        dataField(input, "command", "invalid_command"),
        "invalid_command"
      );
      const commandReference = referenceForCommand(command);
      if (!sameBinding(commandReference.binding, binding)) fail("invalid_command");
      const receipt = snapshotReceipt(
        dataField(input, "receipt", "invalid_receipt"),
        command,
        "invalid_receipt"
      );
      const receiptDigest = digestReceiptSnapshot(receipt);
      const observedAtMs = sampleClock(clock as () => number);
      const expiresAtMs = safeAdd(observedAtMs, ttl, "invalid_input");

      const claims = Object.freeze({
        version: 1 as const,
        kind: OBSERVATION_KIND,
        observationId,
        cursor,
        previous,
        observedAtMs,
        command: commandReference,
        receipt,
        receiptDigest,
      });
      const claimsDigest = digestObservationClaims(claims);
      const statement: ObservationAuthorityStatement = Object.freeze({
        version: 1,
        issuer: OBSERVATION_ISSUER,
        issuerKeyId,
        audience: OBSERVATION_AUDIENCE,
        capability: OBSERVATION_CAPABILITY,
        claimsDigest,
        issuedAtMs: observedAtMs,
        expiresAtMs,
      });
      let signature: string;
      try {
        signature = signEd25519(null, authorityPayload(statement), privateKey).toString(
          "base64url"
        );
      } catch {
        fail("signing_failed");
      }
      if (!ED25519_SIGNATURE.test(signature)) fail("signing_failed");

      return deepFreeze({
        ...claims,
        authority: {
          issuer: OBSERVATION_ISSUER,
          issuerKeyId,
          audience: OBSERVATION_AUDIENCE,
          capability: OBSERVATION_CAPABILITY,
          claimsDigest,
          issuedAtMs: observedAtMs,
          expiresAtMs,
          signature,
        },
      }) as RuntimeCompensationReceiptObservation;
    },
  });
}

export function createRuntimeCompensationReceiptObservationVerifier(
  unsafeOptions: CreateRuntimeCompensationReceiptObservationVerifierOptions
): RuntimeCompensationReceiptObservationVerifier {
  const options = dataRecord(unsafeOptions, "invalid_configuration");
  exactFields(options, ["pinnedPublicKeys"], ["maximumObservationTtlMs"], "invalid_configuration");
  const maximumTtl = boundedInteger(
    optionalDataField(options, "maximumObservationTtlMs", "invalid_configuration") ??
      MAX_OBSERVATION_TTL_MS,
    1,
    MAX_OBSERVATION_TTL_MS,
    "invalid_configuration"
  );
  const pinnedKeys = loadPinnedPublicKeys(
    dataField(options, "pinnedPublicKeys", "invalid_public_key")
  );

  return Object.freeze({
    verify(
      unsafeInput: RuntimeCompensationReceiptObservationVerificationInput
    ): VerifiedRuntimeCompensationReceiptObservation {
      const input = dataRecord(unsafeInput, "invalid_input");
      exactFields(
        input,
        ["observation", "command", "expectedPrevious", "nowMs"],
        [],
        "invalid_input"
      );
      const nowMs = nonNegativeInteger(dataField(input, "nowMs", "invalid_input"), "invalid_input");
      const command = snapshotCompensationCommand(
        dataField(input, "command", "invalid_command"),
        "invalid_command"
      );
      const expectedReference = referenceForCommand(command);
      const expectedPrevious = snapshotCheckpoint(
        dataField(input, "expectedPrevious", "invalid_input"),
        "invalid_input"
      );
      const observation = snapshotObservation(
        dataField(input, "observation", "invalid_observation")
      );

      assertReferenceMatches(observation.command, expectedReference);
      assertChainMatches(observation, expectedPrevious);
      const claimedReceipt = observation.receipt;
      const actualReceiptDigest = digestReceiptSnapshot(claimedReceipt);
      if (!sameDigest(observation.receiptDigest, actualReceiptDigest)) {
        fail("invalid_observation");
      }

      const authority = observation.authority;
      if (
        authority.issuedAtMs !== observation.observedAtMs ||
        authority.expiresAtMs <= authority.issuedAtMs ||
        authority.expiresAtMs - authority.issuedAtMs > maximumTtl
      ) {
        fail("invalid_observation");
      }
      if (nowMs < authority.issuedAtMs || nowMs >= authority.expiresAtMs) fail("expired");

      const claims = observationClaims(observation, claimedReceipt);
      const claimsDigest = digestObservationClaims(claims);
      if (!sameDigest(authority.claimsDigest, claimsDigest)) fail("invalid_observation");
      const pin = pinnedKeys.get(authority.issuerKeyId);
      if (!pin || !sameBinding(pin.binding, expectedReference.binding)) fail("untrusted_issuer");
      const signature = decodeSignature(authority.signature);
      if (!signature) fail("invalid_signature");
      let signatureValid = false;
      try {
        signatureValid = verifyEd25519(
          null,
          authorityPayload({
            version: 1,
            issuer: OBSERVATION_ISSUER,
            issuerKeyId: authority.issuerKeyId,
            audience: OBSERVATION_AUDIENCE,
            capability: OBSERVATION_CAPABILITY,
            claimsDigest,
            issuedAtMs: authority.issuedAtMs,
            expiresAtMs: authority.expiresAtMs,
          }),
          pin.key,
          signature
        );
      } catch {
        fail("invalid_signature");
      }
      if (!signatureValid) fail("invalid_signature");

      // Receipt classification occurs only after exact binding authentication.
      const receipt = snapshotReceipt(claimedReceipt, command, "invalid_receipt");
      const verified = {
        ...observation,
        receipt,
      } as RuntimeCompensationReceiptObservation & Record<PropertyKey, unknown>;
      Object.defineProperty(verified, "observationDigest", {
        value: claimsDigest,
        enumerable: false,
        writable: false,
        configurable: false,
      });
      Object.defineProperty(verified, VERIFIED_RUNTIME_COMPENSATION_RECEIPT_OBSERVATION, {
        value: true,
        enumerable: false,
        writable: false,
        configurable: false,
      });
      return deepFreeze(verified) as unknown as VerifiedRuntimeCompensationReceiptObservation;
    },
  });
}

/** Validate and digest the exact wire receipt for one compensation command. */
export function digestRuntimeCompensationReceiptForObservation(
  receipt: RuntimeCompensationReceipt,
  command: RuntimeCompensationCommand
): string {
  const commandSnapshot = snapshotCompensationCommand(command, "invalid_command");
  return digestReceiptSnapshot(snapshotReceipt(receipt, commandSnapshot, "invalid_receipt"));
}

function snapshotObservation(value: unknown): RuntimeCompensationReceiptObservation {
  const snapshot = snapshotJsonData(value, "invalid_observation");
  const record = dataRecord(snapshot, "invalid_observation");
  exactFields(record, OBSERVATION_FIELDS, [], "invalid_observation");
  if (
    dataField(record, "version", "invalid_observation") !== 1 ||
    dataField(record, "kind", "invalid_observation") !== OBSERVATION_KIND
  ) {
    fail("invalid_observation");
  }
  safeReference(dataField(record, "observationId", "invalid_observation"), "invalid_observation");
  const cursor = safeCursor(
    dataField(record, "cursor", "invalid_observation"),
    "invalid_observation"
  );
  const previous = snapshotCheckpoint(
    dataField(record, "previous", "invalid_observation"),
    "invalid_observation"
  );
  if (previous?.cursor === cursor) fail("invalid_observation");
  nonNegativeInteger(
    dataField(record, "observedAtMs", "invalid_observation"),
    "invalid_observation"
  );
  validateCommandReference(
    dataField(record, "command", "invalid_observation"),
    "invalid_observation"
  );
  sha256(dataField(record, "receiptDigest", "invalid_observation"), "invalid_observation");
  validateObservationAuthority(
    dataField(record, "authority", "invalid_observation"),
    "invalid_observation"
  );
  return record as unknown as RuntimeCompensationReceiptObservation;
}

function observationClaims(
  observation: RuntimeCompensationReceiptObservation,
  receipt: RuntimeCompensationReceipt
): Omit<RuntimeCompensationReceiptObservation, "authority"> {
  return Object.freeze({
    version: observation.version,
    kind: observation.kind,
    observationId: observation.observationId,
    cursor: observation.cursor,
    previous: observation.previous,
    observedAtMs: observation.observedAtMs,
    command: observation.command,
    receipt,
    receiptDigest: observation.receiptDigest,
  });
}

function digestObservationClaims(value: unknown): string {
  try {
    return createHash("sha256")
      .update(RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN, "utf8")
      .update(canonicalRuntimeJson(value), "utf8")
      .digest("hex");
  } catch {
    fail("invalid_observation");
  }
}

function digestReceiptSnapshot(receipt: RuntimeCompensationReceipt): string {
  try {
    return createHash("sha256")
      .update(RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN, "utf8")
      .update(canonicalRuntimeJson(receipt), "utf8")
      .digest("hex");
  } catch {
    fail("invalid_receipt");
  }
}

function snapshotReceipt(
  value: unknown,
  command: RuntimeCompensationCommand,
  code: RuntimeCompensationReceiptObservationErrorCode
): RuntimeCompensationReceipt {
  try {
    return snapshotRuntimeCompensationReceiptForCommand(value, command);
  } catch {
    fail(code);
  }
}

function snapshotCompensationCommand(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): RuntimeCompensationCommand {
  const snapshot = snapshotJsonData(value, code);
  const command = dataRecord(snapshot, code);
  exactFields(command, COMMAND_FIELDS, [], code);
  if (dataField(command, "kind", code) !== "safety.quarantine") fail(code);
  safeReference(dataField(command, "commandId", code), code);
  safeReference(dataField(command, "compensationId", code), code);
  const binding = snapshotBinding(dataField(command, "binding", code), code);
  positiveInteger(dataField(command, "observedRuntimeAuthorizationGeneration", code), code);

  const source = dataRecord(dataField(command, "source", code), code);
  exactFields(source, SOURCE_FIELDS, [], code);
  const lifecycleCommandId = safeReference(dataField(source, "lifecycleCommandId", code), code);
  for (const field of SOURCE_FIELDS.slice(1)) sha256(dataField(source, field, code), code);
  safeReference(dataField(command, "platformSecurityPolicyRevision", code), code);
  sha256(dataField(command, "requiredContainmentEnforcerSetDigest", code), code);
  const containment = dataRecord(dataField(command, "containment", code), code);
  exactFields(
    containment,
    ["revokeTerminalWrites", "stopProcessExecution", "quarantineRuntime"],
    [],
    code
  );
  if (
    dataField(containment, "revokeTerminalWrites", code) !== true ||
    dataField(containment, "stopProcessExecution", code) !== true ||
    dataField(containment, "quarantineRuntime", code) !== true
  ) {
    fail(code);
  }
  positiveInteger(dataField(command, "safetyFence", code), code);
  if (
    dataField(command, "exactBindingOnly", code) !== true ||
    dataField(command, "advanceBeyondCurrentFences", code) !== true
  ) {
    fail(code);
  }
  safeReference(dataField(command, "reasonRef", code), code);
  if (safeReference(dataField(command, "causationId", code), code) !== lifecycleCommandId) {
    fail(code);
  }
  const actor = dataRecord(dataField(command, "actor", code), code);
  exactFields(actor, ["kind", "actorRef"], [], code);
  if (
    dataField(actor, "kind", code) !== "system" ||
    dataField(actor, "actorRef", code) !== "platform-security"
  ) {
    fail(code);
  }

  const issuedAtMs = nonNegativeInteger(dataField(command, "issuedAtMs", code), code);
  const deadlineAtMs = positiveInteger(dataField(command, "deadlineAtMs", code), code);
  if (deadlineAtMs <= issuedAtMs) fail(code);
  const authority = dataRecord(dataField(command, "authority", code), code);
  exactFields(authority, COMMAND_AUTHORITY_FIELDS, [], code);
  if (
    dataField(authority, "issuer", code) !== "platform-security" ||
    dataField(authority, "audience", code) !== "runtime" ||
    dataField(authority, "capability", code) !== "safety.quarantine"
  ) {
    fail(code);
  }
  requiredKeyId(dataField(authority, "issuerKeyId", code), code);
  const authorityIssuedAtMs = nonNegativeInteger(dataField(authority, "issuedAtMs", code), code);
  const authorityExpiresAtMs = positiveInteger(dataField(authority, "expiresAtMs", code), code);
  if (
    authorityIssuedAtMs !== issuedAtMs ||
    authorityExpiresAtMs <= authorityIssuedAtMs ||
    authorityExpiresAtMs > deadlineAtMs
  ) {
    fail(code);
  }
  if (!decodeSignature(dataField(authority, "signature", code))) fail(code);
  const claimedDigest = sha256(dataField(authority, "claimsDigest", code), code);
  let actualDigest: string;
  try {
    actualDigest = digestRuntimeCommandClaims(command);
  } catch {
    fail(code);
  }
  if (!sameDigest(claimedDigest, actualDigest)) fail(code);
  void binding;
  return command as unknown as RuntimeCompensationCommand;
}

function referenceForCommand(
  command: RuntimeCompensationCommand
): RuntimeCompensationReceiptCommandReference {
  let claimsDigest: string;
  try {
    claimsDigest = digestRuntimeCommandClaims(command);
  } catch {
    fail("invalid_command");
  }
  return deepFreeze({
    kind: "safety.quarantine" as const,
    commandId: command.commandId,
    compensationId: command.compensationId,
    claimsDigest,
    binding: snapshotBinding(command.binding, "invalid_command"),
    observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
    safetyFence: command.safetyFence,
    source: {
      lifecycleCommandId: command.source.lifecycleCommandId,
      lifecycleCommandClaimsDigest: command.source.lifecycleCommandClaimsDigest,
      lifecycleReceiptDigest: command.source.lifecycleReceiptDigest,
      lifecycleEnforcementSubjectDigest: command.source.lifecycleEnforcementSubjectDigest,
      lifecycleAggregateProofDigest: command.source.lifecycleAggregateProofDigest,
      sourceRequiredEffectEnforcerSetDigest: command.source.sourceRequiredEffectEnforcerSetDigest,
    },
    requiredContainmentEnforcerSetDigest: command.requiredContainmentEnforcerSetDigest,
  }) as RuntimeCompensationReceiptCommandReference;
}

function validateCommandReference(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): RuntimeCompensationReceiptCommandReference {
  const reference = dataRecord(value, code);
  exactFields(reference, COMMAND_REFERENCE_FIELDS, [], code);
  if (dataField(reference, "kind", code) !== "safety.quarantine") fail(code);
  safeReference(dataField(reference, "commandId", code), code);
  safeReference(dataField(reference, "compensationId", code), code);
  sha256(dataField(reference, "claimsDigest", code), code);
  snapshotBinding(dataField(reference, "binding", code), code);
  positiveInteger(dataField(reference, "observedRuntimeAuthorizationGeneration", code), code);
  positiveInteger(dataField(reference, "safetyFence", code), code);
  const source = dataRecord(dataField(reference, "source", code), code);
  exactFields(source, SOURCE_FIELDS, [], code);
  safeReference(dataField(source, "lifecycleCommandId", code), code);
  for (const field of SOURCE_FIELDS.slice(1)) sha256(dataField(source, field, code), code);
  sha256(dataField(reference, "requiredContainmentEnforcerSetDigest", code), code);
  return reference as unknown as RuntimeCompensationReceiptCommandReference;
}

function assertReferenceMatches(
  actual: RuntimeCompensationReceiptCommandReference,
  expected: RuntimeCompensationReceiptCommandReference
): void {
  if (
    actual.kind !== expected.kind ||
    actual.commandId !== expected.commandId ||
    actual.compensationId !== expected.compensationId ||
    !sameDigest(actual.claimsDigest, expected.claimsDigest) ||
    !sameBinding(actual.binding, expected.binding) ||
    actual.observedRuntimeAuthorizationGeneration !==
      expected.observedRuntimeAuthorizationGeneration ||
    actual.safetyFence !== expected.safetyFence ||
    actual.source.lifecycleCommandId !== expected.source.lifecycleCommandId ||
    !sameDigest(
      actual.source.lifecycleCommandClaimsDigest,
      expected.source.lifecycleCommandClaimsDigest
    ) ||
    !sameDigest(actual.source.lifecycleReceiptDigest, expected.source.lifecycleReceiptDigest) ||
    !sameDigest(
      actual.source.lifecycleEnforcementSubjectDigest,
      expected.source.lifecycleEnforcementSubjectDigest
    ) ||
    !sameDigest(
      actual.source.lifecycleAggregateProofDigest,
      expected.source.lifecycleAggregateProofDigest
    ) ||
    !sameDigest(
      actual.source.sourceRequiredEffectEnforcerSetDigest,
      expected.source.sourceRequiredEffectEnforcerSetDigest
    ) ||
    !sameDigest(
      actual.requiredContainmentEnforcerSetDigest,
      expected.requiredContainmentEnforcerSetDigest
    )
  ) {
    fail("command_mismatch");
  }
}

function assertChainMatches(
  observation: RuntimeCompensationReceiptObservation,
  expected: RuntimeCompensationReceiptObservationCheckpoint | null
): void {
  if (observation.previous === null || expected === null) {
    if (observation.previous !== expected) fail("chain_mismatch");
    return;
  }
  if (
    observation.previous.cursor !== expected.cursor ||
    !sameDigest(observation.previous.observationDigest, expected.observationDigest)
  ) {
    fail("chain_mismatch");
  }
}

function validateObservationAuthority(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): RuntimeCompensationReceiptObservationAuthority {
  const authority = dataRecord(value, code);
  exactFields(authority, AUTHORITY_FIELDS, [], code);
  if (
    dataField(authority, "issuer", code) !== OBSERVATION_ISSUER ||
    dataField(authority, "audience", code) !== OBSERVATION_AUDIENCE ||
    dataField(authority, "capability", code) !== OBSERVATION_CAPABILITY
  ) {
    fail(code);
  }
  requiredKeyId(dataField(authority, "issuerKeyId", code), code);
  sha256(dataField(authority, "claimsDigest", code), code);
  nonNegativeInteger(dataField(authority, "issuedAtMs", code), code);
  positiveInteger(dataField(authority, "expiresAtMs", code), code);
  if (!decodeSignature(dataField(authority, "signature", code))) fail(code);
  return authority as unknown as RuntimeCompensationReceiptObservationAuthority;
}

function snapshotCheckpoint(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): RuntimeCompensationReceiptObservationCheckpoint | null {
  if (value === null) return null;
  const snapshot = snapshotJsonData(value, code);
  const checkpoint = dataRecord(snapshot, code);
  exactFields(checkpoint, ["cursor", "observationDigest"], [], code);
  return Object.freeze({
    cursor: safeCursor(dataField(checkpoint, "cursor", code), code),
    observationDigest: sha256(dataField(checkpoint, "observationDigest", code), code),
  });
}

function loadPrivateKey(value: unknown): KeyObject {
  if (typeof value !== "string" || !isAbsolute(value)) fail("private_key_unavailable");
  if (typeof fsConstants.O_NOFOLLOW !== "number" || typeof process.geteuid !== "function") {
    fail("private_key_unavailable");
  }
  let descriptor: number;
  try {
    descriptor = openSync(value, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch {
    fail("private_key_unavailable");
  }
  let bytes: Buffer | undefined;
  try {
    const stat = fstatSync(descriptor);
    const mode = stat.mode & 0o777;
    if (
      !stat.isFile() ||
      stat.uid !== process.geteuid() ||
      stat.nlink !== 1 ||
      (mode !== 0o400 && mode !== 0o600) ||
      (stat.mode & 0o7000) !== 0 ||
      stat.size < 1 ||
      stat.size > MAX_KEY_FILE_BYTES
    ) {
      fail("private_key_unavailable");
    }
    bytes = readFileSync(descriptor);
  } catch (error) {
    if (error instanceof RuntimeCompensationReceiptObservationError) throw error;
    fail("private_key_unavailable");
  } finally {
    try {
      closeSync(descriptor);
    } catch {
      fail("private_key_unavailable");
    }
  }
  try {
    const key = createPrivateKey(bytes);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
      fail("invalid_private_key");
    }
    return key;
  } catch (error) {
    if (error instanceof RuntimeCompensationReceiptObservationError) throw error;
    fail("invalid_private_key");
  } finally {
    bytes.fill(0);
  }
}

function loadPinnedPublicKeys(value: unknown): ReadonlyMap<string, PinnedKey> {
  const snapshot = snapshotJsonData(value, "invalid_public_key");
  if (!Array.isArray(snapshot) || snapshot.length < 1 || snapshot.length > MAX_PINNED_KEYS) {
    fail("invalid_public_key");
  }
  const result = new Map<string, PinnedKey>();
  for (const entry of snapshot) {
    const pin = dataRecord(entry, "invalid_public_key");
    exactFields(pin, ["issuerKeyId", "binding", "publicKeyPem"], [], "invalid_public_key");
    const issuerKeyId = requiredKeyId(
      dataField(pin, "issuerKeyId", "invalid_public_key"),
      "invalid_public_key"
    );
    if (result.has(issuerKeyId)) fail("invalid_public_key");
    const binding = snapshotBinding(
      dataField(pin, "binding", "invalid_public_key"),
      "invalid_public_key"
    );
    const publicKeyPem = dataField(pin, "publicKeyPem", "invalid_public_key");
    if (
      typeof publicKeyPem !== "string" ||
      Buffer.byteLength(publicKeyPem, "utf8") > MAX_PUBLIC_KEY_BYTES ||
      !publicKeyPem.trim().startsWith("-----BEGIN PUBLIC KEY-----") ||
      !publicKeyPem.trim().endsWith("-----END PUBLIC KEY-----") ||
      publicKeyPem.includes("PRIVATE KEY")
    ) {
      fail("invalid_public_key");
    }
    let key: KeyObject;
    try {
      key = createPublicKey(publicKeyPem);
    } catch {
      fail("invalid_public_key");
    }
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      fail("invalid_public_key");
    }
    result.set(issuerKeyId, Object.freeze({ key, binding }));
  }
  return result;
}

function snapshotBinding(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): RuntimeBinding {
  const snapshot = snapshotJsonData(value, code);
  const binding = dataRecord(snapshot, code);
  exactFields(binding, BINDING_FIELDS, [], code);
  for (const field of [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "sandboxId",
    "runtimePrincipalId",
  ] as const) {
    safeReference(dataField(binding, field, code), code);
  }
  positiveInteger(dataField(binding, "runtimeAssignmentGeneration", code), code);
  positiveInteger(dataField(binding, "sandboxGeneration", code), code);
  return deepFreeze(binding) as unknown as RuntimeBinding;
}

function sameBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
  return BINDING_FIELDS.every((field) => left[field] === right[field]);
}

function authorityPayload(statement: ObservationAuthorityStatement): Buffer {
  return Buffer.concat([
    Buffer.from(RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN, "utf8"),
    Buffer.from(canonicalRuntimeJson(statement), "utf8"),
  ]);
}

function decodeSignature(value: unknown): Buffer | null {
  if (typeof value !== "string" || !ED25519_SIGNATURE.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === 64 && decoded.toString("base64url") === value ? decoded : null;
  } catch {
    return null;
  }
}

function snapshotJsonData(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): unknown {
  try {
    return JSON.parse(canonicalRuntimeJson(value)) as unknown;
  } catch {
    fail(code);
  }
}

function dataRecord(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
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
  required: readonly string[],
  optional: readonly string[],
  code: RuntimeCompensationReceiptObservationErrorCode
): void {
  const allowed = new Set([...required, ...optional]);
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(record);
  } catch {
    fail(code);
  }
  if (
    keys.length < required.length ||
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    required.some((key) => !keys.includes(key))
  ) {
    fail(code);
  }
  try {
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
    }
  } catch (error) {
    if (error instanceof RuntimeCompensationReceiptObservationError) throw error;
    fail(code);
  }
}

function dataField(
  record: Record<string, unknown>,
  key: string,
  code: RuntimeCompensationReceiptObservationErrorCode
): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, key);
  } catch {
    fail(code);
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  return descriptor.value;
}

function optionalDataField(
  record: Record<string, unknown>,
  key: string,
  code: RuntimeCompensationReceiptObservationErrorCode
): unknown {
  let present: boolean;
  try {
    present = Object.hasOwn(record, key);
  } catch {
    fail(code);
  }
  if (!present) return undefined;
  const value = dataField(record, key, code);
  if (value === undefined) fail(code);
  return value;
}

function requiredKeyId(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): string {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) fail(code);
  return value;
}

function safeReference(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): string {
  if (typeof value !== "string" || value.trim() !== value || !SAFE_REFERENCE.test(value)) {
    fail(code);
  }
  return value;
}

function safeCursor(value: unknown, code: RuntimeCompensationReceiptObservationErrorCode): string {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    !SAFE_CURSOR_CHARACTERS.test(value) ||
    runtimeReceiptObservationCursorCodePoints(value) >
      RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS
  ) {
    fail(code);
  }
  return value;
}

function sha256(value: unknown, code: RuntimeCompensationReceiptObservationErrorCode): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(code);
  return value;
}

function nonNegativeInteger(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) fail(code);
  return value as number;
}

function positiveInteger(
  value: unknown,
  code: RuntimeCompensationReceiptObservationErrorCode
): number {
  const result = nonNegativeInteger(value, code);
  if (result < 1) fail(code);
  return result;
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  code: RuntimeCompensationReceiptObservationErrorCode
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail(code);
  }
  return value as number;
}

function safeAdd(
  left: number,
  right: number,
  code: RuntimeCompensationReceiptObservationErrorCode
): number {
  const value = left + right;
  if (!Number.isSafeInteger(value)) fail(code);
  return value;
}

function sampleClock(clock: () => number): number {
  try {
    return nonNegativeInteger(clock(), "invalid_input");
  } catch (error) {
    if (error instanceof RuntimeCompensationReceiptObservationError) throw error;
    fail("invalid_input");
  }
}

function sameDigest(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor) deepFreeze(descriptor.value);
  }
  return Object.freeze(value);
}

function fail(code: RuntimeCompensationReceiptObservationErrorCode): never {
  throw new RuntimeCompensationReceiptObservationError(code);
}
