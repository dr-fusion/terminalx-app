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
import type { RuntimeLifecycleCommand, RuntimeReceipt } from "./contracts";
import { canonicalRuntimeJson, digestRuntimeCommandClaims } from "./runtime-command-canonical";
import { snapshotRuntimeReceiptForCommand } from "./runtime-command-execution";
import {
  RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS,
  runtimeReceiptObservationCursorCodePoints,
} from "./runtime-receipt-observation-contract";

export { RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS } from "./runtime-receipt-observation-contract";

export const RUNTIME_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN =
  "terminalx/runtime-lifecycle-receipt-observation-claims/v1\0" as const;
export const RUNTIME_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN =
  "terminalx/runtime-lifecycle-receipt-observation-signature/v1\0" as const;
export const RUNTIME_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN =
  "terminalx/runtime-lifecycle-receipt-observation-receipt/v1\0" as const;

const OBSERVATION_KIND = "runtime.lifecycle-receipt-observed" as const;
const OBSERVATION_ISSUER = "runtime" as const;
const OBSERVATION_AUDIENCE = "terminalx-control-plane" as const;
const OBSERVATION_CAPABILITY = "runtime.lifecycle-receipt.observe" as const;
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
const COMMAND_REFERENCE_FIELDS = [
  "kind",
  "commandId",
  "claimsDigest",
  "binding",
  "runtimeAuthorizationGeneration",
  "requiredEffectEnforcerSetDigest",
  "agentRunId",
  "runPolicyRevision",
  "fromRunStateVersion",
  "toRunStateVersion",
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
const LIFECYCLE_KINDS = new Set<RuntimeLifecycleCommand["kind"]>([
  "run.start",
  "run.pause",
  "run.resume",
  "run.stop",
]);
const VERIFIED_RUNTIME_RECEIPT_OBSERVATION = Symbol(
  "terminalx.verified-runtime-receipt-observation"
);

export type RuntimeReceiptObservationErrorCode =
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

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeReceiptObservationErrorCode, string>> = {
  invalid_configuration: "Runtime receipt observation configuration is invalid",
  private_key_unavailable: "Runtime receipt observation private key is unavailable",
  invalid_private_key: "Runtime receipt observation private key is invalid",
  invalid_public_key: "Runtime receipt observation public key is invalid",
  invalid_input: "Runtime receipt observation input is invalid",
  invalid_command: "Runtime receipt observation command is invalid",
  invalid_receipt: "Runtime receipt observation receipt is invalid",
  invalid_observation: "Runtime receipt observation is invalid",
  command_mismatch: "Runtime receipt observation does not match the expected command",
  chain_mismatch: "Runtime receipt observation cursor chain does not match",
  untrusted_issuer: "Runtime receipt observation issuer is not trusted",
  invalid_signature: "Runtime receipt observation signature is invalid",
  expired: "Runtime receipt observation has expired",
  signing_failed: "Runtime receipt observation could not be signed",
};

/** Safe failure surface: provider values, key material, and crypto errors are never attached. */
export class RuntimeReceiptObservationError extends Error {
  constructor(readonly code: RuntimeReceiptObservationErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeReceiptObservationError";
  }
}

export interface RuntimeReceiptObservationCheckpoint {
  readonly cursor: string;
  readonly observationDigest: string;
}

export interface RuntimeLifecycleReceiptCommandReference {
  readonly kind: RuntimeLifecycleCommand["kind"];
  readonly commandId: string;
  readonly claimsDigest: string;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly requiredEffectEnforcerSetDigest: string;
  readonly agentRunId: string;
  readonly runPolicyRevision: number;
  readonly fromRunStateVersion: number;
  readonly toRunStateVersion: number;
}

export interface RuntimeReceiptObservationAuthority {
  readonly issuer: "runtime";
  readonly issuerKeyId: string;
  readonly audience: "terminalx-control-plane";
  readonly capability: "runtime.lifecycle-receipt.observe";
  readonly claimsDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly signature: string;
}

/**
 * A Runtime-authenticated observation from a private follow channel. It is not
 * a browser/public event and is only meaningful when checked against the exact
 * durable command and the prior durable cursor checkpoint.
 */
export interface RuntimeLifecycleReceiptObservation {
  readonly version: 1;
  readonly kind: "runtime.lifecycle-receipt-observed";
  readonly observationId: string;
  readonly cursor: string;
  readonly previous: RuntimeReceiptObservationCheckpoint | null;
  readonly observedAtMs: number;
  readonly command: RuntimeLifecycleReceiptCommandReference;
  readonly receipt: RuntimeReceipt;
  readonly receiptDigest: string;
  readonly authority: RuntimeReceiptObservationAuthority;
}

/** Only this module can construct the runtime brand after all checks succeed. */
export type VerifiedRuntimeLifecycleReceiptObservation = RuntimeLifecycleReceiptObservation & {
  readonly observationDigest: string;
  readonly [VERIFIED_RUNTIME_RECEIPT_OBSERVATION]: true;
};

/**
 * Runtime brand check for internal settlement seams. The symbol is module
 * private, so callers cannot manufacture a verified observation by casting a
 * provider object to the exported TypeScript type.
 */
export function isVerifiedRuntimeLifecycleReceiptObservation(
  value: unknown
): value is VerifiedRuntimeLifecycleReceiptObservation {
  if (typeof value !== "object" || value === null) return false;
  try {
    const brand = Object.getOwnPropertyDescriptor(value, VERIFIED_RUNTIME_RECEIPT_OBSERVATION);
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

export interface RuntimeReceiptObservationIssueInput {
  readonly observationId: string;
  readonly cursor: string;
  readonly previous: RuntimeReceiptObservationCheckpoint | null;
  readonly command: RuntimeLifecycleCommand;
  readonly receipt: RuntimeReceipt;
}

export interface CreateRuntimeReceiptObservationIssuerOptions {
  readonly issuerKeyId: string;
  /** The one Runtime binding this key is allowed to attest. */
  readonly binding: RuntimeBinding;
  /** Absolute, owned, non-symlink 0400/0600 Ed25519 PKCS#8 key file. */
  readonly privateKeyFile: string;
  readonly clock?: () => number;
  readonly observationTtlMs?: number;
}

export interface RuntimeReceiptObservationIssuer {
  issue(input: RuntimeReceiptObservationIssueInput): RuntimeLifecycleReceiptObservation;
}

export interface PinnedRuntimeReceiptObservationPublicKey {
  readonly issuerKeyId: string;
  /** The exact Runtime binding this public key is allowed to attest. */
  readonly binding: RuntimeBinding;
  /** Ed25519 SPKI PEM. Private-key and non-Ed25519 PEM are rejected. */
  readonly publicKeyPem: string;
}

export interface CreateRuntimeReceiptObservationVerifierOptions {
  readonly pinnedPublicKeys: readonly PinnedRuntimeReceiptObservationPublicKey[];
  readonly maximumObservationTtlMs?: number;
}

export interface RuntimeReceiptObservationVerificationInput {
  readonly observation: unknown;
  readonly command: RuntimeLifecycleCommand;
  readonly expectedPrevious: RuntimeReceiptObservationCheckpoint | null;
  readonly nowMs: number;
}

export interface RuntimeReceiptObservationVerifier {
  verify(
    input: RuntimeReceiptObservationVerificationInput
  ): VerifiedRuntimeLifecycleReceiptObservation;
}

interface ObservationAuthorityStatement {
  readonly version: 1;
  readonly issuer: "runtime";
  readonly issuerKeyId: string;
  readonly audience: "terminalx-control-plane";
  readonly capability: "runtime.lifecycle-receipt.observe";
  readonly claimsDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

interface PinnedKey {
  readonly key: KeyObject;
  readonly binding: RuntimeBinding;
}

/** Create a binding-scoped issuer for a private Runtime follow channel. */
export function createRuntimeReceiptObservationIssuer(
  unsafeOptions: CreateRuntimeReceiptObservationIssuerOptions
): RuntimeReceiptObservationIssuer {
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
    issue(unsafeInput: RuntimeReceiptObservationIssueInput): RuntimeLifecycleReceiptObservation {
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

      const command = snapshotLifecycleCommand(
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
      }) as RuntimeLifecycleReceiptObservation;
    },
  });
}

/** Create a fail-closed verifier whose trust roots are immutable binding-scoped SPKI pins. */
export function createRuntimeReceiptObservationVerifier(
  unsafeOptions: CreateRuntimeReceiptObservationVerifierOptions
): RuntimeReceiptObservationVerifier {
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
      unsafeInput: RuntimeReceiptObservationVerificationInput
    ): VerifiedRuntimeLifecycleReceiptObservation {
      const input = dataRecord(unsafeInput, "invalid_input");
      exactFields(
        input,
        ["observation", "command", "expectedPrevious", "nowMs"],
        [],
        "invalid_input"
      );
      const nowMs = nonNegativeInteger(dataField(input, "nowMs", "invalid_input"), "invalid_input");
      const command = snapshotLifecycleCommand(
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
      // Authenticate the detached JSON claim before classifying its receipt.
      // Otherwise a signed malformed proof is indistinguishable from an
      // unauthenticated malformed packet at the containment boundary.
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
      if (!pin || !sameBinding(pin.binding, expectedReference.binding)) {
        fail("untrusted_issuer");
      }
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

      // `invalid_receipt` from this point is authenticated by the exact pinned
      // Runtime key. Callers may therefore contain the binding without giving
      // arbitrary transport input a tenant-wide quarantine primitive.
      const receipt = snapshotReceipt(claimedReceipt, command, "invalid_receipt");

      const verified = {
        ...observation,
        receipt,
      } as RuntimeLifecycleReceiptObservation & Record<PropertyKey, unknown>;
      Object.defineProperty(verified, "observationDigest", {
        value: claimsDigest,
        enumerable: false,
        writable: false,
        configurable: false,
      });
      Object.defineProperty(verified, VERIFIED_RUNTIME_RECEIPT_OBSERVATION, {
        value: true,
        enumerable: false,
        writable: false,
        configurable: false,
      });
      return deepFreeze(verified) as unknown as VerifiedRuntimeLifecycleReceiptObservation;
    },
  });
}

/** Validate and digest the exact receipt representation for one lifecycle command. */
export function digestRuntimeLifecycleReceipt(
  receipt: RuntimeReceipt,
  command: RuntimeLifecycleCommand
): string {
  const commandSnapshot = snapshotLifecycleCommand(command, "invalid_command");
  return digestReceiptSnapshot(snapshotReceipt(receipt, commandSnapshot, "invalid_receipt"));
}

function snapshotObservation(value: unknown): RuntimeLifecycleReceiptObservation {
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
  return record as unknown as RuntimeLifecycleReceiptObservation;
}

function observationClaims(
  observation: RuntimeLifecycleReceiptObservation,
  receipt: RuntimeReceipt
): Omit<RuntimeLifecycleReceiptObservation, "authority"> {
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
      .update(RUNTIME_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN, "utf8")
      .update(canonicalRuntimeJson(value), "utf8")
      .digest("hex");
  } catch {
    fail("invalid_observation");
  }
}

function digestReceiptSnapshot(receipt: RuntimeReceipt): string {
  try {
    return createHash("sha256")
      .update(RUNTIME_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN, "utf8")
      .update(canonicalRuntimeJson(receipt), "utf8")
      .digest("hex");
  } catch {
    fail("invalid_receipt");
  }
}

function snapshotReceipt(
  value: unknown,
  command: RuntimeLifecycleCommand,
  code: RuntimeReceiptObservationErrorCode
): RuntimeReceipt {
  try {
    return snapshotRuntimeReceiptForCommand(value as RuntimeReceipt, command);
  } catch {
    fail(code);
  }
}

function snapshotLifecycleCommand(
  value: unknown,
  code: RuntimeReceiptObservationErrorCode
): RuntimeLifecycleCommand {
  const snapshot = snapshotJsonData(value, code);
  const command = dataRecord(snapshot, code);
  const kind = dataField(command, "kind", code);
  if (typeof kind !== "string" || !LIFECYCLE_KINDS.has(kind as RuntimeLifecycleCommand["kind"])) {
    fail(code);
  }
  safeReference(dataField(command, "commandId", code), code);
  const binding = snapshotBinding(dataField(command, "binding", code), code);
  safeReference(dataField(command, "projectCeilingRevision", code), code);
  positiveInteger(dataField(command, "runtimeAuthorizationGeneration", code), code);
  sha256(dataField(command, "requiredEffectEnforcerSetDigest", code), code);
  safeReference(dataField(command, "causationId", code), code);
  validateCommandActor(dataField(command, "actor", code), code);
  const commandIssuedAtMs = nonNegativeInteger(dataField(command, "issuedAtMs", code), code);
  const commandDeadlineAtMs = positiveInteger(dataField(command, "deadlineAtMs", code), code);
  if (commandDeadlineAtMs <= commandIssuedAtMs) fail(code);
  safeReference(dataField(command, "agentRunId", code), code);
  positiveInteger(dataField(command, "runPolicyRevision", code), code);
  const from = positiveInteger(dataField(command, "fromRunStateVersion", code), code);
  const to = positiveInteger(dataField(command, "toRunStateVersion", code), code);
  if (to !== from + 1) fail(code);
  const authority = dataRecord(dataField(command, "authority", code), code);
  exactFields(authority, COMMAND_AUTHORITY_FIELDS, [], code);
  if (
    dataField(authority, "issuer", code) !== "team-session" ||
    dataField(authority, "audience", code) !== "runtime" ||
    dataField(authority, "capability", code) !== kind
  ) {
    fail(code);
  }
  requiredKeyId(dataField(authority, "issuerKeyId", code), code);
  const authorityIssuedAtMs = nonNegativeInteger(dataField(authority, "issuedAtMs", code), code);
  const authorityExpiresAtMs = positiveInteger(dataField(authority, "expiresAtMs", code), code);
  if (
    authorityIssuedAtMs !== commandIssuedAtMs ||
    authorityExpiresAtMs <= authorityIssuedAtMs ||
    authorityExpiresAtMs > commandDeadlineAtMs
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
  // Retain the checked binding type on the otherwise fully snapshotted command.
  void binding;
  return command as unknown as RuntimeLifecycleCommand;
}

function validateCommandActor(value: unknown, code: RuntimeReceiptObservationErrorCode): void {
  const actor = dataRecord(value, code);
  exactFields(actor, ["kind", "actorRef"], [], code);
  const kind = dataField(actor, "kind", code);
  if (kind !== "human" && kind !== "system") fail(code);
  safeReference(dataField(actor, "actorRef", code), code);
}

function referenceForCommand(
  command: RuntimeLifecycleCommand
): RuntimeLifecycleReceiptCommandReference {
  let claimsDigest: string;
  try {
    claimsDigest = digestRuntimeCommandClaims(command);
  } catch {
    fail("invalid_command");
  }
  return deepFreeze({
    kind: command.kind,
    commandId: command.commandId,
    claimsDigest,
    binding: snapshotBinding(command.binding, "invalid_command"),
    runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest: sha256(
      command.requiredEffectEnforcerSetDigest,
      "invalid_command"
    ),
    agentRunId: command.agentRunId,
    runPolicyRevision: command.runPolicyRevision,
    fromRunStateVersion: command.fromRunStateVersion,
    toRunStateVersion: command.toRunStateVersion,
  }) as RuntimeLifecycleReceiptCommandReference;
}

function validateCommandReference(
  value: unknown,
  code: RuntimeReceiptObservationErrorCode
): RuntimeLifecycleReceiptCommandReference {
  const reference = dataRecord(value, code);
  exactFields(reference, COMMAND_REFERENCE_FIELDS, [], code);
  const kind = dataField(reference, "kind", code);
  if (typeof kind !== "string" || !LIFECYCLE_KINDS.has(kind as RuntimeLifecycleCommand["kind"])) {
    fail(code);
  }
  safeReference(dataField(reference, "commandId", code), code);
  sha256(dataField(reference, "claimsDigest", code), code);
  snapshotBinding(dataField(reference, "binding", code), code);
  positiveInteger(dataField(reference, "runtimeAuthorizationGeneration", code), code);
  sha256(dataField(reference, "requiredEffectEnforcerSetDigest", code), code);
  safeReference(dataField(reference, "agentRunId", code), code);
  positiveInteger(dataField(reference, "runPolicyRevision", code), code);
  const from = positiveInteger(dataField(reference, "fromRunStateVersion", code), code);
  if (positiveInteger(dataField(reference, "toRunStateVersion", code), code) !== from + 1) {
    fail(code);
  }
  return reference as unknown as RuntimeLifecycleReceiptCommandReference;
}

function assertReferenceMatches(
  actual: RuntimeLifecycleReceiptCommandReference,
  expected: RuntimeLifecycleReceiptCommandReference
): void {
  if (
    actual.kind !== expected.kind ||
    actual.commandId !== expected.commandId ||
    !sameDigest(actual.claimsDigest, expected.claimsDigest) ||
    !sameBinding(actual.binding, expected.binding) ||
    actual.runtimeAuthorizationGeneration !== expected.runtimeAuthorizationGeneration ||
    !sameDigest(actual.requiredEffectEnforcerSetDigest, expected.requiredEffectEnforcerSetDigest) ||
    actual.agentRunId !== expected.agentRunId ||
    actual.runPolicyRevision !== expected.runPolicyRevision ||
    actual.fromRunStateVersion !== expected.fromRunStateVersion ||
    actual.toRunStateVersion !== expected.toRunStateVersion
  ) {
    fail("command_mismatch");
  }
}

function assertChainMatches(
  observation: RuntimeLifecycleReceiptObservation,
  expected: RuntimeReceiptObservationCheckpoint | null
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
  code: RuntimeReceiptObservationErrorCode
): RuntimeReceiptObservationAuthority {
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
  return authority as unknown as RuntimeReceiptObservationAuthority;
}

function snapshotCheckpoint(
  value: unknown,
  code: RuntimeReceiptObservationErrorCode
): RuntimeReceiptObservationCheckpoint | null {
  if (value === null) return null;
  const snapshot = snapshotJsonData(value, code);
  const checkpoint = dataRecord(snapshot, code);
  exactFields(checkpoint, ["cursor", "observationDigest"], [], code);
  const result = {
    cursor: safeCursor(dataField(checkpoint, "cursor", code), code),
    observationDigest: sha256(dataField(checkpoint, "observationDigest", code), code),
  };
  return Object.freeze(result);
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
    if (error instanceof RuntimeReceiptObservationError) throw error;
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
    if (error instanceof RuntimeReceiptObservationError) throw error;
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

function snapshotBinding(value: unknown, code: RuntimeReceiptObservationErrorCode): RuntimeBinding {
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
    Buffer.from(RUNTIME_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN, "utf8"),
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

/** Clone data without invoking getters, accepting prototypes, or retaining caller mutability. */
function snapshotJsonData(value: unknown, code: RuntimeReceiptObservationErrorCode): unknown {
  try {
    return JSON.parse(canonicalRuntimeJson(value)) as unknown;
  } catch {
    fail(code);
  }
}

function dataRecord(
  value: unknown,
  code: RuntimeReceiptObservationErrorCode
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
  code: RuntimeReceiptObservationErrorCode
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
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  }
}

function dataField(
  record: Record<string, unknown>,
  key: string,
  code: RuntimeReceiptObservationErrorCode
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
  code: RuntimeReceiptObservationErrorCode
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

function requiredKeyId(value: unknown, code: RuntimeReceiptObservationErrorCode): string {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) fail(code);
  return value;
}

function safeReference(value: unknown, code: RuntimeReceiptObservationErrorCode): string {
  if (typeof value !== "string" || value.trim() !== value || !SAFE_REFERENCE.test(value)) {
    fail(code);
  }
  return value;
}

function safeCursor(value: unknown, code: RuntimeReceiptObservationErrorCode): string {
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

function sha256(value: unknown, code: RuntimeReceiptObservationErrorCode): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(code);
  return value;
}

function nonNegativeInteger(value: unknown, code: RuntimeReceiptObservationErrorCode): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) fail(code);
  return value as number;
}

function positiveInteger(value: unknown, code: RuntimeReceiptObservationErrorCode): number {
  const result = nonNegativeInteger(value, code);
  if (result < 1) fail(code);
  return result;
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  code: RuntimeReceiptObservationErrorCode
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail(code);
  }
  return value as number;
}

function safeAdd(left: number, right: number, code: RuntimeReceiptObservationErrorCode): number {
  const value = left + right;
  if (!Number.isSafeInteger(value)) fail(code);
  return value;
}

function sampleClock(clock: () => number): number {
  try {
    return nonNegativeInteger(clock(), "invalid_input");
  } catch (error) {
    if (error instanceof RuntimeReceiptObservationError) throw error;
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

function fail(code: RuntimeReceiptObservationErrorCode): never {
  throw new RuntimeReceiptObservationError(code);
}
