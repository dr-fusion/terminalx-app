import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { TextDecoder, types as utilTypes } from "node:util";
import type { RuntimeBinding } from "../team-sessions/contracts";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import { readTrustedConfigurationFile } from "./runtime-trusted-configuration-file";

export const RUNTIME_OBSERVATION_KEY_DESCRIPTOR_DIGEST_DOMAIN =
  "terminalx/runtime-observation-key-descriptor/v1\0" as const;
export const RUNTIME_OBSERVATION_KEY_ATTESTATION_SIGNATURE_DOMAIN =
  "terminalx/runtime-observation-key-attestation-signature/v1\0" as const;
export const RUNTIME_OBSERVATION_KEY_ATTESTATION_DIGEST_DOMAIN =
  "terminalx/runtime-observation-key-attestation/v1\0" as const;

const DESCRIPTOR_KIND = "runtime.observation-key-descriptor" as const;
const ATTESTATION_KIND = "runtime.observation-key-attestation" as const;
const REGISTRY_KIND = "runtime.observation-key-registry" as const;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const MAX_AUTHORITY_KEYS = 32;
const MAX_REGISTRATIONS = 256;
const MAX_REGISTRY_FILE_BYTES = 1024 * 1024;
const MAX_GRAPH_DEPTH = 32;
const MAX_GRAPH_NODES = 20_000;
const MAX_GRAPH_FIELDS = 1_000;
const MAX_GRAPH_STRING_BYTES = 1024 * 1024;
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
const DESCRIPTOR_FIELDS = [
  "version",
  "kind",
  "binding",
  "runtimeAuthorizationGeneration",
  "issuerKeyId",
  "publicKeySpkiDigest",
  "adapterIdentityRef",
  "adapterConfigurationRef",
  "issuedAtMs",
] as const;
const ATTESTATION_FIELDS = [
  "version",
  "kind",
  "authorityKeyId",
  "descriptorDigest",
  "signature",
] as const;
const SIGNED_REGISTRATION_FIELDS = ["descriptor", "publicKeySpkiPem", "attestation"] as const;
const DYNAMIC_SOURCE_OPTIONS_FIELDS = ["pinnedAuthorityPublicKeys", "registrationSource"] as const;
const SIGNED_REGISTRATION_SOURCE_FIELDS = ["get"] as const;
const VERIFIED_RUNTIME_OBSERVATION_KEY_REGISTRATION = Symbol(
  "terminalx.verified-runtime-observation-key-registration"
);
const AUTHENTICATED_RUNTIME_OBSERVATION_KEY_REGISTRATIONS = new WeakSet<object>();

export type RuntimeObservationKeySourceErrorCode =
  | "invalid_configuration"
  | "source_unavailable"
  | "invalid_source"
  | "invalid_input"
  | "invalid_descriptor"
  | "invalid_attestation"
  | "invalid_public_key"
  | "untrusted_authority"
  | "digest_mismatch"
  | "invalid_signature"
  | "duplicate_registration"
  | "key_reuse";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeObservationKeySourceErrorCode, string>> = {
  invalid_configuration: "Runtime observation-key source configuration is invalid",
  source_unavailable: "Runtime observation-key source is unavailable",
  invalid_source: "Runtime observation-key source data is invalid",
  invalid_input: "Runtime observation-key lookup is invalid",
  invalid_descriptor: "Runtime observation-key descriptor is invalid",
  invalid_attestation: "Runtime observation-key attestation is invalid",
  invalid_public_key: "Runtime observation public key is invalid",
  untrusted_authority: "Runtime observation-key authority is not trusted",
  digest_mismatch: "Runtime observation-key digest does not match",
  invalid_signature: "Runtime observation-key attestation signature is invalid",
  duplicate_registration: "Runtime observation-key registration is duplicated",
  key_reuse: "Runtime observation key is reused across incompatible registrations",
};

/** Safe failure surface: paths, key bytes, signatures, and provider values are never attached. */
export class RuntimeObservationKeySourceError extends Error {
  constructor(readonly code: RuntimeObservationKeySourceErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeObservationKeySourceError";
  }
}

/** Immutable claims signed by the separately pinned observation-key authority. */
export interface RuntimeObservationKeyDescriptor {
  readonly version: 1;
  readonly kind: "runtime.observation-key-descriptor";
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly issuerKeyId: string;
  /** SHA-256 of canonical Ed25519 SubjectPublicKeyInfo DER. */
  readonly publicKeySpkiDigest: string;
  readonly adapterIdentityRef: string;
  readonly adapterConfigurationRef: string;
  readonly issuedAtMs: number;
}

export interface RuntimeObservationKeyAttestation {
  readonly version: 1;
  readonly kind: "runtime.observation-key-attestation";
  readonly authorityKeyId: string;
  readonly descriptorDigest: string;
  readonly signature: string;
}

export interface SignedRuntimeObservationKeyRegistration {
  readonly descriptor: RuntimeObservationKeyDescriptor;
  /** Canonical Ed25519 SubjectPublicKeyInfo PEM, including its final newline. */
  readonly publicKeySpkiPem: string;
  readonly attestation: RuntimeObservationKeyAttestation;
}

export interface PinnedRuntimeObservationKeyAuthorityPublicKey {
  readonly authorityKeyId: string;
  /** Canonical Ed25519 SubjectPublicKeyInfo PEM. Private-key PEM is rejected. */
  readonly publicKeySpkiPem: string;
}

/** Detached result safe to pass into the durable receipt-follow registration seam. */
export interface RuntimeObservationKeyRegistration {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly issuerKeyId: string;
  readonly publicKeySpkiPem: string;
  readonly publicKeySpkiDigest: string;
  readonly descriptorDigest: string;
  readonly attestationDigest: string;
  readonly authorityKeyId: string;
  readonly adapterIdentityRef: string;
  readonly adapterConfigurationRef: string;
  readonly issuedAtMs: number;
}

export type AuthenticatedRuntimeObservationKeyRegistration = RuntimeObservationKeyRegistration & {
  readonly [VERIFIED_RUNTIME_OBSERVATION_KEY_REGISTRATION]: true;
};

export interface RuntimeObservationKeyRegistrationVerifier {
  verify(unsafeRegistration: unknown): AuthenticatedRuntimeObservationKeyRegistration;
}

export interface CreateRuntimeObservationKeyRegistrationVerifierOptions {
  readonly pinnedAuthorityPublicKeys: readonly PinnedRuntimeObservationKeyAuthorityPublicKey[];
}

export interface RuntimeObservationKeyLookup {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
}

/** Exact historical lookup; absence is represented only by `null`. */
export interface RuntimeObservationKeySource {
  get(
    unsafeLookup: RuntimeObservationKeyLookup
  ): AuthenticatedRuntimeObservationKeyRegistration | null;
}

/**
 * Synchronous exact-lookup seam for registrations created after process start.
 * Implementations return one signed portable registration, never bulk state.
 */
export interface SignedRuntimeObservationKeyRegistrationSource {
  readonly get: (lookup: RuntimeObservationKeyLookup) => unknown | null;
}

export interface CreateRuntimeObservationKeySourceWithRegistrationSourceOptions extends CreateRuntimeObservationKeyRegistrationVerifierOptions {
  readonly registrationSource: SignedRuntimeObservationKeyRegistrationSource;
}

export interface CreatePinnedRuntimeObservationKeySourceOptions extends CreateRuntimeObservationKeyRegistrationVerifierOptions {
  readonly registrations: readonly SignedRuntimeObservationKeyRegistration[];
}

export interface LoadPinnedRuntimeObservationKeySourceFromFileOptions extends CreateRuntimeObservationKeyRegistrationVerifierOptions {
  /**
   * Absolute canonical private operator configuration root (0500/0700).
   * This explicit trust boundary must not be an arbitrary browser workspace.
   */
  readonly trustedConfigurationRoot: string;
  /** Absolute canonical 0400/0600 JSON path strictly below the trust root. */
  readonly filePath: string;
}

interface CanonicalPublicKey {
  readonly key: KeyObject;
  readonly pem: string;
  readonly digest: string;
}

interface PinnedAuthorityKey extends CanonicalPublicKey {
  readonly authorityKeyId: string;
}

interface RuntimeObservationKeyAttestationClaims {
  readonly version: 1;
  readonly kind: "runtime.observation-key-attestation";
  readonly authorityKeyId: string;
  readonly descriptorDigest: string;
}

interface GraphState {
  readonly ancestors: Set<object>;
  remainingNodes: number;
  remainingStringBytes: number;
}

export function isAuthenticatedRuntimeObservationKeyRegistration(
  value: unknown
): value is AuthenticatedRuntimeObservationKeyRegistration {
  if (typeof value !== "object" || value === null || utilTypes.isProxy(value)) return false;
  try {
    const brand = Object.getOwnPropertyDescriptor(
      value,
      VERIFIED_RUNTIME_OBSERVATION_KEY_REGISTRATION
    );
    const descriptorDigest = Object.getOwnPropertyDescriptor(value, "descriptorDigest");
    const attestationDigest = Object.getOwnPropertyDescriptor(value, "attestationDigest");
    return (
      Object.isFrozen(value) &&
      AUTHENTICATED_RUNTIME_OBSERVATION_KEY_REGISTRATIONS.has(value) &&
      brand?.value === true &&
      brand.enumerable === false &&
      brand.writable === false &&
      brand.configurable === false &&
      typeof descriptorDigest?.value === "string" &&
      SHA256.test(descriptorDigest.value) &&
      typeof attestationDigest?.value === "string" &&
      SHA256.test(attestationDigest.value)
    );
  } catch {
    return false;
  }
}

/** Strictly snapshot the portable descriptor without retaining caller-owned references. */
export function snapshotRuntimeObservationKeyDescriptor(
  value: unknown
): RuntimeObservationKeyDescriptor {
  const snapshot = snapshotJsonData(value, "invalid_descriptor");
  const descriptor = dataRecord(snapshot, "invalid_descriptor");
  exactFields(descriptor, DESCRIPTOR_FIELDS, "invalid_descriptor");
  if (
    dataField(descriptor, "version", "invalid_descriptor") !== 1 ||
    dataField(descriptor, "kind", "invalid_descriptor") !== DESCRIPTOR_KIND
  ) {
    fail("invalid_descriptor");
  }
  return deepFreeze({
    version: 1 as const,
    kind: DESCRIPTOR_KIND,
    binding: snapshotBinding(dataField(descriptor, "binding", "invalid_descriptor")),
    runtimeAuthorizationGeneration: positiveInteger(
      dataField(descriptor, "runtimeAuthorizationGeneration", "invalid_descriptor"),
      "invalid_descriptor"
    ),
    issuerKeyId: requiredKeyId(
      dataField(descriptor, "issuerKeyId", "invalid_descriptor"),
      "invalid_descriptor"
    ),
    publicKeySpkiDigest: sha256(
      dataField(descriptor, "publicKeySpkiDigest", "invalid_descriptor"),
      "invalid_descriptor"
    ),
    adapterIdentityRef: safeReference(
      dataField(descriptor, "adapterIdentityRef", "invalid_descriptor"),
      "invalid_descriptor"
    ),
    adapterConfigurationRef: safeReference(
      dataField(descriptor, "adapterConfigurationRef", "invalid_descriptor"),
      "invalid_descriptor"
    ),
    issuedAtMs: nonNegativeInteger(
      dataField(descriptor, "issuedAtMs", "invalid_descriptor"),
      "invalid_descriptor"
    ),
  });
}

/** Domain-separated canonical digest of exactly one strict descriptor. */
export function digestRuntimeObservationKeyDescriptor(value: unknown): string {
  const descriptor = snapshotRuntimeObservationKeyDescriptor(value);
  return domainDigest(RUNTIME_OBSERVATION_KEY_DESCRIPTOR_DIGEST_DOMAIN, descriptor);
}

/** Strictly snapshot the detached authority attestation. */
export function snapshotRuntimeObservationKeyAttestation(
  value: unknown
): RuntimeObservationKeyAttestation {
  const snapshot = snapshotJsonData(value, "invalid_attestation");
  const attestation = dataRecord(snapshot, "invalid_attestation");
  exactFields(attestation, ATTESTATION_FIELDS, "invalid_attestation");
  if (
    dataField(attestation, "version", "invalid_attestation") !== 1 ||
    dataField(attestation, "kind", "invalid_attestation") !== ATTESTATION_KIND
  ) {
    fail("invalid_attestation");
  }
  return Object.freeze({
    version: 1 as const,
    kind: ATTESTATION_KIND,
    authorityKeyId: requiredKeyId(
      dataField(attestation, "authorityKeyId", "invalid_attestation"),
      "invalid_attestation"
    ),
    descriptorDigest: sha256(
      dataField(attestation, "descriptorDigest", "invalid_attestation"),
      "invalid_attestation"
    ),
    signature: ed25519Signature(
      dataField(attestation, "signature", "invalid_attestation"),
      "invalid_attestation"
    ),
  });
}

/** Stable digest of the complete signed attestation for durable audit references. */
export function digestRuntimeObservationKeyAttestation(value: unknown): string {
  const attestation = snapshotRuntimeObservationKeyAttestation(value);
  return domainDigest(RUNTIME_OBSERVATION_KEY_ATTESTATION_DIGEST_DOMAIN, attestation);
}

/** Create a verifier backed exclusively by immutable Ed25519 authority pins. */
export function createRuntimeObservationKeyRegistrationVerifier(
  unsafeOptions: CreateRuntimeObservationKeyRegistrationVerifierOptions
): RuntimeObservationKeyRegistrationVerifier {
  const options = dataRecord(unsafeOptions, "invalid_configuration");
  exactFields(options, ["pinnedAuthorityPublicKeys"], "invalid_configuration");
  const authorityKeys = loadPinnedAuthorityKeys(
    dataField(options, "pinnedAuthorityPublicKeys", "invalid_configuration")
  );

  return buildRuntimeObservationKeyRegistrationVerifier(authorityKeys);
}

function buildRuntimeObservationKeyRegistrationVerifier(
  authorityKeys: ReadonlyMap<string, PinnedAuthorityKey>
): RuntimeObservationKeyRegistrationVerifier {
  return Object.freeze({
    verify(unsafeRegistration: unknown): AuthenticatedRuntimeObservationKeyRegistration {
      const snapshot = snapshotJsonData(unsafeRegistration, "invalid_source");
      const registration = dataRecord(snapshot, "invalid_source");
      exactFields(registration, SIGNED_REGISTRATION_FIELDS, "invalid_source");
      const descriptor = snapshotRuntimeObservationKeyDescriptor(
        dataField(registration, "descriptor", "invalid_source")
      );
      const publicKey = canonicalEd25519PublicKey(
        dataField(registration, "publicKeySpkiPem", "invalid_public_key"),
        "invalid_public_key"
      );
      if (!sameDigest(descriptor.publicKeySpkiDigest, publicKey.digest)) {
        fail("digest_mismatch");
      }

      const descriptorDigest = digestRuntimeObservationKeyDescriptor(descriptor);
      const attestation = snapshotRuntimeObservationKeyAttestation(
        dataField(registration, "attestation", "invalid_source")
      );
      if (!sameDigest(attestation.descriptorDigest, descriptorDigest)) {
        fail("digest_mismatch");
      }
      const authorityKey = authorityKeys.get(attestation.authorityKeyId);
      if (!authorityKey) fail("untrusted_authority");
      const signature = decodeSignature(attestation.signature);
      if (!signature) fail("invalid_signature");
      let valid = false;
      try {
        valid = verifyEd25519(
          null,
          attestationPayload(attestationClaims(attestation)),
          authorityKey.key,
          signature
        );
      } catch {
        fail("invalid_signature");
      }
      if (!valid) fail("invalid_signature");

      const result = {
        binding: descriptor.binding,
        runtimeAuthorizationGeneration: descriptor.runtimeAuthorizationGeneration,
        issuerKeyId: descriptor.issuerKeyId,
        publicKeySpkiPem: publicKey.pem,
        publicKeySpkiDigest: publicKey.digest,
        descriptorDigest,
        attestationDigest: digestRuntimeObservationKeyAttestation(attestation),
        authorityKeyId: attestation.authorityKeyId,
        adapterIdentityRef: descriptor.adapterIdentityRef,
        adapterConfigurationRef: descriptor.adapterConfigurationRef,
        issuedAtMs: descriptor.issuedAtMs,
      } as RuntimeObservationKeyRegistration & Record<PropertyKey, unknown>;
      assertSeparateObservationKeyRole(result as RuntimeObservationKeyRegistration, authorityKeys);
      Object.defineProperty(result, VERIFIED_RUNTIME_OBSERVATION_KEY_REGISTRATION, {
        value: true,
        enumerable: false,
        writable: false,
        configurable: false,
      });
      AUTHENTICATED_RUNTIME_OBSERVATION_KEY_REGISTRATIONS.add(result);
      return deepFreeze(result) as unknown as AuthenticatedRuntimeObservationKeyRegistration;
    },
  });
}

/** Build an immutable exact-key registry after verifying every signed descriptor. */
export function createPinnedRuntimeObservationKeySource(
  unsafeOptions: CreatePinnedRuntimeObservationKeySourceOptions
): RuntimeObservationKeySource {
  const options = dataRecord(unsafeOptions, "invalid_configuration");
  exactFields(options, ["pinnedAuthorityPublicKeys", "registrations"], "invalid_configuration");
  const authorityKeys = loadPinnedAuthorityKeys(
    dataField(options, "pinnedAuthorityPublicKeys", "invalid_configuration")
  );
  const verifier = buildRuntimeObservationKeyRegistrationVerifier(authorityKeys);
  const unsafeRegistrations = boundedArray(
    dataField(options, "registrations", "invalid_configuration"),
    1,
    MAX_REGISTRATIONS,
    "invalid_configuration"
  );
  const registrations = new Map<string, AuthenticatedRuntimeObservationKeyRegistration>();
  const publicKeyLookups = new Map<string, string>();
  const issuerLookups = new Map<string, string>();
  const descriptorDigests = new Set<string>();
  const attestationDigests = new Set<string>();

  for (const unsafeRegistration of unsafeRegistrations) {
    const registration = verifier.verify(unsafeRegistration);
    const key = lookupKey(registration);
    if (
      registrations.has(key) ||
      descriptorDigests.has(registration.descriptorDigest) ||
      attestationDigests.has(registration.attestationDigest)
    ) {
      fail("duplicate_registration");
    }
    const publicKeyLookup = publicKeyLookups.get(registration.publicKeySpkiDigest);
    const issuerLookup = issuerLookups.get(registration.issuerKeyId);
    if (
      (publicKeyLookup !== undefined && publicKeyLookup !== key) ||
      (issuerLookup !== undefined && issuerLookup !== key)
    ) {
      fail("key_reuse");
    }
    registrations.set(key, registration);
    publicKeyLookups.set(registration.publicKeySpkiDigest, key);
    issuerLookups.set(registration.issuerKeyId, key);
    descriptorDigests.add(registration.descriptorDigest);
    attestationDigests.add(registration.attestationDigest);
  }

  return Object.freeze({
    get(unsafeLookup: RuntimeObservationKeyLookup) {
      const lookup = snapshotLookup(unsafeLookup);
      return registrations.get(lookupKey(lookup)) ?? null;
    },
  });
}

/**
 * Build an exact dynamic source for per-Sandbox keys provisioned after process
 * construction. No result is cached: every lookup re-fetches and re-verifies
 * one signed registration through the immutable authority pins.
 */
export function createRuntimeObservationKeySourceWithRegistrationSource(
  unsafeOptions: CreateRuntimeObservationKeySourceWithRegistrationSourceOptions
): RuntimeObservationKeySource {
  const options = dataRecord(unsafeOptions, "invalid_configuration");
  exactFields(options, DYNAMIC_SOURCE_OPTIONS_FIELDS, "invalid_configuration");
  const authorityKeys = loadPinnedAuthorityKeys(
    dataField(options, "pinnedAuthorityPublicKeys", "invalid_configuration")
  );
  const verifier = buildRuntimeObservationKeyRegistrationVerifier(authorityKeys);
  const source = dataRecord(
    dataField(options, "registrationSource", "invalid_configuration"),
    "invalid_configuration"
  );
  exactFields(source, SIGNED_REGISTRATION_SOURCE_FIELDS, "invalid_configuration");
  const get = dataField(source, "get", "invalid_configuration");
  if (typeof get !== "function" || utilTypes.isProxy(get)) fail("invalid_configuration");
  const capturedGet = get as SignedRuntimeObservationKeyRegistrationSource["get"];

  return Object.freeze({
    get(unsafeLookup: RuntimeObservationKeyLookup) {
      const lookup = snapshotLookup(unsafeLookup);
      let unsafeRegistration: unknown;
      try {
        unsafeRegistration = Reflect.apply(capturedGet, undefined, [lookup]);
      } catch {
        return null;
      }
      if (unsafeRegistration === null) return null;
      if (hasThenableShape(unsafeRegistration)) {
        suppressNativePromiseRejection(unsafeRegistration);
        return null;
      }

      try {
        const registration = verifier.verify(unsafeRegistration);
        if (lookupKey(registration) !== lookupKey(lookup)) return null;
        return registration;
      } catch {
        return null;
      }
    },
  });
}

/** Load a canonical signed registry from a strict owner-controlled production file. */
export function loadPinnedRuntimeObservationKeySourceFromFile(
  unsafeOptions: LoadPinnedRuntimeObservationKeySourceFromFileOptions
): RuntimeObservationKeySource {
  const options = dataRecord(unsafeOptions, "invalid_configuration");
  exactFields(
    options,
    ["trustedConfigurationRoot", "filePath", "pinnedAuthorityPublicKeys"],
    "invalid_configuration"
  );
  const trustedConfigurationRoot = dataField(
    options,
    "trustedConfigurationRoot",
    "invalid_configuration"
  );
  const filePath = dataField(options, "filePath", "invalid_configuration");
  const parsed = readStrictRegistryFile(trustedConfigurationRoot, filePath);
  const registry = dataRecord(parsed, "invalid_source");
  exactFields(registry, ["version", "kind", "registrations"], "invalid_source");
  if (
    dataField(registry, "version", "invalid_source") !== 1 ||
    dataField(registry, "kind", "invalid_source") !== REGISTRY_KIND
  ) {
    fail("invalid_source");
  }
  return createPinnedRuntimeObservationKeySource({
    pinnedAuthorityPublicKeys: boundedArray(
      dataField(options, "pinnedAuthorityPublicKeys", "invalid_configuration"),
      1,
      MAX_AUTHORITY_KEYS,
      "invalid_configuration"
    ) as readonly PinnedRuntimeObservationKeyAuthorityPublicKey[],
    registrations: boundedArray(
      dataField(registry, "registrations", "invalid_source"),
      1,
      MAX_REGISTRATIONS,
      "invalid_source"
    ) as readonly SignedRuntimeObservationKeyRegistration[],
  });
}

function loadPinnedAuthorityKeys(value: unknown): ReadonlyMap<string, PinnedAuthorityKey> {
  const pins = boundedArray(value, 1, MAX_AUTHORITY_KEYS, "invalid_configuration");
  const result = new Map<string, PinnedAuthorityKey>();
  const publicKeyDigests = new Set<string>();
  for (const unsafePin of pins) {
    const pin = dataRecord(unsafePin, "invalid_configuration");
    exactFields(pin, ["authorityKeyId", "publicKeySpkiPem"], "invalid_configuration");
    const authorityKeyId = requiredKeyId(
      dataField(pin, "authorityKeyId", "invalid_configuration"),
      "invalid_configuration"
    );
    const publicKey = canonicalEd25519PublicKey(
      dataField(pin, "publicKeySpkiPem", "invalid_public_key"),
      "invalid_public_key"
    );
    if (result.has(authorityKeyId) || publicKeyDigests.has(publicKey.digest)) {
      fail("invalid_configuration");
    }
    result.set(authorityKeyId, Object.freeze({ authorityKeyId, ...publicKey }));
    publicKeyDigests.add(publicKey.digest);
  }
  return result;
}

function assertSeparateObservationKeyRole(
  registration: RuntimeObservationKeyRegistration,
  authorityKeys: ReadonlyMap<string, PinnedAuthorityKey>
): void {
  for (const authorityKey of authorityKeys.values()) {
    if (
      authorityKey.authorityKeyId === registration.issuerKeyId ||
      sameDigest(authorityKey.digest, registration.publicKeySpkiDigest)
    ) {
      fail("key_reuse");
    }
  }
}

function snapshotLookup(value: unknown): RuntimeObservationKeyLookup {
  const snapshot = snapshotJsonData(value, "invalid_input");
  const lookup = dataRecord(snapshot, "invalid_input");
  exactFields(lookup, ["binding", "runtimeAuthorizationGeneration"], "invalid_input");
  return deepFreeze({
    binding: snapshotBinding(dataField(lookup, "binding", "invalid_input"), "invalid_input"),
    runtimeAuthorizationGeneration: positiveInteger(
      dataField(lookup, "runtimeAuthorizationGeneration", "invalid_input"),
      "invalid_input"
    ),
  });
}

function snapshotBinding(
  value: unknown,
  code: RuntimeObservationKeySourceErrorCode = "invalid_descriptor"
): RuntimeBinding {
  const snapshot = snapshotJsonData(value, code);
  const binding = dataRecord(snapshot, code);
  exactFields(binding, BINDING_FIELDS, code);
  return deepFreeze({
    teamId: safeReference(dataField(binding, "teamId", code), code),
    projectId: safeReference(dataField(binding, "projectId", code), code),
    sessionId: safeReference(dataField(binding, "sessionId", code), code),
    runtimeAssignmentId: safeReference(dataField(binding, "runtimeAssignmentId", code), code),
    runtimeAssignmentGeneration: positiveInteger(
      dataField(binding, "runtimeAssignmentGeneration", code),
      code
    ),
    sandboxId: safeReference(dataField(binding, "sandboxId", code), code),
    sandboxGeneration: positiveInteger(dataField(binding, "sandboxGeneration", code), code),
    runtimePrincipalId: safeReference(dataField(binding, "runtimePrincipalId", code), code),
  });
}

function canonicalEd25519PublicKey(
  value: unknown,
  code: RuntimeObservationKeySourceErrorCode
): CanonicalPublicKey {
  if (
    typeof value !== "string" ||
    value.length > MAX_PUBLIC_KEY_BYTES ||
    Buffer.byteLength(value, "utf8") > MAX_PUBLIC_KEY_BYTES ||
    !value.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
    !value.endsWith("-----END PUBLIC KEY-----\n") ||
    value.includes("PRIVATE KEY")
  ) {
    fail(code);
  }
  try {
    const key = createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") fail(code);
    const pem = key.export({ type: "spki", format: "pem" }).toString();
    if (pem !== value) fail(code);
    const der = key.export({ type: "spki", format: "der" });
    return Object.freeze({ key, pem, digest: createHash("sha256").update(der).digest("hex") });
  } catch (error) {
    if (error instanceof RuntimeObservationKeySourceError) throw error;
    fail(code);
  }
}

function attestationClaims(
  attestation: RuntimeObservationKeyAttestation
): RuntimeObservationKeyAttestationClaims {
  return Object.freeze({
    version: 1,
    kind: ATTESTATION_KIND,
    authorityKeyId: attestation.authorityKeyId,
    descriptorDigest: attestation.descriptorDigest,
  });
}

function attestationPayload(claims: RuntimeObservationKeyAttestationClaims): Buffer {
  return Buffer.concat([
    Buffer.from(RUNTIME_OBSERVATION_KEY_ATTESTATION_SIGNATURE_DOMAIN, "utf8"),
    Buffer.from(canonicalRuntimeJson(claims), "utf8"),
  ]);
}

function lookupKey(value: RuntimeObservationKeyLookup): string {
  return canonicalRuntimeJson({
    binding: value.binding,
    runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
  });
}

function domainDigest(domain: string, value: unknown): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalRuntimeJson(value), "utf8")
    .digest("hex");
}

function decodeSignature(value: string): Buffer | null {
  if (!ED25519_SIGNATURE.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === 64 && decoded.toString("base64url") === value ? decoded : null;
  } catch {
    return null;
  }
}

/** Detect native Promises and custom thenables without reading or invoking `then`. */
function hasThenableShape(value: unknown): boolean {
  if ((typeof value !== "object" || value === null) && typeof value !== "function") return false;
  if (utilTypes.isProxy(value)) return true;
  let candidate: object | null = value as object;
  try {
    for (let depth = 0; depth < 8 && candidate !== null; depth += 1) {
      if (utilTypes.isProxy(candidate) || Object.getOwnPropertyDescriptor(candidate, "then")) {
        return true;
      }
      candidate = Object.getPrototypeOf(candidate);
    }
    return candidate !== null;
  } catch {
    return true;
  }
}

/** Suppress only native Promise rejection; custom thenables are never invoked. */
function suppressNativePromiseRejection(value: unknown): void {
  try {
    void Promise.prototype.then.call(value as Promise<unknown>, undefined, () => undefined);
  } catch {
    // Proxy-wrapped Promises and custom thenables deliberately remain untouched.
  }
}

function readStrictRegistryFile(trustedConfigurationRoot: unknown, value: unknown): unknown {
  let bytes: Buffer;
  try {
    bytes = readTrustedConfigurationFile({
      trustedConfigurationRoot,
      filePath: value,
      minimumBytes: 1,
      maximumBytes: MAX_REGISTRY_FILE_BYTES,
    });
  } catch {
    fail("source_unavailable");
  }
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("invalid_source");
  } finally {
    bytes.fill(0);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
    if (canonicalRuntimeJson(parsed) !== source) fail("invalid_source");
  } catch (error) {
    if (error instanceof RuntimeObservationKeySourceError) throw error;
    fail("invalid_source");
  }
  return snapshotJsonData(parsed, "invalid_source");
}

function snapshotJsonData(value: unknown, code: RuntimeObservationKeySourceErrorCode): unknown {
  assertPortableData(value, code);
  try {
    return JSON.parse(canonicalRuntimeJson(value)) as unknown;
  } catch {
    fail(code);
  }
}

/** Reject proxies/accessors before canonicalization can detach and hide their origin. */
function assertPortableData(value: unknown, code: RuntimeObservationKeySourceErrorCode): void {
  inspectPortableData(
    value,
    {
      ancestors: new Set<object>(),
      remainingNodes: MAX_GRAPH_NODES,
      remainingStringBytes: MAX_GRAPH_STRING_BYTES,
    },
    0,
    code
  );
}

function inspectPortableData(
  value: unknown,
  state: GraphState,
  depth: number,
  code: RuntimeObservationKeySourceErrorCode
): void {
  if (depth > MAX_GRAPH_DEPTH || state.remainingNodes < 1) fail(code);
  state.remainingNodes -= 1;
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    if (value.length > state.remainingStringBytes) fail(code);
    state.remainingStringBytes -= Buffer.byteLength(value, "utf8");
    if (state.remainingStringBytes < 0) fail(code);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail(code);
    return;
  }
  if (typeof value !== "object" || utilTypes.isProxy(value)) fail(code);
  if (state.ancestors.has(value)) fail(code);
  state.ancestors.add(value);
  try {
    let prototype: object | null;
    let keys: readonly PropertyKey[];
    try {
      prototype = Object.getPrototypeOf(value);
      keys = Reflect.ownKeys(value);
    } catch {
      fail(code);
    }
    if (keys.length > MAX_GRAPH_FIELDS) fail(code);
    if (Array.isArray(value)) {
      if (
        prototype !== Array.prototype ||
        keys.length !== value.length + 1 ||
        !keys.includes("length")
      ) {
        fail(code);
      }
      for (let index = 0; index < value.length; index += 1) {
        inspectDataDescriptor(value, String(index), state, depth, code);
      }
      return;
    }
    if (prototype !== Object.prototype && prototype !== null) fail(code);
    for (const key of keys) {
      if (typeof key !== "string") fail(code);
      if (key.length > state.remainingStringBytes) fail(code);
      state.remainingStringBytes -= Buffer.byteLength(key, "utf8");
      if (state.remainingStringBytes < 0) fail(code);
      inspectDataDescriptor(value, key, state, depth, code);
    }
  } finally {
    state.ancestors.delete(value);
  }
}

function inspectDataDescriptor(
  owner: object,
  key: PropertyKey,
  state: GraphState,
  depth: number,
  code: RuntimeObservationKeySourceErrorCode
): void {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(owner, key);
  } catch {
    fail(code);
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
  inspectPortableData(descriptor.value, state, depth + 1, code);
}

function boundedArray(
  value: unknown,
  minimum: number,
  maximum: number,
  code: RuntimeObservationKeySourceErrorCode
): readonly unknown[] {
  const snapshot = snapshotJsonData(value, code);
  if (!Array.isArray(snapshot) || snapshot.length < minimum || snapshot.length > maximum) {
    fail(code);
  }
  return snapshot;
}

function dataRecord(
  value: unknown,
  code: RuntimeObservationKeySourceErrorCode
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    utilTypes.isProxy(value)
  ) {
    fail(code);
  }
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
  expected: readonly string[],
  code: RuntimeObservationKeySourceErrorCode
): void {
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(record);
  } catch {
    fail(code);
  }
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key)) ||
    expected.some((key) => !keys.includes(key))
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
  code: RuntimeObservationKeySourceErrorCode
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

function requiredKeyId(value: unknown, code: RuntimeObservationKeySourceErrorCode): string {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) fail(code);
  return value;
}

function safeReference(value: unknown, code: RuntimeObservationKeySourceErrorCode): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value) || value.trim() !== value) {
    fail(code);
  }
  return value;
}

function sha256(value: unknown, code: RuntimeObservationKeySourceErrorCode): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(code);
  return value;
}

function ed25519Signature(value: unknown, code: RuntimeObservationKeySourceErrorCode): string {
  if (typeof value !== "string" || !ED25519_SIGNATURE.test(value)) fail(code);
  return value;
}

function nonNegativeInteger(value: unknown, code: RuntimeObservationKeySourceErrorCode): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) fail(code);
  return value as number;
}

function positiveInteger(value: unknown, code: RuntimeObservationKeySourceErrorCode): number {
  const result = nonNegativeInteger(value, code);
  if (result < 1) fail(code);
  return result;
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor) deepFreeze(descriptor.value);
  }
  return Object.freeze(value);
}

function fail(code: RuntimeObservationKeySourceErrorCode): never {
  throw new RuntimeObservationKeySourceError(code);
}
