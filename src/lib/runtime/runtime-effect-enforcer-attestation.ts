import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { TextDecoder, types as utilTypes } from "node:util";
import type { AggregateEnforcementProof } from "./contracts";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import {
  snapshotRuntimeCompensationEnforcementProofVerificationInput,
  type RuntimeCompensationEnforcementProofVerificationInput,
  type SynchronousRuntimeCompensationEnforcementProofVerifier,
} from "./runtime-compensation-enforcement-proof";
import {
  snapshotRuntimeEnforcementProofVerificationInput,
  type RuntimeEnforcementProofVerificationInput,
  type SynchronousRuntimeEnforcementProofVerifier,
} from "./runtime-enforcement-proof";
import { readTrustedConfigurationFile } from "./runtime-trusted-configuration-file";

export const RUNTIME_EFFECT_ENFORCER_MANIFEST_CLAIMS_DIGEST_DOMAIN =
  "terminalx/runtime-effect-enforcer-manifest-claims/v1\0" as const;
export const RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN =
  "terminalx/runtime-effect-enforcer-manifest-authority/v1\0" as const;
export const RUNTIME_EFFECT_ENFORCER_ATTESTATION_CLAIMS_DIGEST_DOMAIN =
  "terminalx/runtime-effect-enforcer-attestation-claims/v1\0" as const;
export const RUNTIME_EFFECT_ENFORCER_ATTESTATION_AUTHORITY_SIGNATURE_DOMAIN =
  "terminalx/runtime-effect-enforcer-attestation-authority/v1\0" as const;
export const RUNTIME_EFFECT_ENFORCER_ATTESTATION_DIGEST_DOMAIN =
  "terminalx/runtime-effect-enforcer-attestation/v1\0" as const;

const MANIFEST_KIND = "runtime.effect-enforcer-manifest" as const;
const ATTESTATION_KIND = "runtime.effect-enforcer-attestation" as const;
const MANIFEST_AUTHORITY_ISSUER = "platform-security" as const;
const MANIFEST_AUTHORITY_AUDIENCE = "terminalx-control-plane" as const;
const MANIFEST_AUTHORITY_CAPABILITY = "runtime.effect-enforcer-manifest.trust" as const;
const ATTESTATION_AUTHORITY_ISSUER = "runtime-effect-enforcer" as const;
const ATTESTATION_AUTHORITY_AUDIENCE = "terminalx-control-plane" as const;
const ATTESTATION_AUTHORITY_CAPABILITY = "runtime.effect-enforcement.attest" as const;
const SHA256 = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const MAX_REGISTRY_FILE_BYTES = 8 * 1024 * 1024;
const MAX_MANIFEST_AUTHORITY_KEYS = 64;
const MAX_ENFORCERS = 64;
const MAX_ATTESTATIONS = 65_536;
const MAX_ATTESTATION_AUTHORITY_TTL_MS = 5 * 60_000;
const MAX_GRAPH_DEPTH = 32;
const MAX_GRAPH_NODES = 20_000;
const MAX_GRAPH_FIELDS = 1_000;
const MAX_GRAPH_STRING_BYTES = 1024 * 1024;

const ENFORCER_KINDS = new Set<RuntimeEffectEnforcerKind>([
  "runtime",
  "credential-proxy",
  "source-control",
  "deployment",
  "signer",
  "other-effect-enforcer",
]);
const PURPOSES = new Set<RuntimeEffectEnforcerPurpose>([
  "runtime-lifecycle",
  "stale-lifecycle-effect-containment",
]);
const MANIFEST_CLAIMS_FIELDS = [
  "version",
  "kind",
  "manifestId",
  "validFromMs",
  "expiresAtMs",
  "enforcers",
] as const;
const MANIFEST_FIELDS = [...MANIFEST_CLAIMS_FIELDS, "authority"] as const;
const ENFORCER_FIELDS = [
  "enforcerRef",
  "enforcerKind",
  "enforcerKeyId",
  "publicKeySpkiPem",
  "publicKeySpkiDigest",
  "allowedPurposes",
] as const;
const MANIFEST_AUTHORITY_FIELDS = [
  "issuer",
  "issuerKeyId",
  "audience",
  "capability",
  "claimsDigest",
  "issuedAtMs",
  "expiresAtMs",
  "signature",
] as const;
const MANIFEST_AUTHORITY_STATEMENT_FIELDS = [
  "version",
  "issuer",
  "issuerKeyId",
  "audience",
  "capability",
  "claimsDigest",
  "issuedAtMs",
  "expiresAtMs",
] as const;
const ATTESTATION_CLAIMS_FIELDS = [
  "version",
  "kind",
  "manifestDigest",
  "purpose",
  "generation",
  "enforcementSubjectDigest",
  "enforcerRef",
  "enforcerKind",
  "enforcerKeyId",
  "enforcerPublicKeySpkiDigest",
  "observedAtMs",
] as const;
const ATTESTATION_FIELDS = [...ATTESTATION_CLAIMS_FIELDS, "authority"] as const;
const ATTESTATION_AUTHORITY_FIELDS = [
  "issuer",
  "issuerKeyId",
  "audience",
  "capability",
  "claimsDigest",
  "issuedAtMs",
  "expiresAtMs",
  "signature",
] as const;
const ATTESTATION_AUTHORITY_STATEMENT_FIELDS = [
  "version",
  "issuer",
  "issuerKeyId",
  "audience",
  "capability",
  "claimsDigest",
  "issuedAtMs",
  "expiresAtMs",
] as const;
const PIN_FIELDS = ["issuerKeyId", "publicKeySpkiPem", "publicKeySpkiDigest"] as const;
const CREATE_FIELDS = ["manifest", "attestations", "pinnedManifestAuthorityPublicKeys"] as const;
const SOURCE_CREATE_FIELDS = [
  "manifest",
  "attestationSource",
  "pinnedManifestAuthorityPublicKeys",
] as const;
const ATTESTATION_SOURCE_FIELDS = ["get"] as const;
const FILE_CREATE_FIELDS = [
  "trustedConfigurationRoot",
  "registryFile",
  "pinnedManifestAuthorityPublicKeys",
] as const;
const REGISTRY_BUNDLE_FIELDS = ["manifest", "attestations"] as const;
const VERIFICATION_INPUT_FIELDS = ["subject", "subjectDigest", "proof"] as const;

export type RuntimeEffectEnforcerPurpose =
  | "runtime-lifecycle"
  | "stale-lifecycle-effect-containment";

export type RuntimeEffectEnforcerKind =
  AggregateEnforcementProof["acknowledgements"][number]["enforcerKind"];

export interface RuntimeEffectEnforcerManifestEntry {
  readonly enforcerRef: string;
  readonly enforcerKind: RuntimeEffectEnforcerKind;
  readonly enforcerKeyId: string;
  /** Exact canonical Ed25519 SubjectPublicKeyInfo PEM, including its trailing newline. */
  readonly publicKeySpkiPem: string;
  /** SHA-256 of canonical Ed25519 SubjectPublicKeyInfo DER. */
  readonly publicKeySpkiDigest: string;
  /** Strictly sorted, duplicate-free purpose set. */
  readonly allowedPurposes: readonly RuntimeEffectEnforcerPurpose[];
}

export interface RuntimeEffectEnforcerManifestClaims {
  readonly version: 1;
  readonly kind: "runtime.effect-enforcer-manifest";
  readonly manifestId: string;
  readonly validFromMs: number;
  readonly expiresAtMs: number;
  /** Exact required enforcer set, strictly sorted by enforcerRef. */
  readonly enforcers: readonly RuntimeEffectEnforcerManifestEntry[];
}

export interface RuntimeEffectEnforcerManifestAuthority {
  readonly issuer: "platform-security";
  readonly issuerKeyId: string;
  readonly audience: "terminalx-control-plane";
  readonly capability: "runtime.effect-enforcer-manifest.trust";
  /** Also the required effect/containment enforcer-set digest. */
  readonly claimsDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly signature: string;
}

export interface RuntimeEffectEnforcerManifest extends RuntimeEffectEnforcerManifestClaims {
  readonly authority: RuntimeEffectEnforcerManifestAuthority;
}

export interface RuntimeEffectEnforcerAttestationClaims {
  readonly version: 1;
  readonly kind: "runtime.effect-enforcer-attestation";
  readonly manifestDigest: string;
  readonly purpose: RuntimeEffectEnforcerPurpose;
  readonly generation: number;
  readonly enforcementSubjectDigest: string;
  readonly enforcerRef: string;
  readonly enforcerKind: RuntimeEffectEnforcerKind;
  readonly enforcerKeyId: string;
  readonly enforcerPublicKeySpkiDigest: string;
  readonly observedAtMs: number;
}

export interface RuntimeEffectEnforcerAttestationAuthority {
  readonly issuer: "runtime-effect-enforcer";
  readonly issuerKeyId: string;
  readonly audience: "terminalx-control-plane";
  readonly capability: "runtime.effect-enforcement.attest";
  readonly claimsDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly signature: string;
}

export interface RuntimeEffectEnforcerAttestation extends RuntimeEffectEnforcerAttestationClaims {
  readonly authority: RuntimeEffectEnforcerAttestationAuthority;
}

export interface PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey {
  readonly issuerKeyId: string;
  /** Exact canonical Ed25519 SubjectPublicKeyInfo PEM. Private-key PEM is rejected. */
  readonly publicKeySpkiPem: string;
  readonly publicKeySpkiDigest: string;
}

export interface CreateRuntimeEffectEnforcerTrustRegistryOptions {
  readonly manifest: unknown;
  readonly attestations: readonly unknown[];
  /** Construction-time pin selection is the revocation decision for this immutable registry. */
  readonly pinnedManifestAuthorityPublicKeys: readonly PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey[];
}

export interface CreateRuntimeEffectEnforcerTrustRegistryFromFileOptions {
  /**
   * Absolute canonical private operator configuration root (0500/0700).
   * This explicit trust boundary must not be an arbitrary browser workspace.
   */
  readonly trustedConfigurationRoot: string;
  /** Absolute canonical 0400/0600 registry path strictly below the trust root. */
  readonly registryFile: string;
  readonly pinnedManifestAuthorityPublicKeys: readonly PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey[];
}

/**
 * A local synchronous lookup adapter. Implementations must not perform remote
 * provider work; Promise and thenable results always fail closed.
 */
export interface RuntimeEffectEnforcerAttestationSource {
  readonly get: (acknowledgementDigest: string) => unknown | null;
}

export interface CreateRuntimeEffectEnforcerTrustRegistryWithAttestationSourceOptions {
  readonly manifest: unknown;
  readonly attestationSource: RuntimeEffectEnforcerAttestationSource;
  /** Construction-time pin selection is the revocation decision for this immutable registry. */
  readonly pinnedManifestAuthorityPublicKeys: readonly PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey[];
}

export interface RuntimeEffectEnforcerTrustRegistry {
  /** Exact manifest claims digest required by commands and aggregate proofs. */
  readonly manifestDigest: string;
  readonly manifest: RuntimeEffectEnforcerManifest;
  readonly verifyRuntimeEnforcementProof: SynchronousRuntimeEnforcementProofVerifier;
  readonly verifyRuntimeCompensationEnforcementProof: SynchronousRuntimeCompensationEnforcementProofVerifier;
}

export type RuntimeEffectEnforcerAttestationErrorCode =
  | "invalid_configuration"
  | "registry_file_unavailable"
  | "invalid_registry_file"
  | "invalid_manifest"
  | "invalid_attestation"
  | "invalid_public_key"
  | "invalid_signature";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeEffectEnforcerAttestationErrorCode, string>> = {
  invalid_configuration: "Runtime effect-enforcer trust configuration is invalid",
  registry_file_unavailable: "Runtime effect-enforcer registry file is unavailable",
  invalid_registry_file: "Runtime effect-enforcer registry file is invalid",
  invalid_manifest: "Runtime effect-enforcer manifest is invalid",
  invalid_attestation: "Runtime effect-enforcer attestation is invalid",
  invalid_public_key: "Runtime effect-enforcer public key is invalid",
  invalid_signature: "Runtime effect-enforcer signature is invalid",
};

/** Safe failure surface: file paths, key bytes, signatures, and crypto errors are omitted. */
export class RuntimeEffectEnforcerAttestationError extends Error {
  constructor(readonly code: RuntimeEffectEnforcerAttestationErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeEffectEnforcerAttestationError";
  }
}

interface ParsedPublicKey {
  readonly key: KeyObject;
  readonly digest: string;
  readonly pem: string;
}

interface ParsedManifestEntry {
  readonly snapshot: RuntimeEffectEnforcerManifestEntry;
  readonly key: KeyObject;
}

interface ParsedManifest {
  readonly snapshot: RuntimeEffectEnforcerManifest;
  readonly digest: string;
  readonly entries: readonly ParsedManifestEntry[];
}

interface ParsedAttestation {
  readonly snapshot: RuntimeEffectEnforcerAttestation;
  readonly claimsDigest: string;
  readonly acknowledgementDigest: string;
}

interface GraphState {
  readonly ancestors: Set<object>;
  remainingNodes: number;
  remainingStringBytes: number;
}

type ResolveRuntimeEffectEnforcerAttestation = (
  acknowledgementDigest: string
) => RuntimeEffectEnforcerAttestation | null;

/** Strictly snapshot manifest claims before hashing or signing them. */
export function snapshotRuntimeEffectEnforcerManifestClaims(
  value: unknown
): RuntimeEffectEnforcerManifestClaims {
  return parseManifestClaims(value, "invalid_manifest").claims;
}

/** The returned digest is the command/proof required enforcer-set digest. */
export function digestRuntimeEffectEnforcerManifestClaims(value: unknown): string {
  const { claims } = parseManifestClaims(value, "invalid_manifest");
  return digestCanonical(RUNTIME_EFFECT_ENFORCER_MANIFEST_CLAIMS_DIGEST_DOMAIN, claims);
}

/** Strictly snapshot a self-consistent signed manifest without granting its authority trust. */
export function snapshotRuntimeEffectEnforcerManifest(
  value: unknown
): RuntimeEffectEnforcerManifest {
  return parseManifest(value).snapshot;
}

/** Strictly snapshot attestation claims before hashing or signing them. */
export function snapshotRuntimeEffectEnforcerAttestationClaims(
  value: unknown
): RuntimeEffectEnforcerAttestationClaims {
  return parseAttestationClaims(value).claims;
}

export function digestRuntimeEffectEnforcerAttestationClaims(value: unknown): string {
  const { claims } = parseAttestationClaims(value);
  return digestCanonical(RUNTIME_EFFECT_ENFORCER_ATTESTATION_CLAIMS_DIGEST_DOMAIN, claims);
}

/** Strictly snapshot a self-consistent signed attestation without granting it manifest trust. */
export function snapshotRuntimeEffectEnforcerAttestation(
  value: unknown
): RuntimeEffectEnforcerAttestation {
  return parseAttestation(value).snapshot;
}

/** Digest referenced by AggregateEnforcementProof.acknowledgements. */
export function digestRuntimeEffectEnforcerAttestation(value: unknown): string {
  return parseAttestation(value).acknowledgementDigest;
}

/**
 * Build an immutable, fully preverified registry. Signature checks and all I/O
 * happen here; the two returned verifier functions perform only synchronous
 * validation and immutable in-memory lookups.
 */
export function createRuntimeEffectEnforcerTrustRegistry(
  unsafeOptions: CreateRuntimeEffectEnforcerTrustRegistryOptions
): RuntimeEffectEnforcerTrustRegistry {
  const options = exactRecord(unsafeOptions, CREATE_FIELDS, "invalid_configuration");
  const manifest = parseAndVerifyManifest(
    field(options, "manifest", "invalid_configuration"),
    field(options, "pinnedManifestAuthorityPublicKeys", "invalid_configuration")
  );
  const rawAttestations = strictArray(
    field(options, "attestations", "invalid_configuration"),
    0,
    MAX_ATTESTATIONS,
    "invalid_configuration"
  );

  const entryByRef = new Map<string, ParsedManifestEntry>();
  for (const entry of manifest.entries) entryByRef.set(entry.snapshot.enforcerRef, entry);
  const attestationByDigest = new Map<string, RuntimeEffectEnforcerAttestation>();
  const claimsDigests = new Set<string>();
  const proofCoordinates = new Set<string>();

  for (const rawAttestation of rawAttestations) {
    const parsed = parseAttestation(rawAttestation);
    const attestation = verifyAttestationAgainstManifest(parsed, manifest, entryByRef);
    const coordinates = attestationCoordinates(attestation);
    if (
      attestationByDigest.has(parsed.acknowledgementDigest) ||
      claimsDigests.has(parsed.claimsDigest) ||
      proofCoordinates.has(coordinates)
    ) {
      fail("invalid_attestation");
    }
    attestationByDigest.set(parsed.acknowledgementDigest, attestation);
    claimsDigests.add(parsed.claimsDigest);
    proofCoordinates.add(coordinates);
  }

  return buildRuntimeEffectEnforcerTrustRegistry(
    manifest,
    (acknowledgementDigest) => attestationByDigest.get(acknowledgementDigest) ?? null
  );
}

/**
 * Keep manifest authority immutable while resolving only the acknowledgement
 * digests referenced by each proof. Each lookup result is parsed and its
 * signature is reverified synchronously before it can contribute to trust.
 */
export function createRuntimeEffectEnforcerTrustRegistryWithAttestationSource(
  unsafeOptions: CreateRuntimeEffectEnforcerTrustRegistryWithAttestationSourceOptions
): RuntimeEffectEnforcerTrustRegistry {
  const options = exactRecord(unsafeOptions, SOURCE_CREATE_FIELDS, "invalid_configuration");
  const manifest = parseAndVerifyManifest(
    field(options, "manifest", "invalid_configuration"),
    field(options, "pinnedManifestAuthorityPublicKeys", "invalid_configuration")
  );
  const sourceRecord = exactRecord(
    field(options, "attestationSource", "invalid_configuration"),
    ATTESTATION_SOURCE_FIELDS,
    "invalid_configuration"
  );
  const get = field(sourceRecord, "get", "invalid_configuration");
  if (typeof get !== "function" || utilTypes.isProxy(get)) fail("invalid_configuration");
  // Capture the one data-property method once. Later source property mutation,
  // accessors, or prototype substitutions cannot change the invoked resolver.
  const capturedGet = get as RuntimeEffectEnforcerAttestationSource["get"];
  const entryByRef = new Map<string, ParsedManifestEntry>();
  for (const entry of manifest.entries) entryByRef.set(entry.snapshot.enforcerRef, entry);

  const resolve: ResolveRuntimeEffectEnforcerAttestation = (acknowledgementDigest) => {
    let rawAttestation: unknown;
    try {
      rawAttestation = Reflect.apply(capturedGet, undefined, [acknowledgementDigest]);
    } catch {
      return null;
    }
    if (rawAttestation === null) return null;
    if (hasThenableShape(rawAttestation)) {
      suppressNativePromiseRejection(rawAttestation);
      return null;
    }
    const parsed = parseAttestation(rawAttestation);
    if (!sameDigest(parsed.acknowledgementDigest, acknowledgementDigest)) return null;
    return verifyAttestationAgainstManifest(parsed, manifest, entryByRef);
  };

  return buildRuntimeEffectEnforcerTrustRegistry(manifest, resolve);
}

function buildRuntimeEffectEnforcerTrustRegistry(
  manifest: ParsedManifest,
  resolveAttestation: ResolveRuntimeEffectEnforcerAttestation
): RuntimeEffectEnforcerTrustRegistry {
  const verifyRuntimeEnforcementProof: SynchronousRuntimeEnforcementProofVerifier = (input) =>
    verifyLifecycleInput(input, manifest, resolveAttestation);
  const verifyRuntimeCompensationEnforcementProof: SynchronousRuntimeCompensationEnforcementProofVerifier =
    (input) => verifyCompensationInput(input, manifest, resolveAttestation);

  return Object.freeze({
    manifestDigest: manifest.digest,
    manifest: manifest.snapshot,
    verifyRuntimeEnforcementProof,
    verifyRuntimeCompensationEnforcementProof,
  });
}

/** Load one canonical public registry bundle through a strict production file seam. */
export function createRuntimeEffectEnforcerTrustRegistryFromFile(
  unsafeOptions: CreateRuntimeEffectEnforcerTrustRegistryFromFileOptions
): RuntimeEffectEnforcerTrustRegistry {
  const options = exactRecord(unsafeOptions, FILE_CREATE_FIELDS, "invalid_configuration");
  const trustedConfigurationRoot = field(
    options,
    "trustedConfigurationRoot",
    "invalid_configuration"
  );
  const registryFile = field(options, "registryFile", "invalid_configuration");
  const bundle = readCanonicalRegistryBundle(trustedConfigurationRoot, registryFile);
  const record = exactRecord(bundle, REGISTRY_BUNDLE_FIELDS, "invalid_registry_file");
  return createRuntimeEffectEnforcerTrustRegistry({
    manifest: field(record, "manifest", "invalid_registry_file"),
    attestations: strictArray(
      field(record, "attestations", "invalid_registry_file"),
      0,
      MAX_ATTESTATIONS,
      "invalid_registry_file"
    ),
    pinnedManifestAuthorityPublicKeys: field(
      options,
      "pinnedManifestAuthorityPublicKeys",
      "invalid_configuration"
    ) as readonly PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey[],
  });
}

function verifyLifecycleInput(
  unsafeInput: RuntimeEnforcementProofVerificationInput,
  manifest: ParsedManifest,
  resolveAttestation: ResolveRuntimeEffectEnforcerAttestation
): boolean {
  try {
    assertPortableVerificationInput(unsafeInput);
    const input = exactRecord(unsafeInput, VERIFICATION_INPUT_FIELDS, "invalid_attestation");
    const suppliedSubjectDigest = sha256(
      field(input, "subjectDigest", "invalid_attestation"),
      "invalid_attestation"
    );
    const snapshot = snapshotRuntimeEnforcementProofVerificationInput(
      field(
        input,
        "subject",
        "invalid_attestation"
      ) as RuntimeEnforcementProofVerificationInput["subject"],
      field(input, "proof", "invalid_attestation") as AggregateEnforcementProof
    );
    if (!sameDigest(suppliedSubjectDigest, snapshot.subjectDigest)) return false;
    return verifyProof(
      "runtime-lifecycle",
      snapshot.subject.runtimeAuthorizationGeneration,
      snapshot.subjectDigest,
      snapshot.proof,
      manifest,
      resolveAttestation
    );
  } catch {
    return false;
  }
}

function verifyCompensationInput(
  unsafeInput: RuntimeCompensationEnforcementProofVerificationInput,
  manifest: ParsedManifest,
  resolveAttestation: ResolveRuntimeEffectEnforcerAttestation
): boolean {
  try {
    assertPortableVerificationInput(unsafeInput);
    const input = exactRecord(unsafeInput, VERIFICATION_INPUT_FIELDS, "invalid_attestation");
    const suppliedSubjectDigest = sha256(
      field(input, "subjectDigest", "invalid_attestation"),
      "invalid_attestation"
    );
    const snapshot = snapshotRuntimeCompensationEnforcementProofVerificationInput(
      field(
        input,
        "subject",
        "invalid_attestation"
      ) as RuntimeCompensationEnforcementProofVerificationInput["subject"],
      field(input, "proof", "invalid_attestation") as AggregateEnforcementProof
    );
    if (
      snapshot.subject.purpose !== "stale-lifecycle-effect-containment" ||
      !sameDigest(suppliedSubjectDigest, snapshot.subjectDigest)
    ) {
      return false;
    }
    return verifyProof(
      "stale-lifecycle-effect-containment",
      snapshot.subject.observedRuntimeAuthorizationGeneration,
      snapshot.subjectDigest,
      snapshot.proof,
      manifest,
      resolveAttestation
    );
  } catch {
    return false;
  }
}

function verifyProof(
  purpose: RuntimeEffectEnforcerPurpose,
  generation: number,
  subjectDigest: string,
  proof: AggregateEnforcementProof,
  manifest: ParsedManifest,
  resolveAttestation: ResolveRuntimeEffectEnforcerAttestation
): boolean {
  if (
    !sameDigest(proof.requiredEffectEnforcerSetDigest, manifest.digest) ||
    !sameDigest(proof.enforcementSubjectDigest, subjectDigest) ||
    proof.generation !== generation
  ) {
    return false;
  }
  const required = manifest.entries.filter((entry) =>
    entry.snapshot.allowedPurposes.includes(purpose)
  );
  if (required.length < 1 || proof.acknowledgements.length !== required.length) return false;

  const acknowledgementDigests = new Set<string>();
  const claimsDigests = new Set<string>();
  const coordinates = new Set<string>();

  for (let index = 0; index < required.length; index += 1) {
    const entry = required[index];
    const acknowledgement = proof.acknowledgements[index];
    if (
      !entry ||
      !acknowledgement ||
      acknowledgement.enforcerRef !== entry.snapshot.enforcerRef ||
      acknowledgement.enforcerKind !== entry.snapshot.enforcerKind
    ) {
      return false;
    }
    if (acknowledgementDigests.has(acknowledgement.acknowledgementDigest)) return false;
    acknowledgementDigests.add(acknowledgement.acknowledgementDigest);
    // Exactly one bounded synchronous lookup for this exact required digest.
    const attestation = resolveAttestation(acknowledgement.acknowledgementDigest);
    if (
      !attestation ||
      !sameDigest(attestation.manifestDigest, manifest.digest) ||
      attestation.purpose !== purpose ||
      attestation.generation !== generation ||
      !sameDigest(attestation.enforcementSubjectDigest, subjectDigest) ||
      attestation.enforcerRef !== entry.snapshot.enforcerRef ||
      attestation.enforcerKind !== entry.snapshot.enforcerKind ||
      attestation.enforcerKeyId !== entry.snapshot.enforcerKeyId ||
      !sameDigest(attestation.enforcerPublicKeySpkiDigest, entry.snapshot.publicKeySpkiDigest)
    ) {
      return false;
    }
    const coordinate = attestationCoordinates(attestation);
    if (claimsDigests.has(attestation.authority.claimsDigest) || coordinates.has(coordinate)) {
      return false;
    }
    claimsDigests.add(attestation.authority.claimsDigest);
    coordinates.add(coordinate);
  }
  return true;
}

function parseAndVerifyManifest(value: unknown, pinValue: unknown): ParsedManifest {
  const manifest = parseManifest(value);
  const pins = parseManifestAuthorityPins(pinValue);
  verifyManifestAuthority(manifest, pins);
  for (const entry of manifest.entries) {
    for (const [issuerKeyId, pin] of pins) {
      if (
        issuerKeyId === entry.snapshot.enforcerKeyId ||
        sameDigest(pin.digest, entry.snapshot.publicKeySpkiDigest)
      ) {
        fail("invalid_configuration");
      }
    }
  }
  return manifest;
}

function verifyAttestationAgainstManifest(
  parsed: ParsedAttestation,
  manifest: ParsedManifest,
  entryByRef: ReadonlyMap<string, ParsedManifestEntry>
): RuntimeEffectEnforcerAttestation {
  const attestation = parsed.snapshot;
  if (!sameDigest(attestation.manifestDigest, manifest.digest)) fail("invalid_attestation");
  const entry = entryByRef.get(attestation.enforcerRef);
  if (
    !entry ||
    entry.snapshot.enforcerKind !== attestation.enforcerKind ||
    entry.snapshot.enforcerKeyId !== attestation.enforcerKeyId ||
    !sameDigest(entry.snapshot.publicKeySpkiDigest, attestation.enforcerPublicKeySpkiDigest) ||
    !entry.snapshot.allowedPurposes.includes(attestation.purpose) ||
    attestation.observedAtMs < manifest.snapshot.validFromMs ||
    attestation.observedAtMs >= manifest.snapshot.expiresAtMs ||
    attestation.authority.expiresAtMs > manifest.snapshot.expiresAtMs
  ) {
    fail("invalid_attestation");
  }
  verifyAttestationAuthority(parsed, entry.key);
  return attestation;
}

function attestationCoordinates(attestation: RuntimeEffectEnforcerAttestation): string {
  return canonicalRuntimeJson({
    manifestDigest: attestation.manifestDigest,
    purpose: attestation.purpose,
    generation: attestation.generation,
    enforcementSubjectDigest: attestation.enforcementSubjectDigest,
    enforcerRef: attestation.enforcerRef,
  });
}

/** Detect native Promises and plain/custom thenables without invoking `then`. */
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

/** Attach a rejection handler only when the value has native Promise slots. */
function suppressNativePromiseRejection(value: unknown): void {
  try {
    void Promise.prototype.then.call(value as Promise<unknown>, undefined, () => undefined);
  } catch {
    // Custom thenables are deliberately not invoked.
  }
}

function parseManifest(value: unknown): ParsedManifest {
  const record = exactRecord(value, MANIFEST_FIELDS, "invalid_manifest");
  const parsedClaims = parseManifestClaimsRecord(record, "invalid_manifest");
  const authority = parseManifestAuthority(field(record, "authority", "invalid_manifest"));
  const digest = digestCanonical(
    RUNTIME_EFFECT_ENFORCER_MANIFEST_CLAIMS_DIGEST_DOMAIN,
    parsedClaims.claims
  );
  if (
    !sameDigest(authority.claimsDigest, digest) ||
    authority.issuedAtMs !== parsedClaims.claims.validFromMs ||
    authority.expiresAtMs !== parsedClaims.claims.expiresAtMs
  ) {
    fail("invalid_manifest");
  }
  return Object.freeze({
    snapshot: Object.freeze({ ...parsedClaims.claims, authority }),
    digest,
    entries: parsedClaims.entries,
  });
}

function parseManifestClaims(
  value: unknown,
  code: RuntimeEffectEnforcerAttestationErrorCode
): {
  readonly claims: RuntimeEffectEnforcerManifestClaims;
  readonly entries: readonly ParsedManifestEntry[];
} {
  return parseManifestClaimsRecord(exactRecord(value, MANIFEST_CLAIMS_FIELDS, code), code);
}

function parseManifestClaimsRecord(
  record: Record<string, unknown>,
  code: RuntimeEffectEnforcerAttestationErrorCode
): {
  readonly claims: RuntimeEffectEnforcerManifestClaims;
  readonly entries: readonly ParsedManifestEntry[];
} {
  if (field(record, "version", code) !== 1 || field(record, "kind", code) !== MANIFEST_KIND) {
    fail(code);
  }
  const validFromMs = nonNegativeInteger(field(record, "validFromMs", code), code);
  const expiresAtMs = positiveInteger(field(record, "expiresAtMs", code), code);
  if (expiresAtMs <= validFromMs) fail(code);
  const rawEntries = strictArray(field(record, "enforcers", code), 1, MAX_ENFORCERS, code);
  const entries: ParsedManifestEntry[] = [];
  const keyIds = new Set<string>();
  const keyDigests = new Set<string>();
  let priorRef: string | undefined;
  for (const rawEntry of rawEntries) {
    const entry = parseManifestEntry(rawEntry, code);
    if (
      (priorRef !== undefined && entry.snapshot.enforcerRef <= priorRef) ||
      keyIds.has(entry.snapshot.enforcerKeyId) ||
      keyDigests.has(entry.snapshot.publicKeySpkiDigest)
    ) {
      fail(code);
    }
    priorRef = entry.snapshot.enforcerRef;
    keyIds.add(entry.snapshot.enforcerKeyId);
    keyDigests.add(entry.snapshot.publicKeySpkiDigest);
    entries.push(entry);
  }
  const snapshots = Object.freeze(entries.map((entry) => entry.snapshot));
  return Object.freeze({
    claims: Object.freeze({
      version: 1,
      kind: MANIFEST_KIND,
      manifestId: safeReference(field(record, "manifestId", code), code),
      validFromMs,
      expiresAtMs,
      enforcers: snapshots,
    }),
    entries: Object.freeze(entries),
  });
}

function parseManifestEntry(
  value: unknown,
  code: RuntimeEffectEnforcerAttestationErrorCode
): ParsedManifestEntry {
  const record = exactRecord(value, ENFORCER_FIELDS, code);
  const publicKey = parseCanonicalEd25519PublicKey(
    field(record, "publicKeySpkiPem", code),
    field(record, "publicKeySpkiDigest", code)
  );
  const allowedPurposes = parsePurposes(field(record, "allowedPurposes", code), code);
  return Object.freeze({
    snapshot: Object.freeze({
      enforcerRef: safeReference(field(record, "enforcerRef", code), code),
      enforcerKind: enforcerKind(field(record, "enforcerKind", code), code),
      enforcerKeyId: keyId(field(record, "enforcerKeyId", code), code),
      publicKeySpkiPem: publicKey.pem,
      publicKeySpkiDigest: publicKey.digest,
      allowedPurposes,
    }),
    key: publicKey.key,
  });
}

function parsePurposes(
  value: unknown,
  code: RuntimeEffectEnforcerAttestationErrorCode
): readonly RuntimeEffectEnforcerPurpose[] {
  const raw = strictArray(value, 1, PURPOSES.size, code);
  const result: RuntimeEffectEnforcerPurpose[] = [];
  let prior: string | undefined;
  for (const candidate of raw) {
    if (typeof candidate !== "string" || !PURPOSES.has(candidate as RuntimeEffectEnforcerPurpose)) {
      fail(code);
    }
    if (prior !== undefined && candidate <= prior) fail(code);
    prior = candidate;
    result.push(candidate as RuntimeEffectEnforcerPurpose);
  }
  return Object.freeze(result);
}

function parseManifestAuthority(value: unknown): RuntimeEffectEnforcerManifestAuthority {
  const record = exactRecord(value, MANIFEST_AUTHORITY_FIELDS, "invalid_manifest");
  if (
    field(record, "issuer", "invalid_manifest") !== MANIFEST_AUTHORITY_ISSUER ||
    field(record, "audience", "invalid_manifest") !== MANIFEST_AUTHORITY_AUDIENCE ||
    field(record, "capability", "invalid_manifest") !== MANIFEST_AUTHORITY_CAPABILITY
  ) {
    fail("invalid_manifest");
  }
  const issuedAtMs = nonNegativeInteger(
    field(record, "issuedAtMs", "invalid_manifest"),
    "invalid_manifest"
  );
  const expiresAtMs = positiveInteger(
    field(record, "expiresAtMs", "invalid_manifest"),
    "invalid_manifest"
  );
  if (expiresAtMs <= issuedAtMs) fail("invalid_manifest");
  return Object.freeze({
    issuer: MANIFEST_AUTHORITY_ISSUER,
    issuerKeyId: keyId(field(record, "issuerKeyId", "invalid_manifest"), "invalid_manifest"),
    audience: MANIFEST_AUTHORITY_AUDIENCE,
    capability: MANIFEST_AUTHORITY_CAPABILITY,
    claimsDigest: sha256(field(record, "claimsDigest", "invalid_manifest"), "invalid_manifest"),
    issuedAtMs,
    expiresAtMs,
    signature: signature(field(record, "signature", "invalid_manifest"), "invalid_manifest"),
  });
}

function parseAttestation(value: unknown): ParsedAttestation {
  const record = exactRecord(value, ATTESTATION_FIELDS, "invalid_attestation");
  const parsedClaims = parseAttestationClaimsRecord(record);
  const authority = parseAttestationAuthority(field(record, "authority", "invalid_attestation"));
  const claimsDigest = digestCanonical(
    RUNTIME_EFFECT_ENFORCER_ATTESTATION_CLAIMS_DIGEST_DOMAIN,
    parsedClaims.claims
  );
  if (
    !sameDigest(authority.claimsDigest, claimsDigest) ||
    authority.issuerKeyId !== parsedClaims.claims.enforcerKeyId ||
    authority.issuedAtMs !== parsedClaims.claims.observedAtMs ||
    authority.expiresAtMs <= parsedClaims.claims.observedAtMs ||
    authority.expiresAtMs - authority.issuedAtMs > MAX_ATTESTATION_AUTHORITY_TTL_MS
  ) {
    fail("invalid_attestation");
  }
  const snapshot = Object.freeze({ ...parsedClaims.claims, authority });
  return Object.freeze({
    snapshot,
    claimsDigest,
    acknowledgementDigest: digestCanonical(
      RUNTIME_EFFECT_ENFORCER_ATTESTATION_DIGEST_DOMAIN,
      snapshot
    ),
  });
}

function parseAttestationClaims(value: unknown): {
  readonly claims: RuntimeEffectEnforcerAttestationClaims;
} {
  return parseAttestationClaimsRecord(
    exactRecord(value, ATTESTATION_CLAIMS_FIELDS, "invalid_attestation")
  );
}

function parseAttestationClaimsRecord(record: Record<string, unknown>): {
  readonly claims: RuntimeEffectEnforcerAttestationClaims;
} {
  if (
    field(record, "version", "invalid_attestation") !== 1 ||
    field(record, "kind", "invalid_attestation") !== ATTESTATION_KIND
  ) {
    fail("invalid_attestation");
  }
  return Object.freeze({
    claims: Object.freeze({
      version: 1,
      kind: ATTESTATION_KIND,
      manifestDigest: sha256(
        field(record, "manifestDigest", "invalid_attestation"),
        "invalid_attestation"
      ),
      purpose: purpose(field(record, "purpose", "invalid_attestation")),
      generation: positiveInteger(
        field(record, "generation", "invalid_attestation"),
        "invalid_attestation"
      ),
      enforcementSubjectDigest: sha256(
        field(record, "enforcementSubjectDigest", "invalid_attestation"),
        "invalid_attestation"
      ),
      enforcerRef: safeReference(
        field(record, "enforcerRef", "invalid_attestation"),
        "invalid_attestation"
      ),
      enforcerKind: enforcerKind(
        field(record, "enforcerKind", "invalid_attestation"),
        "invalid_attestation"
      ),
      enforcerKeyId: keyId(
        field(record, "enforcerKeyId", "invalid_attestation"),
        "invalid_attestation"
      ),
      enforcerPublicKeySpkiDigest: sha256(
        field(record, "enforcerPublicKeySpkiDigest", "invalid_attestation"),
        "invalid_attestation"
      ),
      observedAtMs: nonNegativeInteger(
        field(record, "observedAtMs", "invalid_attestation"),
        "invalid_attestation"
      ),
    }),
  });
}

function parseAttestationAuthority(value: unknown): RuntimeEffectEnforcerAttestationAuthority {
  const record = exactRecord(value, ATTESTATION_AUTHORITY_FIELDS, "invalid_attestation");
  if (
    field(record, "issuer", "invalid_attestation") !== ATTESTATION_AUTHORITY_ISSUER ||
    field(record, "audience", "invalid_attestation") !== ATTESTATION_AUTHORITY_AUDIENCE ||
    field(record, "capability", "invalid_attestation") !== ATTESTATION_AUTHORITY_CAPABILITY
  ) {
    fail("invalid_attestation");
  }
  return Object.freeze({
    issuer: ATTESTATION_AUTHORITY_ISSUER,
    issuerKeyId: keyId(field(record, "issuerKeyId", "invalid_attestation"), "invalid_attestation"),
    audience: ATTESTATION_AUTHORITY_AUDIENCE,
    capability: ATTESTATION_AUTHORITY_CAPABILITY,
    claimsDigest: sha256(
      field(record, "claimsDigest", "invalid_attestation"),
      "invalid_attestation"
    ),
    issuedAtMs: nonNegativeInteger(
      field(record, "issuedAtMs", "invalid_attestation"),
      "invalid_attestation"
    ),
    expiresAtMs: positiveInteger(
      field(record, "expiresAtMs", "invalid_attestation"),
      "invalid_attestation"
    ),
    signature: signature(field(record, "signature", "invalid_attestation"), "invalid_attestation"),
  });
}

function parseManifestAuthorityPins(value: unknown): ReadonlyMap<string, ParsedPublicKey> {
  const rawPins = strictArray(value, 1, MAX_MANIFEST_AUTHORITY_KEYS, "invalid_configuration");
  const result = new Map<string, ParsedPublicKey>();
  const digests = new Set<string>();
  for (const rawPin of rawPins) {
    const pin = exactRecord(rawPin, PIN_FIELDS, "invalid_public_key");
    const issuerKeyId = keyId(
      field(pin, "issuerKeyId", "invalid_public_key"),
      "invalid_public_key"
    );
    const publicKey = parseCanonicalEd25519PublicKey(
      field(pin, "publicKeySpkiPem", "invalid_public_key"),
      field(pin, "publicKeySpkiDigest", "invalid_public_key")
    );
    if (result.has(issuerKeyId) || digests.has(publicKey.digest)) fail("invalid_public_key");
    result.set(issuerKeyId, publicKey);
    digests.add(publicKey.digest);
  }
  return result;
}

function verifyManifestAuthority(
  manifest: ParsedManifest,
  pins: ReadonlyMap<string, ParsedPublicKey>
): void {
  const authority = manifest.snapshot.authority;
  const pin = pins.get(authority.issuerKeyId);
  if (!pin) fail("invalid_signature");
  const statement = exactRecord(
    {
      version: 1,
      issuer: authority.issuer,
      issuerKeyId: authority.issuerKeyId,
      audience: authority.audience,
      capability: authority.capability,
      claimsDigest: authority.claimsDigest,
      issuedAtMs: authority.issuedAtMs,
      expiresAtMs: authority.expiresAtMs,
    },
    MANIFEST_AUTHORITY_STATEMENT_FIELDS,
    "invalid_manifest"
  );
  if (
    !verifySignature(
      RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN,
      statement,
      pin.key,
      authority.signature
    )
  ) {
    fail("invalid_signature");
  }
}

function verifyAttestationAuthority(parsed: ParsedAttestation, publicKey: KeyObject): void {
  const authority = parsed.snapshot.authority;
  const statement = exactRecord(
    {
      version: 1,
      issuer: authority.issuer,
      issuerKeyId: authority.issuerKeyId,
      audience: authority.audience,
      capability: authority.capability,
      claimsDigest: authority.claimsDigest,
      issuedAtMs: authority.issuedAtMs,
      expiresAtMs: authority.expiresAtMs,
    },
    ATTESTATION_AUTHORITY_STATEMENT_FIELDS,
    "invalid_attestation"
  );
  if (
    !verifySignature(
      RUNTIME_EFFECT_ENFORCER_ATTESTATION_AUTHORITY_SIGNATURE_DOMAIN,
      statement,
      publicKey,
      authority.signature
    )
  ) {
    fail("invalid_signature");
  }
}

function verifySignature(
  domain: string,
  statement: Record<string, unknown>,
  publicKey: KeyObject,
  encodedSignature: string
): boolean {
  const decoded = decodeSignature(encodedSignature);
  if (!decoded) return false;
  try {
    return verifyEd25519(
      null,
      Buffer.concat([
        Buffer.from(domain, "utf8"),
        Buffer.from(canonicalRuntimeJson(statement), "utf8"),
      ]),
      publicKey,
      decoded
    );
  } catch {
    return false;
  }
}

function parseCanonicalEd25519PublicKey(pemValue: unknown, digestValue: unknown): ParsedPublicKey {
  if (
    typeof pemValue !== "string" ||
    pemValue.length > MAX_PUBLIC_KEY_BYTES ||
    Buffer.byteLength(pemValue, "utf8") < 1 ||
    Buffer.byteLength(pemValue, "utf8") > MAX_PUBLIC_KEY_BYTES ||
    pemValue.includes("PRIVATE KEY") ||
    !pemValue.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
    !pemValue.endsWith("-----END PUBLIC KEY-----\n")
  ) {
    fail("invalid_public_key");
  }
  const expectedDigest = sha256(digestValue, "invalid_public_key");
  let key: KeyObject;
  let canonicalPem: string;
  let digest: string;
  try {
    key = createPublicKey(pemValue);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      fail("invalid_public_key");
    }
    canonicalPem = key.export({ type: "spki", format: "pem" }).toString();
    digest = createHash("sha256")
      .update(key.export({ type: "spki", format: "der" }))
      .digest("hex");
  } catch (error) {
    if (error instanceof RuntimeEffectEnforcerAttestationError) throw error;
    fail("invalid_public_key");
  }
  if (canonicalPem !== pemValue || !sameDigest(digest, expectedDigest)) {
    fail("invalid_public_key");
  }
  return Object.freeze({ key, digest, pem: canonicalPem });
}

function readCanonicalRegistryBundle(trustedConfigurationRoot: unknown, value: unknown): unknown {
  let bytes: Buffer;
  try {
    bytes = readTrustedConfigurationFile({
      trustedConfigurationRoot,
      filePath: value,
      minimumBytes: 2,
      maximumBytes: MAX_REGISTRY_FILE_BYTES,
    });
  } catch {
    fail("registry_file_unavailable");
  }
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(text) as unknown;
    if (canonicalRuntimeJson(parsed) !== text) fail("invalid_registry_file");
  } catch (error) {
    if (error instanceof RuntimeEffectEnforcerAttestationError) throw error;
    fail("invalid_registry_file");
  } finally {
    bytes.fill(0);
  }
  return parsed;
}

/** Reject proxies and accessors before delegated proof snapshotters can touch them. */
function assertPortableVerificationInput(value: unknown): void {
  inspectPortableVerificationData(
    value,
    {
      ancestors: new Set<object>(),
      remainingNodes: MAX_GRAPH_NODES,
      remainingStringBytes: MAX_GRAPH_STRING_BYTES,
    },
    0
  );
}

function inspectPortableVerificationData(value: unknown, state: GraphState, depth: number): void {
  if (depth > MAX_GRAPH_DEPTH || state.remainingNodes < 1) fail("invalid_attestation");
  state.remainingNodes -= 1;
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    if (value.length > state.remainingStringBytes) fail("invalid_attestation");
    state.remainingStringBytes -= Buffer.byteLength(value, "utf8");
    if (state.remainingStringBytes < 0) fail("invalid_attestation");
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail("invalid_attestation");
    return;
  }
  if (typeof value !== "object" || utilTypes.isProxy(value)) fail("invalid_attestation");
  if (state.ancestors.has(value)) fail("invalid_attestation");
  state.ancestors.add(value);
  try {
    let prototype: object | null;
    let keys: readonly PropertyKey[];
    try {
      prototype = Object.getPrototypeOf(value);
      keys = Reflect.ownKeys(value);
    } catch {
      fail("invalid_attestation");
    }
    if (keys.length > MAX_GRAPH_FIELDS) fail("invalid_attestation");
    if (Array.isArray(value)) {
      if (
        prototype !== Array.prototype ||
        keys.length !== value.length + 1 ||
        !keys.includes("length")
      ) {
        fail("invalid_attestation");
      }
      for (let index = 0; index < value.length; index += 1) {
        inspectPortableVerificationDescriptor(value, String(index), state, depth);
      }
      return;
    }
    if (prototype !== Object.prototype && prototype !== null) fail("invalid_attestation");
    for (const key of keys) {
      if (typeof key !== "string") fail("invalid_attestation");
      if (key.length > state.remainingStringBytes) fail("invalid_attestation");
      state.remainingStringBytes -= Buffer.byteLength(key, "utf8");
      if (state.remainingStringBytes < 0) fail("invalid_attestation");
      inspectPortableVerificationDescriptor(value, key, state, depth);
    }
  } finally {
    state.ancestors.delete(value);
  }
}

function inspectPortableVerificationDescriptor(
  owner: object,
  key: PropertyKey,
  state: GraphState,
  depth: number
): void {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(owner, key);
  } catch {
    fail("invalid_attestation");
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    fail("invalid_attestation");
  }
  inspectPortableVerificationData(descriptor.value, state, depth + 1);
}

function exactRecord(
  value: unknown,
  expectedFields: readonly string[],
  code: RuntimeEffectEnforcerAttestationErrorCode
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
  let keys: PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch {
    fail(code);
  }
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== expectedFields.length ||
    keys.some((key) => typeof key !== "string" || !expectedFields.includes(key))
  ) {
    fail(code);
  }
  for (const expected of expectedFields) field(value as Record<string, unknown>, expected, code);
  return value as Record<string, unknown>;
}

function field(
  record: Record<string, unknown>,
  name: string,
  code: RuntimeEffectEnforcerAttestationErrorCode
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

function strictArray(
  value: unknown,
  minimum: number,
  maximum: number,
  code: RuntimeEffectEnforcerAttestationErrorCode
): readonly unknown[] {
  let keys: PropertyKey[];
  let length: number;
  try {
    if (
      !Array.isArray(value) ||
      utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Array.prototype
    ) {
      fail(code);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      !descriptor ||
      descriptor.enumerable ||
      !("value" in descriptor) ||
      !Number.isSafeInteger(descriptor.value) ||
      descriptor.value < minimum ||
      descriptor.value > maximum
    ) {
      fail(code);
    }
    length = descriptor.value;
    keys = Reflect.ownKeys(value);
  } catch (error) {
    if (error instanceof RuntimeEffectEnforcerAttestationError) throw error;
    fail(code);
  }
  if (
    keys.length !== length + 1 ||
    !keys.includes("length") ||
    keys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" ||
          key.length > 10 ||
          !/^(0|[1-9][0-9]*)$/.test(key) ||
          Number(key) >= length)
    )
  ) {
    fail(code);
  }
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(code);
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}

function digestCanonical(domain: string, value: unknown): string {
  try {
    return createHash("sha256")
      .update(domain, "utf8")
      .update(canonicalRuntimeJson(value), "utf8")
      .digest("hex");
  } catch (error) {
    if (error instanceof RuntimeEffectEnforcerAttestationError) throw error;
    fail("invalid_configuration");
  }
}

function decodeSignature(value: string): Buffer | null {
  if (!ED25519_SIGNATURE.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.byteLength === 64 && decoded.toString("base64url") === value ? decoded : null;
  } catch {
    return null;
  }
}

function signature(value: unknown, code: RuntimeEffectEnforcerAttestationErrorCode): string {
  if (typeof value !== "string" || !decodeSignature(value)) fail(code);
  return value;
}

function safeReference(value: unknown, code: RuntimeEffectEnforcerAttestationErrorCode): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value) || value.trim() !== value) {
    fail(code);
  }
  return value;
}

function keyId(value: unknown, code: RuntimeEffectEnforcerAttestationErrorCode): string {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) fail(code);
  return value;
}

function enforcerKind(
  value: unknown,
  code: RuntimeEffectEnforcerAttestationErrorCode
): RuntimeEffectEnforcerKind {
  if (typeof value !== "string" || !ENFORCER_KINDS.has(value as RuntimeEffectEnforcerKind)) {
    fail(code);
  }
  return value as RuntimeEffectEnforcerKind;
}

function purpose(value: unknown): RuntimeEffectEnforcerPurpose {
  if (typeof value !== "string" || !PURPOSES.has(value as RuntimeEffectEnforcerPurpose)) {
    fail("invalid_attestation");
  }
  return value as RuntimeEffectEnforcerPurpose;
}

function sha256(value: unknown, code: RuntimeEffectEnforcerAttestationErrorCode): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(code);
  return value;
}

function nonNegativeInteger(
  value: unknown,
  code: RuntimeEffectEnforcerAttestationErrorCode
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) fail(code);
  return value as number;
}

function positiveInteger(value: unknown, code: RuntimeEffectEnforcerAttestationErrorCode): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail(code);
  return value as number;
}

function sameDigest(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  try {
    return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
  } catch {
    return false;
  }
}

function fail(code: RuntimeEffectEnforcerAttestationErrorCode): never {
  throw new RuntimeEffectEnforcerAttestationError(code);
}
