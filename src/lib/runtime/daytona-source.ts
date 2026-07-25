import { createHash, timingSafeEqual } from "node:crypto";
import { types as utilTypes } from "node:util";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import { suppressNativePromiseRejection } from "./runtime-native-promise";

export const DAYTONA_FORK_REPOSITORY = "https://github.com/procyon-labs-io/daytona";
export const DAYTONA_PRODUCTION_FORK_COMMIT = "f9b4dfe428d37f3d956acda4403879516aa8d923";
export const DAYTONA_UPSTREAM_REPOSITORY = "https://github.com/daytonaio/daytona";
export const DAYTONA_UPSTREAM_BASE_COMMIT = "b5a5d9e78d76c8bcf351f2049620250e0f34eea4";
export const DAYTONA_DEPLOYMENT_MANIFEST_CLAIMS_DIGEST_DOMAIN =
  "terminalx/daytona-deployment-manifest-claims/v1\0" as const;
export const DAYTONA_DEPLOYMENT_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN =
  "terminalx/daytona-deployment-manifest-authority/v1\0" as const;

const MANIFEST_KIND = "terminalx.daytona-deployment-artifacts" as const;
const AUTHORITY_ISSUER = "terminalx-release" as const;
const AUTHORITY_AUDIENCE = "terminalx-runtime" as const;
const AUTHORITY_CAPABILITY = "daytona.deployment.activate" as const;
const AUTHORITY_ALGORITHM = "ed25519" as const;
const SHA256 = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const SAFE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const OCI_IMAGE_REFERENCE = /^[a-z0-9][a-z0-9._:/-]{0,446}@sha256:[0-9a-f]{64}$/;
const DOCKER_IMAGE_ID = /^sha256:[0-9a-f]{64}$/;
const DAYTONA_SNAPSHOT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FLOATING_REFERENCES = new Set([
  "current",
  "default",
  "head",
  "latest",
  "main",
  "master",
  "stable",
]);

const SOURCE_ENVIRONMENT_FIELDS = [
  "TERMINALX_DAYTONA_FORK_REPOSITORY",
  "TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT",
] as const;
const SOURCE_FIELDS = [
  "forkRepository",
  "forkCommit",
  "upstreamRepository",
  "upstreamBaseCommit",
] as const;
const ARTIFACT_FIELDS = ["sdk", "supervisor", "sbom", "provenance"] as const;
const SDK_ARTIFACT_FIELDS = ["kind", "sha256"] as const;
const SUPERVISOR_ARTIFACT_FIELDS = ["kind", "sha256"] as const;
const SBOM_ARTIFACT_FIELDS = ["kind", "sha256"] as const;
const PROVENANCE_ARTIFACT_FIELDS = ["kind", "sha256"] as const;
const IMAGE_FIELDS = ["kind", "reference", "sha256"] as const;
const SNAPSHOT_FIELDS = ["kind", "snapshotId", "snapshotRef", "imageId", "sha256"] as const;
const ISOLATION_PROFILE_FIELDS = ["profileRef", "sha256"] as const;
const MANIFEST_CLAIMS_FIELDS = [
  "version",
  "kind",
  "manifestId",
  "issuedAtMs",
  "source",
  "artifacts",
  "sandboxArtifact",
  "isolationProfile",
] as const;
const MANIFEST_FIELDS = [...MANIFEST_CLAIMS_FIELDS, "authority"] as const;
const AUTHORITY_FIELDS = [
  "issuer",
  "issuerKeyId",
  "audience",
  "capability",
  "algorithm",
  "claimsDigest",
  "signature",
] as const;
const AUTHORITY_STATEMENT_FIELDS = [
  "version",
  "issuer",
  "issuerKeyId",
  "audience",
  "capability",
  "algorithm",
  "claimsDigest",
] as const;
const VERIFY_OPTIONS_FIELDS = ["sourceEnvironment", "manifest", "signatureVerifier"] as const;
const SIGNATURE_VERIFICATION_FIELDS = [
  "algorithm",
  "issuerKeyId",
  "claimsDigest",
  "canonicalPayload",
  "signature",
] as const;

export interface DaytonaSourcePin {
  readonly forkRepository: typeof DAYTONA_FORK_REPOSITORY;
  readonly forkCommit: typeof DAYTONA_PRODUCTION_FORK_COMMIT;
  readonly upstreamRepository: typeof DAYTONA_UPSTREAM_REPOSITORY;
  readonly upstreamBaseCommit: typeof DAYTONA_UPSTREAM_BASE_COMMIT;
}

export interface DaytonaSourceEnvironment {
  readonly TERMINALX_DAYTONA_FORK_REPOSITORY?: string;
  readonly TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT?: string;
}

export interface DaytonaDeploymentArtifactPin<Kind extends string> {
  readonly kind: Kind;
  /** Lowercase raw SHA-256, without a `sha256:` prefix. */
  readonly sha256: string;
}

export interface DaytonaDeploymentArtifacts {
  readonly sdk: DaytonaDeploymentArtifactPin<"daytona-typescript-sdk">;
  readonly supervisor: DaytonaDeploymentArtifactPin<"terminalx-daytona-supervisor">;
  readonly sbom: DaytonaDeploymentArtifactPin<"spdx-2.3-json">;
  readonly provenance: DaytonaDeploymentArtifactPin<"slsa-v1-dsse">;
}

export type DaytonaImmutableSandboxArtifact =
  | {
      readonly kind: "oci-image";
      /** Canonical lowercase OCI reference ending in the same `@sha256:` digest. */
      readonly reference: string;
      readonly sha256: string;
    }
  | {
      readonly kind: "daytona-snapshot";
      /** Immutable UUID v4 assigned by the pinned Daytona snapshot service. */
      readonly snapshotId: string;
      /** Exact preloaded runner reference resolved from `snapshotId`. */
      readonly snapshotRef: string;
      /** Docker-inspected image configuration ID, pinned independently of the reference. */
      readonly imageId: string;
      /** Snapshot manifest digest attested by release provenance. */
      readonly sha256: string;
    };

export interface DaytonaIsolationProfilePin {
  readonly profileRef: string;
  readonly sha256: string;
}

export interface DaytonaDeploymentArtifactManifestClaims {
  readonly version: 1;
  readonly kind: typeof MANIFEST_KIND;
  readonly manifestId: string;
  readonly issuedAtMs: number;
  readonly source: DaytonaSourcePin;
  readonly artifacts: DaytonaDeploymentArtifacts;
  readonly sandboxArtifact: DaytonaImmutableSandboxArtifact;
  readonly isolationProfile: DaytonaIsolationProfilePin;
}

export interface DaytonaDeploymentArtifactManifestAuthority {
  readonly issuer: typeof AUTHORITY_ISSUER;
  readonly issuerKeyId: string;
  readonly audience: typeof AUTHORITY_AUDIENCE;
  readonly capability: typeof AUTHORITY_CAPABILITY;
  readonly algorithm: typeof AUTHORITY_ALGORITHM;
  readonly claimsDigest: string;
  readonly signature: string;
}

export interface DaytonaDeploymentArtifactManifest extends DaytonaDeploymentArtifactManifestClaims {
  readonly authority: DaytonaDeploymentArtifactManifestAuthority;
}

/** Detached, canonical input for a local pinned-key signature verifier. */
export interface DaytonaDeploymentManifestSignatureVerification {
  readonly algorithm: typeof AUTHORITY_ALGORITHM;
  readonly issuerKeyId: string;
  readonly claimsDigest: string;
  readonly canonicalPayload: string;
  readonly signature: string;
}

/**
 * This verifier is deliberately synchronous. Implementations must use locally
 * pinned trust material; Promise/thenable results fail closed.
 */
export type DaytonaDeploymentManifestSignatureVerifier = (
  verification: DaytonaDeploymentManifestSignatureVerification
) => boolean;

export interface VerifyDaytonaDeploymentArtifactsOptions {
  readonly sourceEnvironment: DaytonaSourceEnvironment;
  readonly manifest: unknown;
  readonly signatureVerifier: DaytonaDeploymentManifestSignatureVerifier;
}

export interface VerifiedDaytonaDeploymentArtifacts {
  readonly sourcePin: DaytonaSourcePin;
  readonly manifestDigest: string;
  readonly manifest: DaytonaDeploymentArtifactManifest;
}

export type DaytonaDeploymentArtifactErrorCode =
  | "invalid_source_pin"
  | "missing_source_pin"
  | "invalid_configuration"
  | "invalid_manifest"
  | "manifest_mismatch"
  | "invalid_signature";

const SAFE_ERROR_MESSAGES: Readonly<Record<DaytonaDeploymentArtifactErrorCode, string>> = {
  invalid_source_pin: "Daytona source pin is invalid",
  missing_source_pin: "Daytona source pin is required",
  invalid_configuration: "Daytona deployment artifact configuration is invalid",
  invalid_manifest: "Daytona deployment artifact manifest is invalid",
  manifest_mismatch: "Daytona deployment artifact manifest does not match the production pin",
  invalid_signature: "Daytona deployment artifact manifest signature is invalid",
};

/** Safe failure surface: manifest contents, signatures, and verifier errors never escape. */
export class DaytonaDeploymentArtifactError extends Error {
  constructor(readonly code: DaytonaDeploymentArtifactErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "DaytonaDeploymentArtifactError";
  }
}

/**
 * Resolve the one accepted fork/base pair. An absent pair keeps optional
 * development composition disabled; `verifyDaytonaDeploymentArtifacts` turns
 * that absence into a production startup failure.
 */
export function resolveDaytonaSourcePin(
  unsafeEnvironment: DaytonaSourceEnvironment = {
    TERMINALX_DAYTONA_FORK_REPOSITORY: process.env.TERMINALX_DAYTONA_FORK_REPOSITORY,
    TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: process.env.TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT,
  }
): DaytonaSourcePin | null {
  const environment = sourceEnvironment(unsafeEnvironment);
  const repository = optionalField(environment, "TERMINALX_DAYTONA_FORK_REPOSITORY");
  const commit = optionalField(environment, "TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT");
  if (repository === undefined && commit === undefined) return null;
  if (repository !== DAYTONA_FORK_REPOSITORY || commit !== DAYTONA_PRODUCTION_FORK_COMMIT) {
    fail("invalid_source_pin");
  }
  return productionSourcePin();
}

/** Lowercase SHA-256 over the domain-separated canonical manifest claims. */
export function digestDaytonaDeploymentArtifactManifestClaims(value: unknown): string {
  const claims = snapshotManifestClaims(value);
  return createHash("sha256")
    .update(DAYTONA_DEPLOYMENT_MANIFEST_CLAIMS_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(claims), "utf8")
    .digest("hex");
}

/**
 * Complete local production activation gate. It performs no network or file
 * I/O: callers supply already-loaded declarative data and a synchronous local
 * pinned-key verifier. This verifies the signed manifest, not artifact bytes;
 * consumers must fetch by immutable digest or compare locally measured hashes.
 */
export function verifyDaytonaDeploymentArtifacts(
  unsafeOptions: VerifyDaytonaDeploymentArtifactsOptions
): VerifiedDaytonaDeploymentArtifacts {
  const options = exactRecord(unsafeOptions, VERIFY_OPTIONS_FIELDS, "invalid_configuration");
  const unsafeSourceEnvironment = field(options, "sourceEnvironment", "invalid_configuration");
  if (unsafeSourceEnvironment === undefined) fail("invalid_configuration");
  const sourcePin = resolveDaytonaSourcePin(unsafeSourceEnvironment as DaytonaSourceEnvironment);
  if (sourcePin === null) fail("missing_source_pin");

  const signatureVerifier = field(options, "signatureVerifier", "invalid_configuration");
  if (typeof signatureVerifier !== "function" || utilTypes.isProxy(signatureVerifier)) {
    fail("invalid_configuration");
  }
  const parsed = parseManifest(field(options, "manifest", "invalid_configuration"));
  if (!sameSourcePin(parsed.manifest.source, sourcePin)) fail("manifest_mismatch");
  verifyManifestSignature(
    parsed.manifest,
    parsed.manifestDigest,
    signatureVerifier as DaytonaDeploymentManifestSignatureVerifier
  );
  return Object.freeze({
    sourcePin,
    manifestDigest: parsed.manifestDigest,
    manifest: parsed.manifest,
  });
}

interface ParsedManifest {
  readonly manifest: DaytonaDeploymentArtifactManifest;
  readonly manifestDigest: string;
}

function parseManifest(value: unknown): ParsedManifest {
  const record = exactRecord(value, MANIFEST_FIELDS, "invalid_manifest");
  const claims = snapshotManifestClaimsRecord(record);
  const authority = snapshotAuthority(field(record, "authority", "invalid_manifest"));
  const manifestDigest = digestSnapshotClaims(claims);
  if (!sameDigest(authority.claimsDigest, manifestDigest)) fail("manifest_mismatch");
  return {
    manifest: Object.freeze({ ...claims, authority }),
    manifestDigest,
  };
}

function snapshotManifestClaims(value: unknown): DaytonaDeploymentArtifactManifestClaims {
  return snapshotManifestClaimsRecord(
    exactRecord(value, MANIFEST_CLAIMS_FIELDS, "invalid_manifest")
  );
}

function snapshotManifestClaimsRecord(
  record: Record<string, unknown>
): DaytonaDeploymentArtifactManifestClaims {
  if (field(record, "version", "invalid_manifest") !== 1) fail("invalid_manifest");
  if (field(record, "kind", "invalid_manifest") !== MANIFEST_KIND) fail("invalid_manifest");
  const manifestId = safeReference(field(record, "manifestId", "invalid_manifest"));
  const issuedAtMs = safeInstant(field(record, "issuedAtMs", "invalid_manifest"));
  const source = snapshotSource(field(record, "source", "invalid_manifest"));
  const artifacts = snapshotArtifacts(field(record, "artifacts", "invalid_manifest"));
  const sandboxArtifact = snapshotSandboxArtifact(
    field(record, "sandboxArtifact", "invalid_manifest")
  );
  const isolationProfile = snapshotIsolationProfile(
    field(record, "isolationProfile", "invalid_manifest")
  );
  const digests = [
    artifacts.sdk.sha256,
    artifacts.supervisor.sha256,
    artifacts.sbom.sha256,
    artifacts.provenance.sha256,
    sandboxArtifact.sha256,
    isolationProfile.sha256,
  ];
  if (new Set(digests).size !== digests.length) fail("invalid_manifest");
  return Object.freeze({
    version: 1,
    kind: MANIFEST_KIND,
    manifestId,
    issuedAtMs,
    source,
    artifacts,
    sandboxArtifact,
    isolationProfile,
  });
}

function snapshotSource(value: unknown): DaytonaSourcePin {
  const source = exactRecord(value, SOURCE_FIELDS, "invalid_manifest");
  if (
    field(source, "forkRepository", "invalid_manifest") !== DAYTONA_FORK_REPOSITORY ||
    field(source, "forkCommit", "invalid_manifest") !== DAYTONA_PRODUCTION_FORK_COMMIT ||
    field(source, "upstreamRepository", "invalid_manifest") !== DAYTONA_UPSTREAM_REPOSITORY ||
    field(source, "upstreamBaseCommit", "invalid_manifest") !== DAYTONA_UPSTREAM_BASE_COMMIT
  ) {
    fail("manifest_mismatch");
  }
  return productionSourcePin();
}

function snapshotArtifacts(value: unknown): DaytonaDeploymentArtifacts {
  const artifacts = exactRecord(value, ARTIFACT_FIELDS, "invalid_manifest");
  return Object.freeze({
    sdk: snapshotArtifact(
      field(artifacts, "sdk", "invalid_manifest"),
      SDK_ARTIFACT_FIELDS,
      "daytona-typescript-sdk"
    ),
    supervisor: snapshotArtifact(
      field(artifacts, "supervisor", "invalid_manifest"),
      SUPERVISOR_ARTIFACT_FIELDS,
      "terminalx-daytona-supervisor"
    ),
    sbom: snapshotArtifact(
      field(artifacts, "sbom", "invalid_manifest"),
      SBOM_ARTIFACT_FIELDS,
      "spdx-2.3-json"
    ),
    provenance: snapshotArtifact(
      field(artifacts, "provenance", "invalid_manifest"),
      PROVENANCE_ARTIFACT_FIELDS,
      "slsa-v1-dsse"
    ),
  });
}

function snapshotArtifact<
  Kind extends DaytonaDeploymentArtifacts[keyof DaytonaDeploymentArtifacts]["kind"],
>(
  value: unknown,
  expectedFields: readonly string[],
  expectedKind: Kind
): DaytonaDeploymentArtifactPin<Kind> {
  const artifact = exactRecord(value, expectedFields, "invalid_manifest");
  if (field(artifact, "kind", "invalid_manifest") !== expectedKind) fail("invalid_manifest");
  return Object.freeze({
    kind: expectedKind,
    sha256: sha256(field(artifact, "sha256", "invalid_manifest")),
  });
}

function snapshotSandboxArtifact(value: unknown): DaytonaImmutableSandboxArtifact {
  const candidate = plainRecord(value, "invalid_manifest");
  const kind = field(candidate, "kind", "invalid_manifest");
  if (kind === "oci-image") {
    const image = exactRecord(candidate, IMAGE_FIELDS, "invalid_manifest");
    const reference = field(image, "reference", "invalid_manifest");
    const digest = sha256(field(image, "sha256", "invalid_manifest"));
    if (
      typeof reference !== "string" ||
      !OCI_IMAGE_REFERENCE.test(reference) ||
      reference.includes("://") ||
      reference.includes("//") ||
      !reference.endsWith(`@sha256:${digest}`)
    ) {
      fail("invalid_manifest");
    }
    return Object.freeze({ kind, reference, sha256: digest });
  }
  if (kind === "daytona-snapshot") {
    const snapshot = exactRecord(candidate, SNAPSHOT_FIELDS, "invalid_manifest");
    const snapshotRef = field(snapshot, "snapshotRef", "invalid_manifest");
    const imageId = field(snapshot, "imageId", "invalid_manifest");
    const digest = sha256(field(snapshot, "sha256", "invalid_manifest"));
    if (
      typeof snapshotRef !== "string" ||
      !OCI_IMAGE_REFERENCE.test(snapshotRef) ||
      snapshotRef.includes("://") ||
      snapshotRef.includes("//") ||
      !snapshotRef.endsWith(`@sha256:${digest}`) ||
      typeof imageId !== "string" ||
      !DOCKER_IMAGE_ID.test(imageId)
    ) {
      fail("invalid_manifest");
    }
    return Object.freeze({
      kind,
      snapshotId: daytonaSnapshotId(field(snapshot, "snapshotId", "invalid_manifest")),
      snapshotRef,
      imageId,
      sha256: digest,
    });
  }
  fail("invalid_manifest");
}

function snapshotIsolationProfile(value: unknown): DaytonaIsolationProfilePin {
  const profile = exactRecord(value, ISOLATION_PROFILE_FIELDS, "invalid_manifest");
  return Object.freeze({
    profileRef: immutableReference(field(profile, "profileRef", "invalid_manifest")),
    sha256: sha256(field(profile, "sha256", "invalid_manifest")),
  });
}

function snapshotAuthority(value: unknown): DaytonaDeploymentArtifactManifestAuthority {
  const authority = exactRecord(value, AUTHORITY_FIELDS, "invalid_manifest");
  if (
    field(authority, "issuer", "invalid_manifest") !== AUTHORITY_ISSUER ||
    field(authority, "audience", "invalid_manifest") !== AUTHORITY_AUDIENCE ||
    field(authority, "capability", "invalid_manifest") !== AUTHORITY_CAPABILITY ||
    field(authority, "algorithm", "invalid_manifest") !== AUTHORITY_ALGORITHM
  ) {
    fail("invalid_manifest");
  }
  const signature = ed25519Signature(field(authority, "signature", "invalid_manifest"));
  return Object.freeze({
    issuer: AUTHORITY_ISSUER,
    issuerKeyId: safeReference(field(authority, "issuerKeyId", "invalid_manifest")),
    audience: AUTHORITY_AUDIENCE,
    capability: AUTHORITY_CAPABILITY,
    algorithm: AUTHORITY_ALGORITHM,
    claimsDigest: sha256(field(authority, "claimsDigest", "invalid_manifest")),
    signature,
  });
}

function verifyManifestSignature(
  manifest: DaytonaDeploymentArtifactManifest,
  manifestDigest: string,
  signatureVerifier: DaytonaDeploymentManifestSignatureVerifier
): void {
  const statement = exactRecord(
    Object.freeze({
      version: 1,
      issuer: manifest.authority.issuer,
      issuerKeyId: manifest.authority.issuerKeyId,
      audience: manifest.authority.audience,
      capability: manifest.authority.capability,
      algorithm: manifest.authority.algorithm,
      claimsDigest: manifestDigest,
    }),
    AUTHORITY_STATEMENT_FIELDS,
    "invalid_signature"
  );
  const verification = exactRecord(
    Object.freeze({
      algorithm: AUTHORITY_ALGORITHM,
      issuerKeyId: manifest.authority.issuerKeyId,
      claimsDigest: manifestDigest,
      canonicalPayload:
        DAYTONA_DEPLOYMENT_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN + canonicalRuntimeJson(statement),
      signature: manifest.authority.signature,
    }),
    SIGNATURE_VERIFICATION_FIELDS,
    "invalid_signature"
  ) as unknown as DaytonaDeploymentManifestSignatureVerification;

  let verified: unknown;
  try {
    verified = Reflect.apply(signatureVerifier, undefined, [verification]);
  } catch {
    fail("invalid_signature");
  }
  if (verified !== true) {
    suppressNativePromiseRejection(verified);
    fail("invalid_signature");
  }
}

function digestSnapshotClaims(claims: DaytonaDeploymentArtifactManifestClaims): string {
  return createHash("sha256")
    .update(DAYTONA_DEPLOYMENT_MANIFEST_CLAIMS_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(claims), "utf8")
    .digest("hex");
}

function productionSourcePin(): DaytonaSourcePin {
  return Object.freeze({
    forkRepository: DAYTONA_FORK_REPOSITORY,
    forkCommit: DAYTONA_PRODUCTION_FORK_COMMIT,
    upstreamRepository: DAYTONA_UPSTREAM_REPOSITORY,
    upstreamBaseCommit: DAYTONA_UPSTREAM_BASE_COMMIT,
  });
}

function sameSourcePin(left: DaytonaSourcePin, right: DaytonaSourcePin): boolean {
  return SOURCE_FIELDS.every((key) => left[key] === right[key]);
}

function sourceEnvironment(value: unknown): Record<string, unknown> {
  const environment = plainRecord(value, "invalid_source_pin");
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(environment);
  } catch {
    fail("invalid_source_pin");
  }
  if (
    keys.some((key) => typeof key !== "string" || !SOURCE_ENVIRONMENT_FIELDS.includes(key as never))
  ) {
    fail("invalid_source_pin");
  }
  for (const key of keys) field(environment, key as string, "invalid_source_pin");
  return environment;
}

function exactRecord(
  value: unknown,
  expectedFields: readonly string[],
  code: DaytonaDeploymentArtifactErrorCode
): Record<string, unknown> {
  const record = plainRecord(value, code);
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(record);
  } catch {
    fail(code);
  }
  if (
    keys.length !== expectedFields.length ||
    keys.some((key) => typeof key !== "string" || !expectedFields.includes(key))
  ) {
    fail(code);
  }
  for (const key of expectedFields) field(record, key, code);
  return record;
}

function plainRecord(
  value: unknown,
  code: DaytonaDeploymentArtifactErrorCode
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

function field(
  record: Record<string, unknown>,
  key: string,
  code: DaytonaDeploymentArtifactErrorCode
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

function optionalField(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (descriptor === undefined) return undefined;
  if (!descriptor.enumerable || !("value" in descriptor)) fail("invalid_source_pin");
  return descriptor.value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) fail("invalid_manifest");
  return value;
}

function immutableReference(value: unknown): string {
  const reference = safeReference(value);
  if (FLOATING_REFERENCES.has(reference.toLowerCase())) fail("invalid_manifest");
  return reference;
}

function daytonaSnapshotId(value: unknown): string {
  if (typeof value !== "string" || !DAYTONA_SNAPSHOT_ID.test(value)) fail("invalid_manifest");
  return value;
}

function safeInstant(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail("invalid_manifest");
  return value as number;
}

function sha256(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail("invalid_manifest");
  return value;
}

function ed25519Signature(value: unknown): string {
  if (typeof value !== "string" || !ED25519_SIGNATURE.test(value)) fail("invalid_signature");
  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    fail("invalid_signature");
  }
  if (decoded.byteLength !== 64 || decoded.toString("base64url") !== value) {
    fail("invalid_signature");
  }
  return value;
}

function sameDigest(left: string, right: string): boolean {
  return timingSafeEqual(Buffer.from(left, "ascii"), Buffer.from(right, "ascii"));
}

function fail(code: DaytonaDeploymentArtifactErrorCode): never {
  throw new DaytonaDeploymentArtifactError(code);
}
