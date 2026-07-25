import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { types as nodeTypes } from "node:util";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { RuntimeHandle } from "./contracts";
import type { HostedRuntimeAssignmentPlan } from "./hosted-runtime-control-plane";
import { canonicalRuntimeJson } from "./runtime-command-canonical";

/**
 * Slice 8F measured capability activation.
 *
 * The hosted Runtime capabilities `brokeredCredentials` and `proxyOnlyEgress`
 * are never a static config assertion. They are advertised only when a
 * per-deployment, per-Runtime-Assignment **signed measured enforcement
 * evidence** proves — against the Phase 7 trust group keys — that the exact
 * running image (a) carries no ambient provider credentials, (b) reaches the
 * Secret Broker only through the supervisor-mediated channel, and (c) has a
 * measured deny-by-default egress lockdown with only the broker/supervisor
 * endpoints allowlisted. Absence, staleness (bound to the assignment
 * generation and Sandbox boot epoch), or any verification failure derives the
 * capability `false`, so hosted credential operations fail closed.
 *
 * Real-runtime evidence is a Phase 12 deliverable. This module is the exact
 * machinery Phase 12 will drive; nothing here can flip a capability to `true`
 * without a valid signed measurement that matches the exact assignment query.
 */
export const RUNTIME_CAPABILITY_ACTIVATION_EVIDENCE_CLAIMS_DIGEST_DOMAIN =
  "terminalx/runtime-capability-activation-evidence-claims/v1\0" as const;
export const RUNTIME_CAPABILITY_ACTIVATION_EVIDENCE_AUTHORITY_SIGNATURE_DOMAIN =
  "terminalx/runtime-capability-activation-evidence-authority/v1\0" as const;

const EVIDENCE_KIND = "runtime.capability-activation-evidence" as const;
const AUTHORITY_ISSUER = "runtime-effect-enforcer" as const;
const AUTHORITY_AUDIENCE = "terminalx-control-plane" as const;
const AUTHORITY_CAPABILITY = "runtime.capability-activation.attest" as const;

const SHA256 = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const MAX_TRUST_GROUP_KEYS = 64;
const MAX_EVIDENCE_TTL_MS = 5 * 60_000;

const ENFORCER_KINDS = new Set<HostedRuntimeCapabilityActivationEnforcerKind>([
  "runtime",
  "credential-proxy",
  "deployment",
  "signer",
  "other-effect-enforcer",
]);

export type HostedRuntimeCapabilityActivationEnforcerKind =
  | "runtime"
  | "credential-proxy"
  | "deployment"
  | "signer"
  | "other-effect-enforcer";

/** The three deny-by-default measurements gating hosted credential capabilities. */
export interface HostedRuntimeCapabilityActivationMeasurements {
  /** Env/filesystem sweep found no ambient provider credential in the image. */
  readonly ambientProviderCredentialsAbsent: boolean;
  /** The image reaches the Secret Broker only via the supervisor-mediated channel. */
  readonly brokerReachOnlyViaSupervisor: boolean;
  /** Deny-by-default network namespace with only broker/supervisor endpoints allowlisted. */
  readonly egressLockdownMeasured: boolean;
}

export interface HostedRuntimeCapabilityActivationClaims {
  readonly version: 1;
  readonly kind: "runtime.capability-activation-evidence";
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly assignmentPlanDigest: string;
  readonly effectEnforcerPolicyDigest: string;
  readonly effectEnforcerSetDigest: string;
  /** Monotonic Sandbox boot epoch; evidence from an earlier boot is stale. */
  readonly bootEpoch: number;
  readonly measurements: HostedRuntimeCapabilityActivationMeasurements;
  readonly observedAtMs: number;
}

export interface HostedRuntimeCapabilityActivationAuthority {
  readonly issuer: "runtime-effect-enforcer";
  readonly issuerKeyId: string;
  readonly enforcerKind: HostedRuntimeCapabilityActivationEnforcerKind;
  readonly audience: "terminalx-control-plane";
  readonly capability: "runtime.capability-activation.attest";
  readonly enforcerPublicKeySpkiDigest: string;
  readonly claimsDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly signature: string;
}

export interface HostedRuntimeCapabilityActivationEvidence extends HostedRuntimeCapabilityActivationClaims {
  readonly authority: HostedRuntimeCapabilityActivationAuthority;
}

/** Exact per-assignment coordinates a piece of evidence must bind to be usable. */
export interface HostedRuntimeCapabilityActivationQuery {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly assignmentPlanDigest: string;
  readonly effectEnforcerPolicyDigest: string;
  readonly effectEnforcerSetDigest: string;
  readonly bootEpoch: number;
}

/**
 * Trusted local source of the exact measured evidence selected by durable
 * bootstrap. Absence is fail-closed; provider responses must never implement
 * this seam.
 */
export interface HostedRuntimeCapabilityActivationSource {
  resolve(
    query: HostedRuntimeCapabilityActivationQuery
  ): HostedRuntimeCapabilityActivationEvidence | null;
}

/**
 * One Phase 7 trust group public key. In production these are the same
 * operator-owned enforcer keys that admit the effect-enforcer manifest;
 * construction-time selection is the revocation decision.
 */
export interface HostedRuntimeCapabilityActivationTrustGroupKey {
  readonly issuerKeyId: string;
  readonly enforcerKind: HostedRuntimeCapabilityActivationEnforcerKind;
  /** Exact canonical Ed25519 SubjectPublicKeyInfo PEM. Private-key PEM is rejected. */
  readonly publicKeySpkiPem: string;
  readonly publicKeySpkiDigest: string;
}

export type HostedRuntimeCapabilityActivationVerifier = (
  evidence: HostedRuntimeCapabilityActivationEvidence
) => boolean;

export interface CreateHostedRuntimeCapabilityActivationVerifierOptions {
  readonly trustGroupPublicKeys: readonly HostedRuntimeCapabilityActivationTrustGroupKey[];
  readonly clock?: () => number;
  readonly maxEvidenceTtlMs?: number;
}

interface ParsedTrustGroupKey {
  readonly issuerKeyId: string;
  readonly enforcerKind: HostedRuntimeCapabilityActivationEnforcerKind;
  readonly digest: string;
  readonly key: KeyObject;
}

/** Base capabilities that never depend on measured evidence. */
function baseCapabilities(
  planCapabilities: HostedRuntimeAssignmentPlan["capabilities"]
): RuntimeHandle["capabilities"] {
  return {
    isolatedExecution: true,
    brokeredCredentials: false,
    proxyOnlyEgress: false,
    checkpoints: planCapabilities.checkpoints === true,
    yoloEligible: false,
  };
}

/**
 * Derive the exact hosted Runtime handle capabilities from measured evidence.
 * `brokeredCredentials`/`proxyOnlyEgress` become `true` only when a valid,
 * trust-group-signed measurement binds to the exact assignment query; every
 * other outcome (absent/tampered/stale/mismatched/partial) is fail-closed.
 */
export function deriveMeasuredHostedRuntimeCapabilities(
  planCapabilities: HostedRuntimeAssignmentPlan["capabilities"],
  query: HostedRuntimeCapabilityActivationQuery,
  source: HostedRuntimeCapabilityActivationSource,
  verify: HostedRuntimeCapabilityActivationVerifier
): RuntimeHandle["capabilities"] {
  const base = baseCapabilities(planCapabilities);
  let evidence: HostedRuntimeCapabilityActivationEvidence | null;
  try {
    const snapshotQuery = snapshotActivationQuery(query);
    const resolved = source.resolve(snapshotQuery);
    if (resolved === null) return Object.freeze(base);
    if (hasThenableShape(resolved)) return Object.freeze(base);
    evidence = snapshotEvidence(resolved);
    if (!evidenceMatchesQuery(evidence, snapshotQuery)) return Object.freeze(base);
    if (verify(evidence) !== true) return Object.freeze(base);
  } catch {
    return Object.freeze(base);
  }
  const measured = evidence.measurements;
  const proxyOnlyEgress = measured.egressLockdownMeasured === true;
  const brokeredCredentials =
    measured.ambientProviderCredentialsAbsent === true &&
    measured.brokerReachOnlyViaSupervisor === true &&
    proxyOnlyEgress;
  return Object.freeze({
    isolatedExecution: true,
    brokeredCredentials,
    proxyOnlyEgress,
    checkpoints: base.checkpoints,
    yoloEligible: false,
  });
}

/**
 * Build an immutable verifier. All key parsing happens here; the returned
 * function performs only synchronous validation and never touches the network.
 */
export function createHostedRuntimeCapabilityActivationVerifier(
  unsafeOptions: CreateHostedRuntimeCapabilityActivationVerifierOptions
): HostedRuntimeCapabilityActivationVerifier {
  const options = exactRecord(unsafeOptions, [
    "trustGroupPublicKeys",
    ...(hasOwn(unsafeOptions, "clock") ? ["clock"] : []),
    ...(hasOwn(unsafeOptions, "maxEvidenceTtlMs") ? ["maxEvidenceTtlMs"] : []),
  ]);
  const rawKeys = field(options, "trustGroupPublicKeys");
  if (!Array.isArray(rawKeys) || rawKeys.length < 1 || rawKeys.length > MAX_TRUST_GROUP_KEYS) {
    throw new TypeError();
  }
  const clockValue = "clock" in options ? field(options, "clock") : undefined;
  if (
    clockValue !== undefined &&
    (typeof clockValue !== "function" || nodeTypes.isProxy(clockValue))
  ) {
    throw new TypeError();
  }
  const clock = (clockValue as (() => number) | undefined) ?? Date.now;
  const ttlValue = "maxEvidenceTtlMs" in options ? field(options, "maxEvidenceTtlMs") : undefined;
  const maxTtlMs = ttlValue === undefined ? MAX_EVIDENCE_TTL_MS : positiveInteger(ttlValue);
  if (maxTtlMs > MAX_EVIDENCE_TTL_MS) throw new TypeError();

  const byIssuerKeyId = new Map<string, ParsedTrustGroupKey>();
  for (const raw of rawKeys) {
    const parsed = parseTrustGroupKey(raw);
    if (byIssuerKeyId.has(parsed.issuerKeyId)) throw new TypeError();
    byIssuerKeyId.set(parsed.issuerKeyId, parsed);
  }

  return (unsafeEvidence: HostedRuntimeCapabilityActivationEvidence): boolean => {
    try {
      const evidence = snapshotEvidence(unsafeEvidence);
      const now = clock();
      if (!Number.isSafeInteger(now) || now < 0) return false;
      const authority = evidence.authority;
      const pinned = byIssuerKeyId.get(authority.issuerKeyId);
      if (!pinned) return false;
      if (
        pinned.enforcerKind !== authority.enforcerKind ||
        !sameDigest(pinned.digest, authority.enforcerPublicKeySpkiDigest)
      ) {
        return false;
      }
      const claimsDigest = digestClaims(claimsOf(evidence));
      if (!sameDigest(claimsDigest, authority.claimsDigest)) return false;
      if (
        authority.issuedAtMs > evidence.observedAtMs ||
        authority.expiresAtMs <= authority.issuedAtMs ||
        authority.expiresAtMs - authority.issuedAtMs > maxTtlMs ||
        now < authority.issuedAtMs ||
        now >= authority.expiresAtMs
      ) {
        return false;
      }
      const statement = canonicalRuntimeJson(authorityStatement(authority));
      const message = Buffer.concat([
        Buffer.from(RUNTIME_CAPABILITY_ACTIVATION_EVIDENCE_AUTHORITY_SIGNATURE_DOMAIN, "utf8"),
        Buffer.from(statement, "utf8"),
      ]);
      return verifyEd25519(
        null,
        message,
        pinned.key,
        Buffer.from(authority.signature, "base64url")
      );
    } catch {
      return false;
    }
  };
}

/** Lowercase SHA-256 over one exact, domain-separated evidence claims record. */
export function digestHostedRuntimeCapabilityActivationClaims(value: unknown): string {
  const claims = snapshotClaims(value);
  return digestClaims(claims);
}

/** Strictly snapshot a self-consistent evidence record without granting it trust. */
export function snapshotHostedRuntimeCapabilityActivationEvidence(
  value: unknown
): HostedRuntimeCapabilityActivationEvidence {
  return snapshotEvidence(value);
}

function claimsOf(
  evidence: HostedRuntimeCapabilityActivationEvidence
): HostedRuntimeCapabilityActivationClaims {
  return {
    version: evidence.version,
    kind: evidence.kind,
    binding: evidence.binding,
    runtimeAuthorizationGeneration: evidence.runtimeAuthorizationGeneration,
    assignmentPlanDigest: evidence.assignmentPlanDigest,
    effectEnforcerPolicyDigest: evidence.effectEnforcerPolicyDigest,
    effectEnforcerSetDigest: evidence.effectEnforcerSetDigest,
    bootEpoch: evidence.bootEpoch,
    measurements: evidence.measurements,
    observedAtMs: evidence.observedAtMs,
  };
}

function digestClaims(claims: HostedRuntimeCapabilityActivationClaims): string {
  return createHash("sha256")
    .update(RUNTIME_CAPABILITY_ACTIVATION_EVIDENCE_CLAIMS_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(claims), "utf8")
    .digest("hex");
}

function authorityStatement(
  authority: HostedRuntimeCapabilityActivationAuthority
): Record<string, unknown> {
  return {
    version: 1,
    issuer: authority.issuer,
    issuerKeyId: authority.issuerKeyId,
    enforcerKind: authority.enforcerKind,
    audience: authority.audience,
    capability: authority.capability,
    enforcerPublicKeySpkiDigest: authority.enforcerPublicKeySpkiDigest,
    claimsDigest: authority.claimsDigest,
    issuedAtMs: authority.issuedAtMs,
    expiresAtMs: authority.expiresAtMs,
  };
}

function evidenceMatchesQuery(
  evidence: HostedRuntimeCapabilityActivationEvidence,
  query: HostedRuntimeCapabilityActivationQuery
): boolean {
  return (
    canonicalRuntimeJson(evidence.binding) === canonicalRuntimeJson(query.binding) &&
    evidence.runtimeAuthorizationGeneration === query.runtimeAuthorizationGeneration &&
    sameDigest(evidence.assignmentPlanDigest, query.assignmentPlanDigest) &&
    sameDigest(evidence.effectEnforcerPolicyDigest, query.effectEnforcerPolicyDigest) &&
    sameDigest(evidence.effectEnforcerSetDigest, query.effectEnforcerSetDigest) &&
    evidence.bootEpoch === query.bootEpoch
  );
}

function snapshotActivationQuery(value: unknown): HostedRuntimeCapabilityActivationQuery {
  const record = exactRecord(value, [
    "binding",
    "runtimeAuthorizationGeneration",
    "assignmentPlanDigest",
    "effectEnforcerPolicyDigest",
    "effectEnforcerSetDigest",
    "bootEpoch",
  ]);
  return Object.freeze({
    binding: snapshotBinding(field(record, "binding")),
    runtimeAuthorizationGeneration: positiveInteger(
      field(record, "runtimeAuthorizationGeneration")
    ),
    assignmentPlanDigest: digest(field(record, "assignmentPlanDigest")),
    effectEnforcerPolicyDigest: digest(field(record, "effectEnforcerPolicyDigest")),
    effectEnforcerSetDigest: digest(field(record, "effectEnforcerSetDigest")),
    bootEpoch: positiveInteger(field(record, "bootEpoch")),
  });
}

function snapshotEvidence(value: unknown): HostedRuntimeCapabilityActivationEvidence {
  const record = exactRecord(value, [
    "version",
    "kind",
    "binding",
    "runtimeAuthorizationGeneration",
    "assignmentPlanDigest",
    "effectEnforcerPolicyDigest",
    "effectEnforcerSetDigest",
    "bootEpoch",
    "measurements",
    "observedAtMs",
    "authority",
  ]);
  const claims = snapshotClaimsFromRecord(record);
  const authority = snapshotAuthority(field(record, "authority"));
  return Object.freeze({ ...claims, authority });
}

function snapshotClaims(value: unknown): HostedRuntimeCapabilityActivationClaims {
  const record = exactRecord(value, [
    "version",
    "kind",
    "binding",
    "runtimeAuthorizationGeneration",
    "assignmentPlanDigest",
    "effectEnforcerPolicyDigest",
    "effectEnforcerSetDigest",
    "bootEpoch",
    "measurements",
    "observedAtMs",
  ]);
  return snapshotClaimsFromRecord(record);
}

function snapshotClaimsFromRecord(
  record: Record<string, unknown>
): HostedRuntimeCapabilityActivationClaims {
  if (field(record, "version") !== 1 || field(record, "kind") !== EVIDENCE_KIND) {
    throw new TypeError();
  }
  return Object.freeze({
    version: 1,
    kind: EVIDENCE_KIND,
    binding: snapshotBinding(field(record, "binding")),
    runtimeAuthorizationGeneration: positiveInteger(
      field(record, "runtimeAuthorizationGeneration")
    ),
    assignmentPlanDigest: digest(field(record, "assignmentPlanDigest")),
    effectEnforcerPolicyDigest: digest(field(record, "effectEnforcerPolicyDigest")),
    effectEnforcerSetDigest: digest(field(record, "effectEnforcerSetDigest")),
    bootEpoch: positiveInteger(field(record, "bootEpoch")),
    measurements: snapshotMeasurements(field(record, "measurements")),
    observedAtMs: nonNegativeInteger(field(record, "observedAtMs")),
  });
}

function snapshotMeasurements(value: unknown): HostedRuntimeCapabilityActivationMeasurements {
  const record = exactRecord(value, [
    "ambientProviderCredentialsAbsent",
    "brokerReachOnlyViaSupervisor",
    "egressLockdownMeasured",
  ]);
  return Object.freeze({
    ambientProviderCredentialsAbsent: booleanValue(
      field(record, "ambientProviderCredentialsAbsent")
    ),
    brokerReachOnlyViaSupervisor: booleanValue(field(record, "brokerReachOnlyViaSupervisor")),
    egressLockdownMeasured: booleanValue(field(record, "egressLockdownMeasured")),
  });
}

function snapshotAuthority(value: unknown): HostedRuntimeCapabilityActivationAuthority {
  const record = exactRecord(value, [
    "issuer",
    "issuerKeyId",
    "enforcerKind",
    "audience",
    "capability",
    "enforcerPublicKeySpkiDigest",
    "claimsDigest",
    "issuedAtMs",
    "expiresAtMs",
    "signature",
  ]);
  const enforcerKind = field(record, "enforcerKind");
  if (
    field(record, "issuer") !== AUTHORITY_ISSUER ||
    field(record, "audience") !== AUTHORITY_AUDIENCE ||
    field(record, "capability") !== AUTHORITY_CAPABILITY ||
    typeof enforcerKind !== "string" ||
    !ENFORCER_KINDS.has(enforcerKind as HostedRuntimeCapabilityActivationEnforcerKind)
  ) {
    throw new TypeError();
  }
  const signature = field(record, "signature");
  if (typeof signature !== "string" || !ED25519_SIGNATURE.test(signature)) throw new TypeError();
  return Object.freeze({
    issuer: AUTHORITY_ISSUER,
    issuerKeyId: keyId(field(record, "issuerKeyId")),
    enforcerKind: enforcerKind as HostedRuntimeCapabilityActivationEnforcerKind,
    audience: AUTHORITY_AUDIENCE,
    capability: AUTHORITY_CAPABILITY,
    enforcerPublicKeySpkiDigest: digest(field(record, "enforcerPublicKeySpkiDigest")),
    claimsDigest: digest(field(record, "claimsDigest")),
    issuedAtMs: nonNegativeInteger(field(record, "issuedAtMs")),
    expiresAtMs: nonNegativeInteger(field(record, "expiresAtMs")),
    signature,
  });
}

function parseTrustGroupKey(value: unknown): ParsedTrustGroupKey {
  const record = exactRecord(value, [
    "issuerKeyId",
    "enforcerKind",
    "publicKeySpkiPem",
    "publicKeySpkiDigest",
  ]);
  const enforcerKind = field(record, "enforcerKind");
  if (
    typeof enforcerKind !== "string" ||
    !ENFORCER_KINDS.has(enforcerKind as HostedRuntimeCapabilityActivationEnforcerKind)
  ) {
    throw new TypeError();
  }
  const pem = field(record, "publicKeySpkiPem");
  const declaredDigest = digest(field(record, "publicKeySpkiDigest"));
  if (typeof pem !== "string" || Buffer.byteLength(pem, "utf8") > MAX_PUBLIC_KEY_BYTES) {
    throw new TypeError();
  }
  const key = createPublicKey({ key: pem, format: "pem" });
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
  const canonicalPem = key.export({ type: "spki", format: "pem" }).toString();
  const der = key.export({ type: "spki", format: "der" });
  const computedDigest = createHash("sha256").update(der).digest("hex");
  if (pem !== canonicalPem || !sameDigest(computedDigest, declaredDigest)) throw new TypeError();
  return {
    issuerKeyId: keyId(field(record, "issuerKeyId")),
    enforcerKind: enforcerKind as HostedRuntimeCapabilityActivationEnforcerKind,
    digest: computedDigest,
    key,
  };
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const record = exactRecord(value, [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ]);
  return Object.freeze({
    teamId: safeReference(field(record, "teamId")),
    projectId: safeReference(field(record, "projectId")),
    sessionId: safeReference(field(record, "sessionId")),
    runtimeAssignmentId: safeReference(field(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(record, "runtimeAssignmentGeneration")),
    sandboxId: safeReference(field(record, "sandboxId")),
    sandboxGeneration: positiveInteger(field(record, "sandboxGeneration")),
    runtimePrincipalId: safeReference(field(record, "runtimePrincipalId")),
  });
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new TypeError();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of fields) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function hasOwn(value: unknown, name: string): boolean {
  return typeof value === "object" && value !== null && Object.hasOwn(value, name);
}

function hasThenableShape(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false;
  const descriptor = Object.getOwnPropertyDescriptor(value, "then");
  return descriptor !== undefined;
}

function booleanValue(value: unknown): boolean {
  if (typeof value !== "boolean") throw new TypeError();
  return value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value) || value !== value.trim()) {
    throw new TypeError();
  }
  return value;
}

function keyId(value: unknown): string {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) throw new TypeError();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || Object.is(value, -0)) {
    throw new TypeError();
  }
  return value as number;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) {
    throw new TypeError();
  }
  return value as number;
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}
