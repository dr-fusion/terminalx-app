import {
  createHash,
  createPublicKey,
  sign as signEd25519,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import { types as nodeTypes } from "node:util";
import type { DaytonaAssignmentEffectEnforcerIdentity } from "./daytona-assignment-key-registry";
import {
  type HostedRuntimeActivation,
  type HostedRuntimeAssignmentPlan,
} from "./hosted-runtime-control-plane";
import { digestHostedRuntimeAssignmentPlan } from "./hosted-runtime-adapter";
import {
  RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN,
  digestRuntimeEffectEnforcerManifestClaims,
  snapshotRuntimeEffectEnforcerManifest,
  snapshotRuntimeEffectEnforcerManifestClaims,
  type RuntimeEffectEnforcerManifest,
  type RuntimeEffectEnforcerManifestClaims,
  type RuntimeEffectEnforcerManifestEntry,
} from "./runtime-effect-enforcer-attestation";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";

export const DAYTONA_EFFECT_MANIFEST_BINDING_DIGEST_DOMAIN =
  "terminalx/daytona-effect-manifest-binding/v1\0" as const;
export const DAYTONA_PROVIDER_IDENTITY_DIGEST_DOMAIN =
  "terminalx/daytona-provider-identity/v1\0" as const;

const SHA256 = /^[0-9a-f]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const CREATE_FIELDS = [
  "plan",
  "providerSandboxId",
  "providerRevision",
  "effectEnforcerIdentity",
  "authorityIssuerKeyId",
  "authoritySigningPrivateKey",
  "validFromMs",
  "expiresAtMs",
] as const;
const IDENTITY_FIELDS = [
  "enforcerRef",
  "enforcerKeyId",
  "publicKeySpkiPem",
  "publicKeySpkiDigest",
] as const;

export interface CreateDaytonaAssignmentEffectManifestOptions {
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly providerSandboxId: string;
  readonly providerRevision: number;
  readonly effectEnforcerIdentity: DaytonaAssignmentEffectEnforcerIdentity;
  readonly authorityIssuerKeyId: string;
  readonly authoritySigningPrivateKey: KeyObject;
  readonly validFromMs: number;
  readonly expiresAtMs: number;
}

export interface DaytonaAssignmentEffectManifestRecord {
  readonly manifest: RuntimeEffectEnforcerManifest;
  readonly activation: HostedRuntimeActivation;
}

/**
 * Build one deterministic provider-bound manifest. Callers choose a fixed,
 * deployment-owned validity window; retry paths must persist and replay the
 * returned record instead of sampling a new clock or re-signing it.
 */
export function createDaytonaAssignmentEffectManifest(
  unsafeOptions: CreateDaytonaAssignmentEffectManifestOptions
): DaytonaAssignmentEffectManifestRecord {
  const options = captureCreateOptions(unsafeOptions);
  const assignmentPlanDigest = digestHostedRuntimeAssignmentPlan(options.plan);
  const providerIdentityCommitment = commitDaytonaProviderIdentity(options.providerSandboxId);
  const entry = manifestEntry(options.effectEnforcerIdentity);
  const effectManifestBindingDigest = digestDaytonaEffectManifestBinding({
    assignmentPlanDigest,
    effectEnforcerPolicyDigest: options.plan.effectEnforcerPolicyDigest,
    providerIdentityCommitment,
    providerRevision: options.providerRevision,
    enforcers: [entry],
  });
  const claims: RuntimeEffectEnforcerManifestClaims = Object.freeze({
    version: 1,
    kind: "runtime.effect-enforcer-manifest",
    manifestId: `daytona-effect-manifest:v1:${effectManifestBindingDigest}`,
    assignmentPlanDigest,
    effectEnforcerPolicyDigest: options.plan.effectEnforcerPolicyDigest,
    providerIdentityCommitment,
    providerRevision: options.providerRevision,
    effectManifestBindingDigest,
    validFromMs: options.validFromMs,
    expiresAtMs: options.expiresAtMs,
    enforcers: Object.freeze([entry]),
  });
  const claimsDigest = digestRuntimeEffectEnforcerManifestClaims(claims);
  const authorityStatement = Object.freeze({
    version: 1,
    issuer: "platform-security" as const,
    issuerKeyId: options.authorityIssuerKeyId,
    audience: "terminalx-control-plane" as const,
    capability: "runtime.effect-enforcer-manifest.trust" as const,
    claimsDigest,
    issuedAtMs: options.validFromMs,
    expiresAtMs: options.expiresAtMs,
  });
  const message = Buffer.from(
    `${RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN}${canonicalRuntimeJson(
      authorityStatement
    )}`,
    "utf8"
  );
  let signatureBytes: Buffer | undefined;
  try {
    signatureBytes = signEd25519(null, message, options.authoritySigningPrivateKey);
    const signature = signatureBytes.toString("base64url");
    if (!SIGNATURE.test(signature)) throw new TypeError();
    const manifest = snapshotRuntimeEffectEnforcerManifest({
      ...claims,
      authority: {
        issuer: authorityStatement.issuer,
        issuerKeyId: authorityStatement.issuerKeyId,
        audience: authorityStatement.audience,
        capability: authorityStatement.capability,
        claimsDigest: authorityStatement.claimsDigest,
        issuedAtMs: authorityStatement.issuedAtMs,
        expiresAtMs: authorityStatement.expiresAtMs,
        signature,
      },
    });
    return Object.freeze({
      manifest,
      activation: activationFromManifest(
        manifest,
        options.plan,
        providerIdentityCommitment,
        options.providerRevision
      ),
    });
  } finally {
    message.fill(0);
    signatureBytes?.fill(0);
  }
}

/** Validate exact assignment semantics after generic authority verification. */
export function verifyDaytonaAssignmentEffectManifestBinding(input: {
  readonly manifest: unknown;
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly providerSandboxId: string;
  readonly providerRevision: number;
  readonly nowMs: number;
}): DaytonaAssignmentEffectManifestRecord {
  const record = exactRecord(input, [
    "manifest",
    "plan",
    "providerSandboxId",
    "providerRevision",
    "nowMs",
  ]);
  const manifest = snapshotRuntimeEffectEnforcerManifest(field(record, "manifest"));
  const plan = snapshotPlan(field(record, "plan"));
  const providerSandboxId = uuid(field(record, "providerSandboxId"));
  const providerRevision = positiveInteger(field(record, "providerRevision"));
  const nowMs = nonNegativeInteger(field(record, "nowMs"));
  if (nowMs < manifest.validFromMs || nowMs >= manifest.expiresAtMs) throw new TypeError();
  const providerIdentityCommitment = commitDaytonaProviderIdentity(providerSandboxId);
  const activation = activationFromManifest(
    manifest,
    plan,
    providerIdentityCommitment,
    providerRevision
  );
  return Object.freeze({ manifest, activation });
}

export function commitDaytonaProviderIdentity(providerSandboxId: string): string {
  return sha256(`${DAYTONA_PROVIDER_IDENTITY_DIGEST_DOMAIN}${uuid(providerSandboxId)}`);
}

export function digestDaytonaEffectManifestBinding(value: {
  readonly assignmentPlanDigest: string;
  readonly effectEnforcerPolicyDigest: string;
  readonly providerIdentityCommitment: string;
  readonly providerRevision: number;
  readonly enforcers: readonly RuntimeEffectEnforcerManifestEntry[];
}): string {
  const record = exactRecord(snapshotRuntimeSupervisorPortableData(value), [
    "assignmentPlanDigest",
    "effectEnforcerPolicyDigest",
    "providerIdentityCommitment",
    "providerRevision",
    "enforcers",
  ]);
  const enforcers = field(record, "enforcers");
  if (!Array.isArray(enforcers) || enforcers.length !== 1) throw new TypeError();
  const entry = snapshotRuntimeEffectEnforcerManifestClaims({
    version: 1,
    kind: "runtime.effect-enforcer-manifest",
    manifestId: "binding-validation",
    assignmentPlanDigest: digest(field(record, "assignmentPlanDigest")),
    effectEnforcerPolicyDigest: digest(field(record, "effectEnforcerPolicyDigest")),
    providerIdentityCommitment: digest(field(record, "providerIdentityCommitment")),
    providerRevision: positiveInteger(field(record, "providerRevision")),
    effectManifestBindingDigest: "0".repeat(64),
    validFromMs: 0,
    expiresAtMs: 1,
    enforcers,
  }).enforcers;
  return sha256(
    `${DAYTONA_EFFECT_MANIFEST_BINDING_DIGEST_DOMAIN}${canonicalRuntimeJson({
      version: 1,
      assignmentPlanDigest: digest(field(record, "assignmentPlanDigest")),
      effectEnforcerPolicyDigest: digest(field(record, "effectEnforcerPolicyDigest")),
      providerIdentityCommitment: digest(field(record, "providerIdentityCommitment")),
      providerRevision: positiveInteger(field(record, "providerRevision")),
      enforcers: entry,
    })}`
  );
}

function activationFromManifest(
  manifest: RuntimeEffectEnforcerManifest,
  plan: HostedRuntimeAssignmentPlan,
  providerIdentityCommitment: string,
  providerRevision: number
): HostedRuntimeActivation {
  const assignmentPlanDigest = digestHostedRuntimeAssignmentPlan(plan);
  if (
    !sameDigest(manifest.assignmentPlanDigest, assignmentPlanDigest) ||
    !sameDigest(manifest.effectEnforcerPolicyDigest, plan.effectEnforcerPolicyDigest) ||
    !sameDigest(manifest.providerIdentityCommitment, providerIdentityCommitment) ||
    manifest.providerRevision !== providerRevision ||
    manifest.manifestId !== `daytona-effect-manifest:v1:${manifest.effectManifestBindingDigest}` ||
    manifest.enforcers.length !== 1
  ) {
    throw new TypeError();
  }
  const entry = manifest.enforcers[0];
  if (
    !entry ||
    entry.enforcerKind !== "runtime" ||
    canonicalRuntimeJson(entry.allowedPurposes) !==
      canonicalRuntimeJson(["runtime-lifecycle", "stale-lifecycle-effect-containment"])
  ) {
    throw new TypeError();
  }
  const bindingDigest = digestDaytonaEffectManifestBinding({
    assignmentPlanDigest,
    effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
    providerIdentityCommitment,
    providerRevision,
    enforcers: manifest.enforcers,
  });
  if (!sameDigest(bindingDigest, manifest.effectManifestBindingDigest)) throw new TypeError();
  return Object.freeze({
    version: 1,
    kind: "hosted-runtime.activation",
    binding: plan.binding,
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    assignmentPlanDigest,
    effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
    providerIdentityCommitment,
    providerRevision,
    effectManifestBindingDigest: bindingDigest,
    effectEnforcerSetDigest: manifest.authority.claimsDigest,
  });
}

function captureCreateOptions(value: unknown): CreateDaytonaAssignmentEffectManifestOptions {
  const record = exactRecord(value, CREATE_FIELDS);
  const plan = snapshotPlan(field(record, "plan"));
  const identityRecord = exactRecord(field(record, "effectEnforcerIdentity"), IDENTITY_FIELDS);
  const effectEnforcerIdentity = Object.freeze({
    enforcerRef: safeReference(field(identityRecord, "enforcerRef")),
    enforcerKeyId: keyId(field(identityRecord, "enforcerKeyId")),
    publicKeySpkiPem: canonicalPublicKey(field(identityRecord, "publicKeySpkiPem")),
    publicKeySpkiDigest: digest(field(identityRecord, "publicKeySpkiDigest")),
  });
  if (
    publicKeyDigest(effectEnforcerIdentity.publicKeySpkiPem) !==
    effectEnforcerIdentity.publicKeySpkiDigest
  ) {
    throw new TypeError();
  }
  const authorityIssuerKeyId = keyId(field(record, "authorityIssuerKeyId"));
  const authoritySigningPrivateKey = field(record, "authoritySigningPrivateKey");
  if (
    !nodeTypes.isKeyObject(authoritySigningPrivateKey) ||
    authoritySigningPrivateKey.type !== "private" ||
    authoritySigningPrivateKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new TypeError();
  }
  const authorityPublic = createPublicKey(authoritySigningPrivateKey);
  const authorityDigest = createHash("sha256")
    .update(authorityPublic.export({ type: "spki", format: "der" }))
    .digest("hex");
  if (
    authorityIssuerKeyId === effectEnforcerIdentity.enforcerKeyId ||
    sameDigest(authorityDigest, effectEnforcerIdentity.publicKeySpkiDigest)
  ) {
    throw new TypeError();
  }
  const validFromMs = nonNegativeInteger(field(record, "validFromMs"));
  const expiresAtMs = positiveInteger(field(record, "expiresAtMs"));
  if (expiresAtMs <= validFromMs) throw new TypeError();
  return Object.freeze({
    plan,
    providerSandboxId: uuid(field(record, "providerSandboxId")),
    providerRevision: positiveInteger(field(record, "providerRevision")),
    effectEnforcerIdentity,
    authorityIssuerKeyId,
    authoritySigningPrivateKey,
    validFromMs,
    expiresAtMs,
  });
}

function manifestEntry(
  identity: DaytonaAssignmentEffectEnforcerIdentity
): RuntimeEffectEnforcerManifestEntry {
  return Object.freeze({
    ...identity,
    enforcerKind: "runtime",
    allowedPurposes: Object.freeze([
      "runtime-lifecycle" as const,
      "stale-lifecycle-effect-containment" as const,
    ]),
  });
}

function snapshotPlan(value: unknown): HostedRuntimeAssignmentPlan {
  const plan = snapshotRuntimeSupervisorPortableData(value) as HostedRuntimeAssignmentPlan;
  canonicalRuntimeJson(plan);
  digest(plan.specificationDigest);
  digest(plan.effectEnforcerPolicyDigest);
  positiveInteger(plan.runtimeAuthorizationGeneration);
  return Object.freeze(plan);
}

function canonicalPublicKey(value: unknown): string {
  if (typeof value !== "string" || value.includes("PRIVATE KEY")) throw new TypeError();
  const key = createPublicKey(value);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (canonical !== value) throw new TypeError();
  return canonical;
}

function publicKeyDigest(pem: string): string {
  return createHash("sha256")
    .update(createPublicKey(pem).export({ type: "spki", format: "der" }))
    .digest("hex");
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

function safeReference(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 300 ||
    value !== value.trim() ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError();
  }
  return value;
}

function keyId(value: unknown): string {
  if (typeof value !== "string" || !KEY_ID.test(value)) throw new TypeError();
  return value;
}

function uuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw new TypeError();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TypeError();
  return value as number;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) {
    throw new TypeError();
  }
  return value as number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}
