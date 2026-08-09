import { timingSafeEqual } from "node:crypto";
import { types as nodeTypes } from "node:util";
import type { HostedRuntimeActivation } from "./hosted-runtime-control-plane";
import { snapshotHostedRuntimeActivation } from "./hosted-runtime-activation";
import {
  createRuntimeEffectEnforcerTrustRegistry,
  createRuntimeEffectEnforcerTrustRegistryWithAttestationSource,
  digestRuntimeEffectEnforcerAttestation,
  snapshotRuntimeEffectEnforcerAttestation,
  snapshotRuntimeEffectEnforcerManifest,
  type PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey,
  type RuntimeEffectEnforcerManifest,
  type RuntimeEffectEnforcerTrustRegistry,
} from "./runtime-effect-enforcer-attestation";
import type { SynchronousRuntimeCompensationEnforcementProofVerifier } from "./runtime-compensation-enforcement-proof";
import type { SynchronousRuntimeEnforcementProofVerifier } from "./runtime-enforcement-proof";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";

const SHA256 = /^[0-9a-f]{64}$/;
const MAX_MANIFESTS = 4096;
const MAX_ATTESTATIONS = 65_536;

export interface RuntimeEffectEnforcerManifestActivation {
  readonly manifest: RuntimeEffectEnforcerManifest;
  readonly activation: HostedRuntimeActivation;
}

export interface RuntimeEffectEnforcerAttestationBatch {
  readonly effectEnforcerSetDigest: string;
  readonly attestations: readonly unknown[];
}

export interface CreateRuntimeEffectEnforcerTrustRouterOptions {
  readonly pinnedManifestAuthorityPublicKeys: readonly PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey[];
}

/**
 * Process-local, digest-routed trust cache. Public manifests are rehydrated
 * from each durable bootstrap intent, while signed attestations are rehydrated
 * from the supervisor's durable command/follow replay envelope.
 */
export interface RuntimeEffectEnforcerTrustRouter {
  readonly registerManifest: (record: RuntimeEffectEnforcerManifestActivation) => void;
  readonly registerAttestations: (batch: RuntimeEffectEnforcerAttestationBatch) => void;
  readonly verifyRuntimeEnforcementProof: SynchronousRuntimeEnforcementProofVerifier;
  readonly verifyRuntimeCompensationEnforcementProof: SynchronousRuntimeCompensationEnforcementProofVerifier;
  readonly close: () => void;
}

interface RoutedManifest {
  readonly manifest: RuntimeEffectEnforcerManifest;
  readonly activation: HostedRuntimeActivation;
  readonly attestations: Map<string, unknown>;
  readonly registry: RuntimeEffectEnforcerTrustRegistry;
}

export function createRuntimeEffectEnforcerTrustRouter(
  unsafeOptions: CreateRuntimeEffectEnforcerTrustRouterOptions
): RuntimeEffectEnforcerTrustRouter {
  const options = exactRecord(unsafeOptions, ["pinnedManifestAuthorityPublicKeys"]);
  const pins = snapshotRuntimeSupervisorPortableData(
    field(options, "pinnedManifestAuthorityPublicKeys")
  ) as readonly PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey[];
  if (!Array.isArray(pins) || pins.length < 1 || pins.length > 64) throw new TypeError();
  const manifests = new Map<string, RoutedManifest>();
  let attestationCount = 0;
  let closed = false;

  const registerManifest = (unsafeRecord: RuntimeEffectEnforcerManifestActivation): void => {
    if (closed) throw new TypeError();
    const record = exactRecord(unsafeRecord, ["manifest", "activation"]);
    const manifest = snapshotRuntimeEffectEnforcerManifest(field(record, "manifest"));
    const activation = snapshotHostedRuntimeActivation(field(record, "activation"));
    assertManifestActivation(manifest, activation);
    const digest = activation.effectEnforcerSetDigest;
    const existing = manifests.get(digest);
    if (existing) {
      if (
        canonicalRuntimeJson(existing.manifest) !== canonicalRuntimeJson(manifest) ||
        canonicalRuntimeJson(existing.activation) !== canonicalRuntimeJson(activation)
      ) {
        throw new TypeError();
      }
      return;
    }
    if (manifests.size >= MAX_MANIFESTS) throw new TypeError();
    const attestations = new Map<string, unknown>();
    const registry = createRuntimeEffectEnforcerTrustRegistryWithAttestationSource({
      manifest,
      attestationSource: Object.freeze({
        get(acknowledgementDigest: string): unknown | null {
          return attestations.get(acknowledgementDigest) ?? null;
        },
      }),
      pinnedManifestAuthorityPublicKeys: pins,
    });
    if (!sameDigest(registry.manifestDigest, digest)) throw new TypeError();
    manifests.set(digest, Object.freeze({ manifest, activation, attestations, registry }));
  };

  const registerAttestations = (unsafeBatch: RuntimeEffectEnforcerAttestationBatch): void => {
    if (closed) throw new TypeError();
    const batch = exactRecord(unsafeBatch, ["effectEnforcerSetDigest", "attestations"]);
    const digest = sha256(field(batch, "effectEnforcerSetDigest"));
    const routed = manifests.get(digest);
    if (!routed) throw new TypeError();
    const raw = field(batch, "attestations");
    if (!Array.isArray(raw) || raw.length > 64) throw new TypeError();
    const additions: Array<readonly [string, unknown]> = [];
    for (const value of raw) {
      const attestation = snapshotRuntimeEffectEnforcerAttestation(value);
      if (!sameDigest(attestation.manifestDigest, digest)) throw new TypeError();
      // Verify authority, manifest membership, purpose and enforcer signature
      // before anything becomes visible through the synchronous lookup seam.
      createRuntimeEffectEnforcerTrustRegistry({
        manifest: routed.manifest,
        attestations: Object.freeze([attestation]),
        pinnedManifestAuthorityPublicKeys: pins,
      });
      const acknowledgementDigest = digestRuntimeEffectEnforcerAttestation(attestation);
      const existing = routed.attestations.get(acknowledgementDigest);
      if (existing !== undefined) {
        if (canonicalRuntimeJson(existing) !== canonicalRuntimeJson(attestation)) {
          throw new TypeError();
        }
        continue;
      }
      additions.push(Object.freeze([acknowledgementDigest, attestation] as const));
    }
    if (attestationCount + additions.length > MAX_ATTESTATIONS) throw new TypeError();
    for (const [digestKey, attestation] of additions) {
      routed.attestations.set(digestKey, attestation);
      attestationCount += 1;
    }
  };

  const verifyRuntimeEnforcementProof: SynchronousRuntimeEnforcementProofVerifier = (input) => {
    try {
      if (closed) return false;
      const digest = proofDigest(input, "requiredEffectEnforcerSetDigest");
      return manifests.get(digest)?.registry.verifyRuntimeEnforcementProof(input) === true;
    } catch {
      return false;
    }
  };
  const verifyRuntimeCompensationEnforcementProof: SynchronousRuntimeCompensationEnforcementProofVerifier =
    (input) => {
      try {
        if (closed) return false;
        const digest = proofDigest(input, "requiredContainmentEnforcerSetDigest");
        return (
          manifests.get(digest)?.registry.verifyRuntimeCompensationEnforcementProof(input) === true
        );
      } catch {
        return false;
      }
    };

  return Object.freeze({
    registerManifest,
    registerAttestations,
    verifyRuntimeEnforcementProof,
    verifyRuntimeCompensationEnforcementProof,
    close(): void {
      closed = true;
      for (const routed of manifests.values()) routed.attestations.clear();
      manifests.clear();
      attestationCount = 0;
    },
  });
}

function assertManifestActivation(
  manifest: RuntimeEffectEnforcerManifest,
  activation: HostedRuntimeActivation
): void {
  if (
    !sameDigest(manifest.authority.claimsDigest, activation.effectEnforcerSetDigest) ||
    !sameDigest(manifest.assignmentPlanDigest, activation.assignmentPlanDigest) ||
    !sameDigest(manifest.effectEnforcerPolicyDigest, activation.effectEnforcerPolicyDigest) ||
    !sameDigest(manifest.providerIdentityCommitment, activation.providerIdentityCommitment) ||
    manifest.providerRevision !== activation.providerRevision ||
    !sameDigest(manifest.effectManifestBindingDigest, activation.effectManifestBindingDigest)
  ) {
    throw new TypeError();
  }
}

function proofDigest(value: unknown, name: string): string {
  if (
    typeof value !== "object" ||
    value === null ||
    nodeTypes.isProxy(value) ||
    !("subject" in value)
  ) {
    throw new TypeError();
  }
  const subject = (value as { readonly subject: unknown }).subject;
  if (typeof subject !== "object" || subject === null || nodeTypes.isProxy(subject)) {
    throw new TypeError();
  }
  return sha256((subject as Record<string, unknown>)[name]);
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
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
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw new TypeError();
  return descriptor.value;
}

function sha256(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}
