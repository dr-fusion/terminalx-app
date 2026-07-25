import { timingSafeEqual } from "node:crypto";
import {
  createRuntimeEffectEnforcerTrustRegistry,
  type PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey,
} from "../../../src/lib/runtime/runtime-effect-enforcer-attestation";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import type { DaytonaSupervisorProofVerifierFactory } from "./supervisor";

const SHA256 = /^[0-9a-f]{64}$/;

export interface CreateDaytonaSupervisorProofVerifierFactoryOptions {
  readonly manifest: unknown;
  readonly pinnedManifestAuthorityPublicKeys: readonly PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey[];
}

/** Build a fresh immutable registry from only the attestations returned for this exact effect. */
export function createDaytonaSupervisorProofVerifierFactory(
  unsafeOptions: CreateDaytonaSupervisorProofVerifierFactoryOptions
): DaytonaSupervisorProofVerifierFactory {
  const manifest = snapshotRuntimeSupervisorPortableData(unsafeOptions?.manifest);
  const pinnedManifestAuthorityPublicKeys = snapshotRuntimeSupervisorPortableData(
    unsafeOptions?.pinnedManifestAuthorityPublicKeys
  ) as readonly PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey[];
  // Validate the manifest and authority pins before admitting any command.
  createRuntimeEffectEnforcerTrustRegistry({
    manifest,
    attestations: Object.freeze([]),
    pinnedManifestAuthorityPublicKeys,
  });

  const registry = (attestations: readonly unknown[], requiredDigest: string) => {
    if (!Array.isArray(attestations) || !SHA256.test(requiredDigest)) throw new TypeError();
    const trust = createRuntimeEffectEnforcerTrustRegistry({
      manifest,
      attestations,
      pinnedManifestAuthorityPublicKeys,
    });
    if (!sameDigest(trust.manifestDigest, requiredDigest)) throw new TypeError();
    return trust;
  };

  return Object.freeze({
    lifecycle(attestations: readonly unknown[], requiredDigest: string) {
      return registry(attestations, requiredDigest).verifyRuntimeEnforcementProof;
    },
    compensation(attestations: readonly unknown[], requiredDigest: string) {
      return registry(attestations, requiredDigest).verifyRuntimeCompensationEnforcementProof;
    },
  });
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}
