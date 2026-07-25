import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AggregateEnforcementProof } from "@/lib/runtime/contracts";
import type { HostedRuntimeActivation } from "@/lib/runtime/hosted-runtime-control-plane";
import {
  RUNTIME_EFFECT_ENFORCER_ATTESTATION_AUTHORITY_SIGNATURE_DOMAIN,
  RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN,
  digestRuntimeEffectEnforcerAttestation,
  digestRuntimeEffectEnforcerAttestationClaims,
  digestRuntimeEffectEnforcerManifestClaims,
  type RuntimeEffectEnforcerAttestation,
  type RuntimeEffectEnforcerAttestationClaims,
  type RuntimeEffectEnforcerManifest,
  type RuntimeEffectEnforcerManifestClaims,
} from "@/lib/runtime/runtime-effect-enforcer-attestation";
import {
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  digestRuntimeEnforcementSubject,
  type RuntimeEnforcementSubject,
} from "@/lib/runtime/runtime-enforcement-proof";
import {
  digestRuntimeCompensationEnforcementSubject,
  type RuntimeCompensationEnforcementSubject,
} from "@/lib/runtime/runtime-compensation-enforcement-proof";
import { canonicalRuntimeJson } from "@/lib/runtime/runtime-command-canonical";
import { createRuntimeEffectEnforcerTrustRouter } from "@/lib/runtime/runtime-effect-enforcer-trust-router";

const BINDING = {
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 1,
  sandboxId: "sandbox-1",
  sandboxGeneration: 1,
  runtimePrincipalId: "principal-1",
} as const;
const GENERATION = 1;
const OBSERVED_AT_MS = 500;

describe("runtime effect-enforcer trust router", () => {
  it("fails closed until the exact manifest and signed replay attestations are registered", () => {
    const value = fixture();
    const router = createRuntimeEffectEnforcerTrustRouter({
      pinnedManifestAuthorityPublicKeys: [value.platformPin],
    });

    expect(router.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(false);
    router.registerManifest({ manifest: value.manifest, activation: value.activation });
    expect(router.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(false);

    router.registerAttestations({
      effectEnforcerSetDigest: value.activation.effectEnforcerSetDigest,
      attestations: value.attestations,
    });
    expect(router.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(true);
    expect(router.verifyRuntimeCompensationEnforcementProof(value.compensationInput)).toBe(true);

    // Exact durable replay is idempotent.
    router.registerManifest({ manifest: value.manifest, activation: value.activation });
    router.registerAttestations({
      effectEnforcerSetDigest: value.activation.effectEnforcerSetDigest,
      attestations: value.attestations,
    });
    expect(router.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(true);
  });

  it("rejects cross-assignment, manifest, policy, set and attestation substitution", () => {
    const value = fixture();
    const router = createRuntimeEffectEnforcerTrustRouter({
      pinnedManifestAuthorityPublicKeys: [value.platformPin],
    });

    for (const activation of [
      { ...value.activation, assignmentPlanDigest: "9".repeat(64) },
      { ...value.activation, effectEnforcerPolicyDigest: "9".repeat(64) },
      { ...value.activation, effectManifestBindingDigest: "9".repeat(64) },
      { ...value.activation, effectEnforcerSetDigest: "9".repeat(64) },
    ]) {
      expect(() => router.registerManifest({ manifest: value.manifest, activation })).toThrow();
    }
    router.registerManifest({ manifest: value.manifest, activation: value.activation });
    expect(() =>
      router.registerAttestations({
        effectEnforcerSetDigest: "9".repeat(64),
        attestations: value.attestations,
      })
    ).toThrow();
    expect(() =>
      router.registerAttestations({
        effectEnforcerSetDigest: value.activation.effectEnforcerSetDigest,
        attestations: [{ ...value.attestations[0], manifestDigest: "9".repeat(64) }],
      })
    ).toThrow();
    expect(router.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(false);
  });

  it("rehydrates after restart solely from durable manifest and replay envelope data", () => {
    const value = fixture();
    const durable = JSON.parse(
      JSON.stringify({
        manifest: value.manifest,
        activation: value.activation,
        value: value.attestations,
      })
    ) as {
      manifest: RuntimeEffectEnforcerManifest;
      activation: HostedRuntimeActivation;
      value: unknown[];
    };
    const restarted = createRuntimeEffectEnforcerTrustRouter({
      pinnedManifestAuthorityPublicKeys: [value.platformPin],
    });
    restarted.registerManifest({ manifest: durable.manifest, activation: durable.activation });
    restarted.registerAttestations({
      effectEnforcerSetDigest: durable.activation.effectEnforcerSetDigest,
      attestations: durable.value,
    });

    expect(restarted.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(true);
    restarted.close();
    expect(restarted.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(false);
    expect(() =>
      restarted.registerManifest({ manifest: durable.manifest, activation: durable.activation })
    ).toThrow();
  });
});

function fixture() {
  const platform = keyMaterial();
  const enforcer = keyMaterial();
  const claims: RuntimeEffectEnforcerManifestClaims = {
    version: 1,
    kind: "runtime.effect-enforcer-manifest",
    manifestId: "daytona-effect-manifest:v1:test",
    assignmentPlanDigest: "1".repeat(64),
    effectEnforcerPolicyDigest: "2".repeat(64),
    providerIdentityCommitment: "3".repeat(64),
    providerRevision: 1,
    effectManifestBindingDigest: "4".repeat(64),
    validFromMs: 100,
    expiresAtMs: 10_000,
    enforcers: [
      {
        enforcerRef: "runtime-enforcer-1",
        enforcerKind: "runtime",
        enforcerKeyId: "runtime-enforcer-key-1",
        publicKeySpkiPem: enforcer.publicKeySpkiPem,
        publicKeySpkiDigest: enforcer.publicKeySpkiDigest,
        allowedPurposes: ["runtime-lifecycle", "stale-lifecycle-effect-containment"],
      },
    ],
  };
  const claimsDigest = digestRuntimeEffectEnforcerManifestClaims(claims);
  const manifestAuthority = {
    issuer: "platform-security" as const,
    issuerKeyId: "platform-manifest-key-1",
    audience: "terminalx-control-plane" as const,
    capability: "runtime.effect-enforcer-manifest.trust" as const,
    claimsDigest,
    issuedAtMs: claims.validFromMs,
    expiresAtMs: claims.expiresAtMs,
  };
  const manifest: RuntimeEffectEnforcerManifest = {
    ...claims,
    authority: {
      ...manifestAuthority,
      signature: signStatement(
        RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN,
        { version: 1, ...manifestAuthority },
        platform.privateKey
      ),
    },
  };
  const activation: HostedRuntimeActivation = {
    version: 1,
    kind: "hosted-runtime.activation",
    binding: BINDING,
    runtimeAuthorizationGeneration: GENERATION,
    assignmentPlanDigest: claims.assignmentPlanDigest,
    effectEnforcerPolicyDigest: claims.effectEnforcerPolicyDigest,
    providerIdentityCommitment: claims.providerIdentityCommitment,
    providerRevision: claims.providerRevision,
    effectManifestBindingDigest: claims.effectManifestBindingDigest,
    effectEnforcerSetDigest: claimsDigest,
  };
  const lifecycleSubject: RuntimeEnforcementSubject = {
    version: 1,
    commandId: "command-1",
    commandClaimsDigest: "5".repeat(64),
    binding: BINDING,
    runtimeAuthorizationGeneration: GENERATION,
    requiredEffectEnforcerSetDigest: claimsDigest,
    effectRefCommitment: commitRuntimeEffectRef("provider-effect-1"),
    enforcedFence: 2,
  };
  const compensationSubject: RuntimeCompensationEnforcementSubject = {
    version: 1,
    purpose: "stale-lifecycle-effect-containment",
    compensationId: "compensation-1",
    commandId: "command-2",
    commandClaimsDigest: "6".repeat(64),
    binding: BINDING,
    observedRuntimeAuthorizationGeneration: GENERATION,
    safetyFence: 2,
    enforcedSafetyFence: 3,
    sourceReceiptDigest: "7".repeat(64),
    sourceEnforcementSubjectDigest: "8".repeat(64),
    sourceAggregateProofDigest: "9".repeat(64),
    requiredContainmentEnforcerSetDigest: claimsDigest,
    effectRefCommitment: commitRuntimeEffectRef("provider-effect-2"),
    containment: {
      terminalWritesRevoked: true,
      processExecutionStopped: true,
      runtimeQuarantined: true,
    },
  };
  const lifecycleSubjectDigest = digestRuntimeEnforcementSubject(lifecycleSubject);
  const compensationSubjectDigest =
    digestRuntimeCompensationEnforcementSubject(compensationSubject);
  const lifecycleAttestation = signedAttestation(
    claimsDigest,
    "runtime-lifecycle",
    lifecycleSubjectDigest,
    enforcer
  );
  const compensationAttestation = signedAttestation(
    claimsDigest,
    "stale-lifecycle-effect-containment",
    compensationSubjectDigest,
    enforcer
  );
  const lifecycleProof = proof(claimsDigest, lifecycleSubjectDigest, lifecycleAttestation);
  const compensationProof = proof(claimsDigest, compensationSubjectDigest, compensationAttestation);
  return {
    platformPin: {
      issuerKeyId: manifestAuthority.issuerKeyId,
      publicKeySpkiPem: platform.publicKeySpkiPem,
      publicKeySpkiDigest: platform.publicKeySpkiDigest,
    },
    manifest,
    activation,
    attestations: [lifecycleAttestation, compensationAttestation],
    lifecycleInput: {
      subject: lifecycleSubject,
      subjectDigest: lifecycleSubjectDigest,
      proof: lifecycleProof,
    },
    compensationInput: {
      subject: compensationSubject,
      subjectDigest: compensationSubjectDigest,
      proof: compensationProof,
    },
  };
}

function signedAttestation(
  manifestDigest: string,
  purpose: RuntimeEffectEnforcerAttestationClaims["purpose"],
  enforcementSubjectDigest: string,
  enforcer: ReturnType<typeof keyMaterial>
): RuntimeEffectEnforcerAttestation {
  const claims: RuntimeEffectEnforcerAttestationClaims = {
    version: 1,
    kind: "runtime.effect-enforcer-attestation",
    manifestDigest,
    purpose,
    generation: GENERATION,
    enforcementSubjectDigest,
    enforcerRef: "runtime-enforcer-1",
    enforcerKind: "runtime",
    enforcerKeyId: "runtime-enforcer-key-1",
    enforcerPublicKeySpkiDigest: enforcer.publicKeySpkiDigest,
    observedAtMs: OBSERVED_AT_MS,
  };
  const authority = {
    issuer: "runtime-effect-enforcer" as const,
    issuerKeyId: claims.enforcerKeyId,
    audience: "terminalx-control-plane" as const,
    capability: "runtime.effect-enforcement.attest" as const,
    claimsDigest: digestRuntimeEffectEnforcerAttestationClaims(claims),
    issuedAtMs: OBSERVED_AT_MS,
    expiresAtMs: OBSERVED_AT_MS + 100,
  };
  return {
    ...claims,
    authority: {
      ...authority,
      signature: signStatement(
        RUNTIME_EFFECT_ENFORCER_ATTESTATION_AUTHORITY_SIGNATURE_DOMAIN,
        { version: 1, ...authority },
        enforcer.privateKey
      ),
    },
  };
}

function proof(
  manifestDigest: string,
  enforcementSubjectDigest: string,
  attestation: RuntimeEffectEnforcerAttestation
): AggregateEnforcementProof {
  const payload = {
    generation: GENERATION,
    requiredEffectEnforcerSetDigest: manifestDigest,
    enforcementSubjectDigest,
    acknowledgements: [
      {
        enforcerRef: attestation.enforcerRef,
        enforcerKind: attestation.enforcerKind,
        acknowledgementDigest: digestRuntimeEffectEnforcerAttestation(attestation),
      },
    ],
  };
  return { ...payload, aggregateProofDigest: digestAggregateEnforcementProof(payload) };
}

function keyMaterial() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicKeySpkiDigest = createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  return { privateKey, publicKeySpkiPem, publicKeySpkiDigest };
}

function signStatement(domain: string, statement: unknown, privateKey: KeyObject): string {
  return sign(
    null,
    Buffer.from(`${domain}${canonicalRuntimeJson(statement)}`, "utf8"),
    privateKey
  ).toString("base64url");
}
