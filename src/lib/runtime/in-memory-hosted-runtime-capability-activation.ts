import { createHash, generateKeyPairSync, sign as signEd25519, type KeyObject } from "node:crypto";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import {
  RUNTIME_CAPABILITY_ACTIVATION_EVIDENCE_AUTHORITY_SIGNATURE_DOMAIN,
  createHostedRuntimeCapabilityActivationVerifier,
  digestHostedRuntimeCapabilityActivationClaims,
  type HostedRuntimeCapabilityActivationClaims,
  type HostedRuntimeCapabilityActivationEnforcerKind,
  type HostedRuntimeCapabilityActivationEvidence,
  type HostedRuntimeCapabilityActivationMeasurements,
  type HostedRuntimeCapabilityActivationQuery,
  type HostedRuntimeCapabilityActivationSource,
  type HostedRuntimeCapabilityActivationTrustGroupKey,
  type HostedRuntimeCapabilityActivationVerifier,
} from "./runtime-capability-activation-evidence";

const ALL_TRUE: HostedRuntimeCapabilityActivationMeasurements = Object.freeze({
  ambientProviderCredentialsAbsent: true,
  brokerReachOnlyViaSupervisor: true,
  egressLockdownMeasured: true,
});

export interface SeedCapabilityActivationOptions {
  readonly measurements?: HostedRuntimeCapabilityActivationMeasurements;
  readonly observedAtMs?: number;
  readonly issuedAtMs?: number;
  readonly expiresAtMs?: number;
  /** Replace the Ed25519 signature with garbage after signing (tamper test). */
  readonly tamperSignature?: boolean;
  /** Sign with a foreign private key not in the trust group (tamper test). */
  readonly signWithForeignKey?: boolean;
  /** Bind evidence to a different boot epoch than the resolve query (stale test). */
  readonly bootEpoch?: number;
}

/**
 * A deterministic, in-memory measured capability-activation control plane for
 * tests and Phase 12 dry-runs. It mints Ed25519-signed evidence with its own
 * generated trust-group key and can deliberately produce tampered, foreign-key,
 * stale, or partial-measurement evidence. It never advertises a capability by
 * itself — it only supplies evidence that the real verifier and derivation gate.
 */
export class InMemoryHostedRuntimeCapabilityActivation implements HostedRuntimeCapabilityActivationSource {
  private readonly privateKey: KeyObject;
  private readonly foreignPrivateKey: KeyObject;
  private readonly issuerKeyId: string;
  private readonly enforcerKind: HostedRuntimeCapabilityActivationEnforcerKind;
  readonly trustGroupKey: HostedRuntimeCapabilityActivationTrustGroupKey;
  private readonly evidenceByKey = new Map<string, HostedRuntimeCapabilityActivationEvidence>();

  constructor(
    options: {
      readonly issuerKeyId?: string;
      readonly enforcerKind?: HostedRuntimeCapabilityActivationEnforcerKind;
    } = {}
  ) {
    this.issuerKeyId = options.issuerKeyId ?? "in-memory-capability-enforcer:v1";
    this.enforcerKind = options.enforcerKind ?? "runtime";
    const pair = generateKeyPairSync("ed25519");
    this.privateKey = pair.privateKey;
    this.foreignPrivateKey = generateKeyPairSync("ed25519").privateKey;
    const publicKeySpkiPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const publicKeySpkiDigest = createHash("sha256")
      .update(pair.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
    this.trustGroupKey = Object.freeze({
      issuerKeyId: this.issuerKeyId,
      enforcerKind: this.enforcerKind,
      publicKeySpkiPem,
      publicKeySpkiDigest,
    });
  }

  createVerifier(
    options: { clock?: () => number; maxEvidenceTtlMs?: number } = {}
  ): HostedRuntimeCapabilityActivationVerifier {
    return createHostedRuntimeCapabilityActivationVerifier({
      trustGroupPublicKeys: [this.trustGroupKey],
      ...(options.clock ? { clock: options.clock } : {}),
      ...(options.maxEvidenceTtlMs !== undefined
        ? { maxEvidenceTtlMs: options.maxEvidenceTtlMs }
        : {}),
    });
  }

  /**
   * Mint and store evidence resolvable for `query`. Returns the exact evidence
   * so tests can assert on it. The store is keyed by the assignment identity
   * excluding the boot epoch, so evidence minted for a superseded boot surfaces
   * for a later query and is rejected as stale by the derivation.
   */
  seed(
    query: HostedRuntimeCapabilityActivationQuery,
    options: SeedCapabilityActivationOptions = {}
  ): HostedRuntimeCapabilityActivationEvidence {
    const observedAtMs = options.observedAtMs ?? 1_000;
    const issuedAtMs = options.issuedAtMs ?? observedAtMs;
    const expiresAtMs = options.expiresAtMs ?? issuedAtMs + 60_000;
    const measurements = options.measurements ?? ALL_TRUE;
    const claims: HostedRuntimeCapabilityActivationClaims = Object.freeze({
      version: 1,
      kind: "runtime.capability-activation-evidence",
      binding: query.binding,
      runtimeAuthorizationGeneration: query.runtimeAuthorizationGeneration,
      assignmentPlanDigest: query.assignmentPlanDigest,
      effectEnforcerPolicyDigest: query.effectEnforcerPolicyDigest,
      effectEnforcerSetDigest: query.effectEnforcerSetDigest,
      bootEpoch: options.bootEpoch ?? query.bootEpoch,
      measurements,
      observedAtMs,
    });
    const claimsDigest = digestHostedRuntimeCapabilityActivationClaims(claims);
    const authorityWithoutSignature = {
      issuer: "runtime-effect-enforcer" as const,
      issuerKeyId: this.issuerKeyId,
      enforcerKind: this.enforcerKind,
      audience: "terminalx-control-plane" as const,
      capability: "runtime.capability-activation.attest" as const,
      enforcerPublicKeySpkiDigest: this.trustGroupKey.publicKeySpkiDigest,
      claimsDigest,
      issuedAtMs,
      expiresAtMs,
    };
    const message = Buffer.concat([
      Buffer.from(RUNTIME_CAPABILITY_ACTIVATION_EVIDENCE_AUTHORITY_SIGNATURE_DOMAIN, "utf8"),
      Buffer.from(canonicalRuntimeJson({ version: 1, ...authorityWithoutSignature }), "utf8"),
    ]);
    let signature = signEd25519(
      null,
      message,
      options.signWithForeignKey ? this.foreignPrivateKey : this.privateKey
    ).toString("base64url");
    if (options.tamperSignature) signature = "A".repeat(86);
    const evidence: HostedRuntimeCapabilityActivationEvidence = Object.freeze({
      ...claims,
      authority: Object.freeze({ ...authorityWithoutSignature, signature }),
    });
    this.evidenceByKey.set(resolveKey(query), evidence);
    return evidence;
  }

  resolve(
    query: HostedRuntimeCapabilityActivationQuery
  ): HostedRuntimeCapabilityActivationEvidence | null {
    return this.evidenceByKey.get(resolveKey(query)) ?? null;
  }
}

function resolveKey(query: HostedRuntimeCapabilityActivationQuery): string {
  return canonicalRuntimeJson({
    binding: query.binding,
    runtimeAuthorizationGeneration: query.runtimeAuthorizationGeneration,
    assignmentPlanDigest: query.assignmentPlanDigest,
    effectEnforcerPolicyDigest: query.effectEnforcerPolicyDigest,
    effectEnforcerSetDigest: query.effectEnforcerSetDigest,
  });
}
