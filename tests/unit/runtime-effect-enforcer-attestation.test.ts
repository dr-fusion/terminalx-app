import { createHash, generateKeyPairSync, sign as signEd25519, type KeyObject } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AggregateEnforcementProof } from "@/lib/runtime/contracts";
import { canonicalRuntimeJson } from "@/lib/runtime/runtime-command-canonical";
import {
  digestRuntimeCompensationEnforcementSubject,
  verifyRuntimeCompensationEnforcementProofSynchronously,
  type RuntimeCompensationEnforcementSubject,
} from "@/lib/runtime/runtime-compensation-enforcement-proof";
import {
  RUNTIME_EFFECT_ENFORCER_ATTESTATION_AUTHORITY_SIGNATURE_DOMAIN,
  RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN,
  RuntimeEffectEnforcerAttestationError,
  createRuntimeEffectEnforcerTrustRegistry,
  createRuntimeEffectEnforcerTrustRegistryFromFile,
  createRuntimeEffectEnforcerTrustRegistryWithAttestationSource,
  digestRuntimeEffectEnforcerAttestation,
  digestRuntimeEffectEnforcerAttestationClaims,
  digestRuntimeEffectEnforcerManifestClaims,
  snapshotRuntimeEffectEnforcerAttestation,
  snapshotRuntimeEffectEnforcerAttestationClaims,
  snapshotRuntimeEffectEnforcerManifest,
  snapshotRuntimeEffectEnforcerManifestClaims,
  type PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey,
  type RuntimeEffectEnforcerAttestation,
  type RuntimeEffectEnforcerAttestationAuthority,
  type RuntimeEffectEnforcerAttestationClaims,
  type RuntimeEffectEnforcerManifest,
  type RuntimeEffectEnforcerManifestAuthority,
  type RuntimeEffectEnforcerManifestClaims,
  type RuntimeEffectEnforcerManifestEntry,
  type RuntimeEffectEnforcerAttestationSource,
} from "@/lib/runtime/runtime-effect-enforcer-attestation";
import {
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  digestRuntimeEnforcementSubject,
  type RuntimeEnforcementSubject,
} from "@/lib/runtime/runtime-enforcement-proof";

const BINDING = {
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 3,
  sandboxId: "sandbox-1",
  sandboxGeneration: 4,
  runtimePrincipalId: "principal-1",
} as const;
const GENERATION = 7;
const VALID_FROM_MS = 100;
const EXPIRES_AT_MS = 10_000;
const OBSERVED_AT_MS = 500;

interface KeyMaterial {
  readonly privateKey: KeyObject;
  readonly publicKeySpkiPem: string;
  readonly publicKeySpkiDigest: string;
}

describe("Runtime effect-enforcer attestation trust registry", () => {
  let directory: string;
  let platform: KeyMaterial;
  let runtime: KeyMaterial;
  let credentialProxy: KeyMaterial;
  let signer: KeyMaterial;
  let replacement: KeyMaterial;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-effect-enforcer-registry-"));
    platform = keyMaterial();
    runtime = keyMaterial();
    credentialProxy = keyMaterial();
    signer = keyMaterial();
    replacement = keyMaterial();
  });

  afterEach(() => {
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("verifies lifecycle and compensation proofs synchronously through one immutable registry", () => {
    const value = fixture();

    const lifecycleResult = value.registry.verifyRuntimeEnforcementProof(value.lifecycleInput);
    const compensationResult = value.registry.verifyRuntimeCompensationEnforcementProof(
      value.compensationInput
    );

    expect(lifecycleResult).toBe(true);
    expect(compensationResult).toBe(true);
    expect(lifecycleResult).not.toBeInstanceOf(Promise);
    expect(compensationResult).not.toBeInstanceOf(Promise);
    expect(() =>
      verifyRuntimeCompensationEnforcementProofSynchronously(
        value.compensationSubject,
        value.compensationProof,
        value.registry.verifyRuntimeCompensationEnforcementProof
      )
    ).not.toThrow();
    expect(value.registry.manifestDigest).toBe(value.manifest.authority.claimsDigest);
    expect(Object.isFrozen(value.registry)).toBe(true);
    expect(Object.isFrozen(value.registry.manifest)).toBe(true);
    expect(Object.isFrozen(value.registry.manifest.enforcers)).toBe(true);
    expect(Object.isFrozen(value.registry.manifest.enforcers[0])).toBe(true);
  });

  it("remains restart-reverifiable using historical observation time, not wall clock", () => {
    const value = fixture({ expiresAtMs: 1_000, observedAtMs: 999, attestationExpiresAtMs: 1_000 });
    const serialized = JSON.parse(
      JSON.stringify({ manifest: value.manifest, attestations: value.attestations })
    ) as { manifest: unknown; attestations: unknown[] };

    const restarted = createRuntimeEffectEnforcerTrustRegistry({
      ...serialized,
      pinnedManifestAuthorityPublicKeys: [platformPin()],
    });

    expect(restarted.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(true);
    expect(restarted.verifyRuntimeCompensationEnforcementProof(value.compensationInput)).toBe(true);

    const atExpiry = fixture({
      expiresAtMs: 1_000,
      observedAtMs: 1_000,
      attestationExpiresAtMs: 1_001,
      createRegistry: false,
    });
    expect(() => registry(atExpiry.manifest, atExpiry.attestations)).toThrow(
      expect.objectContaining({ code: "invalid_attestation" })
    );
  });

  it("detaches and freezes trust state before untrusted constructor inputs can change", () => {
    const value = fixture();
    (value.manifest as unknown as Record<string, unknown>).manifestId = "mutated-manifest";
    (value.manifest.enforcers[0] as unknown as Record<string, unknown>).enforcerRef =
      "mutated-enforcer";
    (value.attestations[0] as unknown as Record<string, unknown>).generation = 999;

    expect(value.registry.manifest.manifestId).toBe("production-effect-enforcers:v1");
    expect(value.registry.manifest.enforcers[0]?.enforcerRef).toBe("a-runtime");
    expect(value.registry.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(true);
    expect(value.registry.verifyRuntimeCompensationEnforcementProof(value.compensationInput)).toBe(
      true
    );
  });

  it("resolves and verifies attestations produced after dynamic registry construction", () => {
    const value = fixture({ createRegistry: false });
    const records = new Map<string, unknown>();
    const lookups: string[] = [];
    const dynamic = dynamicRegistry(value.manifest, {
      get: (digest) => {
        lookups.push(digest);
        return records.get(digest) ?? null;
      },
    });

    expect(dynamic.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(false);
    expect(lookups).toEqual([value.lifecycleProof.acknowledgements[0]?.acknowledgementDigest]);

    for (const attestation of value.attestations) {
      records.set(digestRuntimeEffectEnforcerAttestation(attestation), attestation);
    }
    lookups.length = 0;
    expect(dynamic.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(true);
    expect(lookups).toEqual(
      value.lifecycleProof.acknowledgements.map((entry) => entry.acknowledgementDigest)
    );
    lookups.length = 0;
    expect(dynamic.verifyRuntimeCompensationEnforcementProof(value.compensationInput)).toBe(true);
    expect(lookups).toEqual(
      value.compensationProof.acknowledgements.map((entry) => entry.acknowledgementDigest)
    );
  });

  it("fails closed for missing, wrong, throwing, asynchronous, thenable, proxy, and bulk sources", () => {
    const value = fixture({ createRegistry: false });
    const first = value.attestations[0];
    const wrong = value.attestations[2];
    if (!first || !wrong) throw new Error("Expected fixture attestations");
    let thenGetterInvoked = false;
    const thenable = Object.defineProperty({ ...first }, "then", {
      enumerable: true,
      get() {
        thenGetterInvoked = true;
        return () => undefined;
      },
    });
    let hostileProxyTrapInvoked = false;
    const hostileResult = new Proxy(first, {
      ownKeys() {
        hostileProxyTrapInvoked = true;
        throw new Error("hostile attestation source result");
      },
    });
    const sources: RuntimeEffectEnforcerAttestationSource[] = [
      { get: () => null },
      { get: () => wrong },
      {
        get: () => {
          throw new Error("local source failure detail");
        },
      },
      { get: (() => Promise.resolve(first)) as unknown as () => unknown },
      {
        get: (() =>
          Promise.reject(new Error("async provider rejection detail"))) as unknown as () => unknown,
      },
      { get: () => thenable },
      { get: () => hostileResult },
      { get: () => [first, wrong] },
      { get: () => ({ attestation: first, unrelated: wrong }) },
    ];

    for (const source of sources) {
      expect(
        dynamicRegistry(value.manifest, source).verifyRuntimeEnforcementProof(value.lifecycleInput)
      ).toBe(false);
    }
    expect(thenGetterInvoked).toBe(false);
    expect(hostileProxyTrapInvoked).toBe(false);
  });

  it("captures only an own data-property source method and never invokes source accessors", () => {
    const value = fixture({ createRegistry: false });
    let getterInvoked = false;
    const accessorSource = Object.defineProperty({}, "get", {
      enumerable: true,
      get() {
        getterInvoked = true;
        return () => value.attestations[0];
      },
    });
    const proxySource = new Proxy(
      { get: () => value.attestations[0] },
      {
        getOwnPropertyDescriptor() {
          throw new Error("hostile source descriptor");
        },
      }
    );
    const proxyGet = new Proxy(() => value.attestations[0], {});

    for (const source of [
      accessorSource,
      proxySource,
      { get: proxyGet },
      { get: () => value.attestations[0], extra: true },
      Object.create({ get: () => value.attestations[0] }) as object,
    ]) {
      expect(() =>
        createRuntimeEffectEnforcerTrustRegistryWithAttestationSource({
          manifest: value.manifest,
          attestationSource: source as RuntimeEffectEnforcerAttestationSource,
          pinnedManifestAuthorityPublicKeys: [platformPin()],
        })
      ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
    }
    expect(getterInvoked).toBe(false);
  });

  it("looks up only referenced digests, trusts no bulk data, and never caches source results", () => {
    const value = fixture({ createRegistry: false });
    const records = new Map<string, unknown>();
    for (const attestation of value.attestations) {
      records.set(digestRuntimeEffectEnforcerAttestation(attestation), attestation);
    }
    const unreferencedDigest = "f".repeat(64);
    let unreferencedTouched = false;
    records.set(
      unreferencedDigest,
      new Proxy(
        {},
        {
          ownKeys() {
            unreferencedTouched = true;
            throw new Error("unreferenced bulk data must not be parsed");
          },
        }
      )
    );
    const lookups: string[] = [];
    const dynamic = dynamicRegistry(value.manifest, {
      get: (digest) => {
        lookups.push(digest);
        return records.get(digest) ?? null;
      },
    });

    expect(dynamic.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(true);
    expect(lookups).toEqual(
      value.lifecycleProof.acknowledgements.map((entry) => entry.acknowledgementDigest)
    );
    expect(lookups).not.toContain(unreferencedDigest);
    expect(unreferencedTouched).toBe(false);

    const firstDigest = value.lifecycleProof.acknowledgements[0]?.acknowledgementDigest;
    const firstAttestation = value.attestations[0];
    if (!firstDigest || !firstAttestation) throw new Error("Expected first attestation");
    records.set(firstDigest, {
      ...firstAttestation,
      authority: { ...firstAttestation.authority, signature: "A".repeat(86) },
    });
    lookups.length = 0;
    expect(dynamic.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(false);
    expect(lookups).toEqual([firstDigest]);
  });

  it("rejects digest and coordinate reuse returned by a dynamic source", () => {
    const value = fixture({ createRegistry: false });
    const first = value.attestations[0];
    if (!first) throw new Error("Expected fixture attestation");
    let calls = 0;
    const dynamic = dynamicRegistry(value.manifest, {
      get: () => {
        calls += 1;
        return first;
      },
    });

    expect(dynamic.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(false);
    expect(calls).toBe(2);
  });

  it("requires the exact purpose-specific manifest set with canonical order", () => {
    const value = fixture();
    const [runtimeLifecycle, credentialLifecycle, runtimeContainment, signerContainment] =
      value.attestations;
    if (!runtimeLifecycle || !credentialLifecycle || !runtimeContainment || !signerContainment) {
      throw new Error("Expected fixture attestations");
    }
    const partial = proof(
      value.manifest.authority.claimsDigest,
      value.lifecycleSubjectDigest,
      GENERATION,
      [ack(runtimeLifecycle)]
    );
    const superset = proof(
      value.manifest.authority.claimsDigest,
      value.lifecycleSubjectDigest,
      GENERATION,
      [ack(runtimeLifecycle), ack(credentialLifecycle), ack(signerContainment)]
    );
    const wrongKind = proof(
      value.manifest.authority.claimsDigest,
      value.lifecycleSubjectDigest,
      GENERATION,
      [ack(runtimeLifecycle), { ...ack(credentialLifecycle), enforcerKind: "source-control" }]
    );
    const unknownDigest = proof(
      value.manifest.authority.claimsDigest,
      value.lifecycleSubjectDigest,
      GENERATION,
      [
        ack(runtimeLifecycle),
        { ...ack(credentialLifecycle), acknowledgementDigest: "f".repeat(64) },
      ]
    );
    const unsorted: AggregateEnforcementProof = {
      ...value.lifecycleProof,
      acknowledgements: [...value.lifecycleProof.acknowledgements].reverse(),
    };

    for (const candidate of [partial, superset, wrongKind, unknownDigest, unsorted]) {
      expect(
        value.registry.verifyRuntimeEnforcementProof({
          ...value.lifecycleInput,
          proof: candidate,
        })
      ).toBe(false);
    }

    expect(
      value.registry.verifyRuntimeEnforcementProof({
        ...value.lifecycleInput,
        proof: proof(
          value.manifest.authority.claimsDigest,
          value.lifecycleSubjectDigest,
          GENERATION,
          [ack(runtimeContainment), ack(signerContainment)]
        ),
      })
    ).toBe(false);
  });

  it("rejects generation, subject, manifest, and purpose-domain replay", () => {
    const value = fixture();
    const generationEightSubject: RuntimeEnforcementSubject = {
      ...value.lifecycleSubject,
      runtimeAuthorizationGeneration: 8,
    };
    const generationEightDigest = digestRuntimeEnforcementSubject(generationEightSubject);
    const generationEightProof = proof(
      value.manifest.authority.claimsDigest,
      generationEightDigest,
      8,
      value.lifecycleProof.acknowledgements
    );

    expect(
      value.registry.verifyRuntimeEnforcementProof({
        subject: generationEightSubject,
        subjectDigest: generationEightDigest,
        proof: generationEightProof,
      })
    ).toBe(false);
    expect(
      value.registry.verifyRuntimeEnforcementProof({
        ...value.lifecycleInput,
        subjectDigest: "0".repeat(64),
      })
    ).toBe(false);
    expect(
      value.registry.verifyRuntimeEnforcementProof({
        ...value.lifecycleInput,
        proof: { ...value.lifecycleProof, requiredEffectEnforcerSetDigest: "1".repeat(64) },
      })
    ).toBe(false);
    expect(
      value.registry.verifyRuntimeCompensationEnforcementProof({
        ...value.compensationInput,
        proof: proof(
          value.manifest.authority.claimsDigest,
          value.compensationSubjectDigest,
          GENERATION,
          value.lifecycleProof.acknowledgements
        ),
      })
    ).toBe(false);
    expect(
      value.registry.verifyRuntimeEnforcementProof(
        value.compensationInput as unknown as Parameters<
          typeof value.registry.verifyRuntimeEnforcementProof
        >[0]
      )
    ).toBe(false);
  });

  it("authenticates the exact platform-signed manifest and construction-time pin selection", () => {
    const value = fixture({ createRegistry: false });
    const wrongPin: PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey = {
      issuerKeyId: "platform-manifest-key-1",
      publicKeySpkiPem: replacement.publicKeySpkiPem,
      publicKeySpkiDigest: replacement.publicKeySpkiDigest,
    };
    const malformedSignature = {
      ...value.manifest,
      authority: { ...value.manifest.authority, signature: "A".repeat(86) },
    };
    const unknownIssuer = {
      ...value.manifest,
      authority: { ...value.manifest.authority, issuerKeyId: "revoked-platform-key" },
    };

    expect(() =>
      createRuntimeEffectEnforcerTrustRegistry({
        manifest: value.manifest,
        attestations: value.attestations,
        pinnedManifestAuthorityPublicKeys: [wrongPin],
      })
    ).toThrow(expect.objectContaining({ code: "invalid_signature" }));
    for (const manifest of [malformedSignature, unknownIssuer]) {
      expect(() => registry(manifest, value.attestations)).toThrow(
        expect.objectContaining({ code: "invalid_signature" })
      );
    }
  });

  it("rejects partial, superset, unsorted, duplicate-key, and purpose-invalid manifests", () => {
    const value = fixture({ createRegistry: false });
    const entries = value.manifest.enforcers;
    const partial = resignManifest({ ...claimsOf(value.manifest), enforcers: entries.slice(0, 2) });
    const extraEntry: RuntimeEffectEnforcerManifestEntry = {
      enforcerRef: "z-extra",
      enforcerKind: "deployment",
      enforcerKeyId: "extra-key-1",
      publicKeySpkiPem: replacement.publicKeySpkiPem,
      publicKeySpkiDigest: replacement.publicKeySpkiDigest,
      allowedPurposes: ["runtime-lifecycle"],
    };
    const superset = resignManifest({
      ...claimsOf(value.manifest),
      enforcers: [...entries, extraEntry],
    });
    const unsorted = {
      ...value.manifest,
      enforcers: [...entries].reverse(),
    };
    const duplicateKey = {
      ...value.manifest,
      enforcers: entries.map((entry, index) =>
        index === 2
          ? {
              ...entry,
              enforcerKeyId: entries[1]!.enforcerKeyId,
              publicKeySpkiPem: entries[1]!.publicKeySpkiPem,
              publicKeySpkiDigest: entries[1]!.publicKeySpkiDigest,
            }
          : entry
      ),
    };
    const duplicatePurposes = {
      ...value.manifest,
      enforcers: entries.map((entry, index) =>
        index === 0
          ? { ...entry, allowedPurposes: ["runtime-lifecycle", "runtime-lifecycle"] }
          : entry
      ),
    };
    const unsortedPurposes = {
      ...value.manifest,
      enforcers: entries.map((entry, index) =>
        index === 0
          ? {
              ...entry,
              allowedPurposes: ["stale-lifecycle-effect-containment", "runtime-lifecycle"],
            }
          : entry
      ),
    };

    expect(() => registry(partial, value.attestations)).toThrow(
      expect.objectContaining({ code: "invalid_attestation" })
    );
    expect(() => registry(superset, value.attestations)).toThrow(
      expect.objectContaining({ code: "invalid_attestation" })
    );
    for (const manifest of [unsorted, duplicateKey, duplicatePurposes, unsortedPurposes]) {
      expect(() => registry(manifest, [])).toThrow(RuntimeEffectEnforcerAttestationError);
    }
  });

  it("rejects replaced, malformed, noncanonical, aliased, and private public-key material", () => {
    const value = fixture({ createRegistry: false });
    const privatePem = platform.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const privatePin = {
      ...platformPin(),
      publicKeySpkiPem: privatePem,
    };
    const noncanonicalPin = {
      ...platformPin(),
      publicKeySpkiPem: `${platform.publicKeySpkiPem}\n`,
    };
    const wrongDigestPin = { ...platformPin(), publicKeySpkiDigest: "0".repeat(64) };
    const aliasPin = {
      ...platformPin(),
      issuerKeyId: "platform-manifest-key-alias",
    };

    for (const pins of [
      [privatePin],
      [noncanonicalPin],
      [wrongDigestPin],
      [platformPin(), aliasPin],
    ]) {
      expect(() =>
        createRuntimeEffectEnforcerTrustRegistry({
          manifest: value.manifest,
          attestations: [],
          pinnedManifestAuthorityPublicKeys: pins,
        })
      ).toThrow(expect.objectContaining({ code: "invalid_public_key" }));
    }

    const replacedEntry = value.manifest.enforcers.map((entry, index) =>
      index === 0
        ? {
            ...entry,
            publicKeySpkiPem: replacement.publicKeySpkiPem,
            publicKeySpkiDigest: replacement.publicKeySpkiDigest,
          }
        : entry
    );
    const replacedManifest = resignManifest({
      ...claimsOf(value.manifest),
      enforcers: replacedEntry,
    });
    expect(() => registry(replacedManifest, value.attestations)).toThrow(
      expect.objectContaining({ code: "invalid_attestation" })
    );

    for (const publicKeySpkiPem of [privatePem, "not-a-public-key"]) {
      const invalidEntryManifest = {
        ...value.manifest,
        enforcers: value.manifest.enforcers.map((entry, index) =>
          index === 0 ? { ...entry, publicKeySpkiPem } : entry
        ),
      };
      expect(() => registry(invalidEntryManifest, [])).toThrow(
        expect.objectContaining({ code: "invalid_public_key" })
      );
    }
  });

  it("keeps platform-manifest authority keys and IDs separate from enforcer roles", () => {
    const value = fixture({ createRegistry: false });
    const authorityKeyAsEnforcer = resignManifest({
      ...claimsOf(value.manifest),
      enforcers: value.manifest.enforcers.map((entry, index) =>
        index === 0
          ? {
              ...entry,
              publicKeySpkiPem: platform.publicKeySpkiPem,
              publicKeySpkiDigest: platform.publicKeySpkiDigest,
            }
          : entry
      ),
    });
    const authorityIdAsEnforcer = resignManifest({
      ...claimsOf(value.manifest),
      enforcers: value.manifest.enforcers.map((entry, index) =>
        index === 0
          ? {
              ...entry,
              enforcerKeyId: "platform-manifest-key-1",
            }
          : entry
      ),
    });

    for (const manifest of [authorityKeyAsEnforcer, authorityIdAsEnforcer]) {
      expect(() => registry(manifest, [])).toThrow(
        expect.objectContaining({ code: "invalid_configuration" })
      );
      expect(() =>
        dynamicRegistry(manifest, {
          get: () => null,
        })
      ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
    }
  });

  it("rejects attestation identity, key, signature, and authority substitutions", () => {
    const value = fixture({ createRegistry: false });
    const original = value.attestations[0];
    if (!original) throw new Error("Expected fixture attestation");
    const originalClaims = claimsOfAttestation(original);
    const entry = value.manifest.enforcers[0];
    if (!entry) throw new Error("Expected fixture entry");

    const candidates = [
      signAttestation({ ...originalClaims, manifestDigest: "0".repeat(64) }, runtime.privateKey),
      signAttestation({ ...originalClaims, enforcerRef: "b-credential" }, runtime.privateKey),
      signAttestation({ ...originalClaims, enforcerKind: "source-control" }, runtime.privateKey),
      signAttestation(
        { ...originalClaims, enforcerKeyId: "runtime-key-replaced" },
        runtime.privateKey
      ),
      signAttestation(
        { ...originalClaims, enforcerPublicKeySpkiDigest: replacement.publicKeySpkiDigest },
        runtime.privateKey
      ),
      signAttestation(originalClaims, replacement.privateKey),
      {
        ...original,
        authority: { ...original.authority, signature: "A".repeat(86) },
      },
      {
        ...original,
        authority: { ...original.authority, claimsDigest: "1".repeat(64) },
      },
      {
        ...original,
        authority: { ...original.authority, issuer: "platform-security" },
      },
      {
        ...original,
        authority: {
          ...original.authority,
          signature: signAuthority(
            RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN,
            attestationAuthorityStatement(original.authority),
            runtime.privateKey
          ),
        },
      },
    ];

    for (const attestation of candidates) {
      expect(() => registry(value.manifest, [attestation])).toThrow(
        RuntimeEffectEnforcerAttestationError
      );
    }

    const replacedManifest = resignManifest({
      ...claimsOf(value.manifest),
      enforcers: value.manifest.enforcers.map((candidate, index) =>
        index === 0
          ? {
              ...entry,
              publicKeySpkiPem: replacement.publicKeySpkiPem,
              publicKeySpkiDigest: replacement.publicKeySpkiDigest,
            }
          : candidate
      ),
    });
    const replacedClaims: RuntimeEffectEnforcerAttestationClaims = {
      ...originalClaims,
      manifestDigest: replacedManifest.authority.claimsDigest,
      enforcerPublicKeySpkiDigest: replacement.publicKeySpkiDigest,
    };
    expect(() =>
      registry(replacedManifest, [signAttestation(replacedClaims, runtime.privateKey)])
    ).toThrow(expect.objectContaining({ code: "invalid_signature" }));
  });

  it("validates every historical validity window at observedAtMs", () => {
    const value = fixture({ createRegistry: false });
    const original = value.attestations[0];
    if (!original) throw new Error("Expected fixture attestation");
    const base = claimsOfAttestation(original);
    const beforeManifest = signAttestation(
      { ...base, observedAtMs: VALID_FROM_MS - 1 },
      runtime.privateKey,
      { issuedAtMs: VALID_FROM_MS - 1, expiresAtMs: VALID_FROM_MS + 1 }
    );
    const atManifestExpiry = signAttestation(
      { ...base, observedAtMs: EXPIRES_AT_MS },
      runtime.privateKey,
      { issuedAtMs: EXPIRES_AT_MS, expiresAtMs: EXPIRES_AT_MS + 1 }
    );
    const authorityStartsLate = {
      ...original,
      authority: { ...original.authority, issuedAtMs: original.observedAtMs + 1 },
    };
    const authorityAlreadyExpired = {
      ...original,
      authority: { ...original.authority, expiresAtMs: original.observedAtMs },
    };
    const authorityBeyondManifest = signAttestation(base, runtime.privateKey, {
      expiresAtMs: EXPIRES_AT_MS + 1,
    });

    for (const attestation of [
      beforeManifest,
      atManifestExpiry,
      authorityStartsLate,
      authorityAlreadyExpired,
      authorityBeyondManifest,
    ]) {
      expect(() => registry(value.manifest, [attestation])).toThrow(
        expect.objectContaining({ code: "invalid_attestation" })
      );
    }

    const longClaims = manifestClaims({ expiresAtMs: 1_000_000 });
    const longManifest = signManifest(longClaims);
    const longEntry = longManifest.enforcers[0];
    if (!longEntry) throw new Error("Expected long-window entry");
    const excessiveTtlClaims = attestationClaims(
      longManifest.authority.claimsDigest,
      "runtime-lifecycle",
      "a".repeat(64),
      longEntry,
      { observedAtMs: 500 }
    );
    const excessiveTtl = signAttestation(excessiveTtlClaims, runtime.privateKey, {
      expiresAtMs: 500 + 5 * 60_000 + 1,
    });
    expect(() => registry(longManifest, [excessiveTtl])).toThrow(
      expect.objectContaining({ code: "invalid_attestation" })
    );
  });

  it("rejects negative-zero timestamps and whitespace-ambiguous references", () => {
    const value = fixture({ createRegistry: false });
    expect(() =>
      snapshotRuntimeEffectEnforcerManifestClaims({
        ...claimsOf(value.manifest),
        validFromMs: -0,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_manifest" }));
    expect(() =>
      snapshotRuntimeEffectEnforcerManifestClaims({
        ...claimsOf(value.manifest),
        manifestId: " production-effect-enforcers:v1",
      })
    ).toThrow(expect.objectContaining({ code: "invalid_manifest" }));

    const attestation = value.attestations[0];
    if (!attestation) throw new Error("Expected fixture attestation");
    expect(() =>
      snapshotRuntimeEffectEnforcerAttestationClaims({
        ...claimsOfAttestation(attestation),
        observedAtMs: -0,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_attestation" }));
  });

  it("rejects digest reuse and ambiguous attestations for one proof coordinate", () => {
    const value = fixture({ createRegistry: false });
    const original = value.attestations[0];
    if (!original) throw new Error("Expected fixture attestation");
    const laterClaims = { ...claimsOfAttestation(original), observedAtMs: OBSERVED_AT_MS + 1 };
    const later = signAttestation(laterClaims, runtime.privateKey, {
      issuedAtMs: OBSERVED_AT_MS + 1,
      expiresAtMs: OBSERVED_AT_MS + 101,
    });

    expect(() => registry(value.manifest, [original, original])).toThrow(
      expect.objectContaining({ code: "invalid_attestation" })
    );
    expect(() => registry(value.manifest, [original, later])).toThrow(
      expect.objectContaining({ code: "invalid_attestation" })
    );
  });

  it("rejects accessors, proxies, extra or missing fields without invoking hostile values", () => {
    const value = fixture();
    let getterInvoked = false;
    const accessorManifest = Object.defineProperties(
      {},
      Object.fromEntries(
        Object.entries(value.manifest).map(([key, candidate]) => [
          key,
          key === "manifestId"
            ? {
                enumerable: true,
                get() {
                  getterInvoked = true;
                  return candidate;
                },
              }
            : { enumerable: true, value: candidate },
        ])
      )
    );
    const hostileProxy = new Proxy(value.manifest, {
      ownKeys() {
        throw new Error("hostile ownKeys trap");
      },
    });
    const { authority: _omitted, ...missingAuthority } = value.manifest;

    for (const manifest of [
      accessorManifest,
      hostileProxy,
      { ...value.manifest, extra: true },
      missingAuthority,
    ]) {
      expect(() => snapshotRuntimeEffectEnforcerManifest(manifest)).toThrow(
        RuntimeEffectEnforcerAttestationError
      );
    }
    expect(getterInvoked).toBe(false);

    const attestation = value.attestations[0];
    if (!attestation) throw new Error("Expected fixture attestation");
    const accessorAttestation = Object.defineProperties(
      {},
      Object.fromEntries(
        Object.entries(attestation).map(([key, candidate]) => [
          key,
          key === "authority"
            ? {
                enumerable: true,
                get() {
                  getterInvoked = true;
                  return candidate;
                },
              }
            : { enumerable: true, value: candidate },
        ])
      )
    );
    const { authority: _missingAttestationAuthority, ...missingAttestationAuthority } = attestation;
    for (const candidate of [
      accessorAttestation,
      { ...attestation, extra: true },
      missingAttestationAuthority,
      new Proxy(attestation, {
        getOwnPropertyDescriptor() {
          throw new Error("hostile descriptor trap");
        },
      }),
    ]) {
      expect(() => snapshotRuntimeEffectEnforcerAttestation(candidate)).toThrow(
        RuntimeEffectEnforcerAttestationError
      );
    }
    expect(getterInvoked).toBe(false);
  });

  it("fails closed for accessor, proxy, extra-field, Promise, and malformed verification inputs", () => {
    const value = fixture();
    let getterInvoked = false;
    const accessorInput = Object.defineProperties(
      {},
      {
        subject: {
          enumerable: true,
          get() {
            getterInvoked = true;
            return value.lifecycleSubject;
          },
        },
        subjectDigest: { enumerable: true, value: value.lifecycleSubjectDigest },
        proof: { enumerable: true, value: value.lifecycleProof },
      }
    );
    const proxyInput = new Proxy(value.lifecycleInput, {
      getOwnPropertyDescriptor() {
        throw new Error("hostile input trap");
      },
    });
    let nestedProxyTrapInvoked = false;
    const nestedProxyInput = {
      ...value.lifecycleInput,
      subject: {
        ...value.lifecycleSubject,
        binding: new Proxy(value.lifecycleSubject.binding, {
          ownKeys() {
            nestedProxyTrapInvoked = true;
            throw new Error("hostile nested input trap");
          },
        }),
      },
    };

    for (const input of [
      accessorInput,
      proxyInput,
      nestedProxyInput,
      { ...value.lifecycleInput, extra: true },
      Promise.resolve(value.lifecycleInput),
      null,
    ]) {
      expect(
        value.registry.verifyRuntimeEnforcementProof(
          input as Parameters<typeof value.registry.verifyRuntimeEnforcementProof>[0]
        )
      ).toBe(false);
    }
    expect(getterInvoked).toBe(false);
    expect(nestedProxyTrapInvoked).toBe(false);
  });

  it("loads only owner-controlled canonical JSON through the production file seam", () => {
    const value = fixture({ createRegistry: false });
    const bundle = { manifest: value.manifest, attestations: value.attestations };
    const registryFile = path.join(directory, "effect-enforcer-registry.json");
    fs.writeFileSync(registryFile, canonicalRuntimeJson(bundle), { mode: 0o600 });

    const loaded = createRuntimeEffectEnforcerTrustRegistryFromFile({
      trustedConfigurationRoot: directory,
      registryFile,
      pinnedManifestAuthorityPublicKeys: [platformPin()],
    });

    expect(loaded.verifyRuntimeEnforcementProof(value.lifecycleInput)).toBe(true);
    expect(loaded.verifyRuntimeCompensationEnforcementProof(value.compensationInput)).toBe(true);

    const noncanonicalFile = path.join(directory, "noncanonical.json");
    fs.writeFileSync(noncanonicalFile, `${canonicalRuntimeJson(bundle)}\n`, { mode: 0o600 });
    expect(() =>
      createRuntimeEffectEnforcerTrustRegistryFromFile({
        trustedConfigurationRoot: directory,
        registryFile: noncanonicalFile,
        pinnedManifestAuthorityPublicKeys: [platformPin()],
      })
    ).toThrow(expect.objectContaining({ code: "invalid_registry_file" }));

    const permissiveFile = path.join(directory, "permissive.json");
    fs.writeFileSync(permissiveFile, canonicalRuntimeJson(bundle), { mode: 0o644 });
    expect(() =>
      createRuntimeEffectEnforcerTrustRegistryFromFile({
        trustedConfigurationRoot: directory,
        registryFile: permissiveFile,
        pinnedManifestAuthorityPublicKeys: [platformPin()],
      })
    ).toThrow(expect.objectContaining({ code: "registry_file_unavailable" }));

    const symlinkFile = path.join(directory, "registry-link.json");
    fs.symlinkSync(registryFile, symlinkFile);
    for (const candidate of [symlinkFile, path.basename(registryFile), directory]) {
      expect(() =>
        createRuntimeEffectEnforcerTrustRegistryFromFile({
          trustedConfigurationRoot: directory,
          registryFile: candidate,
          pinnedManifestAuthorityPublicKeys: [platformPin()],
        })
      ).toThrow(expect.objectContaining({ code: "registry_file_unavailable" }));
    }

    const nonCanonicalPath = `${directory}/../${path.basename(directory)}/${path.basename(
      registryFile
    )}`;
    expect(() =>
      createRuntimeEffectEnforcerTrustRegistryFromFile({
        trustedConfigurationRoot: directory,
        registryFile: nonCanonicalPath,
        pinnedManifestAuthorityPublicKeys: [platformPin()],
      })
    ).toThrow(expect.objectContaining({ code: "registry_file_unavailable" }));

    const realParent = path.join(directory, "real-parent");
    fs.mkdirSync(realParent, { mode: 0o700 });
    const parentRegistry = path.join(realParent, "registry.json");
    fs.writeFileSync(parentRegistry, canonicalRuntimeJson(bundle), { mode: 0o600 });
    const linkedParent = path.join(directory, "linked-parent");
    fs.symlinkSync(realParent, linkedParent);
    expect(() =>
      createRuntimeEffectEnforcerTrustRegistryFromFile({
        trustedConfigurationRoot: directory,
        registryFile: path.join(linkedParent, "registry.json"),
        pinnedManifestAuthorityPublicKeys: [platformPin()],
      })
    ).toThrow(expect.objectContaining({ code: "registry_file_unavailable" }));

    const hardLink = path.join(directory, "registry-hard-link.json");
    fs.linkSync(registryFile, hardLink);
    expect(() =>
      createRuntimeEffectEnforcerTrustRegistryFromFile({
        trustedConfigurationRoot: directory,
        registryFile,
        pinnedManifestAuthorityPublicKeys: [platformPin()],
      })
    ).toThrow(expect.objectContaining({ code: "registry_file_unavailable" }));
    fs.rmSync(hardLink);

    const prefixCollisionRoot = `${directory}-outside`;
    fs.mkdirSync(prefixCollisionRoot, { mode: 0o700 });
    const outsideRegistry = path.join(prefixCollisionRoot, "registry.json");
    fs.writeFileSync(outsideRegistry, canonicalRuntimeJson(bundle), { mode: 0o600 });
    expect(() =>
      createRuntimeEffectEnforcerTrustRegistryFromFile({
        trustedConfigurationRoot: directory,
        registryFile: outsideRegistry,
        pinnedManifestAuthorityPublicKeys: [platformPin()],
      })
    ).toThrow(expect.objectContaining({ code: "registry_file_unavailable" }));
    fs.rmSync(prefixCollisionRoot, { recursive: true, force: true });

    fs.chmodSync(directory, 0o770);
    expect(() =>
      createRuntimeEffectEnforcerTrustRegistryFromFile({
        trustedConfigurationRoot: directory,
        registryFile,
        pinnedManifestAuthorityPublicKeys: [platformPin()],
      })
    ).toThrow(expect.objectContaining({ code: "registry_file_unavailable" }));
    fs.chmodSync(directory, 0o700);
  });

  it("keeps manifest, claims, and signed-attestation digests domain separated", () => {
    const value = fixture();
    const attestation = value.attestations[0];
    if (!attestation) throw new Error("Expected fixture attestation");
    const manifestClaimsSnapshot = snapshotRuntimeEffectEnforcerManifestClaims(
      claimsOf(value.manifest)
    );
    const attestationClaimsSnapshot = snapshotRuntimeEffectEnforcerAttestationClaims(
      claimsOfAttestation(attestation)
    );
    const attestationSnapshot = snapshotRuntimeEffectEnforcerAttestation(attestation);

    expect(Object.isFrozen(manifestClaimsSnapshot)).toBe(true);
    expect(Object.isFrozen(attestationClaimsSnapshot)).toBe(true);
    expect(Object.isFrozen(attestationSnapshot)).toBe(true);
    expect(digestRuntimeEffectEnforcerManifestClaims(manifestClaimsSnapshot)).toBe(
      value.manifest.authority.claimsDigest
    );
    expect(digestRuntimeEffectEnforcerAttestationClaims(attestationClaimsSnapshot)).toBe(
      attestation.authority.claimsDigest
    );
    expect(digestRuntimeEffectEnforcerAttestation(attestationSnapshot)).toBe(
      value.lifecycleProof.acknowledgements[0]?.acknowledgementDigest
    );
    expect(
      new Set([
        value.manifest.authority.claimsDigest,
        attestation.authority.claimsDigest,
        digestRuntimeEffectEnforcerAttestation(attestation),
      ]).size
    ).toBe(3);
  });

  function fixture(
    options: {
      readonly expiresAtMs?: number;
      readonly observedAtMs?: number;
      readonly attestationExpiresAtMs?: number;
      readonly createRegistry?: boolean;
    } = {}
  ) {
    const observedAtMs = options.observedAtMs ?? OBSERVED_AT_MS;
    const expiresAtMs = options.expiresAtMs ?? EXPIRES_AT_MS;
    const attestationExpiresAtMs = options.attestationExpiresAtMs ?? observedAtMs + 100;
    const claims = manifestClaims({ expiresAtMs });
    const manifest = signManifest(claims);
    const manifestDigest = manifest.authority.claimsDigest;
    const lifecycleSubject = lifecycleEnforcementSubject(manifestDigest);
    const compensationSubject = compensationEnforcementSubject(manifestDigest);
    const lifecycleSubjectDigest = digestRuntimeEnforcementSubject(lifecycleSubject);
    const compensationSubjectDigest =
      digestRuntimeCompensationEnforcementSubject(compensationSubject);
    const [runtimeEntry, credentialEntry, signerEntry] = manifest.enforcers;
    if (!runtimeEntry || !credentialEntry || !signerEntry) {
      throw new Error("Expected complete manifest");
    }
    const attestations = [
      signAttestation(
        attestationClaims(
          manifestDigest,
          "runtime-lifecycle",
          lifecycleSubjectDigest,
          runtimeEntry,
          { observedAtMs }
        ),
        runtime.privateKey,
        { issuedAtMs: observedAtMs, expiresAtMs: attestationExpiresAtMs }
      ),
      signAttestation(
        attestationClaims(
          manifestDigest,
          "runtime-lifecycle",
          lifecycleSubjectDigest,
          credentialEntry,
          { observedAtMs }
        ),
        credentialProxy.privateKey,
        { issuedAtMs: observedAtMs, expiresAtMs: attestationExpiresAtMs }
      ),
      signAttestation(
        attestationClaims(
          manifestDigest,
          "stale-lifecycle-effect-containment",
          compensationSubjectDigest,
          runtimeEntry,
          { observedAtMs }
        ),
        runtime.privateKey,
        { issuedAtMs: observedAtMs, expiresAtMs: attestationExpiresAtMs }
      ),
      signAttestation(
        attestationClaims(
          manifestDigest,
          "stale-lifecycle-effect-containment",
          compensationSubjectDigest,
          signerEntry,
          { observedAtMs }
        ),
        signer.privateKey,
        { issuedAtMs: observedAtMs, expiresAtMs: attestationExpiresAtMs }
      ),
    ] as const;
    const lifecycleProof = proof(manifestDigest, lifecycleSubjectDigest, GENERATION, [
      ack(attestations[0]),
      ack(attestations[1]),
    ]);
    const compensationProof = proof(manifestDigest, compensationSubjectDigest, GENERATION, [
      ack(attestations[2]),
      ack(attestations[3]),
    ]);
    const lifecycleInput = {
      subject: lifecycleSubject,
      subjectDigest: lifecycleSubjectDigest,
      proof: lifecycleProof,
    };
    const compensationInput = {
      subject: compensationSubject,
      subjectDigest: compensationSubjectDigest,
      proof: compensationProof,
    };
    const createdRegistry =
      options.createRegistry === false ? undefined : registry(manifest, attestations);
    return {
      manifest,
      attestations,
      lifecycleSubject,
      lifecycleSubjectDigest,
      lifecycleProof,
      lifecycleInput,
      compensationSubject,
      compensationSubjectDigest,
      compensationProof,
      compensationInput,
      registry: createdRegistry!,
    };
  }

  function manifestClaims(
    overrides: Partial<
      Pick<RuntimeEffectEnforcerManifestClaims, "validFromMs" | "expiresAtMs">
    > = {}
  ): RuntimeEffectEnforcerManifestClaims {
    return {
      version: 1,
      kind: "runtime.effect-enforcer-manifest",
      manifestId: "production-effect-enforcers:v1",
      assignmentPlanDigest: "1".repeat(64),
      effectEnforcerPolicyDigest: "2".repeat(64),
      providerIdentityCommitment: "3".repeat(64),
      providerRevision: 1,
      effectManifestBindingDigest: "4".repeat(64),
      validFromMs: overrides.validFromMs ?? VALID_FROM_MS,
      expiresAtMs: overrides.expiresAtMs ?? EXPIRES_AT_MS,
      enforcers: [
        {
          enforcerRef: "a-runtime",
          enforcerKind: "runtime",
          enforcerKeyId: "runtime-key-1",
          publicKeySpkiPem: runtime.publicKeySpkiPem,
          publicKeySpkiDigest: runtime.publicKeySpkiDigest,
          allowedPurposes: ["runtime-lifecycle", "stale-lifecycle-effect-containment"],
        },
        {
          enforcerRef: "b-credential",
          enforcerKind: "credential-proxy",
          enforcerKeyId: "credential-proxy-key-1",
          publicKeySpkiPem: credentialProxy.publicKeySpkiPem,
          publicKeySpkiDigest: credentialProxy.publicKeySpkiDigest,
          allowedPurposes: ["runtime-lifecycle"],
        },
        {
          enforcerRef: "c-signer",
          enforcerKind: "signer",
          enforcerKeyId: "signer-key-1",
          publicKeySpkiPem: signer.publicKeySpkiPem,
          publicKeySpkiDigest: signer.publicKeySpkiDigest,
          allowedPurposes: ["stale-lifecycle-effect-containment"],
        },
      ],
    };
  }

  function signManifest(
    claims: RuntimeEffectEnforcerManifestClaims,
    privateKey: KeyObject = platform.privateKey,
    overrides: Partial<Omit<RuntimeEffectEnforcerManifestAuthority, "signature">> & {
      readonly signature?: string;
    } = {}
  ): RuntimeEffectEnforcerManifest {
    const claimsDigest = digestRuntimeEffectEnforcerManifestClaims(claims);
    const authorityWithoutSignature = {
      issuer: "platform-security" as const,
      issuerKeyId: "platform-manifest-key-1",
      audience: "terminalx-control-plane" as const,
      capability: "runtime.effect-enforcer-manifest.trust" as const,
      claimsDigest,
      issuedAtMs: claims.validFromMs,
      expiresAtMs: claims.expiresAtMs,
      ...overrides,
    };
    const signature =
      overrides.signature ??
      signAuthority(
        RUNTIME_EFFECT_ENFORCER_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN,
        manifestAuthorityStatement(authorityWithoutSignature),
        privateKey
      );
    return { ...claims, authority: { ...authorityWithoutSignature, signature } };
  }

  function resignManifest(claims: RuntimeEffectEnforcerManifestClaims) {
    return signManifest(claims);
  }

  function signAttestation(
    claims: RuntimeEffectEnforcerAttestationClaims,
    privateKey: KeyObject,
    overrides: Partial<Omit<RuntimeEffectEnforcerAttestationAuthority, "signature">> & {
      readonly signature?: string;
    } = {}
  ): RuntimeEffectEnforcerAttestation {
    const claimsDigest = digestRuntimeEffectEnforcerAttestationClaims(claims);
    const authorityWithoutSignature = {
      issuer: "runtime-effect-enforcer" as const,
      issuerKeyId: claims.enforcerKeyId,
      audience: "terminalx-control-plane" as const,
      capability: "runtime.effect-enforcement.attest" as const,
      claimsDigest,
      issuedAtMs: claims.observedAtMs,
      expiresAtMs: claims.observedAtMs + 100,
      ...overrides,
    };
    const signature =
      overrides.signature ??
      signAuthority(
        RUNTIME_EFFECT_ENFORCER_ATTESTATION_AUTHORITY_SIGNATURE_DOMAIN,
        attestationAuthorityStatement(authorityWithoutSignature),
        privateKey
      );
    return { ...claims, authority: { ...authorityWithoutSignature, signature } };
  }

  function registry(manifest: unknown, attestations: readonly unknown[]) {
    return createRuntimeEffectEnforcerTrustRegistry({
      manifest,
      attestations,
      pinnedManifestAuthorityPublicKeys: [platformPin()],
    });
  }

  function dynamicRegistry(
    manifest: unknown,
    attestationSource: RuntimeEffectEnforcerAttestationSource
  ) {
    return createRuntimeEffectEnforcerTrustRegistryWithAttestationSource({
      manifest,
      attestationSource,
      pinnedManifestAuthorityPublicKeys: [platformPin()],
    });
  }

  function platformPin(): PinnedRuntimeEffectEnforcerManifestAuthorityPublicKey {
    return {
      issuerKeyId: "platform-manifest-key-1",
      publicKeySpkiPem: platform.publicKeySpkiPem,
      publicKeySpkiDigest: platform.publicKeySpkiDigest,
    };
  }
});

function keyMaterial(): KeyMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicKeySpkiDigest = createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  return { privateKey, publicKeySpkiPem, publicKeySpkiDigest };
}

function lifecycleEnforcementSubject(manifestDigest: string): RuntimeEnforcementSubject {
  return {
    version: 1,
    commandId: "runtime-command-1",
    commandClaimsDigest: "1".repeat(64),
    binding: BINDING,
    runtimeAuthorizationGeneration: GENERATION,
    requiredEffectEnforcerSetDigest: manifestDigest,
    effectRefCommitment: commitRuntimeEffectRef("provider-lifecycle-effect"),
    enforcedFence: 9,
  };
}

function compensationEnforcementSubject(
  manifestDigest: string
): RuntimeCompensationEnforcementSubject {
  return {
    version: 1,
    purpose: "stale-lifecycle-effect-containment",
    compensationId: "compensation-1",
    commandId: "compensation-command-1",
    commandClaimsDigest: "2".repeat(64),
    binding: BINDING,
    observedRuntimeAuthorizationGeneration: GENERATION,
    safetyFence: 10,
    enforcedSafetyFence: 11,
    sourceReceiptDigest: "3".repeat(64),
    sourceEnforcementSubjectDigest: "4".repeat(64),
    sourceAggregateProofDigest: "5".repeat(64),
    requiredContainmentEnforcerSetDigest: manifestDigest,
    effectRefCommitment: commitRuntimeEffectRef("provider-compensation-effect"),
    containment: {
      terminalWritesRevoked: true,
      processExecutionStopped: true,
      runtimeQuarantined: true,
    },
  };
}

function attestationClaims(
  manifestDigest: string,
  purpose: RuntimeEffectEnforcerAttestationClaims["purpose"],
  enforcementSubjectDigest: string,
  entry: RuntimeEffectEnforcerManifestEntry,
  overrides: Partial<
    Pick<RuntimeEffectEnforcerAttestationClaims, "generation" | "observedAtMs">
  > = {}
): RuntimeEffectEnforcerAttestationClaims {
  return {
    version: 1,
    kind: "runtime.effect-enforcer-attestation",
    manifestDigest,
    purpose,
    generation: overrides.generation ?? GENERATION,
    enforcementSubjectDigest,
    enforcerRef: entry.enforcerRef,
    enforcerKind: entry.enforcerKind,
    enforcerKeyId: entry.enforcerKeyId,
    enforcerPublicKeySpkiDigest: entry.publicKeySpkiDigest,
    observedAtMs: overrides.observedAtMs ?? OBSERVED_AT_MS,
  };
}

function proof(
  manifestDigest: string,
  subjectDigest: string,
  generation: number,
  acknowledgements: AggregateEnforcementProof["acknowledgements"]
): AggregateEnforcementProof {
  const payload = {
    generation,
    requiredEffectEnforcerSetDigest: manifestDigest,
    enforcementSubjectDigest: subjectDigest,
    acknowledgements,
  };
  return { ...payload, aggregateProofDigest: digestAggregateEnforcementProof(payload) };
}

function ack(
  attestation: RuntimeEffectEnforcerAttestation
): AggregateEnforcementProof["acknowledgements"][number] {
  return {
    enforcerRef: attestation.enforcerRef,
    enforcerKind: attestation.enforcerKind,
    acknowledgementDigest: digestRuntimeEffectEnforcerAttestation(attestation),
  };
}

function claimsOf(manifest: RuntimeEffectEnforcerManifest): RuntimeEffectEnforcerManifestClaims {
  return {
    version: manifest.version,
    kind: manifest.kind,
    manifestId: manifest.manifestId,
    assignmentPlanDigest: manifest.assignmentPlanDigest,
    effectEnforcerPolicyDigest: manifest.effectEnforcerPolicyDigest,
    providerIdentityCommitment: manifest.providerIdentityCommitment,
    providerRevision: manifest.providerRevision,
    effectManifestBindingDigest: manifest.effectManifestBindingDigest,
    validFromMs: manifest.validFromMs,
    expiresAtMs: manifest.expiresAtMs,
    enforcers: manifest.enforcers,
  };
}

function claimsOfAttestation(
  attestation: RuntimeEffectEnforcerAttestation
): RuntimeEffectEnforcerAttestationClaims {
  return {
    version: attestation.version,
    kind: attestation.kind,
    manifestDigest: attestation.manifestDigest,
    purpose: attestation.purpose,
    generation: attestation.generation,
    enforcementSubjectDigest: attestation.enforcementSubjectDigest,
    enforcerRef: attestation.enforcerRef,
    enforcerKind: attestation.enforcerKind,
    enforcerKeyId: attestation.enforcerKeyId,
    enforcerPublicKeySpkiDigest: attestation.enforcerPublicKeySpkiDigest,
    observedAtMs: attestation.observedAtMs,
  };
}

function manifestAuthorityStatement(
  authority: Omit<RuntimeEffectEnforcerManifestAuthority, "signature">
) {
  return {
    version: 1,
    issuer: authority.issuer,
    issuerKeyId: authority.issuerKeyId,
    audience: authority.audience,
    capability: authority.capability,
    claimsDigest: authority.claimsDigest,
    issuedAtMs: authority.issuedAtMs,
    expiresAtMs: authority.expiresAtMs,
  };
}

function attestationAuthorityStatement(
  authority:
    | Omit<RuntimeEffectEnforcerAttestationAuthority, "signature">
    | RuntimeEffectEnforcerAttestationAuthority
) {
  return {
    version: 1,
    issuer: authority.issuer,
    issuerKeyId: authority.issuerKeyId,
    audience: authority.audience,
    capability: authority.capability,
    claimsDigest: authority.claimsDigest,
    issuedAtMs: authority.issuedAtMs,
    expiresAtMs: authority.expiresAtMs,
  };
}

function signAuthority(domain: string, statement: unknown, privateKey: KeyObject): string {
  return signEd25519(
    null,
    Buffer.concat([
      Buffer.from(domain, "utf8"),
      Buffer.from(canonicalRuntimeJson(statement), "utf8"),
    ]),
    privateKey
  ).toString("base64url");
}
