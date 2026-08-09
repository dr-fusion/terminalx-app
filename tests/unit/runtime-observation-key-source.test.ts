import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as signEd25519,
  type KeyObject,
} from "node:crypto";
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RuntimeBinding } from "@/lib/team-sessions/contracts";
import { canonicalRuntimeJson } from "@/lib/runtime/runtime-command-canonical";
import {
  RUNTIME_OBSERVATION_KEY_ATTESTATION_DIGEST_DOMAIN,
  RUNTIME_OBSERVATION_KEY_ATTESTATION_SIGNATURE_DOMAIN,
  RUNTIME_OBSERVATION_KEY_DESCRIPTOR_DIGEST_DOMAIN,
  RuntimeObservationKeySourceError,
  createPinnedRuntimeObservationKeySource,
  createRuntimeObservationKeyRegistrationVerifier,
  createRuntimeObservationKeySourceWithRegistrationSource,
  digestRuntimeObservationKeyAttestation,
  digestRuntimeObservationKeyDescriptor,
  isAuthenticatedRuntimeObservationKeyRegistration,
  loadPinnedRuntimeObservationKeySourceFromFile,
  snapshotRuntimeObservationKeyAttestation,
  snapshotRuntimeObservationKeyDescriptor,
  type PinnedRuntimeObservationKeyAuthorityPublicKey,
  type RuntimeObservationKeyDescriptor,
  type RuntimeObservationKeyLookup,
  type SignedRuntimeObservationKeyRegistrationSource,
  type SignedRuntimeObservationKeyRegistration,
} from "@/lib/runtime/runtime-observation-key-source";

const binding = {
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 3,
  sandboxId: "sandbox-1",
  sandboxGeneration: 4,
  runtimePrincipalId: "principal-1",
} as const;

describe("pinned Runtime observation-key source", () => {
  let directory: string;
  let authorityPrivateKey: KeyObject;
  let authorityPublicKeyPem: string;
  let observationPrivateKeyPem: string;
  let observationPublicKeyPem: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "terminalx-observation-key-source-"));
    const authority = generateKeyPairSync("ed25519");
    authorityPrivateKey = authority.privateKey;
    authorityPublicKeyPem = canonicalPublicPem(authority.publicKey);
    const observation = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    observationPrivateKeyPem = observation.privateKey;
    observationPublicKeyPem = observation.publicKey;
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  function authorityPins(): readonly PinnedRuntimeObservationKeyAuthorityPublicKey[] {
    return [
      {
        authorityKeyId: "runtime-observation-key-authority:v1",
        publicKeySpkiPem: authorityPublicKeyPem,
      },
    ];
  }

  function source(registrations: readonly SignedRuntimeObservationKeyRegistration[]) {
    return createPinnedRuntimeObservationKeySource({
      pinnedAuthorityPublicKeys: authorityPins(),
      registrations,
    });
  }

  it("returns only an authenticated, exact-bound, deeply frozen detached registration", () => {
    const signed = signedRegistration();
    const registry = source([signed]);
    const registration = registry.get({ binding, runtimeAuthorizationGeneration: 7 });

    expect(registration).toMatchObject({
      binding,
      runtimeAuthorizationGeneration: 7,
      issuerKeyId: "daytona-observer:v1",
      publicKeySpkiPem: observationPublicKeyPem,
      publicKeySpkiDigest: spkiDigest(observationPublicKeyPem),
      descriptorDigest: digestRuntimeObservationKeyDescriptor(signed.descriptor),
      attestationDigest: digestRuntimeObservationKeyAttestation(signed.attestation),
      authorityKeyId: "runtime-observation-key-authority:v1",
      adapterIdentityRef: "daytona-adapter-image:sha256:identity",
      adapterConfigurationRef: "daytona-adapter-config:sha256:configuration",
      issuedAtMs: 1,
    });
    expect(Object.keys(registration!)).not.toContain("signature");
    expect(Object.isFrozen(registry)).toBe(true);
    expect(Object.isFrozen(registration)).toBe(true);
    expect(Object.isFrozen(registration!.binding)).toBe(true);
    expect(isAuthenticatedRuntimeObservationKeyRegistration(registration)).toBe(true);
    expect(
      isAuthenticatedRuntimeObservationKeyRegistration(Object.freeze({ ...registration }))
    ).toBe(false);
    const stolenBrand = Reflect.ownKeys(registration!).find(
      (key): key is symbol => typeof key === "symbol"
    );
    if (!stolenBrand) throw new Error("Expected private authentication brand");
    const forged = { ...registration } as Record<PropertyKey, unknown>;
    Object.defineProperty(forged, stolenBrand, {
      value: true,
      enumerable: false,
      writable: false,
      configurable: false,
    });
    expect(isAuthenticatedRuntimeObservationKeyRegistration(Object.freeze(forged))).toBe(false);

    (signed.descriptor.binding as { sandboxId: string }).sandboxId = "caller-mutated";
    (signed.descriptor as { issuerKeyId: string }).issuerKeyId = "caller-mutated";
    expect(registry.get({ binding, runtimeAuthorizationGeneration: 7 })).toBe(registration);
    expect(registration!.binding.sandboxId).toBe("sandbox-1");
    expect(registration!.issuerKeyId).toBe("daytona-observer:v1");
  });

  it("canonicalizes detached descriptor and attestation snapshots under distinct domains", () => {
    const signed = signedRegistration();
    const descriptor = snapshotRuntimeObservationKeyDescriptor(signed.descriptor);
    const attestation = snapshotRuntimeObservationKeyAttestation(signed.attestation);

    expect(descriptor).toEqual(signed.descriptor);
    expect(attestation).toEqual(signed.attestation);
    expect(Object.isFrozen(descriptor)).toBe(true);
    expect(Object.isFrozen(descriptor.binding)).toBe(true);
    expect(Object.isFrozen(attestation)).toBe(true);
    expect(digestRuntimeObservationKeyDescriptor(descriptor)).toBe(
      domainDigest(RUNTIME_OBSERVATION_KEY_DESCRIPTOR_DIGEST_DOMAIN, descriptor)
    );
    expect(digestRuntimeObservationKeyAttestation(attestation)).toBe(
      domainDigest(RUNTIME_OBSERVATION_KEY_ATTESTATION_DIGEST_DOMAIN, attestation)
    );
    expect(RUNTIME_OBSERVATION_KEY_ATTESTATION_SIGNATURE_DOMAIN).not.toBe(
      RUNTIME_OBSERVATION_KEY_DESCRIPTOR_DIGEST_DOMAIN
    );
    expect(RUNTIME_OBSERVATION_KEY_ATTESTATION_SIGNATURE_DOMAIN).not.toBe(
      RUNTIME_OBSERVATION_KEY_ATTESTATION_DIGEST_DOMAIN
    );
  });

  it("returns null for every incompatible binding field or authorization generation", () => {
    const registry = source([signedRegistration()]);
    const otherBindings: RuntimeBinding[] = [
      { ...binding, teamId: "team-other" },
      { ...binding, projectId: "project-other" },
      { ...binding, sessionId: "session-other" },
      { ...binding, runtimeAssignmentId: "assignment-other" },
      { ...binding, runtimeAssignmentGeneration: 30 },
      { ...binding, sandboxId: "sandbox-other" },
      { ...binding, sandboxGeneration: 40 },
      { ...binding, runtimePrincipalId: "principal-other" },
    ];

    for (const otherBinding of otherBindings) {
      expect(registry.get({ binding: otherBinding, runtimeAuthorizationGeneration: 7 })).toBeNull();
    }
    expect(registry.get({ binding, runtimeAuthorizationGeneration: 8 })).toBeNull();
  });

  it("dynamically resolves newly provisioned exact registrations and re-verifies every lookup", () => {
    const records = new Map<string, unknown>();
    const lookups: RuntimeObservationKeyLookup[] = [];
    const dynamic = createRuntimeObservationKeySourceWithRegistrationSource({
      pinnedAuthorityPublicKeys: authorityPins(),
      registrationSource: {
        get: (lookup) => {
          expect(Object.isFrozen(lookup)).toBe(true);
          expect(Object.isFrozen(lookup.binding)).toBe(true);
          lookups.push(lookup);
          return records.get(lookupKey(lookup)) ?? null;
        },
      },
    });
    const lookup = { binding, runtimeAuthorizationGeneration: 7 } as const;

    expect(dynamic.get(lookup)).toBeNull();
    const signed = signedRegistration();
    records.set(lookupKey(lookup), signed);
    const first = dynamic.get(lookup);
    expect(isAuthenticatedRuntimeObservationKeyRegistration(first)).toBe(true);
    expect(lookups).toHaveLength(2);

    records.set(lookupKey(lookup), {
      ...signed,
      attestation: { ...signed.attestation, signature: "A".repeat(86) },
    });
    expect(dynamic.get(lookup)).toBeNull();
    records.set(lookupKey(lookup), signed);
    expect(dynamic.get(lookup)).not.toBe(first);

    const wrongLookup = {
      binding: { ...binding, sandboxId: "sandbox-other" },
      runtimeAuthorizationGeneration: 7,
    };
    records.set(lookupKey(wrongLookup), signed);
    expect(dynamic.get(wrongLookup)).toBeNull();
  });

  it("fails closed for hostile, asynchronous, thenable, proxy, and malformed dynamic sources", () => {
    const signed = signedRegistration();
    const lookup = { binding, runtimeAuthorizationGeneration: 7 } as const;
    let thenGetterInvoked = false;
    const thenable = Object.defineProperty({ ...signed }, "then", {
      enumerable: true,
      get() {
        thenGetterInvoked = true;
        return () => undefined;
      },
    });
    const results: unknown[] = [
      undefined,
      Promise.resolve(signed),
      Promise.reject(new Error("private provider rejection")),
      thenable,
      new Proxy(signed, {
        ownKeys() {
          throw new Error("hostile result");
        },
      }),
      [signed],
      { registration: signed },
    ];
    for (const result of results) {
      const source = createRuntimeObservationKeySourceWithRegistrationSource({
        pinnedAuthorityPublicKeys: authorityPins(),
        registrationSource: { get: () => result },
      });
      expect(source.get(lookup)).toBeNull();
    }
    expect(thenGetterInvoked).toBe(false);

    let getterInvoked = false;
    const accessorSource = Object.defineProperty({}, "get", {
      enumerable: true,
      get() {
        getterInvoked = true;
        return () => signed;
      },
    });
    const proxySource = new Proxy(
      { get: () => signed },
      {
        ownKeys() {
          throw new Error("hostile source");
        },
      }
    );
    const proxyGet = new Proxy(() => signed, {});
    for (const registrationSource of [
      accessorSource,
      proxySource,
      { get: proxyGet },
      { get: () => signed, extra: true },
      Object.create({ get: () => signed }),
    ]) {
      expect(() =>
        createRuntimeObservationKeySourceWithRegistrationSource({
          pinnedAuthorityPublicKeys: authorityPins(),
          registrationSource: registrationSource as SignedRuntimeObservationKeyRegistrationSource,
        })
      ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
    }
    expect(getterInvoked).toBe(false);
  });

  it("authenticates every descriptor claim and rejects wrong digests, domains, and signatures", () => {
    const signed = signedRegistration();
    const descriptorMutations: RuntimeObservationKeyDescriptor[] = [
      { ...signed.descriptor, binding: { ...binding, teamId: "team-other" } },
      { ...signed.descriptor, binding: { ...binding, projectId: "project-other" } },
      { ...signed.descriptor, binding: { ...binding, sessionId: "session-other" } },
      {
        ...signed.descriptor,
        binding: { ...binding, runtimeAssignmentId: "assignment-other" },
      },
      {
        ...signed.descriptor,
        binding: { ...binding, runtimeAssignmentGeneration: 30 },
      },
      { ...signed.descriptor, binding: { ...binding, sandboxId: "sandbox-other" } },
      { ...signed.descriptor, binding: { ...binding, sandboxGeneration: 40 } },
      {
        ...signed.descriptor,
        binding: { ...binding, runtimePrincipalId: "principal-other" },
      },
      { ...signed.descriptor, runtimeAuthorizationGeneration: 8 },
      { ...signed.descriptor, issuerKeyId: "daytona-observer:v2" },
      { ...signed.descriptor, publicKeySpkiDigest: "0".repeat(64) },
      { ...signed.descriptor, adapterIdentityRef: "adapter-other" },
      { ...signed.descriptor, adapterConfigurationRef: "configuration-other" },
      { ...signed.descriptor, issuedAtMs: 2 },
    ];
    const verifier = createRuntimeObservationKeyRegistrationVerifier({
      pinnedAuthorityPublicKeys: authorityPins(),
    });

    for (const descriptor of descriptorMutations) {
      expect(() => verifier.verify({ ...signed, descriptor })).toThrow(
        expect.objectContaining({ code: "digest_mismatch" })
      );
    }

    expect(() =>
      verifier.verify({
        ...signed,
        attestation: { ...signed.attestation, descriptorDigest: "0".repeat(64) },
      })
    ).toThrow(expect.objectContaining({ code: "digest_mismatch" }));
    expect(() =>
      verifier.verify({
        ...signed,
        attestation: { ...signed.attestation, authorityKeyId: "authority:unknown" },
      })
    ).toThrow(expect.objectContaining({ code: "untrusted_authority" }));

    const wrongDomain = signedRegistration({
      signatureDomain: "terminalx/runtime-receipt-observation/v1\0",
    });
    expect(() => verifier.verify(wrongDomain)).toThrow(
      expect.objectContaining({ code: "invalid_signature" })
    );
    const otherAuthority = generateKeyPairSync("ed25519");
    expect(() =>
      verifier.verify(signedRegistration({ authorityPrivateKey: otherAuthority.privateKey }))
    ).toThrow(expect.objectContaining({ code: "invalid_signature" }));
  });

  it("accepts only canonical Ed25519 SPKI public keys for observations and authority pins", () => {
    const verifier = createRuntimeObservationKeyRegistrationVerifier({
      pinnedAuthorityPublicKeys: authorityPins(),
    });
    const rsa = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    for (const publicKeySpkiPem of [observationPrivateKeyPem, rsa.publicKey]) {
      expect(() => verifier.verify({ ...signedRegistration(), publicKeySpkiPem })).toThrow(
        expect.objectContaining({ code: "invalid_public_key" })
      );
    }
    expect(() =>
      verifier.verify({
        ...signedRegistration(),
        publicKeySpkiPem: observationPublicKeyPem.trimEnd(),
      })
    ).toThrow(expect.objectContaining({ code: "invalid_public_key" }));

    for (const publicKeySpkiPem of [observationPrivateKeyPem, rsa.publicKey]) {
      expect(() =>
        createRuntimeObservationKeyRegistrationVerifier({
          pinnedAuthorityPublicKeys: [
            {
              authorityKeyId: "runtime-observation-key-authority:v1",
              publicKeySpkiPem,
            },
          ],
        })
      ).toThrow(expect.objectContaining({ code: "invalid_public_key" }));
    }
  });

  it("rejects duplicate lookups, duplicate exact keys, and key or key-id reuse", () => {
    const first = signedRegistration();
    expect(() => source([first, first])).toThrow(
      expect.objectContaining({ code: "duplicate_registration" })
    );

    const otherObservation = generateKeyPairSync("ed25519");
    const sameLookupDifferentKey = signedRegistration({
      observationPublicKeyPem: canonicalPublicPem(otherObservation.publicKey),
    });
    expect(() => source([first, sameLookupDifferentKey])).toThrow(
      expect.objectContaining({ code: "duplicate_registration" })
    );

    const sameKeyOtherGeneration = signedRegistration({
      descriptor: { runtimeAuthorizationGeneration: 8, issuerKeyId: "daytona-observer:v2" },
    });
    expect(() => source([first, sameKeyOtherGeneration])).toThrow(
      expect.objectContaining({ code: "key_reuse" })
    );

    const sameKeyOtherBinding = signedRegistration({
      descriptor: {
        binding: { ...binding, runtimeAssignmentId: "assignment-other" },
        issuerKeyId: "daytona-observer:v3",
      },
    });
    expect(() => source([first, sameKeyOtherBinding])).toThrow(
      expect.objectContaining({ code: "key_reuse" })
    );

    const sameIssuerOtherGeneration = signedRegistration({
      descriptor: { runtimeAuthorizationGeneration: 8 },
      observationPublicKeyPem: canonicalPublicPem(otherObservation.publicKey),
    });
    expect(() => source([first, sameIssuerOtherGeneration])).toThrow(
      expect.objectContaining({ code: "key_reuse" })
    );
  });

  it("rejects duplicate authority IDs or one authority key under multiple IDs", () => {
    const pin = authorityPins()[0]!;
    expect(() =>
      createRuntimeObservationKeyRegistrationVerifier({
        pinnedAuthorityPublicKeys: [pin, pin],
      })
    ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
    expect(() =>
      createRuntimeObservationKeyRegistrationVerifier({
        pinnedAuthorityPublicKeys: [pin, { ...pin, authorityKeyId: "authority:alias" }],
      })
    ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
  });

  it("rejects observation signing material or key IDs reused from the authority role", () => {
    const authorityKeyRegistration = signedRegistration({
      observationPublicKeyPem: authorityPublicKeyPem,
      descriptor: { issuerKeyId: "daytona-observer:authority-key-reuse" },
    });
    expect(() =>
      createRuntimeObservationKeyRegistrationVerifier({
        pinnedAuthorityPublicKeys: authorityPins(),
      }).verify(authorityKeyRegistration)
    ).toThrow(expect.objectContaining({ code: "key_reuse" }));
    expect(() => source([authorityKeyRegistration])).toThrow(
      expect.objectContaining({ code: "key_reuse" })
    );
    expect(() =>
      source([
        signedRegistration({
          descriptor: { issuerKeyId: "runtime-observation-key-authority:v1" },
        }),
      ])
    ).toThrow(expect.objectContaining({ code: "key_reuse" }));

    const dynamic = createRuntimeObservationKeySourceWithRegistrationSource({
      pinnedAuthorityPublicKeys: authorityPins(),
      registrationSource: {
        get: () =>
          signedRegistration({
            observationPublicKeyPem: authorityPublicKeyPem,
            descriptor: { issuerKeyId: "daytona-observer:authority-key-reuse" },
          }),
      },
    });
    expect(dynamic.get({ binding, runtimeAuthorizationGeneration: 7 })).toBeNull();
  });

  it("rejects extras, accessors, and proxies without invoking hostile code", () => {
    const signed = signedRegistration();
    let getterCalls = 0;
    const descriptorWithAccessor = { ...signed.descriptor } as Record<string, unknown>;
    Object.defineProperty(descriptorWithAccessor, "issuedAtMs", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 1;
      },
    });
    expect(() => snapshotRuntimeObservationKeyDescriptor(descriptorWithAccessor)).toThrow(
      expect.objectContaining({ code: "invalid_descriptor" })
    );
    expect(getterCalls).toBe(0);
    expect(() =>
      snapshotRuntimeObservationKeyDescriptor({ ...signed.descriptor, extra: true })
    ).toThrow(expect.objectContaining({ code: "invalid_descriptor" }));
    expect(() =>
      snapshotRuntimeObservationKeyAttestation({ ...signed.attestation, extra: true })
    ).toThrow(expect.objectContaining({ code: "invalid_attestation" }));
    expect(() =>
      snapshotRuntimeObservationKeyDescriptor({ ...signed.descriptor, version: 2 })
    ).toThrow(expect.objectContaining({ code: "invalid_descriptor" }));
    expect(() =>
      snapshotRuntimeObservationKeyDescriptor({ ...signed.descriptor, issuedAtMs: -0 })
    ).toThrow(expect.objectContaining({ code: "invalid_descriptor" }));
    expect(() =>
      snapshotRuntimeObservationKeyAttestation({
        ...signed.attestation,
        kind: "runtime.observation-key-descriptor",
      })
    ).toThrow(expect.objectContaining({ code: "invalid_attestation" }));
    expect(() => snapshotRuntimeObservationKeyDescriptor(new Proxy(signed.descriptor, {}))).toThrow(
      expect.objectContaining({ code: "invalid_descriptor" })
    );
    expect(() =>
      snapshotRuntimeObservationKeyDescriptor({
        ...signed.descriptor,
        binding: new Proxy(binding, {}),
      })
    ).toThrow(expect.objectContaining({ code: "invalid_descriptor" }));

    const registry = source([signed]);
    expect(() =>
      registry.get({ binding, runtimeAuthorizationGeneration: 7, extra: true } as never)
    ).toThrow(expect.objectContaining({ code: "invalid_input" }));
    expect(() =>
      createPinnedRuntimeObservationKeySource(
        new Proxy({ pinnedAuthorityPublicKeys: authorityPins(), registrations: [signed] }, {})
      )
    ).toThrow(expect.objectContaining({ code: "invalid_configuration" }));
  });

  it("loads canonical historical registrations from a strict file and re-verifies on restart", () => {
    const signed = signedRegistration({ descriptor: { issuedAtMs: 0 } });
    const filePath = writeRegistryFile("registry.json", [signed]);

    const first = loadPinnedRuntimeObservationKeySourceFromFile({
      trustedConfigurationRoot: directory,
      filePath,
      pinnedAuthorityPublicKeys: authorityPins(),
    }).get({ binding, runtimeAuthorizationGeneration: 7 });
    chmodSync(filePath, 0o400);
    const afterRestart = loadPinnedRuntimeObservationKeySourceFromFile({
      trustedConfigurationRoot: directory,
      filePath,
      pinnedAuthorityPublicKeys: authorityPins(),
    }).get({ binding, runtimeAuthorizationGeneration: 7 });

    expect(first).not.toBeNull();
    expect(first!.issuedAtMs).toBe(0);
    expect(afterRestart).toEqual(first);
    expect(afterRestart!.descriptorDigest).toBe(first!.descriptorDigest);
    expect(afterRestart!.attestationDigest).toBe(first!.attestationDigest);
  });

  it("rejects relative paths, symlinks, symlinked parents, non-files, and unsafe modes", () => {
    const signed = signedRegistration();
    const filePath = writeRegistryFile("registry.json", [signed]);
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath: basename(filePath),
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));
    const nonCanonicalPath = `${directory}/../${basename(directory)}/${basename(filePath)}`;
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath: nonCanonicalPath,
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));

    const fileLink = join(directory, "registry-link.json");
    symlinkSync(filePath, fileLink);
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath: fileLink,
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));

    const realParent = join(directory, "real-parent");
    mkdirSync(realParent, { mode: 0o700 });
    const parentFile = join(realParent, "registry.json");
    writeFileSync(parentFile, registryJson([signed]), { mode: 0o600 });
    const linkedParent = join(directory, "linked-parent");
    symlinkSync(realParent, linkedParent);
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath: join(linkedParent, "registry.json"),
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));

    chmodSync(filePath, 0o644);
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath,
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));
    chmodSync(filePath, 0o600);

    const hardLink = join(directory, "registry-hard-link.json");
    linkSync(filePath, hardLink);
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath,
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));
    rmSync(hardLink);

    const prefixCollisionRoot = `${directory}-outside`;
    mkdirSync(prefixCollisionRoot, { mode: 0o700 });
    const outsideFile = join(prefixCollisionRoot, "registry.json");
    writeFileSync(outsideFile, registryJson([signed]), { mode: 0o600 });
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath: outsideFile,
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));
    rmSync(prefixCollisionRoot, { recursive: true, force: true });

    chmodSync(directory, 0o770);
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath,
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));
    chmodSync(directory, 0o700);

    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath: directory,
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));
  });

  it("rejects malformed, noncanonical, oversized, and schema-expanded registry files", () => {
    const signed = signedRegistration();
    const filePath = join(directory, "registry.json");
    const invalidSources: Array<string | Buffer> = [
      `${registryJson([signed])}\n`,
      JSON.stringify({
        version: 1,
        kind: "runtime.observation-key-registry",
        registrations: [signed],
      }),
      canonicalRuntimeJson({
        version: 1,
        kind: "runtime.observation-key-registry",
        registrations: [signed],
        extra: true,
      }),
      "{",
      Buffer.from([0xff, 0xfe]),
    ];

    for (const contents of invalidSources) {
      writeFileSync(filePath, contents, { mode: 0o600 });
      expect(() =>
        loadPinnedRuntimeObservationKeySourceFromFile({
          trustedConfigurationRoot: directory,
          filePath,
          pinnedAuthorityPublicKeys: authorityPins(),
        })
      ).toThrow(
        expect.objectContaining({
          code: expect.stringMatching(/invalid_source|source_unavailable/),
        })
      );
    }

    writeFileSync(filePath, "x".repeat(1024 * 1024 + 1), { mode: 0o600 });
    expect(() =>
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath,
        pinnedAuthorityPublicKeys: authorityPins(),
      })
    ).toThrow(expect.objectContaining({ code: "source_unavailable" }));
  });

  it("uses only stable safe errors and never exposes paths, PEM contents, or signatures", () => {
    const filePath = writeRegistryFile("registry.json", [signedRegistration()]);
    chmodSync(filePath, 0o644);
    try {
      loadPinnedRuntimeObservationKeySourceFromFile({
        trustedConfigurationRoot: directory,
        filePath,
        pinnedAuthorityPublicKeys: authorityPins(),
      });
      throw new Error("Expected source loading to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(RuntimeObservationKeySourceError);
      expect(String(error)).not.toContain(filePath);
      expect(String(error)).not.toContain("PUBLIC KEY");
      expect(String(error)).not.toContain(authorityPublicKeyPem.slice(30, 60));
    }

    const signed = signedRegistration();
    const signature = signed.attestation.signature;
    const tamperedSignature = `${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}`;
    try {
      createRuntimeObservationKeyRegistrationVerifier({
        pinnedAuthorityPublicKeys: authorityPins(),
      }).verify({
        ...signed,
        attestation: { ...signed.attestation, signature: tamperedSignature },
      });
      throw new Error("Expected signature verification to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(RuntimeObservationKeySourceError);
      expect(String(error)).not.toContain(signature);
      expect(String(error)).not.toContain(signed.descriptor.adapterConfigurationRef);
    }
  });

  function signedRegistration(
    options: {
      descriptor?: Partial<RuntimeObservationKeyDescriptor>;
      observationPublicKeyPem?: string;
      authorityPrivateKey?: KeyObject;
      signatureDomain?: string;
    } = {}
  ): SignedRuntimeObservationKeyRegistration {
    const publicKeySpkiPem = options.observationPublicKeyPem ?? observationPublicKeyPem;
    const descriptor: RuntimeObservationKeyDescriptor = {
      version: 1,
      kind: "runtime.observation-key-descriptor",
      binding: { ...binding },
      runtimeAuthorizationGeneration: 7,
      issuerKeyId: "daytona-observer:v1",
      publicKeySpkiDigest: spkiDigest(publicKeySpkiPem),
      adapterIdentityRef: "daytona-adapter-image:sha256:identity",
      adapterConfigurationRef: "daytona-adapter-config:sha256:configuration",
      issuedAtMs: 1,
      ...options.descriptor,
    };
    const descriptorDigest = digestRuntimeObservationKeyDescriptor(descriptor);
    const claims = {
      version: 1 as const,
      kind: "runtime.observation-key-attestation" as const,
      authorityKeyId: "runtime-observation-key-authority:v1",
      descriptorDigest,
    };
    const signature = signEd25519(
      null,
      Buffer.concat([
        Buffer.from(
          options.signatureDomain ?? RUNTIME_OBSERVATION_KEY_ATTESTATION_SIGNATURE_DOMAIN,
          "utf8"
        ),
        Buffer.from(canonicalRuntimeJson(claims), "utf8"),
      ]),
      options.authorityPrivateKey ?? authorityPrivateKey
    ).toString("base64url");
    return {
      descriptor,
      publicKeySpkiPem,
      attestation: { ...claims, signature },
    };
  }

  function registryJson(registrations: readonly SignedRuntimeObservationKeyRegistration[]): string {
    return canonicalRuntimeJson({
      version: 1,
      kind: "runtime.observation-key-registry",
      registrations,
    });
  }

  function writeRegistryFile(
    name: string,
    registrations: readonly SignedRuntimeObservationKeyRegistration[]
  ): string {
    const filePath = join(directory, name);
    writeFileSync(filePath, registryJson(registrations), { mode: 0o600 });
    return filePath;
  }
});

function canonicalPublicPem(key: KeyObject): string {
  return key.export({ type: "spki", format: "pem" }).toString();
}

function spkiDigest(publicKeyPem: string): string {
  return createHash("sha256")
    .update(createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }))
    .digest("hex");
}

function domainDigest(domain: string, value: unknown): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalRuntimeJson(value), "utf8")
    .digest("hex");
}

function lookupKey(lookup: RuntimeObservationKeyLookup): string {
  return canonicalRuntimeJson({
    binding: lookup.binding,
    runtimeAuthorizationGeneration: lookup.runtimeAuthorizationGeneration,
  });
}
