import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND,
  DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_MARKER,
  digestDaytonaAssignmentBootstrapEnvelope,
  type DaytonaAssignmentBootstrapInstalledDescriptor,
} from "../../packages/daytona-supervisor/src/assignment-bootstrap";
import type { DaytonaSupervisorBootstrapConfiguration } from "../../packages/daytona-supervisor/src/daemon";
import {
  createDurableDaytonaAssignmentBootstrapCoordinator,
  type CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions,
  type DaytonaAssignmentBootstrapInstallRequest,
} from "../../src/lib/runtime/daytona-assignment-bootstrap-saga";
import {
  DaytonaAssignmentBootstrapTransportError,
  type DaytonaAssignmentBootstrapTransport,
} from "../../src/lib/runtime/daytona-assignment-bootstrap-transport";
import { canonicalRuntimeJson } from "../../src/lib/runtime/runtime-command-canonical";
import { createDaytonaAssignmentEffectManifest } from "../../src/lib/runtime/daytona-assignment-effect-manifest";

const PROVIDER_ID = "123e4567-e89b-42d3-a456-426614174000";
const NOW = 10_000;
const uid = process.getuid?.() ?? 0;
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("durable Daytona assignment bootstrap coordinator", () => {
  it("retries the byte-identical envelope after an ambiguous restart and activates once", async () => {
    const fixture = sagaFixture();
    const firstBodies: Buffer[] = [];
    const firstTransport = transportThat((envelope) => {
      firstBodies.push(Buffer.from(envelope));
      throw new DaytonaAssignmentBootstrapTransportError("unavailable");
    });
    const first = fixture.coordinator(firstTransport);

    await expect(
      first.install(fixture.request, new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(fixture.privateKeyCopies).toHaveLength(2);
    expect(fixture.privateKeyCopies.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
    await first.close();

    const secondBodies: Buffer[] = [];
    fixture.failIfPrivateKeysResolve = true;
    const secondTransport = transportThat((envelope) => {
      secondBodies.push(Buffer.from(envelope));
      return fixture.installed(digestDaytonaAssignmentBootstrapEnvelope(envelope));
    });
    const second = fixture.coordinator(secondTransport);
    const installed = await second.install(fixture.request, new AbortController().signal);
    expect(secondBodies).toHaveLength(1);
    expect(secondBodies[0]).toEqual(firstBodies[0]);
    expect(fixture.privateKeyCopies).toHaveLength(2);

    const directory = onlyIntentDirectory(fixture.pendingRoot);
    expect(existsSync(join(directory, "envelope.bin"))).toBe(true);
    await second.activate(fixture.request, installed);
    expect(existsSync(join(directory, "active.json"))).toBe(true);
    expect(existsSync(join(directory, "envelope.bin"))).toBe(false);
    expect(existsSync(join(directory, "effect-manifest.json"))).toBe(true);
    const durableEffectRecord = second.resolveEffectManifest(fixture.request);
    expect(durableEffectRecord).toMatchObject({
      manifest: { authority: { claimsDigest: installed.effectEnforcerSetDigest } },
      activation: {
        assignmentPlanDigest: installed.assignmentPlanDigest,
        effectEnforcerPolicyDigest: installed.effectEnforcerPolicyDigest,
        effectManifestBindingDigest: installed.effectManifestBindingDigest,
        effectEnforcerSetDigest: installed.effectEnforcerSetDigest,
      },
    });
    await second.close();

    const replayTransport = transportThat(() => {
      throw new Error("durable installed replay must not call the runner");
    });
    const replay = fixture.coordinator(replayTransport);
    await expect(replay.install(fixture.request, new AbortController().signal)).resolves.toEqual(
      installed
    );
    await replay.activate(fixture.request, installed);
    expect(replay.resolveEffectManifest(fixture.request)).toEqual(durableEffectRecord);
    await replay.retire(fixture.request);
    expect(readdirSync(fixture.pendingRoot)).toEqual([]);
    await replay.close();
  });

  it("rejects a mismatched installed descriptor and retains the unresolved envelope", async () => {
    const fixture = sagaFixture();
    const transport = transportThat((envelope) => ({
      ...fixture.installed(digestDaytonaAssignmentBootstrapEnvelope(envelope)),
      providerRevision: 2,
    }));
    const coordinator = fixture.coordinator(transport);

    await expect(
      coordinator.install(fixture.request, new AbortController().signal)
    ).rejects.toMatchObject({ code: "conflict" });
    const directory = onlyIntentDirectory(fixture.pendingRoot);
    expect(existsSync(join(directory, "envelope.bin"))).toBe(true);
    expect(existsSync(join(directory, "installed.json"))).toBe(false);
    await coordinator.close();
  });

  it("serializes concurrent installs so keys and transport are used once", async () => {
    const fixture = sagaFixture();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const install = vi.fn(async (envelope: Buffer) => {
      const digest = digestDaytonaAssignmentBootstrapEnvelope(envelope);
      try {
        await gate;
        return fixture.installed(digest);
      } finally {
        envelope.fill(0);
      }
    });
    const transport: DaytonaAssignmentBootstrapTransport = Object.freeze({
      install: (_providerSandboxId: string, envelope: Buffer) => install(envelope),
      close: async () => undefined,
    });
    const coordinator = fixture.coordinator(transport);
    const first = coordinator.install(fixture.request, new AbortController().signal);
    const second = coordinator.install(fixture.request, new AbortController().signal);
    await vi.waitFor(() => expect(install).toHaveBeenCalledTimes(1));
    release();

    const [left, right] = await Promise.all([first, second]);
    expect(left).toEqual(right);
    expect(install).toHaveBeenCalledTimes(1);
    expect(fixture.privateKeyCopies).toHaveLength(2);
    await coordinator.close();
  });

  it("re-signs the same keys only after an expired replay is definitively rejected", async () => {
    const fixture = sagaFixture();
    const originalBodies: Buffer[] = [];
    const first = fixture.coordinator(
      transportThat((envelope) => {
        originalBodies.push(Buffer.from(envelope));
        throw new DaytonaAssignmentBootstrapTransportError("unavailable");
      })
    );
    await expect(
      first.install(fixture.request, new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    await first.close();

    fixture.now = NOW + 60_000;
    const renewedBodies: Buffer[] = [];
    let calls = 0;
    const restarted = fixture.coordinator(
      transportThat((envelope) => {
        renewedBodies.push(Buffer.from(envelope));
        calls += 1;
        if (calls === 1) {
          throw new DaytonaAssignmentBootstrapTransportError("invalid-request");
        }
        return fixture.installed(digestDaytonaAssignmentBootstrapEnvelope(envelope));
      })
    );
    await expect(
      restarted.install(fixture.request, new AbortController().signal)
    ).resolves.toMatchObject({ kind: DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND });
    expect(renewedBodies).toHaveLength(2);
    expect(renewedBodies[0]).toEqual(originalBodies[0]);
    expect(renewedBodies[1]).not.toEqual(originalBodies[0]);
    expect(privateSections(renewedBodies[1]!)).toEqual(privateSections(originalBodies[0]!));
    expect(fixture.privateKeyCopies).toHaveLength(4);
    expect(fixture.privateKeyCopies.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
    await restarted.close();
  });

  it("fails closed on a tampered durable activation marker", async () => {
    const fixture = sagaFixture();
    const transport = transportThat((envelope) =>
      fixture.installed(digestDaytonaAssignmentBootstrapEnvelope(envelope))
    );
    const coordinator = fixture.coordinator(transport);
    const installed = await coordinator.install(fixture.request, new AbortController().signal);
    await coordinator.activate(fixture.request, installed);
    await coordinator.close();

    const activePath = join(onlyIntentDirectory(fixture.pendingRoot), "active.json");
    writeFileSync(
      activePath,
      canonicalRuntimeJson({
        version: 1,
        kind: "terminalx.daytona-assignment-bootstrap-active",
        envelopeDigest: "f".repeat(64),
      }),
      { mode: 0o600 }
    );
    chmodSync(activePath, 0o600);
    fixture.failIfPrivateKeysResolve = true;
    const restarted = fixture.coordinator(transportThat(() => installed));
    await expect(
      restarted.install(fixture.request, new AbortController().signal)
    ).rejects.toMatchObject({ code: "invalid-state" });
    await expect(restarted.retire(fixture.request)).rejects.toMatchObject({
      code: "invalid-state",
    });
    await restarted.close();
  });

  it("fails closed when the durable public effect manifest is replaced", async () => {
    const fixture = sagaFixture();
    const transport = transportThat((envelope) =>
      fixture.installed(digestDaytonaAssignmentBootstrapEnvelope(envelope))
    );
    const coordinator = fixture.coordinator(transport);
    const installed = await coordinator.install(fixture.request, new AbortController().signal);
    await coordinator.activate(fixture.request, installed);
    await coordinator.close();

    const manifestPath = join(onlyIntentDirectory(fixture.pendingRoot), "effect-manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    manifest.manifestId = "replaced-manifest";
    writeFileSync(manifestPath, canonicalRuntimeJson(manifest), { mode: 0o600 });
    const restarted = fixture.coordinator(transportThat(() => installed));
    expect(() => restarted.resolveEffectManifest(fixture.request)).toThrow(
      expect.objectContaining({ code: "invalid-state" })
    );
    await expect(
      restarted.install(fixture.request, new AbortController().signal)
    ).rejects.toMatchObject({ code: "invalid-state" });
    await restarted.close();
  });

  it("rejects a tampered durable envelope before activation and retains the failed state", async () => {
    const fixture = sagaFixture();
    const transport = transportThat((envelope) =>
      fixture.installed(digestDaytonaAssignmentBootstrapEnvelope(envelope))
    );
    const coordinator = fixture.coordinator(transport);
    const installed = await coordinator.install(fixture.request, new AbortController().signal);
    const directory = onlyIntentDirectory(fixture.pendingRoot);
    const envelopePath = join(directory, "envelope.bin");
    const envelope = readFileSync(envelopePath);
    envelope[envelope.byteLength - 1] = envelope[envelope.byteLength - 1]! ^ 0xff;
    writeFileSync(envelopePath, envelope, { mode: 0o600 });
    envelope.fill(0);

    await expect(coordinator.activate(fixture.request, installed)).rejects.toMatchObject({
      code: "invalid-state",
    });
    expect(existsSync(join(directory, "active.json"))).toBe(false);
    expect(existsSync(envelopePath)).toBe(true);
    await coordinator.close();
  });

  it("rejects policy digest drift against a durable pending intent before network replay", async () => {
    const fixture = sagaFixture();
    const first = fixture.coordinator(
      transportThat(() => {
        throw new DaytonaAssignmentBootstrapTransportError("unavailable");
      })
    );
    await expect(
      first.install(fixture.request, new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    await first.close();

    fixture.failIfPrivateKeysResolve = true;
    const install = vi.fn(() => {
      throw new Error("drifted intent must not reach the runner");
    });
    const restarted = fixture.coordinator(transportThat(install));
    await expect(
      restarted.install(
        {
          ...fixture.request,
          plan: {
            ...fixture.request.plan,
            effectEnforcerPolicyDigest: "9".repeat(64),
          },
        },
        new AbortController().signal
      )
    ).rejects.toMatchObject({ code: "conflict" });
    expect(install).not.toHaveBeenCalled();
    await restarted.close();
  });

  it("finishes a retirement whose durable tombstone rename completed before a crash", async () => {
    const fixture = sagaFixture();
    const transport = transportThat((envelope) =>
      fixture.installed(digestDaytonaAssignmentBootstrapEnvelope(envelope))
    );
    const first = fixture.coordinator(transport);
    const installed = await first.install(fixture.request, new AbortController().signal);
    await first.activate(fixture.request, installed);
    await first.close();

    const directory = onlyIntentDirectory(fixture.pendingRoot);
    const retiredDirectory = join(fixture.pendingRoot, `.retired-${basename(directory)}`);
    renameSync(directory, retiredDirectory);
    fixture.failIfPrivateKeysResolve = true;
    const restarted = fixture.coordinator(
      transportThat(() => {
        throw new Error("retirement recovery must not call the runner");
      })
    );
    await restarted.retire(fixture.request);
    expect(readdirSync(fixture.pendingRoot)).toEqual([]);
    await restarted.close();
  });
});

function sagaFixture() {
  const root = mkdtempSync(join(tmpdir(), "terminalx-bootstrap-saga-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const pendingRoot = join(root, "pending");
  mkdirSync(pendingRoot, { mode: 0o700 });
  chmodSync(pendingRoot, 0o700);

  const observation = generateKeyPairSync("ed25519");
  const effect = generateKeyPairSync("ed25519");
  const authority = generateKeyPairSync("ed25519");
  const state = generateKeyPairSync("ed25519");
  const commandAuthority = generateKeyPairSync("ed25519");
  const manifestAuthority = generateKeyPairSync("ed25519");
  const isolationAuthority = generateKeyPairSync("ed25519");
  const observationPrivate = keyDer(observation.privateKey);
  const effectPrivate = keyDer(effect.privateKey);
  const observationPublicPem = keyPem(observation.publicKey);
  const effectPublicPem = keyPem(effect.publicKey);
  const effectPublicDigest = sha256(effect.publicKey.export({ type: "spki", format: "der" }));
  const binding = Object.freeze({
    teamId: "team-1",
    projectId: "project-1",
    sessionId: "session-1",
    runtimeAssignmentId: "assignment-1",
    runtimeAssignmentGeneration: 1,
    sandboxId: "sandbox-1",
    sandboxGeneration: 1,
    runtimePrincipalId: "principal-1",
  });
  const plan = Object.freeze({
    binding,
    runtimeAuthorizationGeneration: 7,
    incarnation: "a".repeat(64),
    specificationDigest: "b".repeat(64),
    effectEnforcerPolicyDigest: "c".repeat(64),
    adapterConfigurationRef: "daytona-production-v1",
    observation: Object.freeze({
      keyProvisioningRef: "observation-provisioning-1",
      issuerKeyId: "observation-key-1",
      publicKeySpkiPem: observationPublicPem,
    }),
    isolation: Object.freeze({
      isolationPolicyDigest: "c".repeat(64),
      publicAccess: false as const,
      hostMounts: false as const,
      linkedSandbox: false as const,
      rootIdentity: false as const,
      network: Object.freeze({
        mode: "blocked" as const,
        policyDigest: "d".repeat(64),
        allowedDestinations: Object.freeze([]),
      }),
      resources: Object.freeze({ cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 256 }),
    }),
    capabilities: Object.freeze({
      isolatedExecution: true as const,
      brokeredCredentials: false as const,
      proxyOnlyEgress: false as const,
      checkpoints: false,
      yoloEligible: false as const,
    }),
  });
  const effectRecord = createDaytonaAssignmentEffectManifest({
    plan,
    providerSandboxId: PROVIDER_ID,
    providerRevision: 1,
    effectEnforcerIdentity: Object.freeze({
      enforcerRef: "runtime-enforcer-1",
      enforcerKeyId: "runtime-enforcer-key-1",
      publicKeySpkiPem: effectPublicPem,
      publicKeySpkiDigest: effectPublicDigest,
    }),
    authorityIssuerKeyId: "manifest-authority-1",
    authoritySigningPrivateKey: manifestAuthority.privateKey,
    validFromMs: 1,
    expiresAtMs: 86_400_000,
  });
  const manifest = effectRecord.manifest;
  const manifestDigest = effectRecord.activation.effectEnforcerSetDigest;
  const request: DaytonaAssignmentBootstrapInstallRequest = Object.freeze({
    providerSandboxId: PROVIDER_ID,
    plan,
    expectedRevision: 1,
    artifactDigest: "1".repeat(64),
    sandboxUser: "terminalx",
    supervisorArtifactDigest: "2".repeat(64),
  });
  const assignmentRoot = "/run/terminalx-root/assignment";
  const bootstrap: DaytonaSupervisorBootstrapConfiguration = Object.freeze({
    version: 1,
    kind: "terminalx.daytona-supervisor-bootstrap",
    assignment: Object.freeze({
      plan,
      providerSandboxId: request.providerSandboxId,
      expectedRevision: request.expectedRevision,
      artifactDigest: request.artifactDigest,
      sandboxUser: request.sandboxUser,
      supervisorArtifactDigest: request.supervisorArtifactDigest,
      effectEnforcerSetDigest: manifestDigest,
      maxOperations: 100,
    }),
    commandAuthority: Object.freeze({
      pinnedPublicKeys: Object.freeze([
        Object.freeze({
          issuer: "team-session" as const,
          issuerKeyId: "team-session-authority-1",
          publicKeyPem: keyPem(commandAuthority.publicKey),
        }),
      ]),
      maximumAuthorityTtlMs: 60_000,
    }),
    observation: Object.freeze({
      provisioningRecordFile: `${assignmentRoot}/observation-provisioning.json`,
      observationTtlMs: 60_000,
    }),
    transport: Object.freeze({
      socketDirectory: "/run/terminalx-root",
      socketPath: "/run/terminalx-root/supervisor.sock",
      peerCredentialExecutableRoot: "/usr/local/libexec/terminalx",
      peerCredentialExecutableFile: "/usr/local/libexec/terminalx/terminalx-peercred",
      peerCredentialExecutableSha256: "3".repeat(64),
      authenticationTimeoutMs: 1_000,
      requestTimeoutMs: 5_000,
      maximumFrameBytes: 1024 * 1024,
      maximumInflightRequests: 32,
    }),
    state: Object.freeze({
      stateDirectory: "/var/lib/terminalx-supervisor/assignment-1",
      stateFileName: "supervisor-state.json",
      signingPrivateKeyFile: `${assignmentRoot}/state-signing.pk8`,
      verificationPublicKeyFile: `${assignmentRoot}/state-verification.pem`,
      maxStateBytes: 1024 * 1024,
    }),
    terminal: Object.freeze({
      requestTimeoutMs: 5_000,
      maximumLifetimeMs: 24 * 60 * 60_000,
      maximumTerminals: 16,
      maximumTerminalsPerSandbox: 8,
      maximumPendingOutputBytes: 1024 * 1024,
      maximumOutputFrameBytes: 64 * 1024,
      maximumPendingWebSocketBytes: 1024 * 1024,
    }),
    isolation: Object.freeze({
      attestationFile: "/run/terminalx-root/live/isolation-attestation.json",
      issuerKeyId: "isolation-key-1",
      issuerPublicKeySpkiPem: keyPem(isolationAuthority.publicKey),
      hardenedDaytonaSourceCommit: "e".repeat(40),
      expectedSandboxImageId: `sha256:${"5".repeat(64)}`,
      expectedSandboxSnapshotRef: `registry.example/terminalx@sha256:${"6".repeat(64)}`,
      expectedSandboxUser: "terminalx",
      expectedSeccompProfileDigest: "7".repeat(64),
      expectedDockerVersion: "docker-29.1.3",
      expectedContainerdVersion: "containerd-2.2.1",
      expectedProviderRevision: 1,
      expectedSupervisorUid: 0,
      expectedDaytonaDaemonUid: 1000,
      expectedAgentUid: 1000,
      maximumAttestationTtlMs: 60_000,
    }),
    effect: Object.freeze({
      executableRoot: "/usr/local/libexec/terminalx",
      executableFile: "/usr/local/libexec/terminalx/terminalx-effect-enforcer",
      executableSha256: "8".repeat(64),
      timeoutMs: 5_000,
      maximumInputBytes: 1024 * 1024,
      maximumOutputBytes: 1024 * 1024,
      manifest,
      pinnedManifestAuthorityPublicKeys: Object.freeze([
        Object.freeze({
          issuerKeyId: "manifest-authority-1",
          publicKeySpkiPem: keyPem(manifestAuthority.publicKey),
          publicKeySpkiDigest: sha256(
            manifestAuthority.publicKey.export({ type: "spki", format: "der" })
          ),
        }),
      ]),
    }),
  });
  const statePublicPem = keyPem(state.publicKey);
  const privateKeyCopies: Buffer[] = [];
  let failIfPrivateKeysResolve = false;
  let now = NOW;

  const fixture = {
    pendingRoot,
    request,
    privateKeyCopies,
    get failIfPrivateKeysResolve() {
      return failIfPrivateKeysResolve;
    },
    set failIfPrivateKeysResolve(value: boolean) {
      failIfPrivateKeysResolve = value;
    },
    get now() {
      return now;
    },
    set now(value: number) {
      now = value;
    },
    installed(envelopeDigest: string): DaytonaAssignmentBootstrapInstalledDescriptor {
      return Object.freeze({
        version: 1,
        kind: DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND,
        envelopeDigest,
        providerIdentityCommitment: sha256(
          `terminalx/daytona-provider-identity/v1\0${PROVIDER_ID}`
        ),
        providerRevision: 1,
        planDigest: sha256(
          `terminalx/hosted-runtime-assignment-plan/v1\0${canonicalRuntimeJson(plan)}`
        ),
        assignmentPlanDigest: effectRecord.activation.assignmentPlanDigest,
        effectEnforcerPolicyDigest: effectRecord.activation.effectEnforcerPolicyDigest,
        effectManifestBindingDigest: effectRecord.activation.effectManifestBindingDigest,
        effectEnforcerSetDigest: effectRecord.activation.effectEnforcerSetDigest,
        bindingDigest: sha256(
          `terminalx/daytona-bootstrap-binding/v1\0${canonicalRuntimeJson(binding)}`
        ),
        observationIssuerKeyId: plan.observation.issuerKeyId,
        observationPublicKeyDigest: sha256(plan.observation.publicKeySpkiPem),
        effectEnforcerKeyId: "runtime-enforcer-key-1",
        effectEnforcerPublicKeyDigest: effectPublicDigest,
        stateVerificationPublicKeySpkiPem: statePublicPem,
        stateVerificationPublicKeyDigest: sha256(statePublicPem),
        supervisorArtifactDigest: request.supervisorArtifactDigest,
        installedMarker: DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_MARKER,
        supervisorReady: false,
      });
    },
    coordinator(transport: DaytonaAssignmentBootstrapTransport) {
      const options: CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions = {
        pendingRoot,
        expectedOwnerUid: uid,
        authorityIssuerKeyId: "platform-bootstrap-1",
        authoritySigningPrivateKey: authority.privateKey,
        authorityTtlMs: 60_000,
        buildEffectManifest: () => effectRecord,
        buildBootstrapConfiguration: () => bootstrap,
        resolvePrivateKeys: () => {
          if (failIfPrivateKeysResolve) throw new Error("private keys unexpectedly resolved");
          const observationCopy = Buffer.from(observationPrivate);
          const effectCopy = Buffer.from(effectPrivate);
          privateKeyCopies.push(observationCopy, effectCopy);
          return Object.freeze({
            observationPrivateKeyPkcs8Der: observationCopy,
            effectEnforcerPrivateKeyPkcs8Der: effectCopy,
          });
        },
        closePrivateKeys: () => undefined,
        transport,
        clock: () => now,
      };
      return createDurableDaytonaAssignmentBootstrapCoordinator(options);
    },
  };
  return fixture;
}

function transportThat(
  response: (envelope: Buffer) => unknown | Promise<unknown>
): DaytonaAssignmentBootstrapTransport {
  return Object.freeze({
    async install(_providerSandboxId: string, envelope: Buffer): Promise<unknown> {
      try {
        return await response(envelope);
      } finally {
        envelope.fill(0);
      }
    },
    async close(): Promise<void> {},
  });
}

function onlyIntentDirectory(pendingRoot: string): string {
  const entries = readdirSync(pendingRoot).filter((entry) => !entry.startsWith("."));
  expect(entries).toHaveLength(1);
  return join(pendingRoot, entries[0]!);
}

function privateSections(envelope: Buffer): readonly [Buffer, Buffer] {
  const headerLength = envelope.readUInt32BE(0);
  const header = JSON.parse(envelope.subarray(4, 4 + headerLength).toString("utf8")) as {
    sections: readonly [{ readonly bytes: number }, { readonly bytes: number }];
  };
  const observationStart = 4 + headerLength;
  const effectStart = observationStart + header.sections[0].bytes;
  return Object.freeze([
    Buffer.from(envelope.subarray(observationStart, effectStart)),
    Buffer.from(envelope.subarray(effectStart, effectStart + header.sections[1].bytes)),
  ] as const);
}

function keyDer(key: KeyObject): Buffer {
  const value = key.export({ type: "pkcs8", format: "der" });
  return Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value);
}

function keyPem(key: KeyObject): string {
  return String(key.export({ type: "spki", format: "pem" }));
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
