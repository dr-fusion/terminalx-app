import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as signEd25519,
  type KeyObject,
} from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const runtimeMocks = vi.hoisted(() => ({
  start: vi.fn(),
  bootstrapTransportClose: vi.fn(),
  keyRegistryClose: vi.fn(),
  relayClose: vi.fn(),
  effectTrustClose: vi.fn(),
}));

vi.mock("../../src/lib/runtime", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/lib/runtime")>();
  return {
    ...actual,
    startDaytonaHostedMultiplayerService: runtimeMocks.start,
    createDaytonaAssignmentBootstrapTransport: (
      ...args: Parameters<typeof actual.createDaytonaAssignmentBootstrapTransport>
    ) => {
      const transport = actual.createDaytonaAssignmentBootstrapTransport(...args);
      return Object.freeze({
        install: (...call: Parameters<typeof transport.install>) => transport.install(...call),
        async close() {
          runtimeMocks.bootstrapTransportClose();
          await transport.close();
        },
      });
    },
    createDaytonaAssignmentKeyRegistry: (
      ...args: Parameters<typeof actual.createDaytonaAssignmentKeyRegistry>
    ) => {
      const registry = actual.createDaytonaAssignmentKeyRegistry(...args);
      return Object.freeze({
        ...registry,
        close() {
          runtimeMocks.keyRegistryClose();
          registry.close();
        },
      });
    },
    createDaytonaSupervisorRelayTransport: (
      ...args: Parameters<typeof actual.createDaytonaSupervisorRelayTransport>
    ) => {
      const relay = actual.createDaytonaSupervisorRelayTransport(...args);
      return Object.freeze({
        attestIsolation: (...call: Parameters<typeof relay.attestIsolation>) =>
          relay.attestIsolation(...call),
        executeAuthenticated: (...call: Parameters<typeof relay.executeAuthenticated>) =>
          relay.executeAuthenticated(...call),
        followSigned: (...call: Parameters<typeof relay.followSigned>) =>
          relay.followSigned(...call),
        open: (...call: Parameters<typeof relay.open>) => relay.open(...call),
        async close() {
          runtimeMocks.relayClose();
          await relay.close();
        },
      });
    },
    createRuntimeEffectEnforcerTrustRouter: (
      ...args: Parameters<typeof actual.createRuntimeEffectEnforcerTrustRouter>
    ) => {
      const router = actual.createRuntimeEffectEnforcerTrustRouter(...args);
      return Object.freeze({
        ...router,
        close() {
          runtimeMocks.effectTrustClose();
          router.close();
        },
      });
    },
  };
});

import { composeProductionDaytonaHostedRuntime } from "../../server/production-daytona-hosted-runtime";
import type { EnabledProductionHostedRuntimeConfiguration } from "../../server/production-hosted-runtime";
import {
  DAYTONA_FORK_REPOSITORY,
  DAYTONA_PRODUCTION_FORK_COMMIT,
  type CreateDaytonaHostedMultiplayerServiceOptions,
  type DaytonaHostedMultiplayerService,
} from "../../src/lib/runtime";

const DIGESTS = Object.freeze({
  sdk: "1".repeat(64),
  supervisor: "2".repeat(64),
  runtimeArtifactManifest: "f".repeat(64),
  runner: "0".repeat(64),
  daemon: "a".repeat(64),
  sbom: "3".repeat(64),
  provenance: "4".repeat(64),
  sandbox: "5".repeat(64),
  isolation: "6".repeat(64),
  image: "7".repeat(64),
  network: "8".repeat(64),
  credential: "9".repeat(64),
  effect: "a".repeat(64),
  profile: "b".repeat(64),
  source: "c".repeat(64),
  tls: "d".repeat(64),
  executable: "e".repeat(64),
});
const SNAPSHOT_REF = `ghcr.io/procyon-labs-io/terminalx-daytona@sha256:${DIGESTS.sandbox}`;
const FAKE_CA = `-----BEGIN CERTIFICATE-----
AA==
-----END CERTIFICATE-----
`;

const directories: string[] = [];

beforeEach(() => {
  for (const mock of Object.values(runtimeMocks)) mock.mockReset();
});

afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

describe("production Daytona hosted Runtime composer", () => {
  it("assembles the concrete pinned graph and transfers every owner to the service", async () => {
    const fixture = createFixture();
    let captured: CreateDaytonaHostedMultiplayerServiceOptions | undefined;
    runtimeMocks.start.mockImplementation(
      async (options: CreateDaytonaHostedMultiplayerServiceOptions) => {
        captured = options;
        // Mirror the production service's synchronous ownership capture.
        options.provider.credential.fill(0);
        options.adapter.opaqueHandleKey.fill(0);
        return fakeService(options);
      }
    );

    const service = await composeProductionDaytonaHostedRuntime(fixture.configuration);
    expect(captured).toBeDefined();
    expect(captured?.deployment.sourceEnvironment).toEqual({
      TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
      TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
    });
    expect(captured?.provider.configuration.sourceCommit).toBe(DAYTONA_PRODUCTION_FORK_COMMIT);
    expect(captured?.provider.supervisor).toBe(captured?.provider.terminal);
    expect(captured?.provider.assignmentBootstrap.resolveEffectManifest).toEqual(
      expect.any(Function)
    );
    expect(captured?.trust.effectTrust).toBeDefined();
    expect(captured?.kernel.runtimeEnforcementProofVerifier).toBe(
      captured?.trust.effectTrust.verifyRuntimeEnforcementProof
    );
    expect(captured?.kernel.runtimeCompensationEnforcementProofVerifier).toBe(
      captured?.trust.effectTrust.verifyRuntimeCompensationEnforcementProof
    );
    expect(
      captured?.deployment.signatureVerifier(
        signedReleaseVerification(fixture.releaseAuthority, "canonical deployment payload")
      )
    ).toBe(true);
    expect(runtimeMocks.bootstrapTransportClose).not.toHaveBeenCalled();
    expect(runtimeMocks.keyRegistryClose).not.toHaveBeenCalled();
    expect(runtimeMocks.relayClose).not.toHaveBeenCalled();
    expect(runtimeMocks.effectTrustClose).not.toHaveBeenCalled();

    await service.close();
    expect(runtimeMocks.bootstrapTransportClose).toHaveBeenCalledTimes(1);
    expect(runtimeMocks.keyRegistryClose).toHaveBeenCalledTimes(1);
    expect(runtimeMocks.relayClose).toHaveBeenCalledTimes(1);
    expect(runtimeMocks.effectTrustClose).toHaveBeenCalledTimes(1);
    fixture.configuration.close();
    expectPrivateMaterialZeroed(fixture.configuration);
  });

  it("rejects an inexact public settings graph before constructing secret owners", async () => {
    const fixture = createFixture();
    const configuration = Object.freeze({
      ...fixture.configuration,
      publicConfiguration: Object.freeze({
        ...fixture.configuration.publicConfiguration,
        settings: Object.freeze({
          ...fixture.configuration.publicConfiguration.settings,
          unexpectedDeploymentControl: true,
        }),
      }),
    }) as EnabledProductionHostedRuntimeConfiguration;

    await expect(composeProductionDaytonaHostedRuntime(configuration)).rejects.toMatchObject({
      name: "ProductionHostedRuntimeConfigurationError",
      code: "invalid-configuration",
    });
    expect(runtimeMocks.start).not.toHaveBeenCalled();
    expect(runtimeMocks.bootstrapTransportClose).not.toHaveBeenCalled();
    expect(runtimeMocks.keyRegistryClose).not.toHaveBeenCalled();
    expect(runtimeMocks.relayClose).not.toHaveBeenCalled();
    expect(runtimeMocks.effectTrustClose).not.toHaveBeenCalled();
    expect([...fixture.configuration.privateMaterial.assignmentMasterKey]).toEqual(
      Array(32).fill(0x31)
    );
    fixture.configuration.close();
  });

  it("normalizes startup failure and closes every partially composed owner once", async () => {
    const fixture = createFixture();
    runtimeMocks.start.mockRejectedValue(
      new Error("private provider sandbox and /secret/operator/path must not escape")
    );

    let failure: unknown;
    try {
      await composeProductionDaytonaHostedRuntime(fixture.configuration);
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      name: "ProductionHostedRuntimeConfigurationError",
      code: "composition-unavailable",
      message: "Production hosted Runtime composition is unavailable",
    });
    expect(String(failure)).not.toContain("provider sandbox");
    expect(String(failure)).not.toContain("/secret/operator/path");
    expect(runtimeMocks.bootstrapTransportClose).toHaveBeenCalledTimes(1);
    expect(runtimeMocks.keyRegistryClose).toHaveBeenCalledTimes(1);
    expect(runtimeMocks.relayClose).toHaveBeenCalledTimes(1);
    expect(runtimeMocks.effectTrustClose).toHaveBeenCalledTimes(1);
    fixture.configuration.close();
    expectPrivateMaterialZeroed(fixture.configuration);
  });
});

interface IdentityFixture {
  readonly keyId: string;
  readonly privateKey: KeyObject;
  readonly publicKeySpkiPem: string;
  readonly publicKeySpkiSha256: string;
}

interface ComposerFixture {
  readonly configuration: EnabledProductionHostedRuntimeConfiguration;
  readonly releaseAuthority: IdentityFixture;
}

function createFixture(): ComposerFixture {
  const directory = mkdtempSync(join(tmpdir(), "terminalx-production-composer-"));
  directories.push(directory);
  chmodSync(directory, 0o700);
  const pendingRoot = join(directory, "pending");
  mkdirSync(pendingRoot, { mode: 0o700 });
  const bootstrap = identity("bootstrap-authority:v1");
  const team = identity("team-command-authority:v1");
  const platform = identity("platform-compensation-authority:v1");
  const isolation = identity("runtime-isolation-authority:v1");
  const releaseAuthority = identity("release-authority:v1");
  const bootstrapFile = join(directory, "bootstrap.pk8");
  const teamFile = join(directory, "team.pk8");
  const platformFile = join(directory, "platform.pk8");
  writePrivateKey(bootstrapFile, bootstrap.privateKey);
  writePrivateKey(teamFile, team.privateKey);
  writePrivateKey(platformFile, platform.privateKey);

  const privateMaterial = {
    assignmentMasterKey: new Uint8Array(32).fill(0x31),
    bootstrapAuthorityPrivateKeyPkcs8: privateKeyBytes(bootstrap.privateKey),
    teamCommandAuthorityPrivateKeyPkcs8: privateKeyBytes(team.privateKey),
    platformCompensationAuthorityPrivateKeyPkcs8: privateKeyBytes(platform.privateKey),
    daytonaApiCredential: new TextEncoder().encode("daytona-production-credential"),
    runnerCredential: new TextEncoder().encode("runner-production-credential"),
    opaqueHandleKey: new Uint8Array(32).fill(0x41),
  };
  let closed = false;
  const settings = productionSettings(directory, pendingRoot, isolation, releaseAuthority);
  const configuration: EnabledProductionHostedRuntimeConfiguration = Object.freeze({
    enabled: true,
    trustedConfigurationRoot: directory,
    publicConfiguration: Object.freeze({
      version: 1,
      kind: "terminalx.daytona-hosted-runtime-configuration",
      identities: Object.freeze({
        bootstrapAuthority: publicIdentity(bootstrap),
        teamCommandAuthority: publicIdentity(team),
        platformCompensationAuthority: publicIdentity(platform),
      }),
      settings,
      fileSha256: "f".repeat(64),
    }),
    privateFiles: Object.freeze({
      bootstrapAuthorityPrivateKey: bootstrapFile,
      teamCommandAuthorityPrivateKey: teamFile,
      platformCompensationAuthorityPrivateKey: platformFile,
    }),
    privateMaterial,
    close: Object.freeze(() => {
      if (closed) return;
      closed = true;
      for (const bytes of Object.values(privateMaterial)) bytes.fill(0);
    }),
  });
  return { configuration, releaseAuthority };
}

function productionSettings(
  directory: string,
  pendingRoot: string,
  isolation: IdentityFixture,
  releaseAuthority: IdentityFixture
) {
  return Object.freeze({
    deployment: {
      manifest: {
        sandboxArtifact: { kind: "daytona-snapshot", snapshotRef: SNAPSHOT_REF },
      },
      releaseAuthority: {
        keyId: releaseAuthority.keyId,
        publicKeySpkiPem: releaseAuthority.publicKeySpkiPem,
      },
      measuredArtifacts: {
        sdkSha256: DIGESTS.sdk,
        supervisorSha256: DIGESTS.supervisor,
        runtimeArtifactManifestDigest: DIGESTS.runtimeArtifactManifest,
        runnerBinaryDigest: DIGESTS.runner,
        daemonBinaryDigest: DIGESTS.daemon,
        sbomSha256: DIGESTS.sbom,
        provenanceSha256: DIGESTS.provenance,
        sandboxSha256: DIGESTS.sandbox,
        isolationProfileSha256: DIGESTS.isolation,
      },
    },
    runtimeProfile: {
      kind: "daytona",
      source: {
        sourceRevision: "source:v1",
        expectedCommitSha: DIGESTS.source,
        setupRef: "setup:v1",
      },
      harnessRef: "harness:v1",
      projectCeiling: {
        revision: "ceiling:v1",
        digest: DIGESTS.profile,
        allowedModes: ["supervised", "autonomous"],
        yoloEnabled: false,
        finiteResourceProfile: { cpu: 2, memoryGiB: 4, diskGiB: 20 },
        maximumRunLimits: {
          wallClock: { kind: "capped", value: { milliseconds: 60_000 } },
          modelTokens: { kind: "capped", value: 10_000 },
          modelSpend: { kind: "capped", value: { currency: "USD", minorUnits: 1_000 } },
          outboundBytes: { kind: "capped", value: 1_000_000 },
          actionCounts: {
            local: { kind: "capped", value: 1_000 },
            "scoped-external": { kind: "capped", value: 100 },
            protected: { kind: "capped", value: 10 },
            forbidden: { kind: "capped", value: 1 },
          },
        },
        scopedExternalRulesDigest: DIGESTS.source,
        isolationPolicyDigest: DIGESTS.isolation,
        networkPolicyDigest: DIGESTS.network,
        credentialPolicyDigest: DIGESTS.credential,
      },
      checkpointPolicyRef: "checkpoint:v1",
      adapterConfigurationRef: "daytona-adapter:v1",
      isolation: {
        isolationPolicyDigest: DIGESTS.isolation,
        publicAccess: false,
        hostMounts: false,
        linkedSandbox: false,
        rootIdentity: false,
        network: { mode: "blocked", policyDigest: DIGESTS.network, allowedDestinations: [] },
        resources: { cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 256 },
      },
      capabilities: {
        isolatedExecution: true,
        brokeredCredentials: false,
        proxyOnlyEgress: false,
        checkpoints: false,
        yoloEligible: false,
      },
    },
    kernel: {
      filename: join(directory, "team-sessions.sqlite"),
      authorization: {
        networkPolicyRef: "network-policy:v1",
        networkPolicyDigest: DIGESTS.network,
        credentialPolicyRef: "credential-policy:v1",
        credentialPolicyDigest: DIGESTS.credential,
        effectEnforcerPolicyDigest: DIGESTS.effect,
      },
      runtimeLifecycleCommandTtlMs: 30_000,
      platformSecurityPolicyRevision: "platform-security:v1",
    },
    provider: {
      endpoint: "https://daytona.example.test/api",
      organizationId: "terminalx-production",
      configuration: {
        sourceCommit: DAYTONA_PRODUCTION_FORK_COMMIT,
        target: "terminalx-production",
        sandboxUser: "terminalx",
        artifact: {
          kind: "snapshot",
          snapshotId: "123e4567-e89b-42d3-a456-426614174000",
          snapshotRef: SNAPSHOT_REF,
          imageId: `sha256:${DIGESTS.image}`,
          contentDigest: DIGESTS.sandbox,
        },
        supervisorArtifactDigest: DIGESTS.supervisor,
        runnerBinaryDigest: DIGESTS.runner,
        lifecycle: {
          autoStopIntervalMinutes: 0,
          autoArchiveIntervalMinutes: 0,
          autoDeleteIntervalMinutes: -1,
        },
      },
    },
    runner: {
      origin: "https://runner.example.test",
      caPem: FAKE_CA,
      tlsSpkiSha256: DIGESTS.tls,
      connectTimeoutMs: 1_000,
      requestTimeoutMs: 1_000,
      terminalLifetimeMs: 60_000,
      maximumPendingTerminalOutputBytes: 64 * 1024,
      maximumFrameBytes: 64 * 1024,
    },
    bootstrap: {
      pendingRoot,
      expectedOwnerUid: typeof process.geteuid === "function" ? process.geteuid() : 1_000,
      assignmentMasterKeyId: "assignment-master-v1",
      authorityTtlMs: 30_000,
      effectManifestTtlMs: 60_000,
    },
    supervisor: {
      commandAuthorityMaximumTtlMs: 30_000,
      maxOperations: 10_000,
      observationTtlMs: 30_000,
      transport: {
        peerCredentialExecutableSha256: DIGESTS.executable,
        authenticationTimeoutMs: 1_000,
        requestTimeoutMs: 1_000,
        maximumFrameBytes: 64 * 1024,
        maximumInflightRequests: 16,
      },
      state: { maxStateBytes: 64 * 1024 },
      terminal: {
        requestTimeoutMs: 1_000,
        maximumLifetimeMs: 60_000,
        maximumTerminals: 16,
        maximumTerminalsPerSandbox: 4,
        maximumPendingOutputBytes: 64 * 1024,
        maximumOutputFrameBytes: 64 * 1024,
        maximumPendingWebSocketBytes: 64 * 1024,
      },
      isolation: {
        issuerKeyId: isolation.keyId,
        issuerPublicKeySpkiPem: isolation.publicKeySpkiPem,
        hardenedDaytonaSourceCommit: DAYTONA_PRODUCTION_FORK_COMMIT,
        expectedSeccompProfileDigest: DIGESTS.profile,
        expectedDockerVersion: "28.3.3",
        expectedContainerdVersion: "1.7.27",
        expectedProviderRevision: 1,
        expectedSupervisorUid: 0,
        expectedDaytonaDaemonUid: 1_000,
        expectedAgentUid: 1_000,
        maximumAttestationTtlMs: 30_000,
      },
      effect: {
        executableSha256: DIGESTS.executable,
        timeoutMs: 1_000,
        maximumInputBytes: 64 * 1024,
        maximumOutputBytes: 64 * 1024,
      },
      workerIdPrefix: "terminalx-hosted:production",
    },
    adapter: { operationTimeoutMs: 1_000 },
    ingress: {
      credentialCheckIntervalMs: 1_000,
      eventPollIntervalMs: 1_000,
      monitorPollIntervalMs: 1_000,
    },
  });
}

function identity(keyId: string): IdentityFixture {
  const pair = generateKeyPairSync("ed25519");
  const publicKeySpkiPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  return Object.freeze({
    keyId,
    privateKey: pair.privateKey,
    publicKeySpkiPem,
    publicKeySpkiSha256: createHash("sha256")
      .update(createPublicKey(publicKeySpkiPem).export({ type: "spki", format: "der" }))
      .digest("hex"),
  });
}

function publicIdentity(identity: IdentityFixture) {
  return Object.freeze({
    keyId: identity.keyId,
    publicKeySpkiPem: identity.publicKeySpkiPem,
    publicKeySpkiSha256: identity.publicKeySpkiSha256,
  });
}

function writePrivateKey(path: string, key: KeyObject): void {
  writeFileSync(path, key.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
}

function privateKeyBytes(key: KeyObject): Uint8Array {
  return new Uint8Array(Buffer.from(key.export({ type: "pkcs8", format: "pem" })));
}

function signedReleaseVerification(identity: IdentityFixture, canonicalPayload: string) {
  return Object.freeze({
    algorithm: "ed25519" as const,
    issuerKeyId: identity.keyId,
    claimsDigest: createHash("sha256").update(canonicalPayload, "utf8").digest("hex"),
    canonicalPayload,
    signature: signEd25519(
      null,
      Buffer.from(canonicalPayload, "utf8"),
      identity.privateKey
    ).toString("base64url"),
  });
}

function fakeService(
  options: CreateDaytonaHostedMultiplayerServiceOptions
): DaytonaHostedMultiplayerService {
  let closed = false;
  return Object.freeze({
    async start() {},
    readiness: () => Object.freeze({ ready: !closed, state: closed ? "stopped" : "running" }),
    runtimeStatus: () =>
      Object.freeze({ kind: "daytona", isolation: "isolated-hosted", yoloEligible: false }),
    shutdownBudgetMs: () => 5_000,
    async handleIngress() {
      return false;
    },
    async close() {
      if (closed) return;
      closed = true;
      await options.ingress.close();
      await options.provider.terminal.close();
      await options.provider.assignmentBootstrap.close();
      options.trust.effectTrust.close();
    },
  });
}

function expectPrivateMaterialZeroed(
  configuration: EnabledProductionHostedRuntimeConfiguration
): void {
  for (const bytes of Object.values(configuration.privateMaterial)) {
    expect([...bytes].every((byte) => byte === 0)).toBe(true);
  }
}
