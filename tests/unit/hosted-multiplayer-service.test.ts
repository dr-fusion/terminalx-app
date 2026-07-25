import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  DAYTONA_FORK_REPOSITORY,
  DAYTONA_PRODUCTION_FORK_COMMIT,
  DAYTONA_UPSTREAM_BASE_COMMIT,
  DAYTONA_UPSTREAM_REPOSITORY,
  digestDaytonaDeploymentArtifactManifestClaims,
  type DaytonaDeploymentArtifactManifest,
  type DaytonaDeploymentArtifactManifestClaims,
} from "@/lib/runtime/daytona-source";
import {
  HostedMultiplayerServiceError,
  createDaytonaHostedMultiplayerService,
  startDaytonaHostedMultiplayerService,
  type CreateDaytonaHostedMultiplayerServiceOptions,
} from "@/lib/runtime/hosted-multiplayer-service";
import {
  getRegisteredTeamSessionKernel,
  installTeamSessionKernel,
} from "@/lib/team-sessions/service";
import type { TeamSessionKernel } from "@/lib/team-sessions/module";
import { getMultiplayerTransportStatus } from "@/lib/team-sessions/feature";

const mocks = vi.hoisted(() => ({
  createKernel: vi.fn(),
  createApi: vi.fn(),
  createControlPlane: vi.fn(),
  createAdapter: vi.fn(),
  createTerminalAdapter: vi.fn(),
  createComposition: vi.fn(),
}));

vi.mock("@/lib/team-sessions/module", () => ({
  createTeamSessionKernel: mocks.createKernel,
}));

vi.mock("@/lib/runtime/daytona-hosted-control-plane", () => ({
  createPinnedDaytonaFetchApi: mocks.createApi,
  createDaytonaHostedRuntimeControlPlane: mocks.createControlPlane,
}));

vi.mock("@/lib/runtime/hosted-runtime-adapter", () => ({
  createHostedRuntimeAdapterBundle: mocks.createAdapter,
}));

vi.mock("@/lib/runtime/daytona-hosted-terminal-adapter", () => ({
  createDaytonaHostedTerminalAdapter: mocks.createTerminalAdapter,
}));

vi.mock("@/lib/runtime/runtime-supervisor-composition", () => ({
  createRuntimeSupervisorComposition: mocks.createComposition,
}));

const DIGESTS = Object.freeze({
  sdk: "a".repeat(64),
  supervisor: "b".repeat(64),
  sbom: "c".repeat(64),
  provenance: "d".repeat(64),
  sandbox: "e".repeat(64),
  imageConfig: "8".repeat(64),
  isolation: "f".repeat(64),
});
const SIGNATURE = "A".repeat(86);
const OBSERVATION_PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFf4/tX72aI7ln4nW9XH7z9xWMNJm9Q7A7jTZSlmWyNg=\n-----END PUBLIC KEY-----\n";

describe("Daytona hosted multiplayer production composition", () => {
  let events: string[];
  let rootReady: boolean;
  let ingressReady: boolean;
  let ingressHandle: () => Promise<boolean>;
  let ingressClose: () => Promise<void>;
  let rootStop: () => Promise<void>;
  let terminalClose: () => Promise<void>;
  let adapterClose: () => Promise<void>;
  let operationalError: ((component: string) => void) | undefined;

  beforeEach(() => {
    for (const key of [
      "__terminalxTeamSessionKernel",
      "__terminalxTeamSessionKernelClose",
      "__terminalxTeamSessionKernelInstallation",
      "__terminalxTeamSessionKernelPhase",
      "__terminalxMultiplayerTransportStatus",
    ]) {
      Reflect.deleteProperty(globalThis, key);
    }
    events = [];
    rootReady = true;
    ingressReady = true;
    ingressHandle = async () => true;
    ingressClose = async () => undefined;
    rootStop = async () => undefined;
    terminalClose = async () => undefined;
    adapterClose = async () => undefined;
    operationalError = undefined;
    vi.clearAllMocks();

    mocks.createKernel.mockImplementation(() => ({
      teamSessions: {
        close() {
          events.push("kernel.close");
        },
      },
      hostedAssignmentPlanSource: {},
      runtimeAssignmentKernel: {},
      runtimeWriteStateSnapshotSource: {},
      runtimeLifecycleJournal: {},
      runtimeReceiptFollowJournal: {},
      runtimeCompensationJournal: {},
      runtimeCompensationMaterializer: {},
    }));
    mocks.createApi.mockImplementation(() => ({
      async close() {
        events.push("api.close");
      },
    }));
    mocks.createControlPlane.mockImplementation(
      ({
        api,
        supervisor,
      }: {
        api: { close(): Promise<void> };
        supervisor: { close(): Promise<void> };
      }) => ({
        async close() {
          events.push("control-plane.close");
          await api.close();
          await supervisor.close();
        },
      })
    );
    mocks.createAdapter.mockImplementation(
      ({ controlPlane }: { controlPlane: { close(): Promise<void> } }) => ({
        assignmentRuntime: {},
        runtime: {},
        receiptTransport: {},
        lifecycleHandles: {},
        receiptFollowHandles: {},
        compensationHandles: {},
        async close() {
          events.push("adapter.close");
          await adapterClose();
          await controlPlane.close();
        },
      })
    );
    mocks.createTerminalAdapter.mockImplementation(() => ({
      async connect() {
        throw new Error("unused terminal connect");
      },
      async close() {
        events.push("terminal-adapter.close");
        await terminalClose();
      },
    }));
    mocks.createComposition.mockImplementation(
      ({ onOperationalError }: { onOperationalError: (component: string) => void }) => {
        operationalError = onOperationalError;
        return {
          root: {
            async start() {
              events.push("root.start");
            },
            readiness() {
              events.push("root.readiness");
              return { ready: rootReady };
            },
            async stop() {
              events.push("root.stop");
              await rootStop();
            },
          },
          writeStateRegistry: { isWriteAllowed: () => true },
        };
      }
    );
  });

  it("exposes ingress only after the durable root is started and ready", async () => {
    const fixture = options();
    const service = await startDaytonaHostedMultiplayerService(fixture.options);

    expect(events.indexOf("root.start")).toBeLessThan(events.indexOf("root.readiness"));
    expect(events.indexOf("root.readiness")).toBeLessThan(events.indexOf("ingress.start"));
    expect(events.indexOf("ingress.start")).toBeLessThan(events.indexOf("availability.true"));
    expect(service.readiness()).toMatchObject({ ready: true, state: "running" });
    expect(service.runtimeStatus()).toEqual({
      kind: "daytona",
      isolation: "isolated-hosted",
      yoloEligible: false,
    });
    expect(service.shutdownBudgetMs()).toBe(5_000);
    expect(getRegisteredTeamSessionKernel()).toBe(mocks.createKernel.mock.results[0]?.value);
    expect(getMultiplayerTransportStatus()).toMatchObject({
      enabled: true,
      runtime: { kind: "daytona", isolation: "isolated-hosted" },
    });
    expect(await service.handleIngress({ kind: "test" })).toBe(true);

    await service.close();
    expect(getRegisteredTeamSessionKernel()).toBeNull();
    expect(fixture.credential.every((byte) => byte === 0)).toBe(true);
    expect(fixture.opaqueHandleKey.every((byte) => byte === 0)).toBe(true);
  });

  it("shares concurrent start and close operations exactly once", async () => {
    const fixture = options();
    let releaseRoot!: () => void;
    const rootBarrier = new Promise<void>((resolve) => {
      releaseRoot = resolve;
    });
    mocks.createComposition.mockImplementationOnce(() => ({
      root: {
        async start() {
          events.push("root.start");
          await rootBarrier;
        },
        readiness: () => ({ ready: true }),
        async stop() {
          events.push("root.stop");
        },
      },
      writeStateRegistry: { isWriteAllowed: () => true },
    }));
    const service = createDaytonaHostedMultiplayerService(fixture.options);
    const firstStart = service.start();
    const secondStart = service.start();
    expect(secondStart).toBe(firstStart);
    releaseRoot();
    await Promise.all([firstStart, secondStart]);

    const firstClose = service.close();
    const secondClose = service.close();
    expect(secondClose).toBe(firstClose);
    await Promise.all([firstClose, secondClose]);

    expect(events.filter((event) => event === "root.start")).toHaveLength(1);
    expect(events.filter((event) => event === "ingress.start")).toHaveLength(1);
    expect(events.filter((event) => event === "root.stop")).toHaveLength(1);
    expect(events.filter((event) => event === "adapter.close")).toHaveLength(1);
    expect(events.filter((event) => event === "kernel.close")).toHaveLength(1);
  });

  it("rolls a partial startup back in reverse order and keeps availability withdrawn", async () => {
    const fixture = options();
    mocks.createComposition.mockImplementationOnce(() => ({
      root: {
        async start() {
          events.push("root.start");
          throw new Error("provider-private failure");
        },
        readiness: () => ({ ready: false }),
        async stop() {
          events.push("root.stop");
        },
      },
      writeStateRegistry: { isWriteAllowed: () => false },
    }));
    const service = createDaytonaHostedMultiplayerService(fixture.options);

    await expect(service.start()).rejects.toMatchObject({ code: "startup-failed" });
    expect(events).not.toContain("ingress.start");
    expect(events).not.toContain("availability.true");
    expectOrdered(events, [
      "root.stop",
      "terminal-adapter.close",
      "adapter.close",
      "control-plane.close",
      "api.close",
      "supervisor.close",
      "kernel.close",
    ]);
    expect(service.readiness()).toEqual({ ready: false, state: "failed" });
  });

  it("rejects a pre-existing LocalTmux identity instead of splitting HTTP and hosted ingress", async () => {
    const localClose = vi.fn();
    const local = {
      teamSessions: { close: localClose },
    } as unknown as TeamSessionKernel;
    const removeLocal = installTeamSessionKernel(local);
    const fixture = options();
    const service = createDaytonaHostedMultiplayerService(fixture.options);

    await expect(service.start()).rejects.toMatchObject({ code: "startup-failed" });
    expect(getRegisteredTeamSessionKernel()).toBe(local);
    expect(localClose).not.toHaveBeenCalled();
    expect(events).not.toContain("availability.true");

    removeLocal();
  });

  it("withdraws availability, closes ingress, stops root, closes provider ownership, then closes SQLite", async () => {
    const fixture = options();
    const service = await startDaytonaHostedMultiplayerService(fixture.options);
    events = [];

    await service.close();

    expectOrdered(events, [
      "availability.false",
      "ingress.close",
      "root.stop",
      "terminal-adapter.close",
      "adapter.close",
      "control-plane.close",
      "api.close",
      "supervisor.close",
      "kernel.close",
    ]);
  });

  it("leaves SQLite open and fails shutdown when ingress cannot settle", async () => {
    ingressClose = async () => {
      throw new Error("unsettled private ingress");
    };
    const fixture = options();
    const service = await startDaytonaHostedMultiplayerService(fixture.options);

    await expect(service.close()).rejects.toMatchObject({ code: "shutdown-failed" });
    expect(events).toContain("ingress.close");
    expect(events).toContain("root.stop");
    expect(events).toContain("terminal-adapter.close");
    expect(events).toContain("adapter.close");
    expect(events).not.toContain("kernel.close");
    expect(getRegisteredTeamSessionKernel()).toBeNull();
    expect(service.readiness()).toEqual({ ready: false, state: "failed" });
  });

  it("keeps SQLite open when any asynchronous upstream owner times out", async () => {
    for (const stage of ["ingress", "root", "terminal", "adapter"] as const) {
      events = [];
      ingressClose = async () => undefined;
      rootStop = async () => undefined;
      terminalClose = async () => undefined;
      adapterClose = async () => undefined;
      const never = () => new Promise<void>(() => undefined);
      if (stage === "ingress") ingressClose = never;
      if (stage === "root") rootStop = never;
      if (stage === "terminal") terminalClose = never;
      if (stage === "adapter") adapterClose = never;
      const fixture = options({ operationTimeoutMs: 100 });
      const service = await startDaytonaHostedMultiplayerService(fixture.options);
      events = [];

      await expect(service.close(), stage).rejects.toMatchObject({ code: "shutdown-failed" });
      expect(events, stage).not.toContain("kernel.close");
      expect(service.readiness(), stage).toEqual({ ready: false, state: "failed" });
    }
  });

  it("fails closed when ingress is not ready", async () => {
    ingressReady = false;
    const fixture = options();
    const service = createDaytonaHostedMultiplayerService(fixture.options);

    await expect(service.start()).rejects.toBeInstanceOf(HostedMultiplayerServiceError);
    expect(events).not.toContain("availability.true");
    expect(events).toContain("ingress.close");
    expect(service.readiness().ready).toBe(false);
  });

  it("aborts existing ingress and rejects a late or new admission on root readiness loss", async () => {
    const fixture = options();
    let releaseAdmission!: (accepted: boolean) => void;
    ingressHandle = () =>
      new Promise<boolean>((resolve) => {
        releaseAdmission = resolve;
      });
    const service = await startDaytonaHostedMultiplayerService(fixture.options);
    events = [];

    const pendingAdmission = service.handleIngress({ connection: "existing" });
    await vi.waitFor(() => expect(events).toContain("ingress.handle"));
    operationalError?.("root");
    expect(getMultiplayerTransportStatus()).toEqual({
      enabled: false,
      runtime: {
        kind: "daytona",
        isolation: "isolated-hosted",
        yoloEligible: false,
      },
    });
    releaseAdmission(true);

    await expect(pendingAdmission).resolves.toBe(false);
    await vi.waitFor(() => expect(events).toContain("ingress.close"));
    expectOrdered(events, ["availability.false", "ingress.close", "root.stop"]);
    const handledBeforeNewAdmission = events.filter((event) => event === "ingress.handle").length;
    await expect(service.handleIngress({ connection: "new" })).resolves.toBe(false);
    expect(events.filter((event) => event === "ingress.handle")).toHaveLength(
      handledBeforeNewAdmission
    );
  });

  it("verifies the raw signature itself and rejects caller-asserted or mismatched deployment data", () => {
    const rejected = options({ signatureVerifier: () => false });
    expectServiceError(
      () => createDaytonaHostedMultiplayerService(rejected.options),
      "deployment-rejected"
    );
    expect(rejected.credential.every((byte) => byte === 0)).toBe(true);
    expect(rejected.opaqueHandleKey.every((byte) => byte === 0)).toBe(true);
    expect(mocks.createKernel).not.toHaveBeenCalled();

    const asserted = options();
    expectServiceError(
      () =>
        createDaytonaHostedMultiplayerService({
          ...asserted.options,
          deployment: {
            ...asserted.options.deployment,
            verified: { manifest: asserted.options.deployment.manifest },
          },
        } as never),
      "invalid-configuration"
    );
    expect(asserted.credential.every((byte) => byte === 0)).toBe(true);
    expect(asserted.opaqueHandleKey.every((byte) => byte === 0)).toBe(true);

    const mismatched = options();
    expectServiceError(
      () =>
        createDaytonaHostedMultiplayerService({
          ...mismatched.options,
          deployment: {
            ...mismatched.options.deployment,
            measuredArtifacts: {
              ...mismatched.options.deployment.measuredArtifacts,
              sdkSha256: "9".repeat(64),
            },
          },
        }),
      "deployment-rejected"
    );
    expect(mismatched.credential.every((byte) => byte === 0)).toBe(true);
    expect(mismatched.opaqueHandleKey.every((byte) => byte === 0)).toBe(true);

    const badLaterConfiguration = options();
    expectServiceError(
      () =>
        createDaytonaHostedMultiplayerService({
          ...badLaterConfiguration.options,
          supervisor: {
            ...badLaterConfiguration.options.supervisor,
            workerIdPrefix: " contains spaces ",
          },
        }),
      "invalid-configuration"
    );
    expect(badLaterConfiguration.credential.every((byte) => byte === 0)).toBe(true);
    expect(badLaterConfiguration.opaqueHandleKey.every((byte) => byte === 0)).toBe(true);

    const unsupportedCheckpoint = options();
    expectServiceError(
      () =>
        createDaytonaHostedMultiplayerService({
          ...unsupportedCheckpoint.options,
          runtimeProfile: {
            ...unsupportedCheckpoint.options.runtimeProfile,
            capabilities: {
              ...unsupportedCheckpoint.options.runtimeProfile.capabilities,
              checkpoints: true,
            },
          },
        }),
      "deployment-rejected"
    );
    expect(mocks.createKernel).not.toHaveBeenCalled();

    const imageClaims = {
      ...manifestClaims(),
      sandboxArtifact: {
        kind: "oci-image" as const,
        reference: `ghcr.io/procyon-labs-io/terminalx-daytona@sha256:${DIGESTS.sandbox}`,
        sha256: DIGESTS.sandbox,
      },
    } satisfies DaytonaDeploymentArtifactManifestClaims;
    const buildBasedImage = options({ manifest: signedManifest(imageClaims) });
    expectServiceError(
      () => createDaytonaHostedMultiplayerService(buildBasedImage.options),
      "deployment-rejected"
    );
    expect(mocks.createKernel).not.toHaveBeenCalled();
  });

  it("requires the complete supervisor trust group and constructs only an explicit Daytona kernel", async () => {
    const incomplete = options();
    const { verifyCompensationAuthority: _missing, ...trust } = incomplete.options.trust;
    expectServiceError(
      () =>
        createDaytonaHostedMultiplayerService({
          ...incomplete.options,
          trust,
        } as never),
      "invalid-configuration"
    );
    expect(mocks.createKernel).not.toHaveBeenCalled();

    const missingProvisioner = options();
    const { hostedRuntimeObservationProvisioner: _missingProvisioner, ...kernel } =
      missingProvisioner.options.kernel;
    expectServiceError(
      () =>
        createDaytonaHostedMultiplayerService({
          ...missingProvisioner.options,
          kernel,
        } as never),
      "invalid-configuration"
    );
    expect(mocks.createKernel).not.toHaveBeenCalled();

    const explicit = options();
    const service = await startDaytonaHostedMultiplayerService(explicit.options);
    expect(mocks.createKernel).toHaveBeenCalledWith(
      expect.objectContaining({
        filename: "/var/lib/terminalx/team-sessions.sqlite",
        runtimeProfile: expect.objectContaining({ kind: "daytona" }),
        hostedRuntimeObservationProvisioner: expect.any(Function),
      })
    );
    expect(mocks.createKernel).not.toHaveBeenCalledWith();
    const kernelOptions = mocks.createKernel.mock.calls.at(-1)?.[0] as {
      hostedRuntimeObservationProvisioner: CreateDaytonaHostedMultiplayerServiceOptions["kernel"]["hostedRuntimeObservationProvisioner"];
    };
    expect(
      kernelOptions.hostedRuntimeObservationProvisioner({
        binding: {
          teamId: "team-1",
          projectId: "project-1",
          sessionId: "session-1",
          runtimeAssignmentId: "assignment-1",
          runtimeAssignmentGeneration: 1,
          sandboxId: "sandbox-1",
          sandboxGeneration: 1,
          runtimePrincipalId: "principal-1",
        },
        runtimeAuthorizationGeneration: 7,
        incarnation: "a".repeat(64),
        adapterConfigurationRef: "daytona-adapter:v1",
      })
    ).toEqual({
      keyProvisioningRef: "observation-provisioning:assignment-1:g7",
      issuerKeyId: "observation-key:assignment-1:g7",
      publicKeySpkiPem: OBSERVATION_PUBLIC_KEY,
    });
    await service.close();
  });

  function options(overrides?: {
    signatureVerifier?: CreateDaytonaHostedMultiplayerServiceOptions["deployment"]["signatureVerifier"];
    operationTimeoutMs?: number;
    manifest?: DaytonaDeploymentArtifactManifest;
  }): {
    options: CreateDaytonaHostedMultiplayerServiceOptions;
    credential: Uint8Array;
    opaqueHandleKey: Uint8Array;
  } {
    const credential = new TextEncoder().encode("daytona-credential");
    const opaqueHandleKey = new Uint8Array(32).fill(7);
    const manifest = overrides?.manifest ?? signedManifest();
    const ingress = {
      async start() {
        events.push("ingress.start");
      },
      readiness() {
        events.push("ingress.readiness");
        return ingressReady;
      },
      async handle() {
        events.push("ingress.handle");
        return ingressHandle();
      },
      async close() {
        events.push("ingress.close");
        await ingressClose();
      },
    };
    const availability = {
      publish(available: boolean) {
        events.push(`availability.${available}`);
      },
    };
    const supervisor = {
      async attestIsolation() {
        return {};
      },
      async executeAuthenticated() {
        return {} as never;
      },
      followSigned() {
        return Object.freeze({
          async *[Symbol.asyncIterator]() {
            // No observations in a composition-only test.
          },
        });
      },
      async close() {
        events.push("supervisor.close");
      },
    };
    const assignmentBootstrap = {
      async install() {
        return {} as never;
      },
      async activate() {},
      resolveActivation() {
        return {} as never;
      },
      resolveEffectManifest() {
        return {} as never;
      },
      async retire() {},
      async close() {
        events.push("assignment-bootstrap.close");
      },
    };
    const terminal = {
      async open() {
        throw new Error("unused terminal open");
      },
      async close() {
        events.push("terminal-transport.close");
      },
    };
    const profile: CreateDaytonaHostedMultiplayerServiceOptions["runtimeProfile"] = {
      kind: "daytona",
      source: {
        sourceRevision: "source:v1",
        expectedCommitSha: "1".repeat(64),
        setupRef: "setup:v1",
      },
      harnessRef: "harness:v1",
      checkpointPolicyRef: "checkpoint:v1",
      adapterConfigurationRef: "daytona-adapter:v1",
      projectCeiling: {
        revision: "hosted-ceiling:v1",
        digest: "2".repeat(64),
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
        scopedExternalRulesDigest: "3".repeat(64),
        isolationPolicyDigest: DIGESTS.isolation,
        networkPolicyDigest: "4".repeat(64),
        credentialPolicyDigest: "5".repeat(64),
      },
      isolation: {
        isolationPolicyDigest: DIGESTS.isolation,
        publicAccess: false,
        hostMounts: false,
        linkedSandbox: false,
        rootIdentity: false,
        network: { mode: "blocked", policyDigest: "4".repeat(64), allowedDestinations: [] },
        resources: { cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 256 },
      },
      capabilities: {
        isolatedExecution: true,
        brokeredCredentials: false,
        proxyOnlyEgress: false,
        checkpoints: false,
        yoloEligible: false,
      },
    };
    const options: CreateDaytonaHostedMultiplayerServiceOptions = {
      deployment: {
        sourceEnvironment: {
          TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
          TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
        },
        manifest,
        signatureVerifier: overrides?.signatureVerifier ?? (() => true),
        measuredArtifacts: {
          sdkSha256: DIGESTS.sdk,
          supervisorSha256: DIGESTS.supervisor,
          sbomSha256: DIGESTS.sbom,
          provenanceSha256: DIGESTS.provenance,
          sandboxSha256: DIGESTS.sandbox,
          isolationProfileSha256: DIGESTS.isolation,
        },
      },
      runtimeProfile: profile,
      kernel: {
        filename: "/var/lib/terminalx/team-sessions.sqlite",
        hostedRuntimeObservationProvisioner: (request) => ({
          keyProvisioningRef: `observation-provisioning:${request.binding.runtimeAssignmentId}:g${request.runtimeAuthorizationGeneration}`,
          issuerKeyId: `observation-key:${request.binding.runtimeAssignmentId}:g${request.runtimeAuthorizationGeneration}`,
          publicKeySpkiPem: OBSERVATION_PUBLIC_KEY,
        }),
        runtimeCommandAuthorityIssuer: { issue: () => ({}) as never },
        runtimeAuthorizationSnapshotSource: { resolve: () => undefined },
        runtimeEnforcementProofVerifier: () => true,
        runtimeLifecycleCommandTtlMs: 30_000,
        runtimeCompensationAuthorityIssuer: { issue: () => ({}) as never },
        runtimeCompensationAuthorityVerifier: () => true,
        runtimeCompensationPolicySource: { resolve: () => undefined },
        runtimeCompensationEnforcementProofVerifier: () => true,
      },
      provider: {
        endpoint: "https://daytona.example.test/api",
        organizationId: "terminalx-production",
        credential,
        fetch: async () => new Response(null, { status: 204 }),
        configuration: {
          sourceCommit: DAYTONA_PRODUCTION_FORK_COMMIT,
          target: "terminalx-production",
          sandboxUser: "terminalx",
          artifact: {
            kind: "snapshot",
            snapshotId:
              manifest.sandboxArtifact.kind === "daytona-snapshot"
                ? manifest.sandboxArtifact.snapshotId
                : "",
            snapshotRef:
              manifest.sandboxArtifact.kind === "daytona-snapshot"
                ? manifest.sandboxArtifact.snapshotRef
                : "",
            imageId:
              manifest.sandboxArtifact.kind === "daytona-snapshot"
                ? manifest.sandboxArtifact.imageId
                : "",
            contentDigest: DIGESTS.sandbox,
          },
          supervisorArtifactDigest: DIGESTS.supervisor,
          lifecycle: {
            autoStopIntervalMinutes: 0,
            autoArchiveIntervalMinutes: 0,
            autoDeleteIntervalMinutes: -1,
          },
        },
        supervisor,
        assignmentBootstrap,
        terminal,
        verifyIsolationAttestation: () => true,
        verifyCommandAuthority: () => true,
      },
      trust: {
        effectTrust: {
          registerManifest() {},
          registerAttestations() {},
          verifyRuntimeEnforcementProof: () => true,
          verifyRuntimeCompensationEnforcementProof: () => true,
          close() {},
        },
        verifyLifecycleAuthority: () => true,
        verifyLifecycleEnforcementProof: () => true,
        verifyCompensationAuthority: () => true,
        verifyCompensationEnforcementProof: () => true,
      },
      adapter: { opaqueHandleKey, operationTimeoutMs: overrides?.operationTimeoutMs ?? 1_000 },
      supervisor: {
        workerIdPrefix: "terminalx-hosted:test",
        clock: () => 2_000_000_000_100,
        onOperationalError: () => undefined,
      },
      ingress,
      availability,
    };
    return { options, credential, opaqueHandleKey };
  }
});

function manifestClaims(): DaytonaDeploymentArtifactManifestClaims {
  return {
    version: 1,
    kind: "terminalx.daytona-deployment-artifacts",
    manifestId: "terminalx-daytona-production:2026-07-24:v1",
    issuedAtMs: 2_000_000_000_000,
    source: {
      forkRepository: DAYTONA_FORK_REPOSITORY,
      forkCommit: DAYTONA_PRODUCTION_FORK_COMMIT,
      upstreamRepository: DAYTONA_UPSTREAM_REPOSITORY,
      upstreamBaseCommit: DAYTONA_UPSTREAM_BASE_COMMIT,
    },
    artifacts: {
      sdk: { kind: "daytona-typescript-sdk", sha256: DIGESTS.sdk },
      supervisor: { kind: "terminalx-daytona-supervisor", sha256: DIGESTS.supervisor },
      sbom: { kind: "spdx-2.3-json", sha256: DIGESTS.sbom },
      provenance: { kind: "slsa-v1-dsse", sha256: DIGESTS.provenance },
    },
    sandboxArtifact: {
      kind: "daytona-snapshot",
      snapshotId: "123e4567-e89b-42d3-a456-426614174000",
      snapshotRef: `ghcr.io/procyon-labs-io/terminalx-daytona@sha256:${DIGESTS.sandbox}`,
      imageId: `sha256:${DIGESTS.imageConfig}`,
      sha256: DIGESTS.sandbox,
    },
    isolationProfile: {
      profileRef: "terminalx-daytona-isolation:v1",
      sha256: DIGESTS.isolation,
    },
  };
}

function signedManifest(
  claims: DaytonaDeploymentArtifactManifestClaims = manifestClaims()
): DaytonaDeploymentArtifactManifest {
  return {
    ...claims,
    authority: {
      issuer: "terminalx-release",
      issuerKeyId: "terminalx-release:daytona-production:v1",
      audience: "terminalx-runtime",
      capability: "daytona.deployment.activate",
      algorithm: "ed25519",
      claimsDigest: digestDaytonaDeploymentArtifactManifestClaims(claims),
      signature: SIGNATURE,
    },
  };
}

function expectServiceError(
  operation: () => unknown,
  code: HostedMultiplayerServiceError["code"]
): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(HostedMultiplayerServiceError);
    expect((error as HostedMultiplayerServiceError).code).toBe(code);
    return;
  }
  throw new Error(`Expected HostedMultiplayerServiceError:${code}`);
}

function expectOrdered(events: readonly string[], ordered: readonly string[]): void {
  let previous = -1;
  for (const event of ordered) {
    const index = events.indexOf(event);
    expect(index, `${event} missing from ${events.join(",")}`).toBeGreaterThan(previous);
    previous = index;
  }
}
