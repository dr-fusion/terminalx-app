import { isAbsolute } from "node:path";
import { types as nodeTypes } from "node:util";
import {
  DAYTONA_PRODUCTION_FORK_COMMIT,
  DaytonaDeploymentArtifactError,
  verifyDaytonaDeploymentArtifacts,
  type DaytonaDeploymentArtifactManifest,
  type DaytonaDeploymentManifestSignatureVerifier,
  type DaytonaSourceEnvironment,
} from "./daytona-source";
import {
  createDaytonaHostedRuntimeControlPlane,
  createPinnedDaytonaFetchApi,
  type DaytonaCommandAuthorityVerifier,
  type DaytonaHostedControlPlaneConfiguration,
  type DaytonaIsolationAttestationVerifier,
  type DaytonaSandboxApiPort,
  type PinnedDaytonaSupervisorTransport,
} from "./daytona-hosted-control-plane";
import type { DaytonaAssignmentBootstrapCoordinator } from "./daytona-assignment-bootstrap-saga";
import {
  createDaytonaHostedTerminalAdapter,
  type DaytonaHostedTerminalAdapter,
  type DaytonaSupervisorPtyTransport,
} from "./daytona-hosted-terminal-adapter";
import {
  createHostedRuntimeAdapterBundle,
  type HostedRuntimeAdapterBundle,
} from "./hosted-runtime-adapter";
import type { HostedRuntimeControlPlane } from "./hosted-runtime-control-plane";
import type { HostedAssignmentPlanSource } from "./hosted-runtime-control-plane";
import {
  createHostedRuntimeActivationRegistry,
  type HostedRuntimeActivationRegistry,
} from "./hosted-runtime-activation-registry";
import type { HostedTerminalAdapter } from "./hosted-terminal";
import type { RuntimeAuthorityVerifier } from "./runtime-command-execution";
import type { RuntimeCommandAuthorityIssuer } from "./runtime-command-authority";
import type { RuntimeCompensationEnforcementProofVerifier } from "./runtime-compensation-enforcement-proof";
import type { RuntimeCompensationAuthorityVerifier } from "./runtime-compensation-execution";
import type {
  RuntimeCompensationAuthorityIssuer,
  RuntimeCompensationCommandAuthorityVerifier,
  RuntimeCompensationPolicySource,
} from "./runtime-compensation-materializer";
import type { RuntimeEnforcementProofVerifier } from "./runtime-enforcement-proof";
import {
  createRuntimeSupervisorComposition,
  type RuntimeSupervisorComponent,
  type RuntimeSupervisorComposition,
} from "./runtime-supervisor-composition";
import {
  snapshotRuntimeSupervisorPortableData,
  exactRuntimeSupervisorDataRecord,
  runtimeSupervisorDataField,
} from "./runtime-supervisor-snapshot";
import type { RuntimeWriteFence } from "./write-state";
import {
  createTeamSessionKernel,
  type HostedRuntimeObservationProvisioner,
  type RuntimeAuthorizationSnapshotSource,
  type RuntimeDeploymentProfile,
  type TeamSessionKernel,
} from "../team-sessions/module";
import { installTeamSessionKernel } from "../team-sessions/service";
import {
  markMultiplayerTransportAvailable,
  type MultiplayerRuntimeStatus,
} from "../team-sessions/feature";
import type { TeamSessions } from "../team-sessions/types";
import type { SynchronousRuntimeCompensationEnforcementProofVerifier } from "./runtime-compensation-enforcement-proof";
import type { SynchronousRuntimeEnforcementProofVerifier } from "./runtime-enforcement-proof";
import type { RuntimeEffectEnforcerTrustRouter } from "./runtime-effect-enforcer-trust-router";

const TOP_LEVEL_FIELDS = [
  "deployment",
  "runtimeProfile",
  "kernel",
  "provider",
  "trust",
  "adapter",
  "supervisor",
  "ingress",
  "availability",
] as const;
const DEPLOYMENT_FIELDS = [
  "sourceEnvironment",
  "manifest",
  "signatureVerifier",
  "measuredArtifacts",
] as const;
const MEASURED_ARTIFACT_FIELDS = [
  "sdkSha256",
  "supervisorSha256",
  "sbomSha256",
  "provenanceSha256",
  "sandboxSha256",
  "isolationProfileSha256",
] as const;
const KERNEL_FIELDS = [
  "filename",
  "hostedRuntimeObservationProvisioner",
  "runtimeCommandAuthorityIssuer",
  "runtimeAuthorizationSnapshotSource",
  "runtimeEnforcementProofVerifier",
  "runtimeLifecycleCommandTtlMs",
  "runtimeCompensationAuthorityIssuer",
  "runtimeCompensationAuthorityVerifier",
  "runtimeCompensationPolicySource",
  "runtimeCompensationEnforcementProofVerifier",
] as const;
const PROVIDER_FIELDS = [
  "endpoint",
  "organizationId",
  "credential",
  "fetch",
  "configuration",
  "supervisor",
  "assignmentBootstrap",
  "terminal",
  "verifyIsolationAttestation",
  "verifyCommandAuthority",
] as const;
const TRUST_FIELDS = [
  "effectTrust",
  "verifyLifecycleAuthority",
  "verifyLifecycleEnforcementProof",
  "verifyCompensationAuthority",
  "verifyCompensationEnforcementProof",
] as const;
const ADAPTER_FIELDS = ["opaqueHandleKey", "operationTimeoutMs"] as const;
const SUPERVISOR_FIELDS = ["workerIdPrefix", "clock", "onOperationalError"] as const;
const SHA256 = /^[0-9a-f]{64}$/;
const MIN_KEY_BYTES = 32;
const MAX_KEY_BYTES = 4_096;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 300_000;
const MAX_PROTOTYPE_DEPTH = 32;
const HOSTED_SHUTDOWN_STAGE_COUNT = 4;
const SHUTDOWN_SCHEDULING_GRACE_MS = 1_000;

type AnyFunction = (...args: never[]) => unknown;

export interface MeasuredDaytonaDeploymentArtifacts {
  readonly sdkSha256: string;
  readonly supervisorSha256: string;
  readonly sbomSha256: string;
  readonly provenanceSha256: string;
  readonly sandboxSha256: string;
  readonly isolationProfileSha256: string;
}

export interface HostedMultiplayerIngressContext {
  readonly teamSessions: TeamSessions;
  readonly hostedAssignmentPlans: HostedAssignmentPlanSource;
  readonly hostedTerminal: HostedTerminalAdapter;
  readonly isRuntimeWriteAllowed: (input: RuntimeWriteFence) => boolean;
}

/**
 * Provider-neutral terminal/chat ingress. A Daytona PTY transport can implement
 * this seam without exposing provider identifiers to the server or browser.
 */
export interface HostedMultiplayerIngress {
  start(context: HostedMultiplayerIngressContext, signal: AbortSignal): Promise<void>;
  readiness(): boolean;
  handle(input: unknown, signal: AbortSignal): Promise<boolean>;
  close(): Promise<void>;
}

/** Availability is deployment-owned and must be withdrawn synchronously. */
export interface HostedMultiplayerAvailability {
  publish(available: boolean, runtime: MultiplayerRuntimeStatus | null): void;
}

export interface CreateDaytonaHostedMultiplayerServiceOptions {
  readonly deployment: {
    readonly sourceEnvironment: DaytonaSourceEnvironment;
    /** Raw signed data. A caller-produced `Verified...` object is never accepted. */
    readonly manifest: unknown;
    readonly signatureVerifier: DaytonaDeploymentManifestSignatureVerifier;
    readonly measuredArtifacts: MeasuredDaytonaDeploymentArtifacts;
  };
  readonly runtimeProfile: Extract<RuntimeDeploymentProfile, { readonly kind: "daytona" }>;
  readonly kernel: {
    /** Explicit durable path; the kernel's environment/cwd fallback is never used. */
    readonly filename: string;
    /**
     * Root-private, in-memory synchronous provisioner. The kernel invokes it
     * inside SQLite, so it must perform no filesystem, vault, or network I/O;
     * only public registration material is returned.
     */
    readonly hostedRuntimeObservationProvisioner: HostedRuntimeObservationProvisioner;
    readonly runtimeCommandAuthorityIssuer: RuntimeCommandAuthorityIssuer;
    readonly runtimeAuthorizationSnapshotSource: RuntimeAuthorizationSnapshotSource;
    readonly runtimeEnforcementProofVerifier: SynchronousRuntimeEnforcementProofVerifier;
    readonly runtimeLifecycleCommandTtlMs: number;
    readonly runtimeCompensationAuthorityIssuer: RuntimeCompensationAuthorityIssuer;
    readonly runtimeCompensationAuthorityVerifier: RuntimeCompensationCommandAuthorityVerifier;
    readonly runtimeCompensationPolicySource: RuntimeCompensationPolicySource;
    readonly runtimeCompensationEnforcementProofVerifier: SynchronousRuntimeCompensationEnforcementProofVerifier;
  };
  readonly provider: {
    readonly endpoint: string;
    readonly organizationId: string | null;
    /** Ownership transfers to this service and the caller's bytes are zeroed. */
    readonly credential: Uint8Array;
    readonly fetch: typeof fetch;
    readonly configuration: DaytonaHostedControlPlaneConfiguration;
    readonly supervisor: PinnedDaytonaSupervisorTransport;
    readonly assignmentBootstrap: DaytonaAssignmentBootstrapCoordinator;
    readonly terminal: DaytonaSupervisorPtyTransport;
    readonly verifyIsolationAttestation: DaytonaIsolationAttestationVerifier;
    readonly verifyCommandAuthority: DaytonaCommandAuthorityVerifier;
  };
  readonly trust: {
    /** Ownership transfers to the service and is closed during shutdown. */
    readonly effectTrust: RuntimeEffectEnforcerTrustRouter;
    readonly verifyLifecycleAuthority: RuntimeAuthorityVerifier;
    readonly verifyLifecycleEnforcementProof: RuntimeEnforcementProofVerifier;
    readonly verifyCompensationAuthority: RuntimeCompensationAuthorityVerifier;
    readonly verifyCompensationEnforcementProof: RuntimeCompensationEnforcementProofVerifier;
  };
  readonly adapter: {
    /** Ownership transfers to this service and the caller's bytes are zeroed. */
    readonly opaqueHandleKey: Uint8Array;
    readonly operationTimeoutMs: number;
  };
  readonly supervisor: {
    readonly workerIdPrefix: string;
    readonly clock: () => number;
    readonly onOperationalError: (component: RuntimeSupervisorComponent) => void;
  };
  readonly ingress: HostedMultiplayerIngress;
  readonly availability: HostedMultiplayerAvailability;
}

export type HostedMultiplayerServiceState =
  | "created"
  | "starting"
  | "running"
  | "stopping"
  | "stopped"
  | "failed";

export interface DaytonaHostedMultiplayerService {
  start(): Promise<void>;
  readiness(): { readonly ready: boolean; readonly state: HostedMultiplayerServiceState };
  runtimeStatus(): Extract<MultiplayerRuntimeStatus, { readonly kind: "daytona" }>;
  /** Upper bound consumed by the process-wide shutdown deadline. */
  shutdownBudgetMs(): number;
  handleIngress(input: unknown): Promise<boolean>;
  close(): Promise<void>;
}

export type HostedMultiplayerServiceErrorCode =
  | "invalid-configuration"
  | "deployment-rejected"
  | "startup-failed"
  | "shutdown-failed";

const SAFE_ERROR_MESSAGES: Readonly<Record<HostedMultiplayerServiceErrorCode, string>> =
  Object.freeze({
    "invalid-configuration": "Hosted multiplayer configuration is invalid",
    "deployment-rejected": "Hosted multiplayer deployment was rejected",
    "startup-failed": "Hosted multiplayer service could not start",
    "shutdown-failed": "Hosted multiplayer service could not stop",
  });

/** Stable failures never include credentials, provider IDs, paths, or verifier errors. */
export class HostedMultiplayerServiceError extends Error {
  constructor(readonly code: HostedMultiplayerServiceErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "HostedMultiplayerServiceError";
  }
}

interface CapturedMethod {
  readonly receiver: object;
  readonly method: AnyFunction;
}

interface CapturedIngress {
  readonly receiver: object;
  readonly start: AnyFunction;
  readonly readiness: AnyFunction;
  readonly handle: AnyFunction;
  readonly close: AnyFunction;
}

interface CapturedConfiguration {
  readonly manifest: DaytonaDeploymentArtifactManifest;
  readonly runtimeProfile: Extract<RuntimeDeploymentProfile, { readonly kind: "daytona" }>;
  readonly runtimeStatus: Extract<MultiplayerRuntimeStatus, { readonly kind: "daytona" }>;
  readonly kernel: CreateDaytonaHostedMultiplayerServiceOptions["kernel"];
  readonly provider: Omit<
    CreateDaytonaHostedMultiplayerServiceOptions["provider"],
    "credential"
  > & {
    readonly credential: Uint8Array;
  };
  readonly trust: CreateDaytonaHostedMultiplayerServiceOptions["trust"];
  readonly adapter: {
    readonly opaqueHandleKey: Uint8Array;
    readonly operationTimeoutMs: number;
  };
  readonly supervisor: CreateDaytonaHostedMultiplayerServiceOptions["supervisor"];
  readonly ingress: CapturedIngress;
  readonly availability: CapturedMethod;
}

class DaytonaHostedMultiplayerServiceImpl implements DaytonaHostedMultiplayerService {
  private readonly configuration: CapturedConfiguration;
  private currentState: HostedMultiplayerServiceState = "created";
  private startPromise: Promise<void> | null = null;
  private closePromise: Promise<void> | null = null;
  private cleanupPromise: Promise<boolean> | null = null;
  private closeRequested = false;
  private ingressStarted = false;
  private kernel: TeamSessionKernel | null = null;
  private kernelClose: CapturedMethod | null = null;
  private kernelUninstall: (() => void) | null = null;
  private api: DaytonaSandboxApiPort | null = null;
  private controlPlane: HostedRuntimeControlPlane | null = null;
  private terminalAdapter: DaytonaHostedTerminalAdapter | null = null;
  private adapter: HostedRuntimeAdapterBundle | null = null;
  private activationRegistry: HostedRuntimeActivationRegistry | null = null;
  private composition: RuntimeSupervisorComposition | null = null;
  private readonly shutdown = new AbortController();

  constructor(configuration: CapturedConfiguration) {
    this.configuration = configuration;
  }

  start(): Promise<void> {
    if (this.currentState === "running") return Promise.resolve();
    if (this.currentState === "starting" && this.startPromise) return this.startPromise;
    if (this.currentState !== "created") {
      return Promise.reject(new HostedMultiplayerServiceError("startup-failed"));
    }
    this.currentState = "starting";
    const start = this.startInternal();
    this.startPromise = start;
    return start;
  }

  readiness(): { readonly ready: boolean; readonly state: HostedMultiplayerServiceState } {
    let ready = false;
    if (this.currentState === "running" && !this.closeRequested) {
      try {
        ready =
          this.composition?.root.readiness().ready === true &&
          this.invokeIngressReadiness() === true;
        ready =
          ready &&
          this.currentState === "running" &&
          !this.closeRequested &&
          !this.shutdown.signal.aborted;
      } catch {
        ready = false;
      }
    }
    if (!ready && this.currentState === "running") this.failClosed();
    return Object.freeze({ ready, state: this.currentState });
  }

  runtimeStatus(): Extract<MultiplayerRuntimeStatus, { readonly kind: "daytona" }> {
    return this.configuration.runtimeStatus;
  }

  shutdownBudgetMs(): number {
    return (
      this.configuration.adapter.operationTimeoutMs * HOSTED_SHUTDOWN_STAGE_COUNT +
      SHUTDOWN_SCHEDULING_GRACE_MS
    );
  }

  async handleIngress(input: unknown): Promise<boolean> {
    if (!this.readiness().ready) return false;
    try {
      const result = Reflect.apply(
        this.configuration.ingress.handle,
        this.configuration.ingress.receiver,
        [input, this.shutdown.signal]
      );
      if (!nodeTypes.isPromise(result)) throw new TypeError();
      const accepted = await result;
      if (accepted !== true && accepted !== false) throw new TypeError();
      // Readiness may have been withdrawn while the ingress was authenticating
      // or opening a stream. Never turn that stale completion into admission.
      const ready = this.readiness().ready;
      return accepted && ready;
    } catch {
      this.failClosed();
      return false;
    }
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closeRequested = true;
    this.shutdown.abort();
    this.publishAvailability(false, true);
    if (this.currentState !== "stopped") this.currentState = "stopping";
    const close = (async () => {
      if (this.startPromise) await this.startPromise.catch(() => undefined);
      const clean = await this.cleanup();
      this.currentState = clean ? "stopped" : "failed";
      if (!clean) throw new HostedMultiplayerServiceError("shutdown-failed");
    })();
    this.closePromise = close;
    return close;
  }

  private async startInternal(): Promise<void> {
    try {
      this.requireStarting();
      this.publishAvailability(false, false);
      const config = this.configuration;
      this.activationRegistry = createHostedRuntimeActivationRegistry();
      this.kernel = createTeamSessionKernel({
        filename: config.kernel.filename,
        runtimeProfile: config.runtimeProfile,
        hostedRuntimeObservationProvisioner: config.kernel.hostedRuntimeObservationProvisioner,
        hostedRuntimeActivationSource: this.activationRegistry,
        runtimeCommandAuthorityIssuer: config.kernel.runtimeCommandAuthorityIssuer,
        runtimeAuthorizationSnapshotSource: config.kernel.runtimeAuthorizationSnapshotSource,
        runtimeEnforcementProofVerifier: config.trust.effectTrust.verifyRuntimeEnforcementProof,
        runtimeLifecycleCommandTtlMs: config.kernel.runtimeLifecycleCommandTtlMs,
        runtimeCompensationAuthorityIssuer: config.kernel.runtimeCompensationAuthorityIssuer,
        runtimeCompensationAuthorityVerifier: config.kernel.runtimeCompensationAuthorityVerifier,
        runtimeCompensationPolicySource: config.kernel.runtimeCompensationPolicySource,
        runtimeCompensationEnforcementProofVerifier:
          config.trust.effectTrust.verifyRuntimeCompensationEnforcementProof,
      });
      this.kernelClose = captureMethod(this.kernel.teamSessions, "close");
      this.requireStarting();

      this.api = createPinnedDaytonaFetchApi({
        endpoint: config.provider.endpoint,
        organizationId: config.provider.organizationId,
        credential: config.provider.credential,
        fetch: config.provider.fetch,
      });
      this.controlPlane = createDaytonaHostedRuntimeControlPlane({
        configuration: config.provider.configuration,
        api: this.api,
        supervisor: config.provider.supervisor,
        assignmentBootstrap: config.provider.assignmentBootstrap,
        effectTrust: config.trust.effectTrust,
        verifyIsolationAttestation: config.provider.verifyIsolationAttestation,
        verifyCommandAuthority: config.provider.verifyCommandAuthority,
        verifyLifecycleEnforcementProof: config.trust.effectTrust.verifyRuntimeEnforcementProof,
        verifyCompensationEnforcementProof:
          config.trust.effectTrust.verifyRuntimeCompensationEnforcementProof,
        clock: config.supervisor.clock,
      });
      this.adapter = createHostedRuntimeAdapterBundle({
        plans: this.kernel.hostedAssignmentPlanSource,
        controlPlane: this.controlPlane,
        activationSink: this.activationRegistry,
        opaqueHandleKey: config.adapter.opaqueHandleKey,
        operationTimeoutMs: config.adapter.operationTimeoutMs,
      });
      this.terminalAdapter = createDaytonaHostedTerminalAdapter({
        plans: this.kernel.hostedAssignmentPlanSource,
        controlPlane: this.controlPlane,
        transport: config.provider.terminal,
        operationTimeoutMs: config.adapter.operationTimeoutMs,
      });
      this.composition = createRuntimeSupervisorComposition({
        kernel: this.kernel,
        assignmentRuntime: this.adapter.assignmentRuntime,
        runtime: this.adapter.runtime,
        receiptTransport: this.adapter.receiptTransport,
        lifecycleHandles: this.adapter.lifecycleHandles,
        receiptFollowHandles: this.adapter.receiptFollowHandles,
        compensationHandles: this.adapter.compensationHandles,
        verifyLifecycleAuthority: config.trust.verifyLifecycleAuthority,
        verifyLifecycleEnforcementProof: config.trust.verifyLifecycleEnforcementProof,
        verifyCompensationAuthority: config.trust.verifyCompensationAuthority,
        verifyCompensationEnforcementProof: config.trust.verifyCompensationEnforcementProof,
        workerIdPrefix: config.supervisor.workerIdPrefix,
        clock: config.supervisor.clock,
        onOperationalError: (component) => {
          // Withdraw admission and abort/close ingress before telemetry. This
          // transition is idempotent when several workers report the same loss.
          this.failClosed();
          try {
            config.supervisor.onOperationalError(component);
          } catch {
            // A telemetry sink cannot alter Runtime safety state.
          }
        },
      });

      await this.composition.root.start();
      this.requireStarting();
      if (!this.composition.root.readiness().ready) throw new TypeError();

      this.ingressStarted = true;
      const context = Object.freeze({
        teamSessions: this.kernel.teamSessions,
        hostedAssignmentPlans: this.kernel.hostedAssignmentPlanSource,
        hostedTerminal: this.terminalAdapter,
        isRuntimeWriteAllowed: (input: RuntimeWriteFence) =>
          this.currentState === "running" &&
          !this.closeRequested &&
          this.composition?.writeStateRegistry.isWriteAllowed(input) === true,
      });
      const ingressStart = Reflect.apply(config.ingress.start, config.ingress.receiver, [
        context,
        this.shutdown.signal,
      ]);
      await requireNativeVoidPromise(ingressStart);
      this.requireStarting();
      if (!this.invokeIngressReadiness()) throw new TypeError();

      // The global route registry is installed only after the exact root and
      // ingress are ready. From this point HTTP and hosted WebSockets share the
      // same kernel identity; a pre-existing LocalTmux singleton is fatal.
      this.kernelUninstall = installTeamSessionKernel(this.kernel);
      this.currentState = "running";
      this.publishAvailability(true, false);
    } catch {
      if (this.currentState !== "stopping") this.currentState = "failed";
      await this.cleanup();
      throw new HostedMultiplayerServiceError("startup-failed");
    }
  }

  private requireStarting(): void {
    if (this.currentState !== "starting" || this.closeRequested || this.shutdown.signal.aborted) {
      throw new TypeError();
    }
  }

  private invokeIngressReadiness(): boolean {
    const result = Reflect.apply(
      this.configuration.ingress.readiness,
      this.configuration.ingress.receiver,
      []
    );
    if (result !== true && result !== false) throw new TypeError();
    return result;
  }

  private publishAvailability(available: boolean, suppressFailure: boolean): boolean {
    let publishedGlobally = false;
    try {
      // Admission withdrawal is process-owned and precedes every optional
      // deployment observer. Availability is published globally only after
      // the observer accepts the fully ready service.
      if (!available) {
        markMultiplayerTransportAvailable(false, this.configuration.runtimeStatus);
        publishedGlobally = true;
      }
      const result = Reflect.apply(
        this.configuration.availability.method,
        this.configuration.availability.receiver,
        [available, this.configuration.runtimeStatus]
      );
      if (result !== undefined) throw new TypeError();
      if (available) {
        markMultiplayerTransportAvailable(true, this.configuration.runtimeStatus);
        publishedGlobally = true;
      }
      return true;
    } catch {
      if (available || !publishedGlobally) {
        try {
          markMultiplayerTransportAvailable(false, this.configuration.runtimeStatus);
        } catch {
          // Registry corruption is still reflected by the false return below.
        }
      }
      if (!suppressFailure) throw new TypeError();
      return false;
    }
  }

  private failClosed(): void {
    this.publishAvailability(false, true);
    this.closeRequested = true;
    this.shutdown.abort();
    if (this.currentState === "running" || this.currentState === "starting") {
      this.currentState = "stopping";
    }
    // Do not await shutdown from a worker callback: root.stop() may need the
    // reporting worker to unwind. `close()` owns one shared settlement.
    void this.close().catch(() => undefined);
  }

  /** Reverse construction order. The SQLite kernel is always the final owner closed. */
  private cleanup(): Promise<boolean> {
    if (this.cleanupPromise) return this.cleanupPromise;
    const cleanup = (async () => {
      let clean = this.publishAvailability(false, true);

      if (this.ingressStarted) {
        clean =
          (await settleCaptured(this.configuration.ingress, "close", [], this.timeout())) && clean;
      }

      if (this.composition !== null) {
        clean = (await settleMethod(this.composition.root, "stop", this.timeout())) && clean;
      }

      if (this.terminalAdapter !== null) {
        clean = (await settleMethod(this.terminalAdapter, "close", this.timeout())) && clean;
      } else {
        clean =
          (await settleMethod(this.configuration.provider.terminal, "close", this.timeout())) &&
          clean;
      }

      if (this.adapter !== null) {
        clean = (await settleMethod(this.adapter, "close", this.timeout())) && clean;
      } else if (this.controlPlane !== null) {
        clean = (await settleMethod(this.controlPlane, "close", this.timeout())) && clean;
      } else {
        if (this.api !== null) {
          clean = (await settleMethod(this.api, "close", this.timeout())) && clean;
        }
        clean =
          (await settleMethod(this.configuration.provider.supervisor, "close", this.timeout())) &&
          clean;
      }

      if (this.kernelUninstall !== null) {
        clean = settleSynchronousFunction(this.kernelUninstall) && clean;
        this.kernelUninstall = null;
      }

      if (this.activationRegistry !== null) {
        clean = settleSynchronousFunction(() => this.activationRegistry?.close()) && clean;
        this.activationRegistry = null;
      }

      clean = settleSynchronousFunction(this.configuration.trust.effectTrust.close) && clean;

      this.configuration.provider.credential.fill(0);
      this.configuration.adapter.opaqueHandleKey.fill(0);

      // SQLite is the durable authorization source used by every ingress and
      // worker. If an earlier owner did not settle, closing it would turn a
      // bounded shutdown failure into a use-after-close race.
      if (clean && this.kernelClose !== null) {
        clean = settleSynchronous(this.kernelClose) && clean;
      }
      return clean;
    })();
    this.cleanupPromise = cleanup;
    return cleanup;
  }

  private timeout(): number {
    return this.configuration.adapter.operationTimeoutMs;
  }
}

/** Construct a stopped service. Concurrent callers may safely share `start()` and `close()`. */
export function createDaytonaHostedMultiplayerService(
  options: CreateDaytonaHostedMultiplayerServiceOptions
): DaytonaHostedMultiplayerService {
  const service = new DaytonaHostedMultiplayerServiceImpl(captureConfiguration(options));
  return Object.freeze({
    start: () => service.start(),
    readiness: () => service.readiness(),
    runtimeStatus: () => service.runtimeStatus(),
    shutdownBudgetMs: () => service.shutdownBudgetMs(),
    handleIngress: (input: unknown) => service.handleIngress(input),
    close: () => service.close(),
  });
}

/** Production one-call activation: nothing is returned until root and ingress are ready. */
export async function startDaytonaHostedMultiplayerService(
  options: CreateDaytonaHostedMultiplayerServiceOptions
): Promise<DaytonaHostedMultiplayerService> {
  const service = createDaytonaHostedMultiplayerService(options);
  try {
    await service.start();
    return service;
  } catch (error) {
    await service.close().catch(() => undefined);
    throw error;
  }
}

function captureConfiguration(
  unsafeOptions: CreateDaytonaHostedMultiplayerServiceOptions
): CapturedConfiguration {
  let availability: CapturedMethod | null = null;
  let providerCredential: Uint8Array | null = null;
  let opaqueHandleKey: Uint8Array | null = null;
  let sourceCredential: Uint8Array | null = null;
  let sourceOpaqueHandleKey: Uint8Array | null = null;
  try {
    const options = exactDataRecord(unsafeOptions, TOP_LEVEL_FIELDS);
    // Ownership begins after the exact top-level record. Capture each byte
    // field through a data descriptor before validating the rest of its nested
    // record, so a later rejection still reaches the zeroization `finally`.
    const unsafeProvider = capabilityObject(dataField(options, "provider"), true) as Record<
      string,
      unknown
    >;
    const unsafeCredential = dataField(unsafeProvider, "credential");
    if (!nodeTypes.isProxy(unsafeCredential) && unsafeCredential instanceof Uint8Array) {
      sourceCredential = unsafeCredential;
    }
    providerCredential = ownedBytes(unsafeCredential, 1);

    const unsafeAdapter = capabilityObject(dataField(options, "adapter"), true) as Record<
      string,
      unknown
    >;
    const unsafeOpaqueHandleKey = dataField(unsafeAdapter, "opaqueHandleKey");
    if (!nodeTypes.isProxy(unsafeOpaqueHandleKey) && unsafeOpaqueHandleKey instanceof Uint8Array) {
      sourceOpaqueHandleKey = unsafeOpaqueHandleKey;
    }
    opaqueHandleKey = ownedBytes(unsafeOpaqueHandleKey, MIN_KEY_BYTES);
    const providerRecord = exactDataRecord(unsafeProvider, PROVIDER_FIELDS);
    const adapterRecord = exactDataRecord(unsafeAdapter, ADAPTER_FIELDS);

    availability = captureMethod(dataField(options, "availability"), "publish");
    publishInitialUnavailable(availability);

    const deployment = exactDataRecord(dataField(options, "deployment"), DEPLOYMENT_FIELDS);
    const measured = snapshotMeasuredArtifacts(dataField(deployment, "measuredArtifacts"));
    const signatureVerifier = captureFunction(dataField(deployment, "signatureVerifier"));
    let verified;
    try {
      verified = verifyDaytonaDeploymentArtifacts({
        sourceEnvironment: snapshotRuntimeSupervisorPortableData(
          dataField(deployment, "sourceEnvironment")
        ) as DaytonaSourceEnvironment,
        manifest: dataField(deployment, "manifest"),
        signatureVerifier: (input) => Reflect.apply(signatureVerifier, undefined, [input]) === true,
      });
    } catch (error) {
      if (error instanceof DaytonaDeploymentArtifactError) {
        throw new HostedMultiplayerServiceError("deployment-rejected");
      }
      throw error;
    }
    assertMeasuredArtifacts(verified.manifest, measured);

    const runtimeProfile = snapshotRuntimeSupervisorPortableData(
      dataField(options, "runtimeProfile")
    ) as Extract<RuntimeDeploymentProfile, { readonly kind: "daytona" }>;
    const kernel = captureKernel(exactDataRecord(dataField(options, "kernel"), KERNEL_FIELDS));
    const trust = captureTrust(exactDataRecord(dataField(options, "trust"), TRUST_FIELDS));
    const supervisorRecord = exactDataRecord(dataField(options, "supervisor"), SUPERVISOR_FIELDS);

    const operationTimeoutMs = boundedInteger(
      dataField(adapterRecord, "operationTimeoutMs"),
      MIN_TIMEOUT_MS,
      MAX_TIMEOUT_MS
    );
    const providerConfiguration = snapshotRuntimeSupervisorPortableData(
      dataField(providerRecord, "configuration")
    ) as DaytonaHostedControlPlaneConfiguration;
    assertManifestComposition(verified.manifest, runtimeProfile, providerConfiguration);

    const ingressObject = dataField(options, "ingress");
    const ingressReceiver = capabilityObject(ingressObject);
    const ingress: CapturedIngress = Object.freeze({
      receiver: ingressReceiver,
      start: captureMethod(ingressReceiver, "start").method,
      readiness: captureMethod(ingressReceiver, "readiness").method,
      handle: captureMethod(ingressReceiver, "handle").method,
      close: captureMethod(ingressReceiver, "close").method,
    });

    const providerSupervisor = captureSupervisor(dataField(providerRecord, "supervisor"));
    const assignmentBootstrap = captureAssignmentBootstrapCoordinator(
      dataField(providerRecord, "assignmentBootstrap")
    );
    const providerTerminal = captureTerminalSupervisor(dataField(providerRecord, "terminal"));
    const filename = dataField(kernel as unknown as Record<string, unknown>, "filename");
    if (
      typeof filename !== "string" ||
      !isAbsolute(filename) ||
      filename.length > 4_096 ||
      filename.includes("\0")
    ) {
      throw new TypeError();
    }

    const workerIdPrefix = dataField(supervisorRecord, "workerIdPrefix");
    if (
      typeof workerIdPrefix !== "string" ||
      workerIdPrefix.length < 1 ||
      workerIdPrefix.length > 96 ||
      !/^[A-Za-z0-9][A-Za-z0-9._~:/-]*$/.test(workerIdPrefix)
    ) {
      throw new TypeError();
    }
    const clock = captureFunction(dataField(supervisorRecord, "clock"));
    const onOperationalError = captureFunction(dataField(supervisorRecord, "onOperationalError"));
    const fetchFunction = captureFetch(dataField(providerRecord, "fetch"));
    const verifyIsolationAttestation = captureFunction(
      dataField(providerRecord, "verifyIsolationAttestation")
    ) as DaytonaIsolationAttestationVerifier;
    const verifyCommandAuthority = captureFunction(
      dataField(providerRecord, "verifyCommandAuthority")
    ) as DaytonaCommandAuthorityVerifier;

    const captured = Object.freeze({
      manifest: verified.manifest,
      runtimeProfile,
      runtimeStatus: Object.freeze({
        kind: "daytona" as const,
        isolation: "isolated-hosted" as const,
        yoloEligible: false as const,
      }),
      kernel,
      provider: Object.freeze({
        endpoint: dataField(providerRecord, "endpoint") as string,
        organizationId: dataField(providerRecord, "organizationId") as string | null,
        credential: providerCredential,
        fetch: fetchFunction,
        configuration: providerConfiguration,
        supervisor: providerSupervisor,
        assignmentBootstrap,
        terminal: providerTerminal,
        verifyIsolationAttestation,
        verifyCommandAuthority,
      }),
      trust,
      adapter: Object.freeze({ opaqueHandleKey, operationTimeoutMs }),
      supervisor: Object.freeze({
        workerIdPrefix,
        clock: clock as () => number,
        onOperationalError: onOperationalError as (component: RuntimeSupervisorComponent) => void,
      }),
      ingress,
      availability,
    });
    return captured;
  } catch (error) {
    providerCredential?.fill(0);
    opaqueHandleKey?.fill(0);
    if (error instanceof HostedMultiplayerServiceError) throw error;
    throw new HostedMultiplayerServiceError("invalid-configuration");
  } finally {
    sourceCredential?.fill(0);
    sourceOpaqueHandleKey?.fill(0);
  }
}

function captureKernel(
  record: Record<string, unknown>
): CreateDaytonaHostedMultiplayerServiceOptions["kernel"] {
  const runtimeLifecycleCommandTtlMs = boundedInteger(
    dataField(record, "runtimeLifecycleCommandTtlMs"),
    1,
    300_000
  );
  const capturedHostedRuntimeObservationProvisioner = captureFunction(
    dataField(record, "hostedRuntimeObservationProvisioner")
  );
  const hostedRuntimeObservationProvisioner: HostedRuntimeObservationProvisioner = (request) =>
    Reflect.apply(capturedHostedRuntimeObservationProvisioner, undefined, [
      request,
    ]) as ReturnType<HostedRuntimeObservationProvisioner>;
  const runtimeCommandAuthorityIssuer = methodWrapper(
    dataField(record, "runtimeCommandAuthorityIssuer"),
    "issue"
  ) as unknown as RuntimeCommandAuthorityIssuer;
  const runtimeAuthorizationSnapshotSource = methodWrapper(
    dataField(record, "runtimeAuthorizationSnapshotSource"),
    "resolve"
  ) as RuntimeAuthorizationSnapshotSource;
  const runtimeCompensationAuthorityIssuer = methodWrapper(
    dataField(record, "runtimeCompensationAuthorityIssuer"),
    "issue"
  ) as RuntimeCompensationAuthorityIssuer;
  const runtimeCompensationPolicySource = methodWrapper(
    dataField(record, "runtimeCompensationPolicySource"),
    "resolve"
  ) as RuntimeCompensationPolicySource;
  return Object.freeze({
    filename: dataField(record, "filename") as string,
    hostedRuntimeObservationProvisioner,
    runtimeCommandAuthorityIssuer,
    runtimeAuthorizationSnapshotSource,
    runtimeEnforcementProofVerifier: captureFunction(
      dataField(record, "runtimeEnforcementProofVerifier")
    ) as SynchronousRuntimeEnforcementProofVerifier,
    runtimeLifecycleCommandTtlMs,
    runtimeCompensationAuthorityIssuer,
    runtimeCompensationAuthorityVerifier: captureFunction(
      dataField(record, "runtimeCompensationAuthorityVerifier")
    ) as RuntimeCompensationCommandAuthorityVerifier,
    runtimeCompensationPolicySource,
    runtimeCompensationEnforcementProofVerifier: captureFunction(
      dataField(record, "runtimeCompensationEnforcementProofVerifier")
    ) as SynchronousRuntimeCompensationEnforcementProofVerifier,
  });
}

function captureTrust(
  record: Record<string, unknown>
): CreateDaytonaHostedMultiplayerServiceOptions["trust"] {
  return Object.freeze({
    effectTrust: captureEffectTrust(dataField(record, "effectTrust")),
    verifyLifecycleAuthority: captureFunction(
      dataField(record, "verifyLifecycleAuthority")
    ) as RuntimeAuthorityVerifier,
    verifyLifecycleEnforcementProof: captureFunction(
      dataField(record, "verifyLifecycleEnforcementProof")
    ) as RuntimeEnforcementProofVerifier,
    verifyCompensationAuthority: captureFunction(
      dataField(record, "verifyCompensationAuthority")
    ) as RuntimeCompensationAuthorityVerifier,
    verifyCompensationEnforcementProof: captureFunction(
      dataField(record, "verifyCompensationEnforcementProof")
    ) as RuntimeCompensationEnforcementProofVerifier,
  });
}

function captureEffectTrust(value: unknown): RuntimeEffectEnforcerTrustRouter {
  const receiver = capabilityObject(value);
  const registerManifest = captureMethod(receiver, "registerManifest");
  const registerAttestations = captureMethod(receiver, "registerAttestations");
  const verifyRuntimeEnforcementProof = captureMethod(receiver, "verifyRuntimeEnforcementProof");
  const verifyRuntimeCompensationEnforcementProof = captureMethod(
    receiver,
    "verifyRuntimeCompensationEnforcementProof"
  );
  const close = captureMethod(receiver, "close");
  return Object.freeze({
    registerManifest: (...args: Parameters<RuntimeEffectEnforcerTrustRouter["registerManifest"]>) =>
      Reflect.apply(registerManifest.method, receiver, args),
    registerAttestations: (
      ...args: Parameters<RuntimeEffectEnforcerTrustRouter["registerAttestations"]>
    ) => Reflect.apply(registerAttestations.method, receiver, args),
    verifyRuntimeEnforcementProof: (
      ...args: Parameters<RuntimeEffectEnforcerTrustRouter["verifyRuntimeEnforcementProof"]>
    ) => Reflect.apply(verifyRuntimeEnforcementProof.method, receiver, args) === true,
    verifyRuntimeCompensationEnforcementProof: (
      ...args: Parameters<
        RuntimeEffectEnforcerTrustRouter["verifyRuntimeCompensationEnforcementProof"]
      >
    ) => Reflect.apply(verifyRuntimeCompensationEnforcementProof.method, receiver, args) === true,
    close: () => {
      const result = Reflect.apply(close.method, receiver, []);
      if (result !== undefined) throw new TypeError();
    },
  });
}

function captureSupervisor(value: unknown): PinnedDaytonaSupervisorTransport {
  const receiver = capabilityObject(value);
  const attestIsolation = captureMethod(receiver, "attestIsolation");
  const executeAuthenticated = captureMethod(receiver, "executeAuthenticated");
  const followSigned = captureMethod(receiver, "followSigned");
  const close = captureMethod(receiver, "close");
  return Object.freeze({
    attestIsolation: (...args: Parameters<PinnedDaytonaSupervisorTransport["attestIsolation"]>) =>
      Reflect.apply(attestIsolation.method, receiver, args),
    executeAuthenticated: (
      ...args: Parameters<PinnedDaytonaSupervisorTransport["executeAuthenticated"]>
    ) =>
      Reflect.apply(executeAuthenticated.method, receiver, args) as ReturnType<
        PinnedDaytonaSupervisorTransport["executeAuthenticated"]
      >,
    followSigned: (...args: Parameters<PinnedDaytonaSupervisorTransport["followSigned"]>) =>
      Reflect.apply(followSigned.method, receiver, args) as ReturnType<
        PinnedDaytonaSupervisorTransport["followSigned"]
      >,
    close: () =>
      Reflect.apply(close.method, receiver, []) as ReturnType<
        PinnedDaytonaSupervisorTransport["close"]
      >,
  }) as PinnedDaytonaSupervisorTransport;
}

function captureAssignmentBootstrapCoordinator(
  value: unknown
): DaytonaAssignmentBootstrapCoordinator {
  const receiver = capabilityObject(value);
  const install = captureMethod(receiver, "install");
  const activate = captureMethod(receiver, "activate");
  const resolveActivation = captureMethod(receiver, "resolveActivation");
  const resolveEffectManifest = captureMethod(receiver, "resolveEffectManifest");
  const retire = captureMethod(receiver, "retire");
  const close = captureMethod(receiver, "close");
  return Object.freeze({
    install: (...args: Parameters<DaytonaAssignmentBootstrapCoordinator["install"]>) =>
      Reflect.apply(install.method, receiver, args) as ReturnType<
        DaytonaAssignmentBootstrapCoordinator["install"]
      >,
    activate: (...args: Parameters<DaytonaAssignmentBootstrapCoordinator["activate"]>) =>
      Reflect.apply(activate.method, receiver, args) as ReturnType<
        DaytonaAssignmentBootstrapCoordinator["activate"]
      >,
    resolveActivation: (
      ...args: Parameters<DaytonaAssignmentBootstrapCoordinator["resolveActivation"]>
    ) =>
      Reflect.apply(resolveActivation.method, receiver, args) as ReturnType<
        DaytonaAssignmentBootstrapCoordinator["resolveActivation"]
      >,
    resolveEffectManifest: (
      ...args: Parameters<DaytonaAssignmentBootstrapCoordinator["resolveEffectManifest"]>
    ) =>
      Reflect.apply(resolveEffectManifest.method, receiver, args) as ReturnType<
        DaytonaAssignmentBootstrapCoordinator["resolveEffectManifest"]
      >,
    retire: (...args: Parameters<DaytonaAssignmentBootstrapCoordinator["retire"]>) =>
      Reflect.apply(retire.method, receiver, args) as ReturnType<
        DaytonaAssignmentBootstrapCoordinator["retire"]
      >,
    close: () =>
      Reflect.apply(close.method, receiver, []) as ReturnType<
        DaytonaAssignmentBootstrapCoordinator["close"]
      >,
  });
}

function captureTerminalSupervisor(value: unknown): DaytonaSupervisorPtyTransport {
  const receiver = capabilityObject(value);
  const open = captureMethod(receiver, "open");
  const close = captureMethod(receiver, "close");
  return Object.freeze({
    open: (...args: Parameters<DaytonaSupervisorPtyTransport["open"]>) =>
      Reflect.apply(open.method, receiver, args) as ReturnType<
        DaytonaSupervisorPtyTransport["open"]
      >,
    close: () =>
      Reflect.apply(close.method, receiver, []) as ReturnType<
        DaytonaSupervisorPtyTransport["close"]
      >,
  });
}

function methodWrapper(value: unknown, name: string): object {
  const captured = captureMethod(value, name);
  return Object.freeze({
    [name]: (...args: unknown[]) => Reflect.apply(captured.method, captured.receiver, args),
  });
}

function captureFetch(value: unknown): typeof fetch {
  const captured = captureFunction(value);
  return ((...args: Parameters<typeof fetch>) =>
    Reflect.apply(captured, undefined, args) as ReturnType<typeof fetch>) as typeof fetch;
}

function snapshotMeasuredArtifacts(value: unknown): MeasuredDaytonaDeploymentArtifacts {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRuntimeSupervisorDataRecord(snapshot, MEASURED_ARTIFACT_FIELDS);
  const result: Record<string, string> = {};
  for (const field of MEASURED_ARTIFACT_FIELDS) {
    const digest = runtimeSupervisorDataField(record, field);
    if (typeof digest !== "string" || !SHA256.test(digest)) throw new TypeError();
    result[field] = digest;
  }
  return Object.freeze(result) as unknown as MeasuredDaytonaDeploymentArtifacts;
}

function assertMeasuredArtifacts(
  manifest: DaytonaDeploymentArtifactManifest,
  measured: MeasuredDaytonaDeploymentArtifacts
): void {
  if (
    manifest.artifacts.sdk.sha256 !== measured.sdkSha256 ||
    manifest.artifacts.supervisor.sha256 !== measured.supervisorSha256 ||
    manifest.artifacts.sbom.sha256 !== measured.sbomSha256 ||
    manifest.artifacts.provenance.sha256 !== measured.provenanceSha256 ||
    manifest.sandboxArtifact.sha256 !== measured.sandboxSha256 ||
    manifest.isolationProfile.sha256 !== measured.isolationProfileSha256
  ) {
    throw new HostedMultiplayerServiceError("deployment-rejected");
  }
}

function assertManifestComposition(
  manifest: DaytonaDeploymentArtifactManifest,
  profile: Extract<RuntimeDeploymentProfile, { readonly kind: "daytona" }>,
  configuration: DaytonaHostedControlPlaneConfiguration
): void {
  const artifact = configuration.artifact;
  const artifactMatches =
    manifest.sandboxArtifact.kind === "daytona-snapshot" &&
    artifact.kind === "snapshot" &&
    artifact.snapshotId === manifest.sandboxArtifact.snapshotId &&
    artifact.snapshotRef === manifest.sandboxArtifact.snapshotRef &&
    artifact.imageId === manifest.sandboxArtifact.imageId &&
    artifact.contentDigest === manifest.sandboxArtifact.sha256;
  const phase7IsolationMatches =
    profile.isolation.network.mode === "blocked" &&
    profile.isolation.network.allowedDestinations.length === 0 &&
    profile.isolation.resources.pids === 256 &&
    profile.capabilities.checkpoints === false &&
    configuration.sandboxUser === "terminalx" &&
    configuration.lifecycle.autoStopIntervalMinutes === 0 &&
    configuration.lifecycle.autoArchiveIntervalMinutes === 0 &&
    configuration.lifecycle.autoDeleteIntervalMinutes === -1;
  if (
    manifest.source.forkCommit !== DAYTONA_PRODUCTION_FORK_COMMIT ||
    configuration.sourceCommit !== DAYTONA_PRODUCTION_FORK_COMMIT ||
    configuration.supervisorArtifactDigest !== manifest.artifacts.supervisor.sha256 ||
    profile.kind !== "daytona" ||
    profile.isolation.isolationPolicyDigest !== manifest.isolationProfile.sha256 ||
    !phase7IsolationMatches ||
    !artifactMatches
  ) {
    throw new HostedMultiplayerServiceError("deployment-rejected");
  }
}

function exactDataRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const record = capabilityObject(value, true) as Record<string, unknown>;
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    throw new TypeError();
  }
  for (const field of fields) dataField(record, field);
  return record as Record<string, unknown>;
}

function dataField(record: Record<string, unknown>, field: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function capabilityObject(value: unknown, plain = false): object {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  if (plain) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  }
  return value;
}

function captureFunction(value: unknown): AnyFunction {
  if (typeof value !== "function" || nodeTypes.isProxy(value)) throw new TypeError();
  return value as AnyFunction;
}

function captureMethod(value: unknown, name: string): CapturedMethod {
  const receiver = capabilityObject(value);
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) break;
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") break;
      return Object.freeze({ receiver, method: captureFunction(descriptor.value) });
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw new TypeError();
}

function ownedBytes(value: unknown, minimum: number): Uint8Array {
  if (
    typeof value !== "object" ||
    value === null ||
    nodeTypes.isProxy(value) ||
    !(value instanceof Uint8Array) ||
    value.byteLength < minimum ||
    value.byteLength > MAX_KEY_BYTES ||
    (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)
  ) {
    throw new TypeError();
  }
  return new Uint8Array(value);
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError();
  }
  return value as number;
}

function publishInitialUnavailable(capability: CapturedMethod): void {
  const result = Reflect.apply(capability.method, capability.receiver, [false, null]);
  if (result !== undefined) throw new TypeError();
}

async function requireNativeVoidPromise(value: unknown): Promise<void> {
  if (!nodeTypes.isPromise(value)) throw new TypeError();
  const result = await value;
  if (result !== undefined) throw new TypeError();
}

async function settleCaptured(
  capability: CapturedIngress,
  method: "close",
  args: readonly unknown[],
  timeoutMs: number
): Promise<boolean> {
  try {
    return await settlePromise(
      Reflect.apply(capability[method], capability.receiver, args),
      timeoutMs
    );
  } catch {
    return false;
  }
}

async function settleMethod(receiver: object, method: string, timeoutMs: number): Promise<boolean> {
  try {
    const captured = captureMethod(receiver, method);
    return await settlePromise(Reflect.apply(captured.method, captured.receiver, []), timeoutMs);
  } catch {
    return false;
  }
}

async function settlePromise(value: unknown, timeoutMs: number): Promise<boolean> {
  if (!nodeTypes.isPromise(value)) return false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<false>((resolve) => {
    timer = setTimeout(() => resolve(false), timeoutMs);
  });
  try {
    const result = await Promise.race([
      (value as Promise<unknown>).then(
        (settled) => settled === undefined,
        () => false
      ),
      timeout,
    ]);
    return result;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function settleSynchronous(capability: CapturedMethod): boolean {
  try {
    return Reflect.apply(capability.method, capability.receiver, []) === undefined;
  } catch {
    return false;
  }
}

function settleSynchronousFunction(operation: () => void): boolean {
  try {
    return Reflect.apply(operation, undefined, []) === undefined;
  } catch {
    return false;
  }
}
