import { createHash, timingSafeEqual } from "node:crypto";
import { types as nodeTypes } from "node:util";
import type { RuntimeBinding } from "../team-sessions/contracts";
import { DAYTONA_PRODUCTION_FORK_COMMIT } from "./daytona-source";
import type {
  DaytonaAssignmentBootstrapCoordinator,
  DaytonaAssignmentBootstrapInstallRequest,
} from "./daytona-assignment-bootstrap-saga";
import { commitDaytonaProviderIdentity } from "./daytona-assignment-effect-manifest";
import { snapshotHostedRuntimeActivation } from "./hosted-runtime-activation";
import { digestHostedRuntimeAssignmentPlan } from "./hosted-runtime-adapter";
import type {
  RuntimeCommand,
  RuntimeCommandReceipt,
  RuntimeCompensationCommand,
  RuntimeLifecycleCommand,
  RuntimeReceipt,
} from "./contracts";
import {
  HostedControlPlaneError,
  type HostedControlPlaneCommandRequest,
  type HostedControlPlaneCommandResult,
  type HostedControlPlaneCreateRequest,
  type HostedControlPlaneFollowRequest,
  type HostedControlPlaneMutationRequest,
  type HostedControlPlaneSandbox,
  type HostedRuntimeActivation,
  type HostedRuntimeAssignmentPlan,
  type HostedRuntimeControlPlane,
} from "./hosted-runtime-control-plane";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import {
  snapshotRuntimeCompensationReceiptForCommand,
  verifyRuntimeCompensationReceiptEnforcementProof,
} from "./runtime-compensation-execution";
import type { RuntimeCompensationEnforcementProofVerifier } from "./runtime-compensation-enforcement-proof";
import {
  snapshotRuntimeReceiptForCommand,
  verifyRuntimeReceiptEnforcementProof,
} from "./runtime-command-execution";
import type { RuntimeEnforcementProofVerifier } from "./runtime-enforcement-proof";
import type { RuntimeEffectEnforcerTrustRouter } from "./runtime-effect-enforcer-trust-router";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";

/** Exact Daytona source inspected for every REST route and model in this adapter. */
export const TERMINALX_DAYTONA_SOURCE_COMMIT = DAYTONA_PRODUCTION_FORK_COMMIT;

const SHA256 = /^[0-9a-f]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SNAPSHOT_DIGEST_REFERENCE =
  /^[a-z0-9](?:[a-z0-9._:/-]{0,253}[a-z0-9])?@sha256:([0-9a-f]{64})$/;
const DOCKER_IMAGE_ID = /^sha256:[0-9a-f]{64}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const SAFE_PROVIDER_STATE = /^[a-z][a-z_]{1,63}$/;
const SAFE_LABEL_KEY = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_LABEL_VALUE = /^[^\u0000-\u001f\u007f]{1,512}$/u;
const ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const MAX_PROVIDER_RESULTS = 16;
const MAX_LIST_PAGES = 8;
const LIST_PAGE_SIZE = 100;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_CREDENTIAL_BYTES = 4096;
const MAX_ENDPOINT_BYTES = 2048;
const MAX_INTERVAL_MINUTES = 525_600;
const MAX_POLL_INTERVAL_MS = 1_000;
const INITIAL_POLL_INTERVAL_MS = 100;
const ASSIGNMENT_BOOTSTRAP_REVISION = 1;

const ACTIVE_PROVIDER_STATES = new Set([
  "creating",
  "restoring",
  "started",
  "starting",
  "pending_build",
  "building_snapshot",
  "pulling_snapshot",
  "resuming",
]);
const IN_PROGRESS_ACTIVE_STATES = new Set([
  "creating",
  "restoring",
  "starting",
  "pending_build",
  "building_snapshot",
  "pulling_snapshot",
  "resuming",
]);

const MANAGED_LABEL = "terminalx.managed";
const PLAN_LABEL = "terminalx.plan";
const BINDING_LABEL = "terminalx.binding";
const AUTHORIZATION_LABEL = "terminalx.authorization-generation";
const INCARNATION_LABEL = "terminalx.incarnation";
const SPECIFICATION_LABEL = "terminalx.specification";
const ADAPTER_LABEL = "terminalx.adapter";
const ISOLATION_LABEL = "terminalx.isolation";
const ARTIFACT_LABEL = "terminalx.artifact";
const STATE_LABEL = "terminalx.state";
const REVISION_LABEL = "terminalx.revision";
const MUTATION_LABEL = "terminalx.mutation";

export interface DaytonaSandboxArtifact {
  readonly kind: "snapshot";
  /** Immutable UUID from the deployment-verified Daytona manifest. */
  readonly snapshotId: string;
  /** Exact immutable reference preloaded on the dedicated runner. */
  readonly snapshotRef: string;
  /** Independently pinned ID returned by Docker image inspection. */
  readonly imageId: string;
  readonly contentDigest: string;
}

export interface DaytonaSandboxLifecycleConfiguration {
  readonly autoStopIntervalMinutes: number;
  readonly autoArchiveIntervalMinutes: number;
  readonly autoDeleteIntervalMinutes: number;
}

/**
 * Deployment-owned configuration. Every field is mandatory so this module can
 * never fall back to an SDK endpoint, environment credential, target, user, or
 * lifecycle default.
 */
export interface DaytonaHostedControlPlaneConfiguration {
  readonly sourceCommit: typeof TERMINALX_DAYTONA_SOURCE_COMMIT;
  readonly target: string;
  readonly sandboxUser: string;
  readonly artifact: DaytonaSandboxArtifact;
  readonly supervisorArtifactDigest: string;
  readonly lifecycle: DaytonaSandboxLifecycleConfiguration;
}

export interface DaytonaSandboxListRequest {
  readonly labels: Readonly<Record<string, string>>;
  readonly cursor: string | null;
  readonly limit: number;
  readonly isPublic: false;
}

export interface DaytonaSandboxCreateBody {
  readonly name: string;
  readonly snapshot: string;
  readonly user: string;
  readonly env: Readonly<Record<string, string>>;
  readonly labels: Readonly<Record<string, string>>;
  readonly public: false;
  readonly target: string;
  readonly cpu: number;
  readonly memory: number;
  readonly disk: number;
  readonly autoStopInterval: number;
  readonly autoArchiveInterval: number;
  readonly autoDeleteInterval: number;
  readonly volumes: readonly [];
  readonly networkBlockAll: boolean;
  readonly networkAllowList?: string;
  readonly domainAllowList?: string;
}

/** Small generated-client-shaped port based on the b5a5d9e OpenAPI client. */
export interface DaytonaSandboxApiPort {
  listSandboxes(request: DaytonaSandboxListRequest, signal: AbortSignal): Promise<unknown>;
  createSandbox(body: DaytonaSandboxCreateBody, signal: AbortSignal): Promise<unknown>;
  getSandbox(providerSandboxId: string, signal: AbortSignal): Promise<unknown>;
  pauseSandbox(providerSandboxId: string, signal: AbortSignal): Promise<unknown>;
  replaceLabels(
    providerSandboxId: string,
    body: { readonly labels: Readonly<Record<string, string>> },
    signal: AbortSignal
  ): Promise<unknown>;
  deleteSandbox(providerSandboxId: string, signal: AbortSignal): Promise<unknown>;
  close(): Promise<void>;
}

export interface DaytonaSupervisorTrustExpectation {
  readonly supervisorArtifactDigest: string;
  readonly observationIssuerKeyId: string;
  readonly observationPublicKeyDigest: string;
  readonly requiredEffectEnforcerSetDigest: string;
}

export interface DaytonaSupervisorIsolationRequest {
  readonly providerSandboxId: string;
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly artifactDigest: string;
  readonly sandboxUser: string;
  readonly trust: Omit<DaytonaSupervisorTrustExpectation, "requiredEffectEnforcerSetDigest">;
}

export interface DaytonaSupervisorCommandRequest {
  readonly providerSandboxId: string;
  readonly operationId: string;
  readonly commandId: string;
  readonly commandDigest: string;
  readonly command: RuntimeCommand;
  readonly expectedRevision: number;
  readonly trust: DaytonaSupervisorTrustExpectation;
}

export interface DaytonaSupervisorCommandOutcome {
  readonly commandId: string;
  readonly commandDigest: string;
  readonly receipt: RuntimeCommandReceipt;
  /** Signed, public effect attestations referenced by the receipt proof. */
  readonly attestations: readonly unknown[];
  /**
   * Signed observation committed to the supervisor replay stream. The matching
   * private key stays in the pinned supervisor; the plan contains only the
   * binding-scoped public key used later by SQLite receipt-follow verification.
   */
  readonly observation: unknown;
}

export interface DaytonaSupervisorFollowItem {
  readonly observation: unknown;
  /** Exact attestations persisted with this observed receipt. */
  readonly attestations: readonly unknown[];
}

export interface DaytonaSupervisorFollowRequest {
  readonly providerSandboxId: string;
  readonly expectedRevision: number;
  readonly checkpoint: HostedControlPlaneFollowRequest["checkpoint"];
  readonly trust: Omit<DaytonaSupervisorTrustExpectation, "requiredEffectEnforcerSetDigest">;
}

/**
 * Private transport to the separately pinned TerminalX supervisor in the
 * Sandbox. Implementations must independently authenticate signed commands,
 * enforce the requested enforcer set, persist `operationId`/`commandId` plus
 * `commandDigest` idempotency (conflicting reuse fails closed), and replay the
 * returned observation after an observationally ambiguous cancellation.
 */
export interface PinnedDaytonaSupervisorTransport {
  attestIsolation(
    request: DaytonaSupervisorIsolationRequest,
    signal: AbortSignal
  ): Promise<unknown>;
  executeAuthenticated(
    request: DaytonaSupervisorCommandRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorCommandOutcome>;
  followSigned(
    request: DaytonaSupervisorFollowRequest,
    signal: AbortSignal
  ): AsyncIterable<unknown>;
  close(): Promise<void>;
}

export interface DaytonaIsolationAttestationVerificationInput {
  readonly attestation: unknown;
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly providerIdentityCommitment: string;
  readonly artifactDigest: string;
  readonly supervisorArtifactDigest: string;
  readonly observationIssuerKeyId: string;
  readonly observationPublicKeyDigest: string;
}

/** Literal true only after signature and effective-isolation verification. */
export type DaytonaIsolationAttestationVerifier = (
  input: DaytonaIsolationAttestationVerificationInput
) => boolean | Promise<boolean>;

export interface DaytonaCommandAuthorityVerificationInput {
  readonly command: RuntimeCommand;
  readonly nowMs: number;
}

/** Literal true only after checking the full signed Runtime authority. */
export type DaytonaCommandAuthorityVerifier = (
  input: DaytonaCommandAuthorityVerificationInput
) => boolean | Promise<boolean>;

export interface CreateDaytonaHostedRuntimeControlPlaneOptions {
  readonly configuration: DaytonaHostedControlPlaneConfiguration;
  readonly api: DaytonaSandboxApiPort;
  readonly supervisor: PinnedDaytonaSupervisorTransport;
  readonly assignmentBootstrap: DaytonaAssignmentBootstrapCoordinator;
  readonly effectTrust: Pick<
    RuntimeEffectEnforcerTrustRouter,
    "registerManifest" | "registerAttestations"
  >;
  readonly verifyIsolationAttestation: DaytonaIsolationAttestationVerifier;
  readonly verifyCommandAuthority: DaytonaCommandAuthorityVerifier;
  readonly verifyLifecycleEnforcementProof: RuntimeEnforcementProofVerifier;
  readonly verifyCompensationEnforcementProof: RuntimeCompensationEnforcementProofVerifier;
  readonly clock: () => number;
}

export interface CreatePinnedDaytonaFetchApiOptions {
  /** Explicit base URL, such as `https://app.daytona.io/api`; there is no default. */
  readonly endpoint: string;
  /** Explicit organization scope. API-key deployments may deliberately pass null. */
  readonly organizationId: string | null;
  /** Ownership transfers to the adapter; both the input and captured copy are zeroed. */
  readonly credential: Uint8Array;
  /** Explicit transport; global fetch is intentionally not consulted. */
  readonly fetch: typeof fetch;
}

interface CapturedApi {
  readonly receiver: object;
  readonly listSandboxes: AnyFunction;
  readonly createSandbox: AnyFunction;
  readonly getSandbox: AnyFunction;
  readonly pauseSandbox: AnyFunction;
  readonly replaceLabels: AnyFunction;
  readonly deleteSandbox: AnyFunction;
  readonly close: AnyFunction;
}

interface CapturedSupervisor {
  readonly receiver: object;
  readonly attestIsolation: AnyFunction;
  readonly executeAuthenticated: AnyFunction;
  readonly followSigned: AnyFunction;
  readonly close: AnyFunction;
}

interface CapturedAssignmentBootstrap {
  readonly receiver: object;
  readonly install: AnyFunction;
  readonly activate: AnyFunction;
  readonly retire: AnyFunction;
  readonly resolveActivation: AnyFunction;
  readonly resolveEffectManifest: AnyFunction;
  readonly close: AnyFunction;
}

interface CapturedEffectTrust {
  readonly receiver: object;
  readonly registerManifest: AnyFunction;
  readonly registerAttestations: AnyFunction;
}

interface CapturedVerifiers {
  readonly isolation: DaytonaIsolationAttestationVerifier;
  readonly authority: DaytonaCommandAuthorityVerifier;
  readonly lifecycleProof: RuntimeEnforcementProofVerifier;
  readonly compensationProof: RuntimeCompensationEnforcementProofVerifier;
}

interface CapturedConstructionOptions {
  readonly configuration: DaytonaHostedControlPlaneConfiguration;
  readonly api: unknown;
  readonly supervisor: unknown;
  readonly assignmentBootstrap: unknown;
  readonly effectTrust: unknown;
  readonly verifyIsolationAttestation: unknown;
  readonly verifyCommandAuthority: unknown;
  readonly verifyLifecycleEnforcementProof: unknown;
  readonly verifyCompensationEnforcementProof: unknown;
  readonly clock: unknown;
}

interface ValidatedProviderSandbox {
  readonly id: string;
  readonly labels: Readonly<Record<string, string>>;
  readonly state: string;
  readonly desiredState: string | null;
  readonly snapshot: string | null;
  readonly user: string;
  readonly public: false;
  readonly networkBlockAll: boolean;
  readonly networkAllowList: string | null;
  readonly domainAllowList: string | null;
  readonly target: string;
  readonly cpu: number;
  readonly memory: number;
  readonly disk: number;
  readonly volumes: readonly unknown[];
  readonly linkedSandboxId: string | null;
  readonly buildInfo: Readonly<Record<string, unknown>> | null;
}

type AnyFunction = (...args: never[]) => unknown;
type HostedErrorCode = ConstructorParameters<typeof HostedControlPlaneError>[0];

/** Construct the provider-neutral private port over an injected Daytona API. */
export function createDaytonaHostedRuntimeControlPlane(
  unsafeOptions: CreateDaytonaHostedRuntimeControlPlaneOptions
): HostedRuntimeControlPlane {
  return new DaytonaHostedRuntimeControlPlane(unsafeOptions);
}

/**
 * Minimal fetch adapter for the exact generated routes in b5a5d9e:
 * `/sandbox`, `/sandbox/{id}`, `/pause`, and `/labels`.
 */
export function createPinnedDaytonaFetchApi(
  unsafeOptions: CreatePinnedDaytonaFetchApiOptions
): DaytonaSandboxApiPort {
  return new PinnedDaytonaFetchApi(unsafeOptions);
}

class DaytonaHostedRuntimeControlPlane implements HostedRuntimeControlPlane {
  private readonly configuration: DaytonaHostedControlPlaneConfiguration;
  private readonly api: CapturedApi;
  private readonly supervisor: CapturedSupervisor;
  private readonly assignmentBootstrap: CapturedAssignmentBootstrap;
  private readonly effectTrust: CapturedEffectTrust;
  private readonly verifiers: CapturedVerifiers;
  private readonly clock: () => number;
  private readonly shutdown = new AbortController();
  private closePromise: Promise<void> | null = null;
  private closed = false;

  constructor(unsafeOptions: CreateDaytonaHostedRuntimeControlPlaneOptions) {
    const options = snapshotOptions(unsafeOptions);
    this.configuration = options.configuration;
    this.api = captureApi(options.api);
    this.supervisor = captureSupervisor(options.supervisor);
    this.assignmentBootstrap = captureAssignmentBootstrap(options.assignmentBootstrap);
    this.effectTrust = captureEffectTrust(options.effectTrust);
    this.verifiers = captureVerifiers(options);
    this.clock = captureClock(options.clock);
  }

  async listExact(
    unsafePlan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<readonly HostedControlPlaneSandbox[]> {
    const plan = snapshotPlan(unsafePlan);
    this.assertAvailable(signal);
    const matches = await this.listProviderMatches(plan, signal);
    const result: HostedControlPlaneSandbox[] = [];
    for (const match of matches) {
      validateObservedProviderLifecycle(match);
      result.push(projectSandbox(match, plan, this.activationFor(match, plan)));
    }
    return Object.freeze(result);
  }

  async create(
    unsafeRequest: HostedControlPlaneCreateRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneSandbox> {
    const request = snapshotCreateRequest(unsafeRequest);
    this.assertAvailable(signal);
    const existing = await this.listProviderMatches(request.plan, signal);
    if (existing.length > 1) fail("conflict");
    if (existing.length === 1) {
      const ready = await this.normalizeListedProviderState(existing[0]!, request.plan, signal);
      if (ready.labels[STATE_LABEL] === "fenced") {
        return projectSandbox(ready, request.plan, this.activationFor(ready, request.plan));
      }
      if (ready.state !== "started") fail("conflict");
      await this.bootstrapAndAttest(ready, request.plan, signal);
      if (ready.labels[STATE_LABEL] === "active") {
        return projectSandbox(ready, request.plan, this.activationFor(ready, request.plan));
      }
      const activeLabels = withLifecycleState(ready.labels, "active");
      await this.replaceAndValidateLabels(ready.id, activeLabels, signal);
      const active = await this.getExact(ready.id, request.plan, activeLabels, signal);
      return projectSandbox(active, request.plan, this.activationFor(active, request.plan));
    }

    // Provider-private provisioning state cannot project as an active Runtime
    // until the signed effective-isolation attestation succeeds.
    const labels = labelsFor(
      request.plan,
      this.configuration,
      "provisioning",
      1,
      request.operationId
    );
    const body = createBody(request.plan, this.configuration, labels);
    let created: unknown;
    try {
      created = await invoke(this.api, "createSandbox", [
        body,
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    const provider = validateProviderSandbox(created, request.plan, this.configuration, labels);
    const ready = await this.waitForState(provider.id, request.plan, labels, "started", signal);
    await this.bootstrapAndAttest(ready, request.plan, signal);
    const activeLabels = withLifecycleState(labels, "active");
    await this.replaceAndValidateLabels(ready.id, activeLabels, signal);
    const active = await this.getExact(ready.id, request.plan, activeLabels, signal);
    return projectSandbox(active, request.plan, this.activationFor(active, request.plan));
  }

  async fence(
    unsafeRequest: HostedControlPlaneMutationRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneSandbox> {
    const request = snapshotMutationRequest(unsafeRequest);
    this.assertAvailable(signal);
    let current = await this.getExact(
      request.expected.providerSandboxId,
      request.plan,
      undefined,
      signal
    );
    const currentActivation = this.activationFor(current, request.plan);
    if (isCompletedFenceReplay(current, request, currentActivation)) {
      return projectSandbox(current, request.plan, currentActivation);
    }
    assertExpected(current, request.expected, request.plan, currentActivation);
    if (current.labels[STATE_LABEL] === "fenced") {
      return projectSandbox(current, request.plan, currentActivation);
    }
    const nextRevision = request.expected.revision + 1;
    const labels = labelsFor(
      request.plan,
      this.configuration,
      "fenced",
      nextRevision,
      request.operationId
    );

    if (current.state !== "paused") {
      if (current.state !== "pausing") {
        try {
          const response = await invoke(this.api, "pauseSandbox", [
            current.id,
            linkedSignal(signal, this.shutdown.signal),
          ]);
          if (response !== undefined) {
            validateProviderSandbox(response, request.plan, this.configuration, current.labels);
          }
        } catch (error) {
          throw normalizeError(error, signal);
        }
      }
      current = await this.waitForState(current.id, request.plan, current.labels, "paused", signal);
    }

    let replaced: unknown;
    try {
      replaced = await invoke(this.api, "replaceLabels", [
        current.id,
        Object.freeze({ labels }),
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    validateReplaceLabelsResponse(replaced, labels);
    const fenced = await this.getExact(current.id, request.plan, labels, signal);
    if (fenced.state !== "paused") fail("conflict");
    return projectSandbox(fenced, request.plan, this.activationFor(fenced, request.plan));
  }

  async retire(
    unsafeRequest: HostedControlPlaneMutationRequest,
    signal: AbortSignal
  ): Promise<void> {
    const request = snapshotMutationRequest(unsafeRequest);
    this.assertAvailable(signal);
    const matches = await this.listProviderMatches(request.plan, signal);
    const bootstrapRequest = assignmentBootstrapRequest(
      request.expected.providerSandboxId,
      request.plan,
      this.configuration
    );
    if (matches.length === 0) {
      await this.retireBootstrapIntent(bootstrapRequest);
      return;
    }
    if (matches.length !== 1) fail("conflict");
    const current = matches[0]!;
    assertExpected(
      current,
      request.expected,
      request.plan,
      this.activationFor(current, request.plan)
    );
    try {
      await invoke(this.api, "deleteSandbox", [
        current.id,
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    await this.waitForDeleted(current.id, request.plan, signal);
    await this.retireBootstrapIntent(bootstrapRequest);
  }

  async command(
    unsafeRequest: HostedControlPlaneCommandRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneCommandResult> {
    const request = snapshotCommandRequest(unsafeRequest);
    this.assertAvailable(signal);
    const current = await this.requireExpected(request, signal);
    if (current.labels[STATE_LABEL] !== "active" || current.state !== "started") fail("conflict");
    await this.verifyEffectiveIsolation(current, request.plan, signal);

    const requiredEffectEnforcerSetDigest = requiredEnforcerDigest(
      request.command,
      request.expected
    );
    await this.verifyCommandAuthority(request.command, signal);
    const trust = supervisorTrust(
      request.plan,
      this.configuration,
      requiredEffectEnforcerSetDigest
    );
    let unsafeOutcome: unknown;
    try {
      unsafeOutcome = await invoke(this.supervisor, "executeAuthenticated", [
        Object.freeze({
          providerSandboxId: current.id,
          operationId: request.operationId,
          commandId: request.commandId,
          commandDigest: request.commandDigest,
          command: request.command,
          expectedRevision: request.expected.revision,
          trust,
        } satisfies DaytonaSupervisorCommandRequest),
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    if (signal.aborted || this.shutdown.signal.aborted) fail("timeout");
    const outcome = await this.snapshotAndVerifyCommandOutcome(
      unsafeOutcome,
      request,
      current.id,
      signal
    );
    return Object.freeze({
      commandId: outcome.commandId,
      commandDigest: outcome.commandDigest,
      receipt: outcome.receipt,
    });
  }

  follow(
    unsafeRequest: HostedControlPlaneFollowRequest,
    signal: AbortSignal
  ): AsyncIterable<unknown> {
    return Object.freeze({
      [Symbol.asyncIterator]: (): AsyncGenerator<unknown> =>
        this.followIterator(unsafeRequest, signal),
    });
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.shutdown.abort();
    this.closePromise = (async () => {
      const outcomes = await Promise.allSettled([
        Promise.resolve().then(() => invoke(this.assignmentBootstrap, "close", [])),
        Promise.resolve().then(() => invoke(this.supervisor, "close", [])),
        Promise.resolve().then(() => invoke(this.api, "close", [])),
      ]);
      if (outcomes.some((outcome) => outcome.status === "rejected")) fail("internal");
    })();
    return this.closePromise;
  }

  private async *followIterator(
    unsafeRequest: HostedControlPlaneFollowRequest,
    signal: AbortSignal
  ): AsyncGenerator<unknown> {
    const request = snapshotFollowRequest(unsafeRequest);
    this.assertAvailable(signal);
    const current = await this.requireExpected(
      {
        operationId: "hosted-follow",
        plan: request.plan,
        expected: request.expected,
      },
      signal
    );
    const activation = this.activationFor(current, request.plan);
    if (!activation) fail("conflict");
    if (current.labels[STATE_LABEL] !== "active" || current.state !== "started") fail("conflict");
    const trust = supervisorTrustWithoutEnforcers(request.plan, this.configuration);
    let iterable: unknown;
    try {
      iterable = invoke(this.supervisor, "followSigned", [
        Object.freeze({
          providerSandboxId: current.id,
          expectedRevision: request.expected.revision,
          checkpoint: request.checkpoint,
          trust,
        } satisfies DaytonaSupervisorFollowRequest),
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    if (!isAsyncIterable(iterable)) fail("invalid-state");
    try {
      for await (const unsafeObservation of iterable) {
        this.assertAvailable(signal);
        const replay = exactRecord(snapshotPortable(unsafeObservation), [
          "observation",
          "attestations",
        ]);
        this.registerEffectAttestations(
          activation.effectEnforcerSetDigest,
          field(replay, "attestations")
        );
        yield snapshotSignedObservation(
          field(replay, "observation"),
          request.plan,
          current.id,
          undefined
        );
      }
    } catch (error) {
      throw normalizeError(error, signal);
    }
  }

  private async listProviderMatches(
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<readonly ValidatedProviderSandbox[]> {
    const identity = identityLabels(plan, this.configuration);
    const items: unknown[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
      let response: unknown;
      try {
        response = await invoke(this.api, "listSandboxes", [
          Object.freeze({ labels: identity, cursor, limit: LIST_PAGE_SIZE, isPublic: false }),
          linkedSignal(signal, this.shutdown.signal),
        ]);
      } catch (error) {
        throw normalizeError(error, signal);
      }
      const parsed = snapshotListResponse(response);
      items.push(...parsed.items);
      if (items.length > MAX_PROVIDER_RESULTS) fail("conflict");
      cursor = parsed.nextCursor;
      if (cursor === null) break;
      if (page === MAX_LIST_PAGES - 1) fail("invalid-state");
    }
    const result: ValidatedProviderSandbox[] = [];
    for (const item of items) {
      const itemRecord = record(item);
      const id = safeReference(field(itemRecord, "id"));
      const detail = await this.getExact(id, plan, undefined, signal);
      assertIdentityLabels(detail.labels, identity);
      result.push(detail);
    }
    const providerIds = new Set(result.map((entry) => entry.id));
    if (providerIds.size !== result.length) fail("conflict");
    return Object.freeze(result);
  }

  private async normalizeListedProviderState(
    provider: ValidatedProviderSandbox,
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<ValidatedProviderSandbox> {
    const lifecycleState = provider.labels[STATE_LABEL];
    if (lifecycleState === "provisioning") {
      return provider.state === "started"
        ? provider
        : await this.waitForState(provider.id, plan, provider.labels, "started", signal);
    }
    if (lifecycleState === "fenced") {
      if (provider.state === "paused") return provider;
      return this.waitForState(provider.id, plan, provider.labels, "paused", signal);
    }
    if (lifecycleState !== "active") fail("invalid-state");
    // A paused/pausing Sandbox with active labels is an ambiguous fence whose
    // label write did not complete. Returning revision N lets the same exact
    // fence operation finish it without creating or resuming anything.
    if (provider.state === "paused" || provider.state === "pausing") return provider;
    if (provider.state === "started") return provider;
    if (!IN_PROGRESS_ACTIVE_STATES.has(provider.state)) fail("invalid-state");
    return this.waitForState(provider.id, plan, provider.labels, "started", signal);
  }

  private async getExact(
    providerSandboxId: string,
    plan: HostedRuntimeAssignmentPlan,
    expectedLabels: Readonly<Record<string, string>> | undefined,
    signal: AbortSignal
  ): Promise<ValidatedProviderSandbox> {
    let response: unknown;
    try {
      response = await invoke(this.api, "getSandbox", [
        safeReference(providerSandboxId),
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    return validateProviderSandbox(response, plan, this.configuration, expectedLabels);
  }

  private async waitForState(
    providerSandboxId: string,
    plan: HostedRuntimeAssignmentPlan,
    expectedLabels: Readonly<Record<string, string>>,
    desiredState: "started" | "paused",
    signal: AbortSignal
  ): Promise<ValidatedProviderSandbox> {
    let interval = INITIAL_POLL_INTERVAL_MS;
    while (true) {
      this.assertAvailable(signal);
      const current = await this.getExact(providerSandboxId, plan, expectedLabels, signal);
      if (current.state === desiredState) return current;
      const allowed =
        desiredState === "started"
          ? ACTIVE_PROVIDER_STATES.has(current.state)
          : current.state === "pausing";
      if (!allowed) fail("invalid-state");
      await abortableDelay(interval, linkedSignal(signal, this.shutdown.signal));
      interval = Math.min(Math.ceil(interval * 1.5), MAX_POLL_INTERVAL_MS);
    }
  }

  private async waitForDeleted(
    providerSandboxId: string,
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<void> {
    let interval = INITIAL_POLL_INTERVAL_MS;
    while (true) {
      this.assertAvailable(signal);
      const matches = await this.listProviderMatches(plan, signal);
      if (matches.length === 0) return;
      if (matches.length !== 1 || matches[0]!.id !== providerSandboxId) fail("conflict");
      await abortableDelay(interval, linkedSignal(signal, this.shutdown.signal));
      interval = Math.min(Math.ceil(interval * 1.5), MAX_POLL_INTERVAL_MS);
    }
  }

  private async requireExpected(
    request: HostedControlPlaneMutationRequest,
    signal: AbortSignal
  ): Promise<ValidatedProviderSandbox> {
    const current = await this.getExact(
      request.expected.providerSandboxId,
      request.plan,
      undefined,
      signal
    );
    assertExpected(
      current,
      request.expected,
      request.plan,
      this.activationFor(current, request.plan)
    );
    return current;
  }

  private async replaceAndValidateLabels(
    providerSandboxId: string,
    labels: Readonly<Record<string, string>>,
    signal: AbortSignal
  ): Promise<void> {
    let response: unknown;
    try {
      response = await invoke(this.api, "replaceLabels", [
        providerSandboxId,
        Object.freeze({ labels }),
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    validateReplaceLabelsResponse(response, labels);
  }

  private async verifyEffectiveIsolation(
    sandbox: ValidatedProviderSandbox,
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<void> {
    if (sandbox.labels[STATE_LABEL] === "fenced") return;
    const trust = supervisorTrustWithoutEnforcers(plan, this.configuration);
    let attestation: unknown;
    try {
      attestation = await invoke(this.supervisor, "attestIsolation", [
        Object.freeze({
          providerSandboxId: sandbox.id,
          plan,
          artifactDigest: artifactDigest(this.configuration.artifact),
          sandboxUser: this.configuration.sandboxUser,
          trust,
        } satisfies DaytonaSupervisorIsolationRequest),
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    const snapshot = snapshotPortable(attestation);
    let verified: unknown;
    try {
      verified = await this.verifiers.isolation(
        Object.freeze({
          attestation: snapshot,
          plan,
          providerIdentityCommitment: providerIdentityCommitment(sandbox.id),
          artifactDigest: artifactDigest(this.configuration.artifact),
          supervisorArtifactDigest: this.configuration.supervisorArtifactDigest,
          observationIssuerKeyId: plan.observation.issuerKeyId,
          observationPublicKeyDigest: observationPublicKeyDigest(plan),
        })
      );
    } catch {
      fail("invalid-state");
    }
    if (verified !== true || signal.aborted || this.shutdown.signal.aborted) fail("invalid-state");
  }

  private async bootstrapAndAttest(
    sandbox: ValidatedProviderSandbox,
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<void> {
    const request = assignmentBootstrapRequest(sandbox.id, plan, this.configuration);
    let installed: unknown;
    try {
      installed = await invoke(this.assignmentBootstrap, "install", [
        request,
        linkedSignal(signal, this.shutdown.signal),
      ]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
    await this.verifyEffectiveIsolation(sandbox, plan, signal);
    try {
      await invoke(this.assignmentBootstrap, "activate", [request, installed]);
    } catch (error) {
      throw normalizeError(error, signal);
    }
  }

  private activationFor(
    sandbox: ValidatedProviderSandbox,
    plan: HostedRuntimeAssignmentPlan
  ): HostedRuntimeActivation | null {
    const state = internalLifecycleState(sandbox.labels[STATE_LABEL]);
    if (state === "provisioning") return null;
    const request = assignmentBootstrapRequest(sandbox.id, plan, this.configuration);
    let unsafeActivation: unknown;
    try {
      unsafeActivation = Reflect.apply(
        this.assignmentBootstrap.resolveActivation,
        this.assignmentBootstrap.receiver,
        [request]
      );
    } catch {
      fail("invalid-state");
    }
    const activation = snapshotHostedRuntimeActivation(unsafeActivation);
    if (
      canonicalRuntimeJson(activation.binding) !== canonicalRuntimeJson(plan.binding) ||
      activation.runtimeAuthorizationGeneration !== plan.runtimeAuthorizationGeneration ||
      !sameDigest(activation.assignmentPlanDigest, digestHostedRuntimeAssignmentPlan(plan)) ||
      !sameDigest(activation.effectEnforcerPolicyDigest, plan.effectEnforcerPolicyDigest) ||
      !sameDigest(
        activation.providerIdentityCommitment,
        commitDaytonaProviderIdentity(sandbox.id)
      ) ||
      activation.providerRevision !== ASSIGNMENT_BOOTSTRAP_REVISION
    ) {
      fail("conflict");
    }
    let effectRecord: unknown;
    try {
      effectRecord = Reflect.apply(
        this.assignmentBootstrap.resolveEffectManifest,
        this.assignmentBootstrap.receiver,
        [request]
      );
      Reflect.apply(this.effectTrust.registerManifest, this.effectTrust.receiver, [effectRecord]);
    } catch {
      fail("invalid-state");
    }
    return activation;
  }

  private registerEffectAttestations(effectEnforcerSetDigest: string, value: unknown): void {
    const attestations = snapshotAttestationBatch(value);
    try {
      Reflect.apply(this.effectTrust.registerAttestations, this.effectTrust.receiver, [
        Object.freeze({ effectEnforcerSetDigest, attestations }),
      ]);
    } catch {
      fail("invalid-state");
    }
  }

  private async retireBootstrapIntent(
    request: DaytonaAssignmentBootstrapInstallRequest
  ): Promise<void> {
    try {
      await invoke(this.assignmentBootstrap, "retire", [request]);
    } catch (error) {
      throw normalizeError(error, this.shutdown.signal);
    }
  }

  private async verifyCommandAuthority(
    command: RuntimeCommand,
    signal: AbortSignal
  ): Promise<void> {
    const nowMs = sampleClock(this.clock);
    let verified: unknown;
    try {
      verified = await this.verifiers.authority(Object.freeze({ command, nowMs }));
    } catch {
      fail("permission-denied");
    }
    if (verified !== true) fail("permission-denied");
    const after = sampleClock(this.clock);
    if (after < nowMs || signal.aborted || this.shutdown.signal.aborted) fail("timeout");
    if (after >= command.deadlineAtMs || after >= command.authority.expiresAtMs) {
      fail("permission-denied");
    }
  }

  private async snapshotAndVerifyCommandOutcome(
    unsafeOutcome: unknown,
    request: HostedControlPlaneCommandRequest,
    providerSandboxId: string,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorCommandOutcome> {
    const outcome = exactRecord(snapshotPortable(unsafeOutcome), [
      "commandId",
      "commandDigest",
      "receipt",
      "observation",
      "attestations",
    ]);
    if (
      !sameText(field(outcome, "commandId"), request.commandId) ||
      !sameDigest(field(outcome, "commandDigest"), request.commandDigest)
    ) {
      fail("conflict");
    }
    const activation = request.expected.activation;
    if (!activation) fail("conflict");
    this.registerEffectAttestations(
      activation.effectEnforcerSetDigest,
      field(outcome, "attestations")
    );
    const receipt = await verifyEnforcedReceipt(
      field(outcome, "receipt"),
      request.command,
      this.verifiers
    );
    const observation = snapshotSignedObservation(
      field(outcome, "observation"),
      request.plan,
      providerSandboxId,
      request.commandId,
      isCompensationCommand(request.command)
        ? "runtime.compensation-receipt-observed"
        : "runtime.lifecycle-receipt-observed"
    );
    if (containsProviderIdentifier(receipt, providerSandboxId)) fail("invalid-state");
    if (signal.aborted || this.shutdown.signal.aborted) fail("timeout");
    return Object.freeze({
      commandId: request.commandId,
      commandDigest: request.commandDigest,
      receipt,
      observation,
      attestations: snapshotAttestationBatch(field(outcome, "attestations")),
    });
  }

  private assertAvailable(signal: AbortSignal): void {
    if (!isNativeAbortSignal(signal)) fail("invalid-state");
    if (this.closed || this.shutdown.signal.aborted) fail("unavailable");
    if (signal.aborted) fail("timeout");
  }
}

function validateObservedProviderLifecycle(provider: ValidatedProviderSandbox): void {
  const lifecycle = internalLifecycleState(provider.labels[STATE_LABEL]);
  if (lifecycle === "provisioning") {
    if (!ACTIVE_PROVIDER_STATES.has(provider.state)) fail("invalid-state");
    return;
  }
  if (lifecycle === "active") {
    if (
      provider.state !== "started" &&
      provider.state !== "paused" &&
      provider.state !== "pausing" &&
      !IN_PROGRESS_ACTIVE_STATES.has(provider.state)
    ) {
      fail("invalid-state");
    }
    return;
  }
  if (provider.state !== "paused" && provider.state !== "pausing") fail("invalid-state");
}

class PinnedDaytonaFetchApi implements DaytonaSandboxApiPort {
  private readonly endpoint: string;
  private readonly organizationId: string | null;
  private readonly credential: Uint8Array;
  private readonly sourceCredential: Uint8Array;
  private readonly fetchFunction: typeof fetch;
  private readonly shutdown = new AbortController();
  private closed = false;
  private closePromise: Promise<void> | null = null;

  constructor(unsafeOptions: CreatePinnedDaytonaFetchApiOptions) {
    if (
      typeof unsafeOptions !== "object" ||
      unsafeOptions === null ||
      nodeTypes.isProxy(unsafeOptions)
    ) {
      fail("invalid-state");
    }
    this.endpoint = endpoint(unsafeOptions.endpoint);
    this.organizationId =
      unsafeOptions.organizationId === null ? null : safeReference(unsafeOptions.organizationId);
    if (
      !(unsafeOptions.credential instanceof Uint8Array) ||
      unsafeOptions.credential.byteLength < 1 ||
      unsafeOptions.credential.byteLength > MAX_CREDENTIAL_BYTES
    ) {
      fail("invalid-state");
    }
    this.sourceCredential = unsafeOptions.credential;
    this.credential = new Uint8Array(unsafeOptions.credential);
    validateCredential(this.credential);
    if (typeof unsafeOptions.fetch !== "function") fail("invalid-state");
    this.fetchFunction = unsafeOptions.fetch;
  }

  listSandboxes(request: DaytonaSandboxListRequest, signal: AbortSignal): Promise<unknown> {
    const labels = snapshotLabels(request.labels);
    const url = this.route("sandbox");
    url.searchParams.set("labels", JSON.stringify(labels));
    url.searchParams.set("limit", String(boundedInteger(request.limit, 1, LIST_PAGE_SIZE)));
    url.searchParams.set("isPublic", request.isPublic === false ? "false" : invalidState());
    if (request.cursor !== null) url.searchParams.set("cursor", safeReference(request.cursor));
    return this.request(url, { method: "GET" }, signal);
  }

  createSandbox(body: DaytonaSandboxCreateBody, signal: AbortSignal): Promise<unknown> {
    return this.jsonRequest(this.route("sandbox"), "POST", body, signal);
  }

  getSandbox(providerSandboxId: string, signal: AbortSignal): Promise<unknown> {
    return this.request(this.route("sandbox", providerSandboxId), { method: "GET" }, signal);
  }

  pauseSandbox(providerSandboxId: string, signal: AbortSignal): Promise<unknown> {
    return this.request(
      this.route("sandbox", providerSandboxId, "pause"),
      { method: "POST" },
      signal
    );
  }

  replaceLabels(
    providerSandboxId: string,
    body: { readonly labels: Readonly<Record<string, string>> },
    signal: AbortSignal
  ): Promise<unknown> {
    return this.jsonRequest(
      this.route("sandbox", providerSandboxId, "labels"),
      "PUT",
      Object.freeze({ labels: snapshotLabels(body.labels) }),
      signal
    );
  }

  deleteSandbox(providerSandboxId: string, signal: AbortSignal): Promise<unknown> {
    return this.request(this.route("sandbox", providerSandboxId), { method: "DELETE" }, signal);
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.shutdown.abort();
    this.credential.fill(0);
    this.sourceCredential.fill(0);
    this.closePromise = Promise.resolve();
    return this.closePromise;
  }

  private jsonRequest(
    url: URL,
    method: "POST" | "PUT",
    body: unknown,
    signal: AbortSignal
  ): Promise<unknown> {
    return this.request(
      url,
      { method, headers: { "content-type": "application/json" }, body: canonicalRuntimeJson(body) },
      signal
    );
  }

  private async request(url: URL, init: RequestInit, signal: AbortSignal): Promise<unknown> {
    if (this.closed) fail("unavailable");
    if (!isNativeAbortSignal(signal)) fail("invalid-state");
    if (signal.aborted) fail("timeout");
    const controller = linkedController(signal, this.shutdown.signal);
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json");
    headers.set("authorization", `Bearer ${decodeCredential(this.credential)}`);
    if (this.organizationId !== null) {
      headers.set("x-daytona-organization-id", this.organizationId);
    }
    try {
      const response = await Reflect.apply(this.fetchFunction, undefined, [
        url,
        {
          ...init,
          headers,
          signal: controller.signal,
          // Never forward the bearer credential through a provider-controlled
          // redirect. The deployment endpoint is an exact trust boundary.
          redirect: "error",
        },
      ]);
      if (!(response instanceof Response)) fail("invalid-state");
      if (!response.ok) fail(mapHttpStatus(response.status));
      if (response.status === 204 || response.headers.get("content-length") === "0") {
        return undefined;
      }
      const contentType = response.headers.get("content-type") ?? "";
      if (!/^application\/json(?:\s*;|$)/i.test(contentType)) fail("invalid-state");
      return await readBoundedJson(response, controller.signal);
    } catch (error) {
      throw normalizeError(error, controller.signal);
    } finally {
      controller.abort();
    }
  }

  private route(...segments: string[]): URL {
    const url = new URL(this.endpoint);
    const base = url.pathname.endsWith("/") ? url.pathname.slice(0, -1) : url.pathname;
    url.pathname = `${base}/${segments.map((segment) => encodeURIComponent(safeReference(segment))).join("/")}`;
    return url;
  }
}

async function verifyEnforcedReceipt(
  value: unknown,
  command: RuntimeCommand,
  verifiers: CapturedVerifiers
): Promise<RuntimeCommandReceipt> {
  if (isCompensationCommand(command)) {
    let receipt;
    try {
      receipt = snapshotRuntimeCompensationReceiptForCommand(value, command);
      requirePositiveEnforcedOutcome(receipt);
      await verifyRuntimeCompensationReceiptEnforcementProof(
        command,
        receipt,
        verifiers.compensationProof
      );
    } catch {
      fail("invalid-state");
    }
    return receipt;
  }
  if (!isLifecycleCommand(command)) fail("invalid-state");
  let receipt: RuntimeReceipt;
  try {
    receipt = snapshotRuntimeReceiptForCommand(value as RuntimeReceipt, command);
    requirePositiveEnforcedOutcome(receipt);
    await verifyRuntimeReceiptEnforcementProof(command, receipt, verifiers.lifecycleProof);
  } catch {
    fail("invalid-state");
  }
  return receipt;
}

function requirePositiveEnforcedOutcome(receipt: RuntimeCommandReceipt): void {
  const effective = receipt.outcome === "duplicate" ? receipt.originalReceipt : receipt;
  if (effective.outcome === "accepted") fail("invalid-state");
  if (effective.outcome === "enforced" && !effective.aggregateEnforcementProof) {
    fail("invalid-state");
  }
}

function requiredEnforcerDigest(
  command: RuntimeCommand,
  expected: HostedControlPlaneSandbox
): string {
  const activation = expected.activation;
  if (!activation || expected.state === "provisioning") fail("permission-denied");
  const required = activation.effectEnforcerSetDigest;
  if (isCompensationCommand(command)) {
    if (!sameDigest(command.requiredContainmentEnforcerSetDigest, required)) {
      fail("permission-denied");
    }
    return command.requiredContainmentEnforcerSetDigest;
  }
  if (!isLifecycleCommand(command)) fail("invalid-state");
  if (
    !command.requiredEffectEnforcerSetDigest ||
    !sameDigest(command.requiredEffectEnforcerSetDigest, required)
  ) {
    fail("permission-denied");
  }
  return command.requiredEffectEnforcerSetDigest;
}

function snapshotOptions(unsafeOptions: unknown): CapturedConstructionOptions {
  const options = exactRawRecord(unsafeOptions, [
    "configuration",
    "api",
    "supervisor",
    "assignmentBootstrap",
    "effectTrust",
    "verifyIsolationAttestation",
    "verifyCommandAuthority",
    "verifyLifecycleEnforcementProof",
    "verifyCompensationEnforcementProof",
    "clock",
  ]);
  return Object.freeze({
    configuration: snapshotConfiguration(field(options, "configuration")),
    api: field(options, "api"),
    supervisor: field(options, "supervisor"),
    assignmentBootstrap: field(options, "assignmentBootstrap"),
    effectTrust: field(options, "effectTrust"),
    verifyIsolationAttestation: field(options, "verifyIsolationAttestation"),
    verifyCommandAuthority: field(options, "verifyCommandAuthority"),
    verifyLifecycleEnforcementProof: field(options, "verifyLifecycleEnforcementProof"),
    verifyCompensationEnforcementProof: field(options, "verifyCompensationEnforcementProof"),
    clock: field(options, "clock"),
  });
}

function snapshotConfiguration(value: unknown): DaytonaHostedControlPlaneConfiguration {
  const configuration = exactRecord(snapshotPortable(value), [
    "sourceCommit",
    "target",
    "sandboxUser",
    "artifact",
    "supervisorArtifactDigest",
    "lifecycle",
  ]);
  if (field(configuration, "sourceCommit") !== TERMINALX_DAYTONA_SOURCE_COMMIT) {
    fail("invalid-state");
  }
  const sandboxUser = safeReference(field(configuration, "sandboxUser"));
  if (sandboxUser !== "terminalx") fail("invalid-state");
  const lifecycle = exactRecord(field(configuration, "lifecycle"), [
    "autoStopIntervalMinutes",
    "autoArchiveIntervalMinutes",
    "autoDeleteIntervalMinutes",
  ]);
  if (
    field(lifecycle, "autoStopIntervalMinutes") !== 0 ||
    field(lifecycle, "autoArchiveIntervalMinutes") !== 0 ||
    field(lifecycle, "autoDeleteIntervalMinutes") !== -1
  ) {
    fail("invalid-state");
  }
  return Object.freeze({
    sourceCommit: TERMINALX_DAYTONA_SOURCE_COMMIT,
    target: safeReference(field(configuration, "target")),
    sandboxUser,
    artifact: snapshotArtifact(field(configuration, "artifact")),
    supervisorArtifactDigest: digest(field(configuration, "supervisorArtifactDigest")),
    lifecycle: Object.freeze({
      autoStopIntervalMinutes: boundedInteger(
        field(lifecycle, "autoStopIntervalMinutes"),
        0,
        MAX_INTERVAL_MINUTES
      ),
      autoArchiveIntervalMinutes: boundedInteger(
        field(lifecycle, "autoArchiveIntervalMinutes"),
        0,
        MAX_INTERVAL_MINUTES
      ),
      autoDeleteIntervalMinutes: boundedInteger(
        field(lifecycle, "autoDeleteIntervalMinutes"),
        -1,
        MAX_INTERVAL_MINUTES
      ),
    }),
  });
}

function snapshotArtifact(value: unknown): DaytonaSandboxArtifact {
  const artifact = record(value);
  const kind = field(artifact, "kind");
  exactFields(artifact, ["kind", "snapshotId", "snapshotRef", "imageId", "contentDigest"]);
  if (kind !== "snapshot") fail("invalid-state");
  const snapshotId = field(artifact, "snapshotId");
  const snapshotRef = field(artifact, "snapshotRef");
  const imageId = field(artifact, "imageId");
  const contentDigest = digest(field(artifact, "contentDigest"));
  if (typeof snapshotRef !== "string") fail("invalid-state");
  const match = SNAPSHOT_DIGEST_REFERENCE.exec(snapshotRef);
  if (
    typeof snapshotId !== "string" ||
    !UUID_V4.test(snapshotId) ||
    match === null ||
    !sameDigest(match[1]!, contentDigest) ||
    typeof imageId !== "string" ||
    !DOCKER_IMAGE_ID.test(imageId)
  ) {
    fail("invalid-state");
  }
  return Object.freeze({ kind, snapshotId, snapshotRef, imageId, contentDigest });
}

function snapshotPlan(value: unknown): HostedRuntimeAssignmentPlan {
  try {
    const plan = snapshotPortable(value) as HostedRuntimeAssignmentPlan;
    // The private adapter already performs the canonical deep plan validation.
    // Requiring successful canonicalization here prevents direct callers from
    // supplying functions, proxies, accessors, cycles, or non-finite numbers.
    canonicalRuntimeJson(plan);
    if (!plan || typeof plan !== "object") fail("invalid-state");
    digest(plan.specificationDigest);
    digest(plan.effectEnforcerPolicyDigest);
    digest(plan.incarnation);
    digest(plan.isolation.isolationPolicyDigest);
    digest(plan.isolation.network.policyDigest);
    safeReference(plan.adapterConfigurationRef);
    safeReference(plan.observation.keyProvisioningRef);
    if (
      plan.isolation.network.mode !== "blocked" ||
      plan.isolation.network.allowedDestinations.length !== 0 ||
      plan.isolation.resources.pids !== 256 ||
      plan.capabilities.isolatedExecution !== true ||
      plan.capabilities.brokeredCredentials !== false ||
      plan.capabilities.proxyOnlyEgress !== false ||
      plan.capabilities.checkpoints !== false ||
      plan.capabilities.yoloEligible !== false
    ) {
      fail("invalid-state");
    }
    safeReference(plan.observation.issuerKeyId);
    if (typeof plan.observation.publicKeySpkiPem !== "string") fail("invalid-state");
    if (
      plan.isolation.publicAccess !== false ||
      plan.isolation.hostMounts !== false ||
      plan.isolation.linkedSandbox !== false ||
      plan.isolation.rootIdentity !== false
    ) {
      fail("invalid-state");
    }
    return plan;
  } catch (error) {
    if (error instanceof HostedControlPlaneError) throw error;
    fail("invalid-state");
  }
}

function snapshotCreateRequest(value: unknown): HostedControlPlaneCreateRequest {
  const request = exactRecord(snapshotPortable(value), ["operationId", "plan"]);
  return Object.freeze({
    operationId: safeReference(field(request, "operationId")),
    plan: snapshotPlan(field(request, "plan")),
  });
}

function snapshotMutationRequest(value: unknown): HostedControlPlaneMutationRequest {
  const request = exactRecord(snapshotPortable(value), ["operationId", "plan", "expected"]);
  const plan = snapshotPlan(field(request, "plan"));
  return Object.freeze({
    operationId: safeReference(field(request, "operationId")),
    plan,
    expected: snapshotExpected(field(request, "expected"), plan),
  });
}

function snapshotCommandRequest(value: unknown): HostedControlPlaneCommandRequest {
  const request = exactRecord(snapshotPortable(value), [
    "operationId",
    "plan",
    "expected",
    "commandId",
    "commandDigest",
    "command",
  ]);
  const plan = snapshotPlan(field(request, "plan"));
  const command = snapshotPortable(field(request, "command")) as RuntimeCommand;
  const commandId = safeReference(field(request, "commandId"));
  if (field(record(command), "commandId") !== commandId) fail("conflict");
  return Object.freeze({
    operationId: safeReference(field(request, "operationId")),
    plan,
    expected: snapshotExpected(field(request, "expected"), plan),
    commandId,
    commandDigest: digest(field(request, "commandDigest")),
    command,
  });
}

function snapshotFollowRequest(value: unknown): HostedControlPlaneFollowRequest {
  const request = exactRecord(snapshotPortable(value), ["plan", "expected", "checkpoint"]);
  const plan = snapshotPlan(field(request, "plan"));
  const checkpoint = field(request, "checkpoint");
  return Object.freeze({
    plan,
    expected: snapshotExpected(field(request, "expected"), plan),
    checkpoint:
      checkpoint === null
        ? null
        : (snapshotPortable(checkpoint) as HostedControlPlaneFollowRequest["checkpoint"]),
  });
}

function snapshotExpected(
  value: unknown,
  plan: HostedRuntimeAssignmentPlan
): HostedControlPlaneSandbox {
  const expected = exactRecord(value, [
    "providerSandboxId",
    "binding",
    "runtimeAuthorizationGeneration",
    "incarnation",
    "specificationDigest",
    "effectEnforcerPolicyDigest",
    "adapterConfigurationRef",
    "isolationPolicyDigest",
    "state",
    "revision",
    "activation",
  ]);
  const projection = Object.freeze({
    providerSandboxId: safeReference(field(expected, "providerSandboxId")),
    binding: snapshotPortable(field(expected, "binding")) as RuntimeBinding,
    runtimeAuthorizationGeneration: positiveInteger(
      field(expected, "runtimeAuthorizationGeneration")
    ),
    incarnation: digest(field(expected, "incarnation")),
    specificationDigest: digest(field(expected, "specificationDigest")),
    effectEnforcerPolicyDigest: digest(field(expected, "effectEnforcerPolicyDigest")),
    adapterConfigurationRef: safeReference(field(expected, "adapterConfigurationRef")),
    isolationPolicyDigest: digest(field(expected, "isolationPolicyDigest")),
    state: internalLifecycleState(field(expected, "state")),
    revision: positiveInteger(field(expected, "revision")),
    activation:
      field(expected, "activation") === null
        ? null
        : snapshotHostedRuntimeActivation(field(expected, "activation")),
  });
  if (!sameProjectionPlan(projection, plan)) fail("conflict");
  return projection;
}

function createBody(
  plan: HostedRuntimeAssignmentPlan,
  configuration: DaytonaHostedControlPlaneConfiguration,
  labels: Readonly<Record<string, string>>
): DaytonaSandboxCreateBody {
  const network = networkConfiguration(plan);
  const artifact = configuration.artifact;
  const base = {
    name: `tx-${planDigest(plan).slice(0, 40)}`,
    user: configuration.sandboxUser,
    env: Object.freeze({}),
    labels,
    public: false as const,
    target: configuration.target,
    cpu: positiveInteger(plan.isolation.resources.cpu),
    memory: positiveInteger(plan.isolation.resources.memoryGiB),
    disk: positiveInteger(plan.isolation.resources.diskGiB),
    autoStopInterval: configuration.lifecycle.autoStopIntervalMinutes,
    autoArchiveInterval: configuration.lifecycle.autoArchiveIntervalMinutes,
    autoDeleteInterval: configuration.lifecycle.autoDeleteIntervalMinutes,
    volumes: Object.freeze([]) as readonly [],
    networkBlockAll: network.blockAll,
    ...(network.networkAllowList === null ? {} : { networkAllowList: network.networkAllowList }),
    ...(network.domainAllowList === null ? {} : { domainAllowList: network.domainAllowList }),
  };
  return Object.freeze({ ...base, snapshot: artifact.snapshotId });
}

function networkConfiguration(plan: HostedRuntimeAssignmentPlan): {
  readonly blockAll: boolean;
  readonly networkAllowList: string | null;
  readonly domainAllowList: string | null;
} {
  const destinations = plan.isolation.network.allowedDestinations;
  if (!Array.isArray(destinations) || destinations.length > 256) fail("invalid-state");
  if (plan.isolation.network.mode !== "blocked" || destinations.length !== 0) {
    fail("invalid-state");
  }
  return Object.freeze({ blockAll: true, networkAllowList: null, domainAllowList: null });
}

function validateProviderSandbox(
  value: unknown,
  plan: HostedRuntimeAssignmentPlan,
  configuration: DaytonaHostedControlPlaneConfiguration,
  expectedLabels?: Readonly<Record<string, string>>
): ValidatedProviderSandbox {
  const sandbox = record(snapshotPortable(value));
  const id = safeReference(field(sandbox, "id"));
  const labels = snapshotLabels(field(sandbox, "labels"));
  assertIdentityLabels(labels, identityLabels(plan, configuration));
  validateLifecycleLabels(labels);
  if (expectedLabels !== undefined && !sameLabels(labels, expectedLabels)) fail("conflict");
  if (field(sandbox, "public") !== false) fail("invalid-state");
  const state = providerState(field(sandbox, "state"));
  const desiredState = optionalProviderState(optionalField(sandbox, "desiredState"));
  const snapshot = optionalString(optionalField(sandbox, "snapshot"));
  const user = safeReference(field(sandbox, "user"));
  const target = safeReference(field(sandbox, "target"));
  const cpu = positiveNumber(field(sandbox, "cpu"));
  const memory = positiveNumber(field(sandbox, "memory"));
  const disk = positiveNumber(field(sandbox, "disk"));
  const networkBlockAll = booleanValue(field(sandbox, "networkBlockAll"));
  const networkAllowList = optionalString(optionalField(sandbox, "networkAllowList"));
  const domainAllowList = optionalString(optionalField(sandbox, "domainAllowList"));
  const volumes = optionalField(sandbox, "volumes") ?? Object.freeze([]);
  if (!Array.isArray(volumes) || volumes.length !== 0) fail("invalid-state");
  const linkedSandboxId = optionalString(optionalField(sandbox, "linkedSandboxId"));
  if (linkedSandboxId !== null) fail("invalid-state");
  const buildInfoValue = optionalField(sandbox, "buildInfo");
  const buildInfo = buildInfoValue === undefined ? null : record(buildInfoValue);

  if (
    user !== configuration.sandboxUser ||
    target !== configuration.target ||
    cpu !== plan.isolation.resources.cpu ||
    memory !== plan.isolation.resources.memoryGiB ||
    disk !== plan.isolation.resources.diskGiB
  ) {
    fail("invalid-state");
  }
  validateArtifactResponse(snapshot, buildInfo, configuration.artifact);
  validateNetworkResponse(
    networkBlockAll,
    networkAllowList,
    domainAllowList,
    networkConfiguration(plan)
  );
  return Object.freeze({
    id,
    labels,
    state,
    desiredState,
    snapshot,
    user,
    public: false,
    networkBlockAll,
    networkAllowList,
    domainAllowList,
    target,
    cpu,
    memory,
    disk,
    volumes: Object.freeze([]),
    linkedSandboxId: null,
    buildInfo,
  });
}

function validateArtifactResponse(
  snapshot: string | null,
  buildInfo: Readonly<Record<string, unknown>> | null,
  artifact: DaytonaSandboxArtifact
): void {
  if (snapshot !== artifact.snapshotId || buildInfo !== null) fail("invalid-state");
}

function validateNetworkResponse(
  blockAll: boolean,
  cidrs: string | null,
  domains: string | null,
  expected: ReturnType<typeof networkConfiguration>
): void {
  if (
    blockAll !== expected.blockAll ||
    !sameNullableText(cidrs, expected.networkAllowList) ||
    !sameNullableText(domains, expected.domainAllowList)
  ) {
    fail("invalid-state");
  }
}

function projectSandbox(
  provider: ValidatedProviderSandbox,
  plan: HostedRuntimeAssignmentPlan,
  activation: HostedRuntimeActivation | null
): HostedControlPlaneSandbox {
  return Object.freeze({
    providerSandboxId: provider.id,
    binding: plan.binding,
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    incarnation: plan.incarnation,
    specificationDigest: plan.specificationDigest,
    effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
    adapterConfigurationRef: plan.adapterConfigurationRef,
    isolationPolicyDigest: plan.isolation.isolationPolicyDigest,
    state: internalLifecycleState(provider.labels[STATE_LABEL]),
    revision: positiveInteger(Number(provider.labels[REVISION_LABEL])),
    activation,
  });
}

function assertExpected(
  provider: ValidatedProviderSandbox,
  expected: HostedControlPlaneSandbox,
  plan: HostedRuntimeAssignmentPlan,
  activation: HostedRuntimeActivation | null
): void {
  const projection = projectSandbox(provider, plan, activation);
  if (
    !sameText(projection.providerSandboxId, expected.providerSandboxId) ||
    projection.revision !== expected.revision ||
    projection.state !== expected.state ||
    canonicalRuntimeJson(projection) !== canonicalRuntimeJson(expected)
  ) {
    fail("conflict");
  }
}

function isCompletedFenceReplay(
  provider: ValidatedProviderSandbox,
  request: HostedControlPlaneMutationRequest,
  activation: HostedRuntimeActivation | null
): boolean {
  const projection = projectSandbox(provider, request.plan, activation);
  return (
    request.expected.state === "active" &&
    projection.providerSandboxId === request.expected.providerSandboxId &&
    projection.state === "fenced" &&
    projection.revision === request.expected.revision + 1 &&
    sameDigest(provider.labels[MUTATION_LABEL], sha256(request.operationId))
  );
}

function identityLabels(
  plan: HostedRuntimeAssignmentPlan,
  configuration: DaytonaHostedControlPlaneConfiguration
): Readonly<Record<string, string>> {
  return Object.freeze({
    [MANAGED_LABEL]: "terminalx-hosted-runtime-v1",
    [PLAN_LABEL]: planDigest(plan),
    [BINDING_LABEL]: sha256(canonicalRuntimeJson(plan.binding)),
    [AUTHORIZATION_LABEL]: String(plan.runtimeAuthorizationGeneration),
    [INCARNATION_LABEL]: plan.incarnation,
    [SPECIFICATION_LABEL]: plan.specificationDigest,
    [ADAPTER_LABEL]: sha256(plan.adapterConfigurationRef),
    [ISOLATION_LABEL]: plan.isolation.isolationPolicyDigest,
    [ARTIFACT_LABEL]: artifactDigest(configuration.artifact),
  });
}

function labelsFor(
  plan: HostedRuntimeAssignmentPlan,
  configuration: DaytonaHostedControlPlaneConfiguration,
  state: "provisioning" | "active" | "fenced",
  revision: number,
  operationId: string
): Readonly<Record<string, string>> {
  return Object.freeze({
    ...identityLabels(plan, configuration),
    [STATE_LABEL]: state,
    [REVISION_LABEL]: String(positiveInteger(revision)),
    [MUTATION_LABEL]: sha256(operationId),
  });
}

function withLifecycleState(
  labels: Readonly<Record<string, string>>,
  state: "active" | "fenced"
): Readonly<Record<string, string>> {
  return Object.freeze({ ...labels, [STATE_LABEL]: state });
}

function validateLifecycleLabels(labels: Readonly<Record<string, string>>): void {
  internalLifecycleState(labels[STATE_LABEL]);
  positiveInteger(Number(labels[REVISION_LABEL]));
  digest(labels[MUTATION_LABEL]);
}

function assertIdentityLabels(
  labels: Readonly<Record<string, string>>,
  expected: Readonly<Record<string, string>>
): void {
  for (const [key, value] of Object.entries(expected)) {
    if (!sameText(labels[key], value)) fail("conflict");
  }
  const expectedKeys = new Set([
    ...Object.keys(expected),
    STATE_LABEL,
    REVISION_LABEL,
    MUTATION_LABEL,
  ]);
  if (Object.keys(labels).some((key) => !expectedKeys.has(key))) fail("invalid-state");
}

function artifactDigest(artifact: DaytonaSandboxArtifact): string {
  return sha256(`terminalx/daytona-sandbox-artifact/v1\0${canonicalRuntimeJson(artifact)}`);
}

function assignmentBootstrapRequest(
  providerSandboxId: string,
  plan: HostedRuntimeAssignmentPlan,
  configuration: DaytonaHostedControlPlaneConfiguration
): DaytonaAssignmentBootstrapInstallRequest {
  return Object.freeze({
    providerSandboxId: safeReference(providerSandboxId),
    plan,
    // Provider labels may advance when the Sandbox is fenced. The immutable
    // root assignment itself is installed once at revision one.
    expectedRevision: ASSIGNMENT_BOOTSTRAP_REVISION,
    artifactDigest: artifactDigest(configuration.artifact),
    sandboxUser: "terminalx",
    supervisorArtifactDigest: configuration.supervisorArtifactDigest,
  });
}

function planDigest(plan: HostedRuntimeAssignmentPlan): string {
  return digestHostedRuntimeAssignmentPlan(plan);
}

function providerIdentityCommitment(providerSandboxId: string): string {
  return commitDaytonaProviderIdentity(providerSandboxId);
}

function observationPublicKeyDigest(plan: HostedRuntimeAssignmentPlan): string {
  return sha256(plan.observation.publicKeySpkiPem);
}

function supervisorTrust(
  plan: HostedRuntimeAssignmentPlan,
  configuration: DaytonaHostedControlPlaneConfiguration,
  requiredEffectEnforcerSetDigest: string
): DaytonaSupervisorTrustExpectation {
  return Object.freeze({
    ...supervisorTrustWithoutEnforcers(plan, configuration),
    requiredEffectEnforcerSetDigest,
  });
}

function supervisorTrustWithoutEnforcers(
  plan: HostedRuntimeAssignmentPlan,
  configuration: DaytonaHostedControlPlaneConfiguration
): Omit<DaytonaSupervisorTrustExpectation, "requiredEffectEnforcerSetDigest"> {
  return Object.freeze({
    supervisorArtifactDigest: configuration.supervisorArtifactDigest,
    observationIssuerKeyId: plan.observation.issuerKeyId,
    observationPublicKeyDigest: observationPublicKeyDigest(plan),
  });
}

function snapshotSignedObservation(
  value: unknown,
  plan: HostedRuntimeAssignmentPlan,
  providerSandboxId: string,
  expectedCommandId: string | undefined,
  expectedKind:
    | "runtime.lifecycle-receipt-observed"
    | "runtime.compensation-receipt-observed" = "runtime.lifecycle-receipt-observed"
): unknown {
  const snapshot = snapshotPortable(value);
  const observation = record(snapshot);
  if (field(observation, "kind") !== expectedKind) {
    fail("invalid-state");
  }
  const authority = record(field(observation, "authority"));
  if (field(authority, "issuer") !== "runtime") fail("invalid-state");
  if (!sameText(field(authority, "issuerKeyId"), plan.observation.issuerKeyId)) {
    fail("invalid-state");
  }
  const signature = field(authority, "signature");
  if (typeof signature !== "string" || !ED25519_SIGNATURE.test(signature)) {
    fail("invalid-state");
  }
  if (expectedCommandId !== undefined) {
    const command = record(field(observation, "command"));
    if (!sameText(field(command, "commandId"), expectedCommandId)) fail("conflict");
  }
  if (containsProviderIdentifier(snapshot, providerSandboxId)) fail("invalid-state");
  return snapshot;
}

function snapshotListResponse(value: unknown): {
  readonly items: readonly unknown[];
  readonly nextCursor: string | null;
} {
  const response = exactRecord(snapshotPortable(value), ["items", "nextCursor"]);
  const items = field(response, "items");
  if (!Array.isArray(items) || items.length > LIST_PAGE_SIZE) fail("invalid-state");
  const nextCursor = field(response, "nextCursor");
  if (nextCursor !== null) safeReference(nextCursor);
  return Object.freeze({ items, nextCursor: nextCursor as string | null });
}

function validateReplaceLabelsResponse(
  value: unknown,
  expected: Readonly<Record<string, string>>
): void {
  // The exact b5a5d9e route returns a complete SandboxDto, rather than the
  // narrower SandboxLabelsDto documented by one generated response schema.
  // Consume only the labels projection here; the subsequent GET validates the
  // complete Sandbox against the immutable plan and expected labels.
  const response = record(snapshotPortable(value));
  const labels = snapshotLabels(field(response, "labels"));
  if (!sameLabels(labels, expected)) fail("conflict");
}

function snapshotLabels(value: unknown): Readonly<Record<string, string>> {
  const labels = record(snapshotPortable(value));
  const result: Record<string, string> = Object.create(null);
  const keys = Object.keys(labels);
  if (keys.length < 1 || keys.length > 64) fail("invalid-state");
  for (const key of keys.sort()) {
    const label = field(labels, key);
    if (!SAFE_LABEL_KEY.test(key) || typeof label !== "string" || !SAFE_LABEL_VALUE.test(label)) {
      fail("invalid-state");
    }
    result[key] = label;
  }
  return Object.freeze(result);
}

function captureApi(value: unknown): CapturedApi {
  const receiver = objectValue(value);
  return Object.freeze({
    receiver,
    listSandboxes: captureDataMethod(receiver, "listSandboxes"),
    createSandbox: captureDataMethod(receiver, "createSandbox"),
    getSandbox: captureDataMethod(receiver, "getSandbox"),
    pauseSandbox: captureDataMethod(receiver, "pauseSandbox"),
    replaceLabels: captureDataMethod(receiver, "replaceLabels"),
    deleteSandbox: captureDataMethod(receiver, "deleteSandbox"),
    close: captureDataMethod(receiver, "close"),
  });
}

function captureSupervisor(value: unknown): CapturedSupervisor {
  const receiver = objectValue(value);
  return Object.freeze({
    receiver,
    attestIsolation: captureDataMethod(receiver, "attestIsolation"),
    executeAuthenticated: captureDataMethod(receiver, "executeAuthenticated"),
    followSigned: captureDataMethod(receiver, "followSigned"),
    close: captureDataMethod(receiver, "close"),
  });
}

function captureAssignmentBootstrap(value: unknown): CapturedAssignmentBootstrap {
  const receiver = objectValue(value);
  return Object.freeze({
    receiver,
    install: captureDataMethod(receiver, "install"),
    activate: captureDataMethod(receiver, "activate"),
    retire: captureDataMethod(receiver, "retire"),
    resolveActivation: captureDataMethod(receiver, "resolveActivation"),
    resolveEffectManifest: captureDataMethod(receiver, "resolveEffectManifest"),
    close: captureDataMethod(receiver, "close"),
  });
}

function captureEffectTrust(value: unknown): CapturedEffectTrust {
  const receiver = objectValue(value);
  return Object.freeze({
    receiver,
    registerManifest: captureDataMethod(receiver, "registerManifest"),
    registerAttestations: captureDataMethod(receiver, "registerAttestations"),
  });
}

function captureVerifiers(options: CapturedConstructionOptions): CapturedVerifiers {
  if (
    typeof options.verifyIsolationAttestation !== "function" ||
    typeof options.verifyCommandAuthority !== "function" ||
    typeof options.verifyLifecycleEnforcementProof !== "function" ||
    typeof options.verifyCompensationEnforcementProof !== "function"
  ) {
    fail("invalid-state");
  }
  return Object.freeze({
    isolation: options.verifyIsolationAttestation as DaytonaIsolationAttestationVerifier,
    authority: options.verifyCommandAuthority as DaytonaCommandAuthorityVerifier,
    lifecycleProof: options.verifyLifecycleEnforcementProof as RuntimeEnforcementProofVerifier,
    compensationProof:
      options.verifyCompensationEnforcementProof as RuntimeCompensationEnforcementProofVerifier,
  });
}

function captureClock(value: unknown): () => number {
  if (typeof value !== "function") fail("invalid-state");
  return value as () => number;
}

function captureDataMethod(receiver: object, name: string): AnyFunction {
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) fail("invalid-state");
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        fail("invalid-state");
      }
      return descriptor.value as AnyFunction;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  fail("invalid-state");
}

function invoke(
  target: CapturedApi | CapturedSupervisor | CapturedAssignmentBootstrap,
  method: keyof CapturedApi | keyof CapturedSupervisor | keyof CapturedAssignmentBootstrap,
  args: readonly unknown[]
): unknown {
  const callable = (target as unknown as Record<PropertyKey, unknown>)[method];
  if (typeof callable !== "function") fail("invalid-state");
  return Reflect.apply(callable, target.receiver, args);
}

async function readBoundedJson(response: Response, signal: AbortSignal): Promise<unknown> {
  if (!response.body) fail("invalid-state");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      if (signal.aborted) fail("timeout");
      const result = await reader.read();
      if (result.done) break;
      size += result.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) fail("invalid-state");
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let textValue: string;
  try {
    textValue = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("invalid-state");
  }
  try {
    return JSON.parse(textValue);
  } catch {
    fail("invalid-state");
  }
}

function endpoint(value: unknown): string {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") > MAX_ENDPOINT_BYTES ||
    value.trim() !== value
  ) {
    fail("invalid-state");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail("invalid-state");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    fail("invalid-state");
  }
  return url.toString();
}

function validateCredential(value: Uint8Array): void {
  const decoded = decodeCredential(value);
  if (
    decoded.trim() !== decoded ||
    decoded.length < 1 ||
    /[^\x21-\x7e]/.test(decoded) ||
    /^Bearer\s/i.test(decoded)
  ) {
    fail("invalid-state");
  }
}

function decodeCredential(value: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    fail("invalid-state");
  }
}

function mapHttpStatus(status: number): HostedErrorCode {
  if (status === 401 || status === 403) return "permission-denied";
  if (status === 408 || status === 504) return "timeout";
  if (status === 404 || status === 409 || status === 412) return "conflict";
  if (status === 429 || status >= 500) return "unavailable";
  return "internal";
}

function normalizeError(error: unknown, signal: AbortSignal): HostedControlPlaneError {
  if (error instanceof HostedControlPlaneError) return error;
  if (signal.aborted || isAbortError(error)) return new HostedControlPlaneError("timeout");
  return new HostedControlPlaneError("unavailable");
}

function isAbortError(error: unknown): boolean {
  if (typeof DOMException !== "undefined" && error instanceof DOMException) {
    return error.name === "AbortError" || error.name === "TimeoutError";
  }
  return false;
}

function linkedController(...signals: readonly AbortSignal[]): AbortController {
  for (const signal of signals) {
    if (!isNativeAbortSignal(signal)) fail("invalid-state");
  }
  const settlement = new AbortController();
  const signal = AbortSignal.any([...signals, settlement.signal]);
  return Object.freeze({
    signal,
    abort: () => settlement.abort(),
  }) as AbortController;
}

function linkedSignal(...signals: readonly AbortSignal[]): AbortSignal {
  for (const signal of signals) {
    if (!isNativeAbortSignal(signal)) fail("invalid-state");
  }
  return AbortSignal.any([...signals]);
}

function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(new HostedControlPlaneError("timeout"));
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timeout);
        reject(new HostedControlPlaneError("timeout"));
      },
      { once: true }
    );
  });
}

function snapshotPortable(value: unknown): unknown {
  try {
    return snapshotRuntimeSupervisorPortableData(value);
  } catch {
    fail("invalid-state");
  }
}

function snapshotAttestationBatch(value: unknown): readonly unknown[] {
  if (!Array.isArray(value) || value.length > 64) fail("invalid-state");
  return Object.freeze(value.map((attestation) => snapshotPortable(attestation)));
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("invalid-state");
  return value as Record<string, unknown>;
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const result = record(value);
  exactFields(result, fields);
  return result;
}

function exactRawRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    fail("invalid-state");
  }
  const result = value as Record<string, unknown>;
  exactFields(result, fields);
  return result;
}

function exactFields(value: Record<string, unknown>, fields: readonly string[]): void {
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    fail("invalid-state");
  }
  for (const name of fields) field(value, name);
}

function field(recordValue: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(recordValue, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail("invalid-state");
  return descriptor.value;
}

function optionalField(recordValue: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(recordValue, name);
  if (descriptor === undefined) return undefined;
  if (!descriptor.enumerable || !("value" in descriptor)) fail("invalid-state");
  return descriptor.value;
}

function objectValue(value: unknown): object {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value))
    fail("invalid-state");
  return value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || value.trim() !== value || !SAFE_REFERENCE.test(value)) {
    fail("invalid-state");
  }
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail("invalid-state");
  return value;
}

function providerState(value: unknown): string {
  if (typeof value !== "string" || !SAFE_PROVIDER_STATE.test(value)) fail("invalid-state");
  return value;
}

function optionalProviderState(value: unknown): string | null {
  return value === undefined ? null : providerState(value);
}

function optionalString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  return safeReference(value);
}

function booleanValue(value: unknown): boolean {
  if (typeof value !== "boolean") fail("invalid-state");
  return value;
}

function positiveNumber(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0 || Object.is(value, -0)) {
    fail("invalid-state");
  }
  return value;
}

function positiveInteger(value: unknown): number {
  return boundedInteger(value, 1, Number.MAX_SAFE_INTEGER);
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail("invalid-state");
  }
  return value as number;
}

function internalLifecycleState(value: unknown): "provisioning" | "active" | "fenced" {
  if (value !== "provisioning" && value !== "active" && value !== "fenced") {
    fail("invalid-state");
  }
  return value;
}

function sampleClock(clock: () => number): number {
  let value: unknown;
  try {
    value = clock();
  } catch {
    fail("internal");
  }
  return boundedInteger(value, 0, Number.MAX_SAFE_INTEGER);
}

function isLifecycleCommand(command: RuntimeCommand): command is RuntimeLifecycleCommand {
  return (
    command.kind === "run.start" ||
    command.kind === "run.pause" ||
    command.kind === "run.resume" ||
    command.kind === "run.stop"
  );
}

function isCompensationCommand(command: RuntimeCommand): command is RuntimeCompensationCommand {
  return command.kind === "safety.quarantine";
}

function isNativeAbortSignal(value: unknown): value is AbortSignal {
  return value instanceof AbortSignal && !nodeTypes.isProxy(value);
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) return false;
  const descriptor = findDescriptor(value, Symbol.asyncIterator);
  return descriptor !== null && "value" in descriptor && typeof descriptor.value === "function";
}

function findDescriptor(value: object, key: PropertyKey): PropertyDescriptor | null {
  const visited = new Set<object>();
  let current: object | null = value;
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) return null;
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (descriptor) return descriptor;
    current = Object.getPrototypeOf(current) as object | null;
  }
  return null;
}

function containsProviderIdentifier(value: unknown, needle: string): boolean {
  if (typeof value === "string") return value.includes(needle);
  if (Array.isArray(value)) return value.some((entry) => containsProviderIdentifier(entry, needle));
  if (typeof value !== "object" || value === null) return false;
  for (const key of Object.keys(value)) {
    if (key.includes(needle)) return true;
    if (containsProviderIdentifier(field(value as Record<string, unknown>, key), needle))
      return true;
  }
  return false;
}

function sameProjectionPlan(
  projection: HostedControlPlaneSandbox,
  plan: HostedRuntimeAssignmentPlan
): boolean {
  return (
    canonicalRuntimeJson(projection.binding) === canonicalRuntimeJson(plan.binding) &&
    projection.runtimeAuthorizationGeneration === plan.runtimeAuthorizationGeneration &&
    sameDigest(projection.incarnation, plan.incarnation) &&
    sameDigest(projection.specificationDigest, plan.specificationDigest) &&
    sameDigest(projection.effectEnforcerPolicyDigest, plan.effectEnforcerPolicyDigest) &&
    sameText(projection.adapterConfigurationRef, plan.adapterConfigurationRef) &&
    sameDigest(projection.isolationPolicyDigest, plan.isolation.isolationPolicyDigest)
  );
}

function sameLabels(
  left: Readonly<Record<string, string>>,
  right: Readonly<Record<string, string>>
): boolean {
  return canonicalRuntimeJson(left) === canonicalRuntimeJson(right);
}

function sameNullableText(left: string | null, right: string | null): boolean {
  if (left === null || right === null) return left === right;
  return sameText(left, right);
}

function sameText(left: unknown, right: unknown): boolean {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function sameDigest(left: unknown, right: unknown): boolean {
  if (typeof left !== "string" || typeof right !== "string") return false;
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function invalidState(): never {
  fail("invalid-state");
}

function fail(code: HostedErrorCode): never {
  throw new HostedControlPlaneError(code);
}
