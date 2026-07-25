import type { RuntimeBinding } from "../team-sessions/contracts";
import type { RuntimeOutboxDelivery } from "../team-sessions/types";
import type { RuntimeCommand, RuntimeCommandReceipt } from "./contracts";
import type { RuntimeReceiptObservationCheckpoint } from "./runtime-receipt-observation";

export const HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN =
  "terminalx/hosted-runtime-assignment-plan/v1\0" as const;

/**
 * Provider-independent, effective isolation controls for one hosted Runtime.
 * These are enforcement inputs, not claims inferred from a provider response.
 */
export interface HostedRuntimeIsolationControls {
  readonly isolationPolicyDigest: string;
  readonly publicAccess: false;
  readonly hostMounts: false;
  readonly linkedSandbox: false;
  readonly rootIdentity: false;
  readonly network: {
    readonly mode: "blocked" | "allowlist";
    readonly policyDigest: string;
    readonly allowedDestinations: readonly string[];
  };
  readonly resources: {
    readonly cpu: number;
    readonly memoryGiB: number;
    readonly diskGiB: number;
    readonly pids: number;
  };
}

/** Immutable TerminalX plan. It deliberately contains no provider-native ID. */
export interface HostedRuntimeAssignmentPlan {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly incarnation: string;
  readonly specificationDigest: string;
  /** Key-independent policy committed by RuntimeSpec before provider creation. */
  readonly effectEnforcerPolicyDigest: string;
  readonly adapterConfigurationRef: string;
  /** Public-only key used by the binding-scoped durable receipt-follow registration. */
  readonly observation: {
    /** Opaque root-private lookup handle; it never contains credential bytes. */
    readonly keyProvisioningRef: string;
    readonly issuerKeyId: string;
    readonly publicKeySpkiPem: string;
  };
  readonly isolation: HostedRuntimeIsolationControls;
  readonly capabilities: {
    readonly isolatedExecution: true;
    readonly brokeredCredentials: false;
    /** Phase 7 has no credential-proxy proof; infrastructure allowlists do not satisfy it. */
    readonly proxyOnlyEgress: false;
    readonly checkpoints: boolean;
    readonly yoloEligible: false;
  };
}

export type HostedAssignmentLookup =
  | {
      readonly kind: "delivery";
      readonly delivery: RuntimeOutboxDelivery;
    }
  | {
      readonly kind: "binding";
      readonly binding: RuntimeBinding;
      readonly runtimeAuthorizationGeneration: number;
    }
  | {
      /** Resolve only the current ready hosted assignment for this Session generation. */
      readonly kind: "session";
      readonly sessionId: string;
      readonly runtimeAuthorizationGeneration: number;
    };

/**
 * Trusted local source for the exact immutable plan selected by durable work.
 * Absence is fail-closed. Provider responses must never implement this seam.
 */
export interface HostedAssignmentPlanSource {
  resolve(lookup: HostedAssignmentLookup): HostedRuntimeAssignmentPlan | null;
  /** Exact durable desired-state check. Plan existence alone is insufficient. */
  isCurrent(lookup: HostedAssignmentLookup): boolean;
}

/** Private provider identity retained behind the hosted adapter boundary. */
export interface HostedControlPlaneSandbox {
  readonly providerSandboxId: string;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly incarnation: string;
  readonly specificationDigest: string;
  readonly effectEnforcerPolicyDigest: string;
  readonly adapterConfigurationRef: string;
  readonly isolationPolicyDigest: string;
  /** `provisioning` is observable but never command-ready. */
  readonly state: "provisioning" | "active" | "fenced";
  readonly revision: number;
  /** Present only after exact provider-bound bootstrap activation. */
  readonly activation: HostedRuntimeActivation | null;
}

export interface HostedRuntimeActivation {
  readonly version: 1;
  readonly kind: "hosted-runtime.activation";
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly assignmentPlanDigest: string;
  readonly effectEnforcerPolicyDigest: string;
  readonly providerIdentityCommitment: string;
  readonly providerRevision: number;
  readonly effectManifestBindingDigest: string;
  /** Concrete signed manifest claims digest injected into issued commands. */
  readonly effectEnforcerSetDigest: string;
}

export interface HostedRuntimeActivationQuery {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly assignmentPlanDigest: string;
  readonly effectEnforcerPolicyDigest: string;
}

/** Pure synchronous lookup safe to invoke inside the SQLite settlement transaction. */
export interface HostedRuntimeActivationSource {
  resolve(query: HostedRuntimeActivationQuery): HostedRuntimeActivation | null;
}

/** Private adapter seam; exact replay is idempotent and replacement is rejected. */
export interface HostedRuntimeActivationSink {
  register(activation: HostedRuntimeActivation): void;
}

export interface HostedControlPlaneCreateRequest {
  readonly operationId: string;
  readonly plan: HostedRuntimeAssignmentPlan;
}

export interface HostedControlPlaneMutationRequest {
  readonly operationId: string;
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly expected: HostedControlPlaneSandbox;
}

export interface HostedControlPlaneCommandRequest extends HostedControlPlaneMutationRequest {
  readonly commandId: string;
  readonly commandDigest: string;
  readonly command: RuntimeCommand;
}

export interface HostedControlPlaneCommandResult {
  readonly commandId: string;
  readonly commandDigest: string;
  readonly receipt: RuntimeCommandReceipt;
}

export interface HostedControlPlaneFollowRequest {
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly expected: HostedControlPlaneSandbox;
  readonly checkpoint: RuntimeReceiptObservationCheckpoint | null;
}

/**
 * Narrow provider-neutral port. Daytona SDK/API objects remain behind an
 * implementation of this interface and cannot leak into portable Runtime APIs.
 */
export interface HostedRuntimeControlPlane {
  listExact(
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<readonly HostedControlPlaneSandbox[]>;
  create(
    request: HostedControlPlaneCreateRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneSandbox>;
  fence(
    request: HostedControlPlaneMutationRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneSandbox>;
  retire(request: HostedControlPlaneMutationRequest, signal: AbortSignal): Promise<void>;
  command(
    request: HostedControlPlaneCommandRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneCommandResult>;
  follow(request: HostedControlPlaneFollowRequest, signal: AbortSignal): AsyncIterable<unknown>;
  close(): Promise<void>;
}

export type HostedControlPlaneErrorCode =
  | "unavailable"
  | "timeout"
  | "conflict"
  | "permission-denied"
  | "invalid-state"
  | "internal";

const SAFE_ERROR_MESSAGES: Readonly<Record<HostedControlPlaneErrorCode, string>> = Object.freeze({
  unavailable: "Hosted Runtime control plane is unavailable",
  timeout: "Hosted Runtime control plane operation timed out",
  conflict: "Hosted Runtime control plane state conflicts",
  "permission-denied": "Hosted Runtime control plane denied the operation",
  "invalid-state": "Hosted Runtime control plane state is invalid",
  internal: "Hosted Runtime control plane operation failed",
});

/** Safe error surface: provider values are never interpolated. */
export class HostedControlPlaneError extends Error {
  constructor(readonly code: HostedControlPlaneErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "HostedControlPlaneError";
  }
}
