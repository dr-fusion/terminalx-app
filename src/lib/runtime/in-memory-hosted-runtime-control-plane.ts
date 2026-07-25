import { createHash } from "node:crypto";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { RuntimeOutboxDelivery } from "../team-sessions/types";
import type { RuntimeCommandReceipt } from "./contracts";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import { digestHostedRuntimeAssignmentPlan } from "./hosted-runtime-adapter";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";
import {
  HostedControlPlaneError,
  type HostedAssignmentLookup,
  type HostedAssignmentPlanSource,
  type HostedControlPlaneCommandRequest,
  type HostedControlPlaneCommandResult,
  type HostedControlPlaneCreateRequest,
  type HostedControlPlaneFollowRequest,
  type HostedControlPlaneMutationRequest,
  type HostedControlPlaneSandbox,
  type HostedRuntimeAssignmentPlan,
  type HostedRuntimeControlPlane,
} from "./hosted-runtime-control-plane";

export type InMemoryHostedControlPlaneOperation =
  | "list"
  | "create"
  | "fence"
  | "retire"
  | "command"
  | "follow"
  | "close";

export interface InMemoryHostedControlPlaneFault {
  readonly operation: InMemoryHostedControlPlaneOperation;
  /** `after` models an ambiguous effect whose response never arrived. */
  readonly phase: "before" | "after";
  readonly failure: "timeout" | "unavailable" | "conflict" | "internal";
}

interface StoredSandbox {
  readonly planKey: string;
  readonly sandbox: HostedControlPlaneSandbox;
}

interface StoredCreate {
  readonly requestDigest: string;
  readonly sandbox: HostedControlPlaneSandbox;
}

interface StoredFence {
  readonly requestDigest: string;
  readonly sandbox: HostedControlPlaneSandbox;
}

interface StoredRetire {
  readonly requestDigest: string;
}

interface StoredCommand {
  readonly requestDigest: string;
  readonly commandDigest: string;
  readonly result: HostedControlPlaneCommandResult;
}

/**
 * Persistent provider state for deterministic restart and ambiguity tests.
 * A new client can reuse this state without reusing any adapter-local handle.
 */
export class InMemoryHostedRuntimeControlPlaneState {
  private readonly sandboxes = new Map<string, StoredSandbox>();
  private readonly creates = new Map<string, StoredCreate>();
  private readonly fences = new Map<string, StoredFence>();
  private readonly retires = new Map<string, StoredRetire>();
  private readonly commandsByOperation = new Map<string, StoredCommand>();
  private readonly commandsById = new Map<string, StoredCommand>();
  private readonly observations = new Map<string, readonly unknown[]>();
  private readonly faults: InMemoryHostedControlPlaneFault[] = [];
  private nextProviderId = 1;

  faultNext(fault: InMemoryHostedControlPlaneFault): void {
    this.faults.push(Object.freeze({ ...fault }));
  }

  countExact(plan: HostedRuntimeAssignmentPlan): number {
    const key = planKey(plan);
    let count = 0;
    for (const stored of this.sandboxes.values()) {
      if (stored.planKey === key) count += 1;
    }
    return count;
  }

  /** Deliberate provider corruption hook used to verify 0/1/>1 handling. */
  injectDuplicate(plan: HostedRuntimeAssignmentPlan): string {
    const snapshot = snapshotPlan(plan);
    const providerSandboxId = this.allocateProviderId("duplicate");
    this.sandboxes.set(providerSandboxId, {
      planKey: planKey(snapshot),
      sandbox: sandboxFromPlan(providerSandboxId, snapshot, 1, "active"),
    });
    return providerSandboxId;
  }

  appendObservation(plan: HostedRuntimeAssignmentPlan, observation: unknown): void {
    const key = planKey(snapshotPlan(plan));
    const current = this.observations.get(key) ?? Object.freeze([]);
    const snapshot = snapshotRuntimeSupervisorPortableData(observation);
    this.observations.set(key, Object.freeze([...current, snapshot]));
  }

  providerIdsExact(plan: HostedRuntimeAssignmentPlan): readonly string[] {
    const key = planKey(plan);
    return Object.freeze(
      [...this.sandboxes.values()]
        .filter((entry) => entry.planKey === key)
        .map((entry) => entry.sandbox.providerSandboxId)
        .sort()
    );
  }

  takeFault(
    operation: InMemoryHostedControlPlaneOperation,
    phase: "before" | "after"
  ): InMemoryHostedControlPlaneFault | null {
    const index = this.faults.findIndex(
      (candidate) => candidate.operation === operation && candidate.phase === phase
    );
    if (index < 0) return null;
    return this.faults.splice(index, 1)[0] ?? null;
  }

  list(plan: HostedRuntimeAssignmentPlan): readonly HostedControlPlaneSandbox[] {
    const key = planKey(plan);
    return Object.freeze(
      [...this.sandboxes.values()]
        .filter((entry) => entry.planKey === key)
        .map((entry) => entry.sandbox)
        .sort((left, right) => left.providerSandboxId.localeCompare(right.providerSandboxId))
    );
  }

  create(request: HostedControlPlaneCreateRequest): HostedControlPlaneSandbox {
    const requestDigest = digestValue(request);
    const previous = this.creates.get(request.operationId);
    if (previous) {
      if (previous.requestDigest !== requestDigest) fail("conflict");
      return previous.sandbox;
    }
    const providerSandboxId = this.allocateProviderId(request.operationId);
    const sandbox = sandboxFromPlan(providerSandboxId, request.plan, 1, "active");
    this.sandboxes.set(providerSandboxId, { planKey: planKey(request.plan), sandbox });
    this.creates.set(request.operationId, { requestDigest, sandbox });
    return sandbox;
  }

  fence(request: HostedControlPlaneMutationRequest): HostedControlPlaneSandbox {
    const requestDigest = digestValue(request);
    const previous = this.fences.get(request.operationId);
    if (previous) {
      if (previous.requestDigest !== requestDigest) fail("conflict");
      return previous.sandbox;
    }
    const current = this.requireExpected(request);
    const sandbox = Object.freeze({
      ...current,
      state: "fenced" as const,
      revision: current.revision + 1,
    });
    this.sandboxes.set(current.providerSandboxId, {
      planKey: planKey(request.plan),
      sandbox,
    });
    this.fences.set(request.operationId, { requestDigest, sandbox });
    return sandbox;
  }

  retire(request: HostedControlPlaneMutationRequest): void {
    const requestDigest = digestValue(request);
    const previous = this.retires.get(request.operationId);
    if (previous) {
      if (previous.requestDigest !== requestDigest) fail("conflict");
      return;
    }
    const current = this.requireExpected(request);
    this.sandboxes.delete(current.providerSandboxId);
    this.retires.set(request.operationId, { requestDigest });
  }

  command(request: HostedControlPlaneCommandRequest): HostedControlPlaneCommandResult {
    const canonicalCommandDigest = sha256(
      `terminalx/hosted-command/v1\0${canonicalRuntimeJson(request.command)}`
    );
    if (canonicalCommandDigest !== request.commandDigest) fail("invalid-state");
    const requestDigest = commandRequestDigest(request);
    const byOperation = this.commandsByOperation.get(request.operationId);
    if (byOperation) {
      if (
        byOperation.requestDigest !== requestDigest ||
        byOperation.commandDigest !== request.commandDigest
      ) {
        fail("conflict");
      }
      return byOperation.result;
    }
    const commandKey = commandIdKey(request);
    const byId = this.commandsById.get(commandKey);
    if (byId) {
      if (byId.commandDigest !== request.commandDigest || byId.requestDigest !== requestDigest) {
        fail("conflict");
      }
      this.commandsByOperation.set(request.operationId, byId);
      return byId.result;
    }
    this.requireExpected(request);
    const receipt = receiptForCommand(request);
    const result = Object.freeze({
      commandId: request.commandId,
      commandDigest: request.commandDigest,
      receipt,
    });
    const stored = Object.freeze({ requestDigest, commandDigest: request.commandDigest, result });
    this.commandsByOperation.set(request.operationId, stored);
    this.commandsById.set(commandKey, stored);
    return result;
  }

  observationsFor(request: HostedControlPlaneFollowRequest): readonly unknown[] {
    this.requireExpected({
      operationId: "follow",
      plan: request.plan,
      expected: request.expected,
    });
    const observations = this.observations.get(planKey(request.plan)) ?? Object.freeze([]);
    if (request.checkpoint === null) return observations;
    const checkpointIndex = observations.findIndex(
      (observation) => observationCursor(observation) === request.checkpoint?.cursor
    );
    if (checkpointIndex < 0) fail("conflict");
    return Object.freeze(observations.slice(checkpointIndex + 1));
  }

  private allocateProviderId(seed: string): string {
    const sequence = String(this.nextProviderId).padStart(6, "0");
    this.nextProviderId += 1;
    return `provider-sandbox-${sequence}-${sha256(seed).slice(0, 12)}`;
  }

  private requireExpected(request: HostedControlPlaneMutationRequest): HostedControlPlaneSandbox {
    const current = this.sandboxes.get(request.expected.providerSandboxId);
    if (
      !current ||
      current.planKey !== planKey(request.plan) ||
      !sameSandbox(current.sandbox, request.expected)
    ) {
      fail("conflict");
    }
    return current.sandbox;
  }
}

/** A deterministic control-plane client. Disposing it does not erase provider state. */
export class InMemoryHostedRuntimeControlPlane implements HostedRuntimeControlPlane {
  private closed = false;

  constructor(readonly state = new InMemoryHostedRuntimeControlPlaneState()) {}

  async listExact(
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<readonly HostedControlPlaneSandbox[]> {
    await this.phase("list", "before", signal);
    const result = this.state.list(snapshotPlan(plan));
    await this.phase("list", "after", signal);
    return result;
  }

  async create(
    request: HostedControlPlaneCreateRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneSandbox> {
    await this.phase("create", "before", signal);
    const result = this.state.create(snapshotCreateRequest(request));
    await this.phase("create", "after", signal);
    return result;
  }

  async fence(
    request: HostedControlPlaneMutationRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneSandbox> {
    await this.phase("fence", "before", signal);
    const result = this.state.fence(snapshotMutationRequest(request));
    await this.phase("fence", "after", signal);
    return result;
  }

  async retire(request: HostedControlPlaneMutationRequest, signal: AbortSignal): Promise<void> {
    await this.phase("retire", "before", signal);
    this.state.retire(snapshotMutationRequest(request));
    await this.phase("retire", "after", signal);
  }

  async command(
    request: HostedControlPlaneCommandRequest,
    signal: AbortSignal
  ): Promise<HostedControlPlaneCommandResult> {
    await this.phase("command", "before", signal);
    const result = this.state.command(snapshotCommandRequest(request));
    await this.phase("command", "after", signal);
    return result;
  }

  follow(request: HostedControlPlaneFollowRequest, signal: AbortSignal): AsyncIterable<unknown> {
    return Object.freeze({
      [Symbol.asyncIterator]: (): AsyncGenerator<unknown> => this.followIterator(request, signal),
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    const signal = new AbortController().signal;
    await this.phase("close", "before", signal);
    this.closed = true;
    await applyFault(this.state.takeFault("close", "after"), signal);
  }

  private async *followIterator(
    request: HostedControlPlaneFollowRequest,
    signal: AbortSignal
  ): AsyncGenerator<unknown> {
    await this.phase("follow", "before", signal);
    const observations = this.state.observationsFor(snapshotFollowRequest(request));
    for (const observation of observations) {
      assertSignal(signal);
      yield observation;
    }
    await this.phase("follow", "after", signal);
  }

  private async phase(
    operation: InMemoryHostedControlPlaneOperation,
    phase: "before" | "after",
    signal: AbortSignal
  ): Promise<void> {
    if (this.closed) fail("unavailable");
    assertSignal(signal);
    await applyFault(this.state.takeFault(operation, phase), signal);
  }
}

/** Exact explicit plan registry suitable for interface and composition tests. */
export class InMemoryHostedAssignmentPlanSource implements HostedAssignmentPlanSource {
  private readonly deliveries = new Map<string, HostedRuntimeAssignmentPlan>();
  private readonly bindings = new Map<string, HostedRuntimeAssignmentPlan>();
  private readonly currentBySession = new Map<string, HostedRuntimeAssignmentPlan>();
  private readonly currentBySessionId = new Map<string, HostedRuntimeAssignmentPlan>();

  registerBinding(plan: HostedRuntimeAssignmentPlan): void {
    const snapshot = snapshotPlan(plan);
    this.bindings.set(
      bindingLookupKey(snapshot.binding, snapshot.runtimeAuthorizationGeneration),
      snapshot
    );
    this.currentBySession.set(sessionLookupKey(snapshot.binding), snapshot);
    this.currentBySessionId.set(snapshot.binding.sessionId, snapshot);
  }

  registerDelivery(delivery: RuntimeOutboxDelivery, plan: HostedRuntimeAssignmentPlan): void {
    const snapshot = snapshotPlan(plan);
    this.deliveries.set(deliveryLookupKey(delivery), snapshot);
  }

  resolve(lookup: HostedAssignmentLookup): HostedRuntimeAssignmentPlan | null {
    if (lookup.kind === "delivery") {
      return this.deliveries.get(deliveryLookupKey(lookup.delivery)) ?? null;
    }
    if (lookup.kind === "session") {
      const plan = this.currentBySessionId.get(lookup.sessionId);
      return plan?.runtimeAuthorizationGeneration === lookup.runtimeAuthorizationGeneration
        ? plan
        : null;
    }
    return (
      this.bindings.get(bindingLookupKey(lookup.binding, lookup.runtimeAuthorizationGeneration)) ??
      null
    );
  }

  isCurrent(lookup: HostedAssignmentLookup): boolean {
    const plan = this.resolve(lookup);
    if (plan === null) return false;
    const current = this.currentBySession.get(sessionLookupKey(plan.binding));
    return current !== undefined && planKey(current) === planKey(plan);
  }
}

async function applyFault(
  fault: InMemoryHostedControlPlaneFault | null,
  signal: AbortSignal
): Promise<void> {
  if (!fault) return;
  switch (fault.failure) {
    case "timeout":
      await waitForAbort(signal);
      fail("timeout");
    case "unavailable":
      fail("unavailable");
    case "conflict":
      fail("conflict");
    case "internal":
      fail("internal");
  }
}

function waitForAbort(signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) =>
    signal.addEventListener("abort", () => resolve(), { once: true })
  );
}

function snapshotPlan(plan: HostedRuntimeAssignmentPlan): HostedRuntimeAssignmentPlan {
  return snapshotRuntimeSupervisorPortableData(plan) as HostedRuntimeAssignmentPlan;
}

function snapshotCreateRequest(
  request: HostedControlPlaneCreateRequest
): HostedControlPlaneCreateRequest {
  return snapshotRuntimeSupervisorPortableData(request) as HostedControlPlaneCreateRequest;
}

function snapshotMutationRequest(
  request: HostedControlPlaneMutationRequest
): HostedControlPlaneMutationRequest {
  return snapshotRuntimeSupervisorPortableData(request) as HostedControlPlaneMutationRequest;
}

function snapshotCommandRequest(
  request: HostedControlPlaneCommandRequest
): HostedControlPlaneCommandRequest {
  return snapshotRuntimeSupervisorPortableData(request) as HostedControlPlaneCommandRequest;
}

function snapshotFollowRequest(
  request: HostedControlPlaneFollowRequest
): HostedControlPlaneFollowRequest {
  return snapshotRuntimeSupervisorPortableData(request) as HostedControlPlaneFollowRequest;
}

function sandboxFromPlan(
  providerSandboxId: string,
  plan: HostedRuntimeAssignmentPlan,
  revision: number,
  state: "active" | "fenced"
): HostedControlPlaneSandbox {
  return Object.freeze({
    providerSandboxId,
    binding: plan.binding,
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    incarnation: plan.incarnation,
    specificationDigest: plan.specificationDigest,
    effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
    adapterConfigurationRef: plan.adapterConfigurationRef,
    isolationPolicyDigest: plan.isolation.isolationPolicyDigest,
    state,
    revision,
    activation: Object.freeze({
      version: 1 as const,
      kind: "hosted-runtime.activation" as const,
      binding: plan.binding,
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(plan),
      effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
      providerIdentityCommitment: sha256(
        `terminalx/in-memory-provider-identity/v1\0${providerSandboxId}`
      ),
      providerRevision: 1,
      effectManifestBindingDigest: sha256(
        `terminalx/in-memory-effect-binding/v1\0${providerSandboxId}\0${digestHostedRuntimeAssignmentPlan(plan)}`
      ),
      effectEnforcerSetDigest: sha256(
        `terminalx/in-memory-effect-enforcer-set/v1\0${providerSandboxId}\0${digestHostedRuntimeAssignmentPlan(plan)}`
      ),
    }),
  });
}

function receiptForCommand(request: HostedControlPlaneCommandRequest): RuntimeCommandReceipt {
  const effectRef = `hosted-effect:${sha256(
    `terminalx/in-memory-hosted-effect/v1\0${request.commandId}\0${request.commandDigest}`
  )}`;
  if (request.command.kind === "safety.quarantine") {
    return Object.freeze({
      receiptKind: "runtime.compensation" as const,
      compensationId: request.command.compensationId,
      commandId: request.commandId,
      binding: request.plan.binding,
      observedRuntimeAuthorizationGeneration:
        request.command.observedRuntimeAuthorizationGeneration,
      outcome: "accepted" as const,
      effectRef,
    });
  }
  return Object.freeze({
    commandId: request.commandId,
    binding: request.plan.binding,
    runtimeAuthorizationGeneration: request.plan.runtimeAuthorizationGeneration,
    outcome: "accepted" as const,
    effectRef,
  });
}

function planKey(plan: HostedRuntimeAssignmentPlan): string {
  return digestValue({
    binding: plan.binding,
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    incarnation: plan.incarnation,
    specificationDigest: plan.specificationDigest,
    adapterConfigurationRef: plan.adapterConfigurationRef,
    observation: plan.observation,
    isolation: plan.isolation,
    capabilities: plan.capabilities,
  });
}

function deliveryLookupKey(delivery: RuntimeOutboxDelivery): string {
  return digestValue({ kind: "delivery", delivery });
}

function bindingLookupKey(binding: RuntimeBinding, runtimeAuthorizationGeneration: number): string {
  return digestValue({ kind: "binding", binding, runtimeAuthorizationGeneration });
}

function sessionLookupKey(binding: RuntimeBinding): string {
  return digestValue({
    kind: "session",
    teamId: binding.teamId,
    projectId: binding.projectId,
    sessionId: binding.sessionId,
  });
}

function sameSandbox(left: HostedControlPlaneSandbox, right: HostedControlPlaneSandbox): boolean {
  return digestValue(left) === digestValue(right);
}

function commandRequestDigest(request: HostedControlPlaneCommandRequest): string {
  return digestValue({
    plan: request.plan,
    providerSandboxId: request.expected.providerSandboxId,
    commandId: request.commandId,
    commandDigest: request.commandDigest,
  });
}

function commandIdKey(request: HostedControlPlaneCommandRequest): string {
  return digestValue({
    plan: request.plan,
    providerSandboxId: request.expected.providerSandboxId,
    commandId: request.commandId,
  });
}

function observationCursor(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const descriptor = Object.getOwnPropertyDescriptor(value, "cursor");
  return descriptor && "value" in descriptor && typeof descriptor.value === "string"
    ? descriptor.value
    : null;
}

function digestValue(value: unknown): string {
  return sha256(canonicalRuntimeJson(value));
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function assertSignal(signal: AbortSignal): void {
  if (!(signal instanceof AbortSignal) || signal.aborted) fail("timeout");
}

function fail(code: ConstructorParameters<typeof HostedControlPlaneError>[0]): never {
  throw new HostedControlPlaneError(code);
}
