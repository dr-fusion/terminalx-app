import { createHash, createHmac, createPublicKey } from "node:crypto";
import { types as nodeTypes } from "node:util";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { RuntimeOutboxDelivery } from "../team-sessions/types";
import type { RuntimeCommand, RuntimeCommandReceipt, RuntimeHandle } from "./contracts";
import type { RuntimeOutboxApplier } from "./outbox-worker";
import { snapshotHostedRuntimeActivation } from "./hosted-runtime-activation";
import { RuntimeEffectError } from "./local-tmux-runtime";
import type { RuntimeCommandCapability } from "./runtime-command-dispatch";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import type { RuntimeCompensationHandleResolver } from "./runtime-compensation-supervisor";
import type { RuntimeLifecycleHandleResolver } from "./runtime-lifecycle-supervisor";
import type {
  RuntimeReceiptFollowHandleResolver,
  RuntimeReceiptFollowLease,
  RuntimeReceiptFollowTransport,
} from "./runtime-receipt-follow-supervisor";
import type { RuntimeReceiptObservationCheckpoint } from "./runtime-receipt-observation";
import { runBoundedRuntimeOperation } from "./runtime-supervisor-operation";
import {
  exactRuntimeSupervisorDataRecord,
  runtimeSupervisorDataField,
  snapshotRuntimeSupervisorPortableData,
} from "./runtime-supervisor-snapshot";
import {
  HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN,
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
  type HostedRuntimeActivationSink,
  type HostedRuntimeControlPlane,
} from "./hosted-runtime-control-plane";

const SHA256 = /^[0-9a-f]{64}$/;
const INCARNATION = /^[0-9a-f]{64}$/;
const MAX_REFERENCE_LENGTH = 300;
const MAX_PUBLIC_KEY_BYTES = 4_000;
const MAX_OUTCOME_BYTES = 256 * 1024;
const DEFAULT_OPERATION_TIMEOUT_MS = 30_000;
const MIN_OPERATION_TIMEOUT_MS = 10;
const MAX_OPERATION_TIMEOUT_MS = 300_000;
const MIN_OPAQUE_KEY_BYTES = 32;
const MAX_OPAQUE_KEY_BYTES = 128;
const RECEIPT_BACKED_COMMANDS = new Set([
  "run.start",
  "run.pause",
  "run.resume",
  "run.stop",
  "safety.quarantine",
]);
const CURRENT_DESIRED_LIFECYCLE_COMMANDS = new Set([
  "run.start",
  "run.pause",
  "run.resume",
  "run.stop",
]);

type AnyFunction = (...args: unknown[]) => unknown;

interface CapturedControlPlane {
  readonly receiver: object;
  readonly listExact: AnyFunction;
  readonly create: AnyFunction;
  readonly fence: AnyFunction;
  readonly retire: AnyFunction;
  readonly command: AnyFunction;
  readonly follow: AnyFunction;
  readonly close: AnyFunction;
}

interface CapturedPlanSource {
  readonly receiver: object;
  readonly resolve: AnyFunction;
  readonly isCurrent: AnyFunction;
}

interface ResolvedHostedHandle {
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly sandbox: HostedControlPlaneSandbox;
  readonly handle: RuntimeHandle;
}

export interface CreateHostedRuntimeAdapterBundleOptions {
  readonly plans: HostedAssignmentPlanSource;
  readonly controlPlane: HostedRuntimeControlPlane;
  /** Process-private, synchronous bridge into exact kernel settlement. */
  readonly activationSink: HostedRuntimeActivationSink;
  /** Stable deployment key. It is copied at construction and zeroed at close. */
  readonly opaqueHandleKey: Uint8Array;
  readonly operationTimeoutMs?: number;
}

/**
 * Complete portable capability group consumed by RuntimeSupervisorComposition.
 * Provider-native objects and IDs remain inside this module.
 */
export interface HostedRuntimeAdapterBundle extends AsyncDisposable {
  readonly assignmentRuntime: RuntimeOutboxApplier;
  readonly runtime: RuntimeCommandCapability;
  readonly receiptTransport: RuntimeReceiptFollowTransport;
  readonly lifecycleHandles: RuntimeLifecycleHandleResolver;
  readonly receiptFollowHandles: RuntimeReceiptFollowHandleResolver;
  readonly compensationHandles: RuntimeCompensationHandleResolver;
  close(): Promise<void>;
}

export function createHostedRuntimeAdapterBundle(
  unsafeOptions: CreateHostedRuntimeAdapterBundleOptions
): HostedRuntimeAdapterBundle {
  const core = new HostedRuntimeAdapterCore(unsafeOptions);
  const assignmentRuntime = Object.freeze({
    apply: (delivery: RuntimeOutboxDelivery, signal: AbortSignal) =>
      core.assignment(delivery, "apply", signal),
    reconcile: (delivery: RuntimeOutboxDelivery, signal: AbortSignal) =>
      core.assignment(delivery, "reconcile", signal),
  });
  const runtime = Object.freeze({
    command: (handle: RuntimeHandle, command: RuntimeCommand, signal: AbortSignal) =>
      core.command(handle, command, signal),
  });
  const handles = Object.freeze({
    resolve: (
      input: RuntimeCommand | RuntimeReceiptFollowLease,
      signal: AbortSignal
    ): Promise<RuntimeHandle | null> => core.resolveHandle(input, signal),
  });
  const receiptTransport = Object.freeze({
    follow: (
      handle: RuntimeHandle,
      checkpoint: RuntimeReceiptObservationCheckpoint | null,
      signal: AbortSignal
    ) => core.follow(handle, checkpoint, signal),
  });
  const close = (): Promise<void> => core.close();
  return Object.freeze({
    assignmentRuntime,
    runtime,
    receiptTransport,
    lifecycleHandles: handles,
    receiptFollowHandles: handles,
    compensationHandles: handles,
    close,
    [Symbol.asyncDispose]: close,
  });
}

/** Canonical durable commitment shared with hosted outbox payloads. */
export function digestHostedRuntimeAssignmentPlan(unsafePlan: HostedRuntimeAssignmentPlan): string {
  const plan = snapshotPlan(unsafePlan);
  return sha256(`${HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN}${canonicalRuntimeJson(plan)}`);
}

class HostedRuntimeAdapterCore {
  private readonly plans: CapturedPlanSource;
  private readonly controlPlane: CapturedControlPlane;
  private readonly activationSink: (
    activation: Parameters<HostedRuntimeActivationSink["register"]>[0]
  ) => void;
  private readonly opaqueHandleKey: Uint8Array;
  private readonly operationTimeoutMs: number;
  private readonly serial = new KeyedSerialExecutor();
  private readonly shutdownController = new AbortController();
  private readonly handleVault = new Map<string, ResolvedHostedHandle>();
  private closed = false;
  private closePromise: Promise<void> | null = null;

  constructor(unsafeOptions: CreateHostedRuntimeAdapterBundleOptions) {
    const options = exactRecord(unsafeOptions, [
      "plans",
      "controlPlane",
      "activationSink",
      "opaqueHandleKey",
      ...(Object.hasOwn(unsafeOptions ?? {}, "operationTimeoutMs") ? ["operationTimeoutMs"] : []),
    ]);
    this.plans = capturePlanSource(field(options, "plans"));
    this.controlPlane = captureControlPlane(field(options, "controlPlane"));
    this.activationSink = captureActivationSink(field(options, "activationSink"));
    const key = field(options, "opaqueHandleKey");
    if (
      !(key instanceof Uint8Array) ||
      key.byteLength < MIN_OPAQUE_KEY_BYTES ||
      key.byteLength > MAX_OPAQUE_KEY_BYTES
    ) {
      invalidState();
    }
    this.opaqueHandleKey = new Uint8Array(key);
    const timeout = optionalField(options, "operationTimeoutMs") ?? DEFAULT_OPERATION_TIMEOUT_MS;
    this.operationTimeoutMs = boundedInteger(
      timeout,
      MIN_OPERATION_TIMEOUT_MS,
      MAX_OPERATION_TIMEOUT_MS
    );
  }

  assignment(
    unsafeDelivery: RuntimeOutboxDelivery,
    expectedMode: "apply" | "reconcile",
    signal: AbortSignal
  ): Promise<void> {
    this.assertAvailable(signal);
    const delivery = snapshotRuntimeSupervisorPortableData(unsafeDelivery) as RuntimeOutboxDelivery;
    if (delivery.dispatchMode !== expectedMode) invalidState();
    const lookup = Object.freeze({ kind: "delivery" as const, delivery });
    const plan = this.resolvePlan(lookup);
    return this.serial.run(sessionSerialKey(plan.binding), signal, async () => {
      this.assertAvailable(signal);
      switch (delivery.kind) {
        case "runtime.session.ensure":
          await this.ensure(delivery, lookup, plan, signal);
          return;
        case "runtime.authorization.fence":
          await this.fence(delivery, lookup, plan, signal);
          return;
        case "runtime.session.retire":
          await this.retire(delivery, lookup, plan, signal);
          return;
      }
    });
  }

  async resolveHandle(
    unsafeInput: RuntimeCommand | RuntimeReceiptFollowLease,
    signal: AbortSignal
  ): Promise<RuntimeHandle | null> {
    this.assertAvailable(signal);
    const input = snapshotRuntimeSupervisorPortableData(unsafeInput) as
      | RuntimeCommand
      | RuntimeReceiptFollowLease;
    const { binding, runtimeAuthorizationGeneration } = bindingLookupFromInput(input);
    const lookup = Object.freeze({
      kind: "binding" as const,
      binding,
      runtimeAuthorizationGeneration,
    });
    const plan = this.resolvePlan(lookup);
    validateObservationLease(input, plan);
    const requiresCurrentDesiredPlan = isCurrentDesiredLifecycleInput(input);
    if (requiresCurrentDesiredPlan && !this.planIsCurrent(lookup, plan)) return null;
    return this.serial.run(sessionSerialKey(plan.binding), signal, async () => {
      if (requiresCurrentDesiredPlan && !this.planIsCurrent(lookup, plan)) return null;
      const match = await this.oneExactMatch(plan, signal, true);
      if (match === null || match.state !== "active") return null;
      if (requiresCurrentDesiredPlan && !this.planIsCurrent(lookup, plan)) return null;
      const opaqueHandleRef = this.opaqueHandleRef(plan, match);
      const handle = Object.freeze({
        binding: plan.binding,
        opaqueHandleRef,
        capabilities: plan.capabilities,
      });
      this.handleVault.set(opaqueHandleRef, Object.freeze({ plan, sandbox: match, handle }));
      return handle;
    });
  }

  async command(
    unsafeHandle: RuntimeHandle,
    unsafeCommand: RuntimeCommand,
    signal: AbortSignal
  ): Promise<RuntimeCommandReceipt> {
    this.assertAvailable(signal);
    const command = snapshotRuntimeSupervisorPortableData(unsafeCommand) as RuntimeCommand;
    const commandRecord = dataRecord(command);
    const commandKind = field(commandRecord, "kind");
    if (typeof commandKind !== "string" || !RECEIPT_BACKED_COMMANDS.has(commandKind)) {
      invalidState();
    }
    const { binding, runtimeAuthorizationGeneration } = bindingLookupFromInput(command);
    const handle = snapshotHandle(unsafeHandle, binding);
    const lookup = Object.freeze({
      kind: "binding" as const,
      binding,
      runtimeAuthorizationGeneration,
    });
    const plan = this.resolvePlan(lookup);
    const requiresCurrentDesiredPlan = CURRENT_DESIRED_LIFECYCLE_COMMANDS.has(commandKind);
    return this.serial.run(sessionSerialKey(binding), signal, async () => {
      if (requiresCurrentDesiredPlan && !this.planIsCurrent(lookup, plan)) invalidState();
      const resolved = await this.requireResolvedHandle(handle, plan, signal);
      if (resolved.sandbox.state !== "active" && commandKind !== "safety.quarantine") {
        invalidState();
      }
      const commandId = safeReference(field(commandRecord, "commandId"));
      const commandJson = canonicalRuntimeJson(command);
      if (Buffer.byteLength(commandJson, "utf8") > MAX_OUTCOME_BYTES) invalidState();
      const commandDigest = sha256(`terminalx/hosted-command/v1\0${commandJson}`);
      const request: HostedControlPlaneCommandRequest = Object.freeze({
        operationId: `hosted-command:${sha256(
          `terminalx/hosted-command-operation/v1\0${canonicalRuntimeJson({ binding, commandId })}`
        )}`,
        plan,
        expected: resolved.sandbox,
        commandId,
        commandDigest,
        command,
      });
      // This synchronous desired-state read is the final boundary before an
      // ordinary lifecycle command reaches hosted compute. Historical receipt
      // follow and proof-backed containment intentionally use separate rules.
      if (requiresCurrentDesiredPlan && !this.planIsCurrent(lookup, plan)) invalidState();
      const result = await this.invokeProvider<HostedControlPlaneCommandResult>(
        this.controlPlane.command,
        [request],
        signal
      );
      const snapshot = snapshotCommandResult(result, commandId, commandDigest, binding);
      assertProviderIdentifierAbsent(snapshot.receipt, resolved.sandbox.providerSandboxId);
      return snapshot.receipt;
    });
  }

  follow(
    unsafeHandle: RuntimeHandle,
    unsafeCheckpoint: RuntimeReceiptObservationCheckpoint | null,
    signal: AbortSignal
  ): AsyncIterable<unknown> {
    return Object.freeze({
      [Symbol.asyncIterator]: (): AsyncGenerator<unknown> =>
        this.followIterator(unsafeHandle, unsafeCheckpoint, signal),
    });
  }

  private async *followIterator(
    unsafeHandle: RuntimeHandle,
    unsafeCheckpoint: RuntimeReceiptObservationCheckpoint | null,
    signal: AbortSignal
  ): AsyncGenerator<unknown> {
    this.assertAvailable(signal);
    const handle = snapshotHandle(unsafeHandle);
    const checkpoint = snapshotOptionalPortable(unsafeCheckpoint);
    const resolved = this.handleVault.get(handle.opaqueHandleRef);
    if (!resolved || !sameHandle(resolved.handle, handle)) invalidState();
    const current = await this.serial.run(sessionSerialKey(handle.binding), signal, async () =>
      this.requireResolvedHandle(handle, resolved.plan, signal)
    );
    const controller = linkedController(signal, this.shutdownController.signal);
    let iterable: unknown;
    try {
      const request: HostedControlPlaneFollowRequest = Object.freeze({
        plan: current.plan,
        expected: current.sandbox,
        checkpoint,
      });
      iterable = Reflect.apply(this.controlPlane.follow, this.controlPlane.receiver, [
        request,
        controller.signal,
      ]);
      if (!isAsyncIterable(iterable)) invalidState();
      for await (const unsafeObservation of iterable as AsyncIterable<unknown>) {
        if (controller.signal.aborted) return;
        const observation = snapshotBoundedOutcome(unsafeObservation);
        assertProviderIdentifierAbsent(observation, current.sandbox.providerSandboxId);
        yield observation;
      }
    } catch (error) {
      if (controller.signal.aborted) return;
      throw normalizeProviderError(error);
    } finally {
      controller.abort();
    }
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.shutdownController.abort();
    const close = (async () => {
      try {
        await this.serial.settle();
        const signal = new AbortController().signal;
        const outcome = await runBoundedRuntimeOperation(
          () => Reflect.apply(this.controlPlane.close, this.controlPlane.receiver, []),
          this.operationTimeoutMs,
          signal,
          { abortOnSettlement: true }
        );
        if (outcome.kind !== "value" || outcome.value !== undefined) {
          throw new TypeError("Hosted Runtime adapter could not close");
        }
      } finally {
        this.handleVault.clear();
        this.opaqueHandleKey.fill(0);
      }
    })();
    this.closePromise = close;
    return close;
  }

  private async ensure(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.session.ensure" }>,
    lookup: HostedAssignmentLookup,
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<void> {
    let match = await this.oneExactMatch(plan, signal, true);
    if (!this.planIsCurrent(lookup, plan)) {
      await this.retireSupersededEnsure(delivery, lookup, plan, match, signal);
      return;
    }
    if (match === null || match.state === "provisioning") {
      this.requireUnchangedPlan(lookup, plan);
      if (!this.planIsCurrent(lookup, plan)) return;
      const request: HostedControlPlaneCreateRequest = Object.freeze({
        operationId: `hosted-assignment:${delivery.outboxId}:ensure`,
        plan,
      });
      const created = await this.invokeProvider<HostedControlPlaneSandbox>(
        this.controlPlane.create,
        [request],
        signal
      );
      snapshotSandbox(created, plan);
      match = await this.oneExactMatch(plan, signal, false);
    }
    if (!this.planIsCurrent(lookup, plan)) {
      await this.retireSupersededEnsure(delivery, lookup, plan, match, signal);
      return;
    }
    if (match.state !== "active") invalidState();
    if (!match.activation) invalidState();
    this.activationSink(match.activation);
  }

  private async retireSupersededEnsure(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.session.ensure" }>,
    lookup: HostedAssignmentLookup,
    plan: HostedRuntimeAssignmentPlan,
    initialMatch: HostedControlPlaneSandbox | null,
    signal: AbortSignal
  ): Promise<void> {
    let match = initialMatch;
    if (match === null) return;
    this.requireUnchangedPlan(lookup, plan);
    if (match.state === "active") {
      const fenceRequest: HostedControlPlaneMutationRequest = Object.freeze({
        operationId: `hosted-assignment:${delivery.outboxId}:superseded-fence`,
        plan,
        expected: match,
      });
      const fenced = snapshotSandbox(
        await this.invokeProvider<HostedControlPlaneSandbox>(
          this.controlPlane.fence,
          [fenceRequest],
          signal
        ),
        plan
      );
      if (
        fenced.providerSandboxId !== match.providerSandboxId ||
        fenced.state !== "fenced" ||
        fenced.revision <= match.revision
      ) {
        conflict();
      }
      const afterFence = await this.oneExactMatch(plan, signal, true);
      if (afterFence === null) {
        this.dropHandlesForPlan(plan);
        return;
      }
      if (
        afterFence.providerSandboxId !== match.providerSandboxId ||
        afterFence.state !== "fenced"
      ) {
        conflict();
      }
      match = afterFence;
    }
    const retireRequest: HostedControlPlaneMutationRequest = Object.freeze({
      operationId: `hosted-assignment:${delivery.outboxId}:superseded-retire`,
      plan,
      expected: match,
    });
    await this.invokeProvider<void>(this.controlPlane.retire, [retireRequest], signal);
    if ((await this.oneExactMatch(plan, signal, true)) !== null) conflict();
    this.dropHandlesForPlan(plan);
  }

  private async fence(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.authorization.fence" }>,
    lookup: HostedAssignmentLookup,
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<void> {
    if (!this.planIsCurrent(lookup, plan)) return;
    const match = await this.oneExactMatch(plan, signal, true);
    if (match === null) return;
    if (match.state === "fenced") return;
    if (!this.planIsCurrent(lookup, plan)) return;
    const request: HostedControlPlaneMutationRequest = Object.freeze({
      operationId: `hosted-assignment:${delivery.outboxId}:fence`,
      plan,
      expected: match,
    });
    const fenced = await this.invokeProvider<HostedControlPlaneSandbox>(
      this.controlPlane.fence,
      [request],
      signal
    );
    const snapshot = snapshotSandbox(fenced, plan);
    if (
      snapshot.providerSandboxId !== match.providerSandboxId ||
      snapshot.state !== "fenced" ||
      snapshot.revision <= match.revision
    ) {
      conflict();
    }
    const after = await this.oneExactMatch(plan, signal, true);
    if (
      after !== null &&
      (after.providerSandboxId !== match.providerSandboxId || after.state !== "fenced")
    ) {
      conflict();
    }
  }

  private async retire(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.session.retire" }>,
    lookup: HostedAssignmentLookup,
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<void> {
    if (!this.planIsCurrent(lookup, plan)) return;
    const match = await this.oneExactMatch(plan, signal, true);
    if (match === null) return;
    if (!this.planIsCurrent(lookup, plan)) return;
    const request: HostedControlPlaneMutationRequest = Object.freeze({
      operationId: `hosted-assignment:${delivery.outboxId}:retire`,
      plan,
      expected: match,
    });
    await this.invokeProvider<void>(this.controlPlane.retire, [request], signal);
    if ((await this.oneExactMatch(plan, signal, true)) !== null) conflict();
    this.dropHandlesForPlan(plan);
  }

  private resolvePlan(lookup: HostedAssignmentLookup): HostedRuntimeAssignmentPlan {
    let value: unknown;
    try {
      value = Reflect.apply(this.plans.resolve, this.plans.receiver, [lookup]);
      if (value === null) invalidState();
      const plan = snapshotPlan(value);
      validatePlanForLookup(plan, lookup);
      return plan;
    } catch {
      invalidState();
    }
  }

  private requireUnchangedPlan(
    lookup: HostedAssignmentLookup,
    expected: HostedRuntimeAssignmentPlan
  ): void {
    const current = this.resolvePlan(lookup);
    if (planDigest(current) !== planDigest(expected)) conflict();
  }

  private planIsCurrent(
    lookup: HostedAssignmentLookup,
    expected: HostedRuntimeAssignmentPlan
  ): boolean {
    this.requireUnchangedPlan(lookup, expected);
    let current: unknown;
    try {
      current = Reflect.apply(this.plans.isCurrent, this.plans.receiver, [lookup]);
    } catch {
      invalidState();
    }
    if (typeof current !== "boolean") invalidState();
    return current;
  }

  private async oneExactMatch(
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal,
    allowAbsent: false
  ): Promise<HostedControlPlaneSandbox>;
  private async oneExactMatch(
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal,
    allowAbsent: true
  ): Promise<HostedControlPlaneSandbox | null>;
  private async oneExactMatch(
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal,
    allowAbsent: boolean
  ): Promise<HostedControlPlaneSandbox | null> {
    const value = await this.invokeProvider<unknown>(this.controlPlane.listExact, [plan], signal);
    if (!Array.isArray(value)) invalidState();
    if (value.length > 1) conflict();
    const match = value.length === 0 ? null : snapshotSandbox(value[0], plan);
    if (match === null && !allowAbsent) conflict();
    return match;
  }

  private async requireResolvedHandle(
    handle: RuntimeHandle,
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<ResolvedHostedHandle> {
    const cached = this.handleVault.get(handle.opaqueHandleRef);
    if (
      !cached ||
      !sameHandle(cached.handle, handle) ||
      !sameBinding(cached.plan.binding, plan.binding) ||
      cached.plan.runtimeAuthorizationGeneration !== plan.runtimeAuthorizationGeneration ||
      planDigest(cached.plan) !== planDigest(plan)
    ) {
      invalidState();
    }
    const match = await this.oneExactMatch(plan, signal, false);
    if (
      match.providerSandboxId !== cached.sandbox.providerSandboxId ||
      this.opaqueHandleRef(plan, match) !== handle.opaqueHandleRef
    ) {
      conflict();
    }
    return Object.freeze({ plan, sandbox: match, handle: cached.handle });
  }

  private opaqueHandleRef(
    plan: HostedRuntimeAssignmentPlan,
    sandbox: HostedControlPlaneSandbox
  ): string {
    const payload = canonicalRuntimeJson({
      binding: plan.binding,
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      incarnation: plan.incarnation,
      specificationDigest: plan.specificationDigest,
      adapterConfigurationRef: plan.adapterConfigurationRef,
      providerIdentityCommitmentInput: sandbox.providerSandboxId,
    });
    const ref = `txh1_${createHmac("sha256", this.opaqueHandleKey)
      .update("terminalx/hosted-runtime-handle/v1\0", "utf8")
      .update(payload, "utf8")
      .digest("base64url")}`;
    if (ref === sandbox.providerSandboxId || ref.includes(sandbox.providerSandboxId)) {
      invalidState();
    }
    return ref;
  }

  private async invokeProvider<T>(
    method: AnyFunction,
    args: readonly unknown[],
    signal: AbortSignal
  ): Promise<T> {
    this.assertAvailable(signal);
    const linked = linkedController(signal, this.shutdownController.signal);
    const outcome = await runBoundedRuntimeOperation(
      (operationSignal) =>
        Reflect.apply(method, this.controlPlane.receiver, [...args, operationSignal]),
      this.operationTimeoutMs,
      linked.signal,
      { abortOnSettlement: true }
    );
    linked.abort();
    switch (outcome.kind) {
      case "value":
        return outcome.value as T;
      case "timeout":
      case "aborted":
        throw new RuntimeEffectError("runtime_timeout", true);
      case "error":
        throw normalizeProviderError(outcome.error);
    }
  }

  private assertAvailable(signal: AbortSignal): void {
    if (this.closed || this.shutdownController.signal.aborted) {
      throw new RuntimeEffectError("runtime_unavailable", true);
    }
    if (!(signal instanceof AbortSignal) || signal.aborted) {
      throw new RuntimeEffectError("runtime_timeout", true);
    }
  }

  private dropHandlesForPlan(plan: HostedRuntimeAssignmentPlan): void {
    for (const [ref, resolved] of this.handleVault) {
      if (
        sameBinding(resolved.plan.binding, plan.binding) &&
        resolved.plan.runtimeAuthorizationGeneration === plan.runtimeAuthorizationGeneration
      ) {
        this.handleVault.delete(ref);
      }
    }
  }
}

class KeyedSerialExecutor {
  private readonly tails = new Map<string, Promise<void>>();

  run<T>(key: string, signal: AbortSignal, operation: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    const result = previous
      .catch(() => undefined)
      .then(async () => {
        if (signal.aborted) throw new RuntimeEffectError("runtime_timeout", true);
        return operation();
      });
    const tail = result.then(
      () => undefined,
      () => undefined
    );
    this.tails.set(key, tail);
    void tail.finally(() => {
      if (this.tails.get(key) === tail) this.tails.delete(key);
    });
    return result;
  }

  async settle(): Promise<void> {
    await Promise.allSettled([...this.tails.values()]);
  }
}

function capturePlanSource(value: unknown): CapturedPlanSource {
  const receiver = objectValue(value);
  return Object.freeze({
    receiver,
    resolve: captureDataMethod(receiver, "resolve"),
    isCurrent: captureDataMethod(receiver, "isCurrent"),
  });
}

function captureActivationSink(
  value: unknown
): (activation: Parameters<HostedRuntimeActivationSink["register"]>[0]) => void {
  const receiver = objectValue(value);
  const register = captureDataMethod(receiver, "register");
  return (activation) => {
    const result = Reflect.apply(register, receiver, [activation]);
    if (result !== undefined) invalidState();
  };
}

function captureControlPlane(value: unknown): CapturedControlPlane {
  const receiver = objectValue(value);
  return Object.freeze({
    receiver,
    listExact: captureDataMethod(receiver, "listExact"),
    create: captureDataMethod(receiver, "create"),
    fence: captureDataMethod(receiver, "fence"),
    retire: captureDataMethod(receiver, "retire"),
    command: captureDataMethod(receiver, "command"),
    follow: captureDataMethod(receiver, "follow"),
    close: captureDataMethod(receiver, "close"),
  });
}

function captureDataMethod(receiver: object, name: string): AnyFunction {
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) invalidState();
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") invalidState();
      return descriptor.value as AnyFunction;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  invalidState();
}

function snapshotPlan(value: unknown): HostedRuntimeAssignmentPlan {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const plan = exactRuntimeSupervisorDataRecord(snapshot, [
    "binding",
    "runtimeAuthorizationGeneration",
    "incarnation",
    "specificationDigest",
    "effectEnforcerPolicyDigest",
    "adapterConfigurationRef",
    "observation",
    "isolation",
    "capabilities",
  ]);
  const binding = snapshotBinding(field(plan, "binding"));
  const runtimeAuthorizationGeneration = positiveInteger(
    field(plan, "runtimeAuthorizationGeneration")
  );
  const incarnation = field(plan, "incarnation");
  const specificationDigest = field(plan, "specificationDigest");
  if (typeof incarnation !== "string" || !INCARNATION.test(incarnation)) invalidState();
  if (typeof specificationDigest !== "string" || !SHA256.test(specificationDigest)) invalidState();
  const isolation = snapshotIsolation(field(plan, "isolation"));
  const capabilities = snapshotCapabilities(field(plan, "capabilities"));
  return Object.freeze({
    binding,
    runtimeAuthorizationGeneration,
    incarnation,
    specificationDigest,
    effectEnforcerPolicyDigest: digest(field(plan, "effectEnforcerPolicyDigest")),
    adapterConfigurationRef: safeReference(field(plan, "adapterConfigurationRef")),
    observation: snapshotObservation(field(plan, "observation")),
    isolation,
    capabilities,
  });
}

function snapshotObservation(value: unknown): HostedRuntimeAssignmentPlan["observation"] {
  const record = exactRuntimeSupervisorDataRecord(value, [
    "keyProvisioningRef",
    "issuerKeyId",
    "publicKeySpkiPem",
  ]);
  const publicKeySpkiPem = field(record, "publicKeySpkiPem");
  if (
    typeof publicKeySpkiPem !== "string" ||
    Buffer.byteLength(publicKeySpkiPem, "utf8") > MAX_PUBLIC_KEY_BYTES ||
    !isCanonicalEd25519PublicKey(publicKeySpkiPem)
  ) {
    invalidState();
  }
  return Object.freeze({
    keyProvisioningRef: safeReference(field(record, "keyProvisioningRef")),
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    publicKeySpkiPem,
  });
}

function snapshotIsolation(value: unknown): HostedRuntimeAssignmentPlan["isolation"] {
  const record = exactRuntimeSupervisorDataRecord(value, [
    "isolationPolicyDigest",
    "publicAccess",
    "hostMounts",
    "linkedSandbox",
    "rootIdentity",
    "network",
    "resources",
  ]);
  if (
    field(record, "publicAccess") !== false ||
    field(record, "hostMounts") !== false ||
    field(record, "linkedSandbox") !== false ||
    field(record, "rootIdentity") !== false
  ) {
    invalidState();
  }
  const isolationPolicyDigest = digest(field(record, "isolationPolicyDigest"));
  const networkRecord = exactRuntimeSupervisorDataRecord(field(record, "network"), [
    "mode",
    "policyDigest",
    "allowedDestinations",
  ]);
  const mode = field(networkRecord, "mode");
  if (mode !== "blocked" && mode !== "allowlist") invalidState();
  const unsafeDestinations = field(networkRecord, "allowedDestinations");
  if (!Array.isArray(unsafeDestinations) || unsafeDestinations.length > 256) invalidState();
  const allowedDestinations = unsafeDestinations.map((entry) => safeDestination(entry));
  if (
    new Set(allowedDestinations).size !== allowedDestinations.length ||
    (mode === "blocked" && allowedDestinations.length !== 0) ||
    (mode === "allowlist" && allowedDestinations.length === 0)
  ) {
    invalidState();
  }
  const resourcesRecord = exactRuntimeSupervisorDataRecord(field(record, "resources"), [
    "cpu",
    "memoryGiB",
    "diskGiB",
    "pids",
  ]);
  return Object.freeze({
    isolationPolicyDigest,
    publicAccess: false,
    hostMounts: false,
    linkedSandbox: false,
    rootIdentity: false,
    network: Object.freeze({
      mode,
      policyDigest: digest(field(networkRecord, "policyDigest")),
      allowedDestinations: Object.freeze(allowedDestinations),
    }),
    resources: Object.freeze({
      cpu: boundedInteger(field(resourcesRecord, "cpu"), 1, 64),
      memoryGiB: boundedInteger(field(resourcesRecord, "memoryGiB"), 1, 512),
      diskGiB: boundedInteger(field(resourcesRecord, "diskGiB"), 1, 4_096),
      pids: boundedInteger(field(resourcesRecord, "pids"), 1, 1_000_000),
    }),
  });
}

function snapshotCapabilities(value: unknown): HostedRuntimeAssignmentPlan["capabilities"] {
  const record = exactRuntimeSupervisorDataRecord(value, [
    "isolatedExecution",
    "brokeredCredentials",
    "proxyOnlyEgress",
    "checkpoints",
    "yoloEligible",
  ]);
  const checkpoints = field(record, "checkpoints");
  if (
    field(record, "isolatedExecution") !== true ||
    field(record, "brokeredCredentials") !== false ||
    field(record, "proxyOnlyEgress") !== false ||
    typeof checkpoints !== "boolean" ||
    field(record, "yoloEligible") !== false
  ) {
    invalidState();
  }
  return Object.freeze({
    isolatedExecution: true,
    brokeredCredentials: false,
    proxyOnlyEgress: false,
    checkpoints,
    yoloEligible: false,
  });
}

function validatePlanForLookup(
  plan: HostedRuntimeAssignmentPlan,
  lookup: HostedAssignmentLookup
): void {
  if (lookup.kind === "binding") {
    if (
      !sameBinding(plan.binding, lookup.binding) ||
      plan.runtimeAuthorizationGeneration !== lookup.runtimeAuthorizationGeneration
    ) {
      invalidState();
    }
    return;
  }
  if (lookup.kind === "session") {
    if (
      plan.binding.sessionId !== safeReference(lookup.sessionId) ||
      plan.runtimeAuthorizationGeneration !== lookup.runtimeAuthorizationGeneration
    ) {
      invalidState();
    }
    return;
  }
  const delivery = lookup.delivery;
  const payload = dataRecord(delivery.payload);
  if (field(payload, "runtimeKind") !== "daytona") invalidState();
  const deliveryGeneration = positiveInteger(field(payload, "runtimeAuthorizationGeneration"));
  const assignmentPlanRuntimeAuthorizationGeneration =
    delivery.kind === "runtime.session.ensure"
      ? deliveryGeneration
      : positiveInteger(field(payload, "assignmentPlanRuntimeAuthorizationGeneration"));
  if (
    (delivery.kind === "runtime.session.ensure" &&
      assignmentPlanRuntimeAuthorizationGeneration !== deliveryGeneration) ||
    (delivery.kind !== "runtime.session.ensure" &&
      assignmentPlanRuntimeAuthorizationGeneration >= deliveryGeneration)
  ) {
    invalidState();
  }
  if (
    !sameBinding(plan.binding, snapshotBinding(field(payload, "binding"))) ||
    plan.binding.sessionId !== delivery.sessionId ||
    plan.binding.sessionId !== field(payload, "sessionId") ||
    plan.runtimeAuthorizationGeneration !== assignmentPlanRuntimeAuthorizationGeneration
  ) {
    invalidState();
  }
  safeReference(field(payload, "assignmentPlanRef"));
  if (digest(field(payload, "assignmentPlanDigest")) !== planDigest(plan)) invalidState();
  if (
    delivery.kind === "runtime.session.retire" &&
    (field(payload, "runtimeAssignmentId") !== plan.binding.runtimeAssignmentId ||
      field(payload, "runtimeAssignmentGeneration") !== plan.binding.runtimeAssignmentGeneration ||
      field(payload, "sandboxId") !== plan.binding.sandboxId ||
      field(payload, "sandboxGeneration") !== plan.binding.sandboxGeneration)
  ) {
    invalidState();
  }
}

function isCurrentDesiredLifecycleInput(
  input: RuntimeCommand | RuntimeReceiptFollowLease
): boolean {
  const record = dataRecord(input);
  const kind = optionalField(record, "kind");
  return typeof kind === "string" && CURRENT_DESIRED_LIFECYCLE_COMMANDS.has(kind);
}

function snapshotSandbox(
  value: unknown,
  plan: HostedRuntimeAssignmentPlan
): HostedControlPlaneSandbox {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRuntimeSupervisorDataRecord(snapshot, [
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
  const result = Object.freeze({
    providerSandboxId: safeProviderIdentifier(field(record, "providerSandboxId")),
    binding: snapshotBinding(field(record, "binding")),
    runtimeAuthorizationGeneration: positiveInteger(
      field(record, "runtimeAuthorizationGeneration")
    ),
    incarnation: safeIncarnation(field(record, "incarnation")),
    specificationDigest: digest(field(record, "specificationDigest")),
    effectEnforcerPolicyDigest: digest(field(record, "effectEnforcerPolicyDigest")),
    adapterConfigurationRef: safeReference(field(record, "adapterConfigurationRef")),
    isolationPolicyDigest: digest(field(record, "isolationPolicyDigest")),
    state: runtimeState(field(record, "state")),
    revision: positiveInteger(field(record, "revision")),
    activation:
      field(record, "activation") === null
        ? null
        : snapshotHostedRuntimeActivation(field(record, "activation")),
  });
  if (
    !sameBinding(result.binding, plan.binding) ||
    result.runtimeAuthorizationGeneration !== plan.runtimeAuthorizationGeneration ||
    result.incarnation !== plan.incarnation ||
    result.specificationDigest !== plan.specificationDigest ||
    result.effectEnforcerPolicyDigest !== plan.effectEnforcerPolicyDigest ||
    result.adapterConfigurationRef !== plan.adapterConfigurationRef ||
    result.isolationPolicyDigest !== plan.isolation.isolationPolicyDigest ||
    (result.state === "provisioning" ? result.activation !== null : result.activation === null) ||
    (result.activation !== null &&
      (canonicalRuntimeJson(result.activation.binding) !== canonicalRuntimeJson(plan.binding) ||
        result.activation.runtimeAuthorizationGeneration !== plan.runtimeAuthorizationGeneration ||
        result.activation.effectEnforcerPolicyDigest !== plan.effectEnforcerPolicyDigest))
  ) {
    invalidState();
  }
  return result;
}

function snapshotCommandResult(
  value: unknown,
  commandId: string,
  commandDigest: string,
  binding: RuntimeBinding
): HostedControlPlaneCommandResult {
  const snapshot = snapshotBoundedOutcome(value);
  const record = exactRuntimeSupervisorDataRecord(snapshot, [
    "commandId",
    "commandDigest",
    "receipt",
  ]);
  if (
    field(record, "commandId") !== commandId ||
    field(record, "commandDigest") !== commandDigest
  ) {
    conflict();
  }
  const receipt = field(record, "receipt") as RuntimeCommandReceipt;
  const receiptRecord = dataRecord(receipt);
  if (
    field(receiptRecord, "commandId") !== commandId ||
    !sameBinding(snapshotBinding(field(receiptRecord, "binding")), binding)
  ) {
    conflict();
  }
  return Object.freeze({ commandId, commandDigest, receipt });
}

function snapshotBoundedOutcome(value: unknown): unknown {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const encoded = canonicalRuntimeJson(snapshot);
  if (Buffer.byteLength(encoded, "utf8") > MAX_OUTCOME_BYTES) invalidState();
  return snapshot;
}

function snapshotOptionalPortable<T>(value: T | null): T | null {
  return value === null ? null : (snapshotRuntimeSupervisorPortableData(value) as T);
}

function snapshotHandle(value: unknown, expectedBinding?: RuntimeBinding): RuntimeHandle {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRuntimeSupervisorDataRecord(snapshot, [
    "binding",
    "opaqueHandleRef",
    "capabilities",
  ]);
  const binding = snapshotBinding(field(record, "binding"));
  if (expectedBinding && !sameBinding(binding, expectedBinding)) invalidState();
  const opaqueHandleRef = safeReference(field(record, "opaqueHandleRef"));
  const capabilitiesRecord = exactRuntimeSupervisorDataRecord(field(record, "capabilities"), [
    "isolatedExecution",
    "brokeredCredentials",
    "proxyOnlyEgress",
    "checkpoints",
    "yoloEligible",
  ]);
  for (const key of [
    "isolatedExecution",
    "brokeredCredentials",
    "proxyOnlyEgress",
    "checkpoints",
    "yoloEligible",
  ]) {
    if (typeof field(capabilitiesRecord, key) !== "boolean") invalidState();
  }
  return Object.freeze({
    binding,
    opaqueHandleRef,
    capabilities: Object.freeze({
      isolatedExecution: field(capabilitiesRecord, "isolatedExecution") as boolean,
      brokeredCredentials: field(capabilitiesRecord, "brokeredCredentials") as boolean,
      proxyOnlyEgress: field(capabilitiesRecord, "proxyOnlyEgress") as boolean,
      checkpoints: field(capabilitiesRecord, "checkpoints") as boolean,
      yoloEligible: field(capabilitiesRecord, "yoloEligible") as boolean,
    }),
  });
}

function bindingLookupFromInput(input: RuntimeCommand | RuntimeReceiptFollowLease): {
  binding: RuntimeBinding;
  runtimeAuthorizationGeneration: number;
} {
  const record = dataRecord(input);
  const binding = snapshotBinding(field(record, "binding"));
  const direct = optionalField(record, "runtimeAuthorizationGeneration");
  const observed = optionalField(record, "observedRuntimeAuthorizationGeneration");
  const runtimeAuthorizationGeneration = positiveInteger(direct ?? observed);
  return { binding, runtimeAuthorizationGeneration };
}

function validateObservationLease(
  input: RuntimeCommand | RuntimeReceiptFollowLease,
  plan: HostedRuntimeAssignmentPlan
): void {
  const record = dataRecord(input);
  if (optionalField(record, "kind") !== undefined) return;
  if (
    safeReference(field(record, "issuerKeyId")) !== plan.observation.issuerKeyId ||
    digest(field(record, "publicKeySpkiDigest")) !==
      observationPublicKeyDigest(plan.observation.publicKeySpkiPem)
  ) {
    invalidState();
  }
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const record = exactRuntimeSupervisorDataRecord(value, [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ]);
  return Object.freeze({
    teamId: safeReference(field(record, "teamId")),
    projectId: safeReference(field(record, "projectId")),
    sessionId: safeReference(field(record, "sessionId")),
    runtimeAssignmentId: safeReference(field(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(record, "runtimeAssignmentGeneration")),
    sandboxId: safeReference(field(record, "sandboxId")),
    sandboxGeneration: positiveInteger(field(record, "sandboxGeneration")),
    runtimePrincipalId: safeReference(field(record, "runtimePrincipalId")),
  });
}

function normalizeProviderError(error: unknown): RuntimeEffectError {
  let code: unknown;
  try {
    if (!(error instanceof HostedControlPlaneError)) {
      return new RuntimeEffectError("runtime_internal", true);
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, "code");
    if (!descriptor || !("value" in descriptor)) {
      return new RuntimeEffectError("runtime_internal", true);
    }
    code = descriptor.value;
  } catch {
    return new RuntimeEffectError("runtime_internal", true);
  }
  switch (code) {
    case "unavailable":
      return new RuntimeEffectError("runtime_unavailable", true);
    case "timeout":
      return new RuntimeEffectError("runtime_timeout", true);
    case "conflict":
      return new RuntimeEffectError("runtime_conflict", false);
    case "permission-denied":
      return new RuntimeEffectError("runtime_permission_denied", false);
    case "invalid-state":
      return new RuntimeEffectError("runtime_invalid_state", false);
    case "internal":
      return new RuntimeEffectError("runtime_internal", true);
    default:
      return new RuntimeEffectError("runtime_internal", true);
  }
}

function assertProviderIdentifierAbsent(value: unknown, providerId: string): void {
  const visit = (entry: unknown): void => {
    if (typeof entry === "string") {
      if (entry.includes(providerId)) invalidState();
      return;
    }
    if (entry === null || typeof entry !== "object") return;
    if (Array.isArray(entry)) {
      for (const item of entry) visit(item);
      return;
    }
    for (const key of Reflect.ownKeys(entry)) {
      if (typeof key !== "string") invalidState();
      if (key.includes(providerId)) invalidState();
      visit(field(entry as Record<string, unknown>, key));
    }
  };
  visit(value);
}

function planDigest(plan: HostedRuntimeAssignmentPlan): string {
  return digestHostedRuntimeAssignmentPlan(plan);
}

function sessionSerialKey(binding: RuntimeBinding): string {
  return sha256(
    `terminalx/hosted-session-serial/v1\0${canonicalRuntimeJson({
      teamId: binding.teamId,
      projectId: binding.projectId,
      sessionId: binding.sessionId,
    })}`
  );
}

function linkedController(...signals: readonly AbortSignal[]): AbortController {
  const controller = new AbortController();
  const listeners: Array<readonly [AbortSignal, () => void]> = [];
  controller.signal.addEventListener(
    "abort",
    () => {
      for (const [signal, listener] of listeners) {
        signal.removeEventListener("abort", listener);
      }
      listeners.length = 0;
    },
    { once: true }
  );
  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort();
      break;
    }
    const listener = (): void => controller.abort();
    listeners.push([signal, listener]);
    signal.addEventListener("abort", listener, { once: true });
  }
  return controller;
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return false;
  const descriptor = findDataDescriptor(value as object, Symbol.asyncIterator);
  return descriptor !== null && typeof descriptor.value === "function";
}

function findDataDescriptor(
  value: object,
  property: PropertyKey
): { readonly value: unknown } | null {
  const visited = new Set<object>();
  let current: object | null = value;
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) return null;
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, property);
    if (descriptor) return "value" in descriptor ? { value: descriptor.value } : null;
    current = Object.getPrototypeOf(current) as object | null;
  }
  return null;
}

function objectValue(value: unknown): object {
  if (
    (typeof value !== "object" && typeof value !== "function") ||
    value === null ||
    nodeTypes.isProxy(value)
  ) {
    invalidState();
  }
  return value;
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  return exactRuntimeSupervisorDataRecord(value, fields);
}

function dataRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalidState();
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, key: string): unknown {
  return runtimeSupervisorDataField(record, key);
}

function optionalField(record: Record<string, unknown>, key: string): unknown | undefined {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor) return undefined;
  if (!descriptor.enumerable || !("value" in descriptor)) invalidState();
  return descriptor.value;
}

function safeReference(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_REFERENCE_LENGTH ||
    value.trim() !== value ||
    /[\0\r\n\t]/.test(value)
  ) {
    invalidState();
  }
  return value;
}

function safeProviderIdentifier(value: unknown): string {
  const providerId = safeReference(value);
  if (providerId.length < 8) invalidState();
  return providerId;
}

function safeDestination(value: unknown): string {
  const destination = safeReference(value);
  if (destination.length > 253 || /\s/.test(destination)) invalidState();
  return destination;
}

function safeIncarnation(value: unknown): string {
  if (typeof value !== "string" || !INCARNATION.test(value)) invalidState();
  return value;
}

function isCanonicalEd25519PublicKey(value: string): boolean {
  if (
    !value.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
    !value.endsWith("-----END PUBLIC KEY-----\n") ||
    value.includes("PRIVATE KEY")
  ) {
    return false;
  }
  try {
    const key = createPublicKey(value);
    return (
      key.type === "public" &&
      key.asymmetricKeyType === "ed25519" &&
      key.export({ format: "pem", type: "spki" }).toString() === value
    );
  } catch {
    return false;
  }
}

function observationPublicKeyDigest(value: string): string {
  try {
    const key = createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") invalidState();
    return createHash("sha256")
      .update(key.export({ format: "der", type: "spki" }))
      .digest("hex");
  } catch {
    invalidState();
  }
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) invalidState();
  return value;
}

function runtimeState(value: unknown): "provisioning" | "active" | "fenced" {
  if (value !== "provisioning" && value !== "active" && value !== "fenced") invalidState();
  return value;
}

function positiveInteger(value: unknown): number {
  return boundedInteger(value, 1, Number.MAX_SAFE_INTEGER);
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalidState();
  }
  return value as number;
}

function sameBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
  return (
    left.teamId === right.teamId &&
    left.projectId === right.projectId &&
    left.sessionId === right.sessionId &&
    left.runtimeAssignmentId === right.runtimeAssignmentId &&
    left.runtimeAssignmentGeneration === right.runtimeAssignmentGeneration &&
    left.sandboxId === right.sandboxId &&
    left.sandboxGeneration === right.sandboxGeneration &&
    left.runtimePrincipalId === right.runtimePrincipalId
  );
}

function sameHandle(left: RuntimeHandle, right: RuntimeHandle): boolean {
  return (
    sameBinding(left.binding, right.binding) &&
    left.opaqueHandleRef === right.opaqueHandleRef &&
    left.capabilities.isolatedExecution === right.capabilities.isolatedExecution &&
    left.capabilities.brokeredCredentials === right.capabilities.brokeredCredentials &&
    left.capabilities.proxyOnlyEgress === right.capabilities.proxyOnlyEgress &&
    left.capabilities.checkpoints === right.capabilities.checkpoints &&
    left.capabilities.yoloEligible === right.capabilities.yoloEligible
  );
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function invalidState(): never {
  throw new RuntimeEffectError("runtime_invalid_state", false);
}

function conflict(): never {
  throw new RuntimeEffectError("runtime_conflict", false);
}
