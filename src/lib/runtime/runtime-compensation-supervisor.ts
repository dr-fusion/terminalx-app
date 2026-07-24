import type {
  Runtime,
  RuntimeCompensationCommand,
  RuntimeCompensationReceipt,
  RuntimeHandle,
} from "./contracts";
import {
  RuntimeCompensationExecutionError,
  captureRuntimeCompensationDispatch,
  executeCapturedRuntimeCompensationCommand,
  type RuntimeCompensationAuthorityVerifier,
  type RuntimeCompensationDispatch,
  type RuntimeCompensationDispatchCertainty,
  type RuntimeCompensationExecutionErrorCode,
} from "./runtime-compensation-execution";
import type { RuntimeCompensationEnforcementProofVerifier } from "./runtime-compensation-enforcement-proof";
import {
  captureRuntimeHandleResolver,
  snapshotExactRuntimeHandle,
  type CapturedRuntimeHandleResolver,
} from "./runtime-handle-resolution";

const MAX_WORKER_ID_LENGTH = 128;
const LEASE_COMPLETION_MARGIN_MS = 250;

export interface RuntimeCompensationReconcileOptions {
  readonly nowMs: number;
}

export interface RuntimeCompensationClaimOptions {
  readonly workerId: string;
  readonly leaseDurationMs: number;
  readonly nowMs: number;
}

export interface RuntimeCompensationRenewalOptions {
  readonly commandId: string;
  readonly workerId: string;
  readonly expectedAttempt: number;
  readonly expectedLeaseExpiresAtMs: number;
  readonly leaseDurationMs: number;
  readonly nowMs: number;
}

export type RuntimeCompensationRenewal =
  | { readonly kind: "renewed"; readonly leaseExpiresAtMs: number }
  | { readonly kind: "expired-before-dispatch" };

export interface RuntimeCompensationDelivery {
  readonly command: RuntimeCompensationCommand;
  readonly attempt: number;
  readonly leaseOwner: string;
  readonly leaseExpiresAtMs: number;
  readonly priorDispatchCertainty: "not-dispatched";
}

export type RuntimeCompensationFailureCode =
  | RuntimeCompensationExecutionErrorCode
  | "runtime_handle_unavailable"
  | "lease_expired_before_dispatch"
  | "runtime_internal";

export type RuntimeCompensationAttemptOutcome =
  | { readonly kind: "receipt"; readonly receipt: RuntimeCompensationReceipt }
  | {
      readonly kind: "failure";
      readonly code: RuntimeCompensationFailureCode;
      readonly dispatchCertainty: RuntimeCompensationDispatchCertainty;
    };

export interface RuntimeCompensationCompletion {
  readonly commandId: string;
  readonly workerId: string;
  readonly expectedAttempt: number;
  readonly expectedLeaseExpiresAtMs: number;
  readonly observedAtMs: number;
  readonly outcome: RuntimeCompensationAttemptOutcome;
}

/** Durable historical-binding journal; current tenant state must not supersede its work. */
export interface RuntimeCompensationJournal {
  reconcile(options: RuntimeCompensationReconcileOptions): Promise<void>;
  claim(options: RuntimeCompensationClaimOptions): Promise<RuntimeCompensationDelivery | null>;
  renew(options: RuntimeCompensationRenewalOptions): Promise<RuntimeCompensationRenewal>;
  complete(completion: RuntimeCompensationCompletion): Promise<void>;
}

export interface RuntimeCompensationHandleResolver {
  /** Resolve only the exact historical binding, including both Sandbox generations. */
  resolve(command: RuntimeCompensationCommand, signal: AbortSignal): Promise<RuntimeHandle | null>;
}

export interface RuntimeCompensationSupervisorOptions {
  readonly journal: RuntimeCompensationJournal;
  readonly runtime: Runtime;
  readonly handles: RuntimeCompensationHandleResolver;
  readonly verifyAuthority: RuntimeCompensationAuthorityVerifier;
  readonly verifyEnforcementProof: RuntimeCompensationEnforcementProofVerifier;
  readonly workerId: string;
  readonly clock?: () => number;
  readonly leaseDurationMs?: number;
  readonly handleResolveTimeoutMs?: number;
  readonly runtimeCommandTimeoutMs?: number;
  readonly idleDelayMs?: number;
  readonly busyDelayMs?: number;
  readonly errorDelayMs?: number;
  readonly onOperationalError?: (code: "runtime_internal") => void;
}

export interface RuntimeCompensationRunResult {
  readonly claimed: number;
  readonly receipts: number;
  readonly failedBeforeDispatch: number;
  readonly dispatchUncertain: number;
}

/** Singular, bounded supervisor for platform-security containment commands. */
export class RuntimeCompensationSupervisor {
  private readonly journal: RuntimeCompensationJournal;
  private readonly runtimeDispatch: RuntimeCompensationDispatch;
  private readonly resolveHandle: CapturedRuntimeHandleResolver<RuntimeCompensationCommand>;
  private readonly verifyAuthority: RuntimeCompensationAuthorityVerifier;
  private readonly verifyEnforcementProof: RuntimeCompensationEnforcementProofVerifier;
  private readonly workerId: string;
  private readonly clock: () => number;
  private readonly leaseDurationMs: number;
  private readonly handleResolveTimeoutMs: number;
  private readonly runtimeCommandTimeoutMs: number;
  private readonly idleDelayMs: number;
  private readonly busyDelayMs: number;
  private readonly errorDelayMs: number;
  private readonly onOperationalError?: (code: "runtime_internal") => void;
  private controller: AbortController | null = null;
  private loopPromise: Promise<void> | null = null;
  private activeRun: Promise<RuntimeCompensationRunResult> | null = null;
  private activeRunController: AbortController | null = null;

  constructor(options: RuntimeCompensationSupervisorOptions) {
    const resolveHandle = captureRuntimeHandleResolver<RuntimeCompensationCommand>(
      options?.handles
    );
    if (!isSafeIdentifier(options.workerId, MAX_WORKER_ID_LENGTH)) {
      throw new TypeError("Invalid Runtime compensation worker ID");
    }
    if (
      typeof options.journal?.reconcile !== "function" ||
      typeof options.journal?.claim !== "function" ||
      typeof options.journal?.renew !== "function" ||
      typeof options.journal?.complete !== "function" ||
      typeof options.verifyAuthority !== "function" ||
      typeof options.verifyEnforcementProof !== "function"
    ) {
      throw new TypeError("Invalid Runtime compensation supervisor dependency");
    }
    this.runtimeDispatch = captureRuntimeCompensationDispatch(options.runtime);
    this.journal = options.journal;
    this.resolveHandle = resolveHandle;
    this.verifyAuthority = options.verifyAuthority;
    this.verifyEnforcementProof = options.verifyEnforcementProof;
    this.workerId = options.workerId;
    this.clock = options.clock ?? Date.now;
    if (typeof this.clock !== "function") throw new TypeError("Invalid Runtime clock");
    this.leaseDurationMs = boundedInteger(options.leaseDurationMs ?? 30_000, 1_000, 300_000);
    const maximumOperationMs = this.leaseDurationMs - 2 * LEASE_COMPLETION_MARGIN_MS;
    this.handleResolveTimeoutMs = boundedInteger(
      options.handleResolveTimeoutMs ?? Math.min(5_000, maximumOperationMs),
      1,
      maximumOperationMs
    );
    this.runtimeCommandTimeoutMs = boundedInteger(
      options.runtimeCommandTimeoutMs ?? Math.min(20_000, maximumOperationMs),
      1,
      maximumOperationMs
    );
    this.idleDelayMs = boundedInteger(options.idleDelayMs ?? 250, 1, 60_000);
    this.busyDelayMs = boundedInteger(options.busyDelayMs ?? 10, 1, 60_000);
    this.errorDelayMs = boundedInteger(options.errorDelayMs ?? 1_000, 1, 60_000);
    this.onOperationalError = options.onOperationalError;
  }

  get running(): boolean {
    return this.loopPromise !== null;
  }

  start(): void {
    if (this.loopPromise) return;
    const controller = new AbortController();
    this.controller = controller;
    this.loopPromise = this.loop(controller.signal).finally(() => {
      if (this.controller === controller) this.controller = null;
      this.loopPromise = null;
    });
  }

  async stop(): Promise<void> {
    const loop = this.loopPromise;
    const activeRun = this.activeRun;
    this.controller?.abort();
    this.activeRunController?.abort();
    await Promise.allSettled([...(loop ? [loop] : []), ...(activeRun ? [activeRun] : [])]);
  }

  /** Concurrent callers share one attempt; compensation is never batch-leased. */
  runOnce(): Promise<RuntimeCompensationRunResult> {
    if (this.activeRun) return this.activeRun;
    const controller = new AbortController();
    const unlink = linkAbortSignal(this.controller?.signal, controller);
    this.activeRunController = controller;
    const run = this.processOne(controller.signal).finally(() => {
      unlink();
      if (this.activeRunController === controller) this.activeRunController = null;
      if (this.activeRun === run) this.activeRun = null;
    });
    this.activeRun = run;
    return run;
  }

  private async loop(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      try {
        const result = await this.runOnce();
        const delay =
          result.failedBeforeDispatch + result.dispatchUncertain > 0
            ? this.errorDelayMs
            : result.claimed > 0
              ? this.busyDelayMs
              : this.idleDelayMs;
        await abortableDelay(delay, signal);
      } catch {
        reportOperationalError(this.onOperationalError);
        await abortableDelay(this.errorDelayMs, signal);
      }
    }
  }

  private async processOne(signal: AbortSignal): Promise<RuntimeCompensationRunResult> {
    if (signal.aborted) return emptyRunResult();
    const reconcileAtMs = sampleClock(this.clock);
    await this.journal.reconcile({ nowMs: reconcileAtMs });
    if (signal.aborted) return emptyRunResult();
    const claimedAtMs = sampleClock(this.clock, reconcileAtMs);
    const delivery = await this.journal.claim({
      workerId: this.workerId,
      leaseDurationMs: this.leaseDurationMs,
      nowMs: claimedAtMs,
    });
    if (delivery === null) return emptyRunResult();
    validateDelivery(delivery, this.workerId, claimedAtMs);

    const execution = await this.executeDelivery(delivery, signal);
    if (execution.kind === "expired-before-dispatch") {
      return { claimed: 1, receipts: 0, failedBeforeDispatch: 1, dispatchUncertain: 0 };
    }
    const observedAtMs = sampleClock(this.clock, claimedAtMs);
    await this.journal.complete({
      commandId: execution.delivery.command.commandId,
      workerId: this.workerId,
      expectedAttempt: execution.delivery.attempt,
      expectedLeaseExpiresAtMs: execution.delivery.leaseExpiresAtMs,
      observedAtMs,
      outcome: execution.outcome,
    });
    return {
      claimed: 1,
      receipts: execution.outcome.kind === "receipt" ? 1 : 0,
      failedBeforeDispatch:
        execution.outcome.kind === "failure" &&
        execution.outcome.dispatchCertainty === "not-dispatched"
          ? 1
          : 0,
      dispatchUncertain:
        execution.outcome.kind === "failure" &&
        execution.outcome.dispatchCertainty === "dispatch-uncertain"
          ? 1
          : 0,
    };
  }

  private async executeDelivery(
    delivery: RuntimeCompensationDelivery,
    signal: AbortSignal
  ): Promise<RuntimeCompensationExecution> {
    const resolveAtMs = sampleClock(this.clock);
    const remainingBeforeResolve = delivery.leaseExpiresAtMs - resolveAtMs;
    if (remainingBeforeResolve <= LEASE_COMPLETION_MARGIN_MS || signal.aborted) {
      return failureBeforeDispatch(delivery, "lease_expired_before_dispatch");
    }
    const resolved = await boundedOperation(
      (operationSignal) => this.resolveHandle(delivery.command, operationSignal),
      Math.min(this.handleResolveTimeoutMs, remainingBeforeResolve - LEASE_COMPLETION_MARGIN_MS),
      signal
    );
    const handle =
      resolved.kind === "value"
        ? snapshotExactRuntimeHandle(resolved.value, delivery.command.binding)
        : null;
    if (handle === null) {
      return failureBeforeDispatch(delivery, "runtime_handle_unavailable");
    }
    const renewalAtMs = sampleClock(this.clock);
    if (signal.aborted || renewalAtMs >= delivery.leaseExpiresAtMs - LEASE_COMPLETION_MARGIN_MS) {
      return failureBeforeDispatch(delivery, "lease_expired_before_dispatch");
    }
    const renewal = await this.journal.renew({
      commandId: delivery.command.commandId,
      workerId: this.workerId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      leaseDurationMs: this.leaseDurationMs,
      nowMs: renewalAtMs,
    });
    if (renewal.kind === "expired-before-dispatch") return { kind: renewal.kind };
    const renewedDelivery = validateRenewal(delivery, renewal, renewalAtMs);

    const dispatchAtMs = sampleClock(this.clock, renewalAtMs);
    const remainingAfterInterlock = renewedDelivery.leaseExpiresAtMs - dispatchAtMs;
    if (signal.aborted || remainingAfterInterlock <= LEASE_COMPLETION_MARGIN_MS) {
      return failureAfterInterlock(renewedDelivery);
    }
    const executed = await boundedOperation(
      (operationSignal) =>
        executeCapturedRuntimeCompensationCommand(
          this.runtimeDispatch,
          handle,
          renewedDelivery.command,
          this.verifyAuthority,
          this.clock,
          this.verifyEnforcementProof,
          operationSignal
        ),
      Math.min(this.runtimeCommandTimeoutMs, remainingAfterInterlock - LEASE_COMPLETION_MARGIN_MS),
      signal
    );
    if (executed.kind === "value") {
      return {
        kind: "attempt",
        delivery: renewedDelivery,
        outcome: { kind: "receipt", receipt: executed.value },
      };
    }
    if (executed.kind === "error" && executed.error instanceof RuntimeCompensationExecutionError) {
      return {
        kind: "attempt",
        delivery: renewedDelivery,
        outcome: {
          kind: "failure",
          code: executed.error.code,
          dispatchCertainty: executed.error.dispatchCertainty,
        },
      };
    }
    return failureAfterInterlock(renewedDelivery);
  }
}

export function createRuntimeCompensationSupervisor(
  options: RuntimeCompensationSupervisorOptions
): RuntimeCompensationSupervisor {
  return new RuntimeCompensationSupervisor(options);
}

type RuntimeCompensationExecution =
  | {
      readonly kind: "attempt";
      readonly delivery: RuntimeCompensationDelivery;
      readonly outcome: RuntimeCompensationAttemptOutcome;
    }
  | { readonly kind: "expired-before-dispatch" };

function failureBeforeDispatch(
  delivery: RuntimeCompensationDelivery,
  code: "runtime_handle_unavailable" | "lease_expired_before_dispatch"
): Extract<RuntimeCompensationExecution, { kind: "attempt" }> {
  return {
    kind: "attempt",
    delivery,
    outcome: { kind: "failure", code, dispatchCertainty: "not-dispatched" },
  };
}

function failureAfterInterlock(
  delivery: RuntimeCompensationDelivery
): Extract<RuntimeCompensationExecution, { kind: "attempt" }> {
  return {
    kind: "attempt",
    delivery,
    outcome: {
      kind: "failure",
      code: "runtime_internal",
      dispatchCertainty: "dispatch-uncertain",
    },
  };
}

function validateDelivery(
  delivery: RuntimeCompensationDelivery,
  workerId: string,
  claimedAtMs: number
): void {
  if (
    !delivery ||
    typeof delivery !== "object" ||
    !Number.isSafeInteger(delivery.attempt) ||
    delivery.attempt < 1 ||
    delivery.leaseOwner !== workerId ||
    !Number.isSafeInteger(delivery.leaseExpiresAtMs) ||
    delivery.leaseExpiresAtMs <= claimedAtMs ||
    delivery.priorDispatchCertainty !== "not-dispatched" ||
    !delivery.command ||
    typeof delivery.command !== "object" ||
    delivery.command.kind !== "safety.quarantine" ||
    !isSafeIdentifier(delivery.command.commandId, 300)
  ) {
    throw new TypeError("Invalid Runtime compensation delivery");
  }
}

function validateRenewal(
  delivery: RuntimeCompensationDelivery,
  renewal: Extract<RuntimeCompensationRenewal, { kind: "renewed" }>,
  renewedAtMs: number
): RuntimeCompensationDelivery {
  if (
    !Number.isSafeInteger(renewal.leaseExpiresAtMs) ||
    renewal.leaseExpiresAtMs < delivery.leaseExpiresAtMs ||
    renewal.leaseExpiresAtMs <= renewedAtMs
  ) {
    throw new TypeError("Invalid Runtime compensation lease renewal");
  }
  return Object.freeze({ ...delivery, leaseExpiresAtMs: renewal.leaseExpiresAtMs });
}

function emptyRunResult(): RuntimeCompensationRunResult {
  return { claimed: 0, receipts: 0, failedBeforeDispatch: 0, dispatchUncertain: 0 };
}

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError("Invalid Runtime compensation supervisor bound");
  }
  return value;
}

function sampleClock(clock: () => number, minimum = 0): number {
  let nowMs: number;
  try {
    nowMs = clock();
  } catch {
    throw new TypeError("Invalid Runtime clock");
  }
  if (!Number.isSafeInteger(nowMs) || nowMs < minimum) {
    throw new TypeError("Invalid Runtime clock");
  }
  return nowMs;
}

function isSafeIdentifier(value: unknown, maximumLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    !/[\0\r\n\t]/.test(value)
  );
}

function reportOperationalError(
  callback: RuntimeCompensationSupervisorOptions["onOperationalError"]
): void {
  try {
    callback?.("runtime_internal");
  } catch {
    // Observability must not terminate the supervisor loop.
  }
}

type BoundedOperationResult<T> =
  | { readonly kind: "value"; readonly value: T }
  | { readonly kind: "error"; readonly error: unknown }
  | { readonly kind: "timeout" }
  | { readonly kind: "aborted" };

function boundedOperation<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  parentSignal: AbortSignal
): Promise<BoundedOperationResult<T>> {
  return new Promise((resolve) => {
    let settled = false;
    const controller = new AbortController();
    if (parentSignal.aborted) {
      controller.abort();
      resolve({ kind: "aborted" });
      return;
    }
    const finish = (result: BoundedOperationResult<T>): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      parentSignal.removeEventListener("abort", abortFromParent);
      resolve(result);
    };
    const abortFromParent = () => {
      controller.abort();
      finish({ kind: "aborted" });
    };
    parentSignal.addEventListener("abort", abortFromParent, { once: true });
    const timer = setTimeout(() => {
      controller.abort();
      finish({ kind: "timeout" });
    }, timeoutMs);
    let pending: Promise<T>;
    try {
      pending = operation(controller.signal);
    } catch (error) {
      finish({ kind: "error", error });
      return;
    }
    Promise.resolve(pending).then(
      (value) => finish({ kind: "value", value }),
      (error: unknown) => finish({ kind: "error", error })
    );
  });
}

function linkAbortSignal(source: AbortSignal | undefined, target: AbortController): () => void {
  if (!source) return () => undefined;
  const abort = () => target.abort();
  if (source.aborted) {
    abort();
    return () => undefined;
  }
  source.addEventListener("abort", abort, { once: true });
  return () => source.removeEventListener("abort", abort);
}

function abortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(done, milliseconds);
    signal.addEventListener("abort", done, { once: true });
    function done() {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    }
  });
}
