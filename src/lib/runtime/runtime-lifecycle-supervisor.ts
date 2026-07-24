import type { Runtime, RuntimeHandle, RuntimeLifecycleCommand, RuntimeReceipt } from "./contracts";
import {
  RuntimeCommandExecutionError,
  captureRuntimeLifecycleDispatch,
  executeCapturedRuntimeCommand,
  type RuntimeAuthorityVerifier,
  type RuntimeCommandDispatchCertainty,
  type RuntimeCommandExecutionErrorCode,
  type RuntimeLifecycleDispatch,
} from "./runtime-command-execution";
import type { RuntimeEnforcementProofVerifier } from "./runtime-enforcement-proof";
import {
  captureRuntimeHandleResolver,
  snapshotExactRuntimeHandle,
  type CapturedRuntimeHandleResolver,
} from "./runtime-handle-resolution";

const MAX_WORKER_ID_LENGTH = 128;

export interface RuntimeLifecycleReconcileOptions {
  /** Stale processing leases at or before this instant must be reconciled conservatively. */
  readonly nowMs: number;
}

export interface RuntimeLifecycleClaimOptions {
  readonly workerId: string;
  readonly limit: number;
  readonly leaseDurationMs: number;
  readonly nowMs: number;
}

export interface RuntimeLifecycleRenewalOptions {
  readonly commandId: string;
  readonly workerId: string;
  readonly expectedAttempt: number;
  readonly expectedLeaseExpiresAtMs: number;
  readonly leaseDurationMs: number;
  readonly nowMs: number;
}

export type RuntimeLifecycleRenewal =
  | {
      /** The exact attempt is still current and exclusively fenced for dispatch. */
      readonly kind: "renewed";
      readonly leaseExpiresAtMs: number;
    }
  | {
      /** Current trust changed; the journal durably proved and recorded non-dispatch. */
      readonly kind: "superseded";
    };

/** One exact command protected by an attempt-and-lease ownership fence. */
export interface RuntimeLifecycleDelivery {
  readonly command: RuntimeLifecycleCommand;
  readonly attempt: number;
  readonly leaseOwner: string;
  readonly leaseExpiresAtMs: number;
  /** Proof that no earlier attempt or receipt made enforcement possible. */
  readonly priorDispatchCertainty: "not-dispatched";
}

export type RuntimeLifecycleFailureCode =
  | RuntimeCommandExecutionErrorCode
  | "runtime_handle_unavailable"
  | "lease_expired_before_dispatch"
  | "runtime_internal";

export type RuntimeLifecycleAttemptOutcome =
  | { readonly kind: "receipt"; readonly receipt: RuntimeReceipt }
  | {
      readonly kind: "failure";
      readonly code: RuntimeLifecycleFailureCode;
      readonly dispatchCertainty: RuntimeCommandDispatchCertainty;
    };

/**
 * Completion is accepted only when the stored processing state, owner, attempt,
 * and exact expiry still match. It may race lease reconciliation; exactly one
 * transaction wins. A journal must record the receipt or failure and transition
 * dispatch state in one transaction. Accepted receipts and
 * `dispatch-uncertain` failures become receipt-reconciliation work, never generic
 * command retries.
 */
export interface RuntimeLifecycleCompletion {
  readonly commandId: string;
  readonly workerId: string;
  readonly expectedAttempt: number;
  readonly expectedLeaseExpiresAtMs: number;
  readonly observedAtMs: number;
  readonly outcome: RuntimeLifecycleAttemptOutcome;
}

/**
 * Durable dispatch journal seam. Implementations own recovery and state-machine
 * policy; the supervisor never writes lifecycle state or receipts itself.
 * `reconcile` must move an expired processing lease to awaiting-receipt, not
 * pending. `claim` may lease only pending commands for which every prior attempt
 * is provably not-dispatched; it must never lease awaiting-receipt work or a
 * command with any accepted receipt. `renew` is the final pre-dispatch
 * authorization point: it must atomically re-check the complete persisted
 * Run/Session/Assignment/policy/authorization/deadline fence while extending
 * the exact live lease. A changed trust fence is durably superseded as
 * not-dispatched; a missing or expired lease is a stale error. Receipt/follow
 * reconciliation is a separate path outside this supervisor.
 */
export interface RuntimeLifecycleJournal {
  reconcile(options: RuntimeLifecycleReconcileOptions): Promise<void>;
  claim(options: RuntimeLifecycleClaimOptions): Promise<ReadonlyArray<RuntimeLifecycleDelivery>>;
  renew(options: RuntimeLifecycleRenewalOptions): Promise<RuntimeLifecycleRenewal>;
  complete(completion: RuntimeLifecycleCompletion): Promise<void>;
}

/** Resolve only a handle whose binding exactly matches the claimed command. */
export interface RuntimeLifecycleHandleResolver {
  /** Implementations must propagate cancellation to any backing transport or lookup. */
  resolve(command: RuntimeLifecycleCommand, signal: AbortSignal): Promise<RuntimeHandle | null>;
}

export interface RuntimeLifecycleSupervisorOptions {
  readonly journal: RuntimeLifecycleJournal;
  readonly runtime: Runtime;
  readonly handles: RuntimeLifecycleHandleResolver;
  readonly verifyAuthority: RuntimeAuthorityVerifier;
  readonly verifyEnforcementProof: RuntimeEnforcementProofVerifier;
  readonly workerId: string;
  readonly clock?: () => number;
  readonly claimLimit?: number;
  readonly leaseDurationMs?: number;
  readonly handleResolveTimeoutMs?: number;
  readonly runtimeCommandTimeoutMs?: number;
  readonly idleDelayMs?: number;
  readonly busyDelayMs?: number;
  readonly errorDelayMs?: number;
  readonly onOperationalError?: (code: "runtime_internal") => void;
}

export interface RuntimeLifecycleRunResult {
  readonly claimed: number;
  readonly receipts: number;
  readonly failedBeforeDispatch: number;
  readonly dispatchUncertain: number;
}

/**
 * Bounded orchestration around the portable Runtime executor. This class is
 * deliberately inert until `start` or `runOnce` is called by a composition
 * root; importing it has no production side effects.
 */
export class RuntimeLifecycleSupervisor {
  private readonly journal: RuntimeLifecycleJournal;
  private readonly runtimeDispatch: RuntimeLifecycleDispatch;
  private readonly resolveHandle: CapturedRuntimeHandleResolver<RuntimeLifecycleCommand>;
  private readonly verifyAuthority: RuntimeAuthorityVerifier;
  private readonly verifyEnforcementProof: RuntimeEnforcementProofVerifier;
  private readonly workerId: string;
  private readonly clock: () => number;
  private readonly claimLimit: number;
  private readonly leaseDurationMs: number;
  private readonly handleResolveTimeoutMs: number;
  private readonly runtimeCommandTimeoutMs: number;
  private readonly idleDelayMs: number;
  private readonly busyDelayMs: number;
  private readonly errorDelayMs: number;
  private readonly onOperationalError?: (code: "runtime_internal") => void;
  private controller: AbortController | null = null;
  private loopPromise: Promise<void> | null = null;
  private activeRun: Promise<RuntimeLifecycleRunResult> | null = null;
  private activeRunController: AbortController | null = null;

  constructor(options: RuntimeLifecycleSupervisorOptions) {
    const resolveHandle = captureRuntimeHandleResolver<RuntimeLifecycleCommand>(options?.handles);
    if (!isSafeWorkerId(options.workerId)) throw new TypeError("Invalid Runtime worker ID");
    if (
      typeof options.verifyAuthority !== "function" ||
      typeof options.verifyEnforcementProof !== "function" ||
      typeof options.journal?.reconcile !== "function" ||
      typeof options.journal?.claim !== "function" ||
      typeof options.journal?.renew !== "function" ||
      typeof options.journal?.complete !== "function"
    ) {
      throw new TypeError("Invalid Runtime lifecycle supervisor dependency");
    }
    this.runtimeDispatch = captureRuntimeLifecycleDispatch(options.runtime);
    this.journal = options.journal;
    this.resolveHandle = resolveHandle;
    this.verifyAuthority = options.verifyAuthority;
    this.verifyEnforcementProof = options.verifyEnforcementProof;
    this.workerId = options.workerId;
    this.clock = options.clock ?? Date.now;
    if (typeof this.clock !== "function") throw new TypeError("Invalid Runtime clock");
    // Keep a batch singular so earlier work can never consume a later
    // delivery's initial lease before that delivery can renew its own fence.
    this.claimLimit = boundedInteger(options.claimLimit ?? 1, 1, 1);
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

  /** Concurrent callers share one batch so a worker cannot claim against itself. */
  runOnce(): Promise<RuntimeLifecycleRunResult> {
    if (this.activeRun) return this.activeRun;
    const controller = new AbortController();
    const unlink = linkAbortSignal(this.controller?.signal, controller);
    this.activeRunController = controller;
    const run = this.processOneBatch(controller.signal).finally(() => {
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
        const failures = result.failedBeforeDispatch + result.dispatchUncertain;
        const delay =
          failures > 0
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

  private async processOneBatch(signal: AbortSignal): Promise<RuntimeLifecycleRunResult> {
    if (signal.aborted) return emptyRunResult();
    const reconcileAtMs = sampleClock(this.clock);
    await this.journal.reconcile({ nowMs: reconcileAtMs });
    if (signal.aborted) return emptyRunResult();
    const claimAtMs = sampleClock(this.clock, reconcileAtMs);
    const deliveries = await this.journal.claim({
      workerId: this.workerId,
      limit: this.claimLimit,
      leaseDurationMs: this.leaseDurationMs,
      nowMs: claimAtMs,
    });
    if (!Array.isArray(deliveries) || deliveries.length > this.claimLimit) {
      throw new TypeError("Invalid Runtime lifecycle claim result");
    }

    const result = {
      claimed: deliveries.length,
      receipts: 0,
      failedBeforeDispatch: 0,
      dispatchUncertain: 0,
    };
    for (const delivery of deliveries) {
      validateDelivery(delivery, this.workerId, claimAtMs);
      const execution = await this.executeDelivery(delivery, signal);
      if (execution.kind === "superseded") {
        result.failedBeforeDispatch += 1;
        continue;
      }
      const observedAtMs = sampleClock(this.clock, claimAtMs);
      await this.journal.complete({
        commandId: execution.delivery.command.commandId,
        workerId: this.workerId,
        expectedAttempt: execution.delivery.attempt,
        expectedLeaseExpiresAtMs: execution.delivery.leaseExpiresAtMs,
        observedAtMs,
        outcome: execution.outcome,
      });
      if (execution.outcome.kind === "receipt") result.receipts += 1;
      else if (execution.outcome.dispatchCertainty === "not-dispatched") {
        result.failedBeforeDispatch += 1;
      } else {
        result.dispatchUncertain += 1;
      }
    }
    return result;
  }

  private async executeDelivery(
    delivery: RuntimeLifecycleDelivery,
    signal: AbortSignal
  ): Promise<RuntimeLifecycleExecution> {
    const resolveAtMs = sampleClock(this.clock);
    const resolveRemainingMs = delivery.leaseExpiresAtMs - resolveAtMs;
    if (resolveRemainingMs <= LEASE_COMPLETION_MARGIN_MS) {
      return {
        kind: "attempt",
        delivery,
        outcome: {
          kind: "failure",
          code: "lease_expired_before_dispatch",
          dispatchCertainty: "not-dispatched",
        },
      };
    }
    if (signal.aborted) return unavailableBeforeDispatch(delivery);
    const resolved = await boundedOperation(
      (operationSignal) => this.resolveHandle(delivery.command, operationSignal),
      Math.min(this.handleResolveTimeoutMs, resolveRemainingMs - LEASE_COMPLETION_MARGIN_MS),
      signal
    );
    const handle =
      resolved.kind === "value"
        ? snapshotExactRuntimeHandle(resolved.value, delivery.command.binding)
        : null;
    if (handle === null) {
      return {
        kind: "attempt",
        delivery,
        outcome: {
          kind: "failure",
          code: "runtime_handle_unavailable",
          dispatchCertainty: "not-dispatched",
        },
      };
    }
    const renewalAtMs = sampleClock(this.clock);
    if (signal.aborted) return unavailableBeforeDispatch(delivery);
    if (renewalAtMs >= delivery.leaseExpiresAtMs - LEASE_COMPLETION_MARGIN_MS) {
      return {
        kind: "attempt",
        delivery,
        outcome: {
          kind: "failure",
          code: "lease_expired_before_dispatch",
          dispatchCertainty: "not-dispatched",
        },
      };
    }

    const renewal = await this.journal.renew({
      commandId: delivery.command.commandId,
      workerId: this.workerId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      leaseDurationMs: this.leaseDurationMs,
      nowMs: renewalAtMs,
    });
    const renewedDelivery = validateRenewal(delivery, renewal, renewalAtMs);
    if (renewedDelivery === null) return { kind: "superseded" };
    const dispatchAtMs = sampleClock(this.clock, renewalAtMs);
    if (signal.aborted) return unavailableBeforeDispatch(renewedDelivery);
    const remainingMs = renewedDelivery.leaseExpiresAtMs - dispatchAtMs;
    if (remainingMs <= LEASE_COMPLETION_MARGIN_MS) {
      return {
        kind: "attempt",
        delivery: renewedDelivery,
        outcome: {
          kind: "failure",
          code: "lease_expired_before_dispatch",
          dispatchCertainty: "not-dispatched",
        },
      };
    }
    const timeoutMs = Math.min(
      this.runtimeCommandTimeoutMs,
      remainingMs - LEASE_COMPLETION_MARGIN_MS
    );

    const executed = await boundedOperation(
      (operationSignal) =>
        executeCapturedRuntimeCommand(
          this.runtimeDispatch,
          handle,
          renewedDelivery.command,
          this.verifyAuthority,
          this.clock,
          this.verifyEnforcementProof,
          operationSignal
        ),
      timeoutMs,
      signal
    );
    if (executed.kind === "value") {
      return {
        kind: "attempt",
        delivery: renewedDelivery,
        outcome: { kind: "receipt", receipt: executed.value },
      };
    }
    if (executed.kind === "error" && executed.error instanceof RuntimeCommandExecutionError) {
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
    return {
      kind: "attempt",
      delivery: renewedDelivery,
      outcome: {
        kind: "failure",
        code: "runtime_internal",
        dispatchCertainty: "dispatch-uncertain",
      },
    };
  }
}

export function createRuntimeLifecycleSupervisor(
  options: RuntimeLifecycleSupervisorOptions
): RuntimeLifecycleSupervisor {
  return new RuntimeLifecycleSupervisor(options);
}

function emptyRunResult(): RuntimeLifecycleRunResult {
  return {
    claimed: 0,
    receipts: 0,
    failedBeforeDispatch: 0,
    dispatchUncertain: 0,
  };
}

function unavailableBeforeDispatch(delivery: RuntimeLifecycleDelivery): {
  readonly kind: "attempt";
  readonly delivery: RuntimeLifecycleDelivery;
  readonly outcome: RuntimeLifecycleAttemptOutcome;
} {
  return {
    kind: "attempt",
    delivery,
    outcome: {
      kind: "failure",
      code: "runtime_handle_unavailable",
      dispatchCertainty: "not-dispatched",
    },
  };
}

function validateDelivery(
  delivery: RuntimeLifecycleDelivery,
  workerId: string,
  claimedAtMs: number
): void {
  if (
    delivery === null ||
    typeof delivery !== "object" ||
    !Number.isSafeInteger(delivery.attempt) ||
    delivery.attempt < 1 ||
    delivery.leaseOwner !== workerId ||
    !Number.isSafeInteger(delivery.leaseExpiresAtMs) ||
    delivery.leaseExpiresAtMs <= claimedAtMs ||
    delivery.priorDispatchCertainty !== "not-dispatched" ||
    delivery.command === null ||
    typeof delivery.command !== "object" ||
    !isSafeIdentifier(delivery.command.commandId, 300)
  ) {
    throw new TypeError("Invalid Runtime lifecycle delivery");
  }
}

function validateRenewal(
  delivery: RuntimeLifecycleDelivery,
  renewal: RuntimeLifecycleRenewal,
  renewedAtMs: number
): RuntimeLifecycleDelivery | null {
  if (
    renewal === null ||
    typeof renewal !== "object" ||
    (renewal.kind !== "renewed" && renewal.kind !== "superseded")
  ) {
    throw new TypeError("Invalid Runtime lifecycle lease renewal");
  }
  if (renewal.kind === "superseded") return null;
  if (
    !Number.isSafeInteger(renewal.leaseExpiresAtMs) ||
    renewal.leaseExpiresAtMs < delivery.leaseExpiresAtMs ||
    renewal.leaseExpiresAtMs <= renewedAtMs
  ) {
    throw new TypeError("Invalid Runtime lifecycle lease renewal");
  }
  return Object.freeze({ ...delivery, leaseExpiresAtMs: renewal.leaseExpiresAtMs });
}

type RuntimeLifecycleExecution =
  | {
      readonly kind: "attempt";
      readonly delivery: RuntimeLifecycleDelivery;
      readonly outcome: RuntimeLifecycleAttemptOutcome;
    }
  | { readonly kind: "superseded" };

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError("Invalid Runtime lifecycle supervisor bound");
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

function isSafeWorkerId(value: string): boolean {
  return isSafeIdentifier(value, MAX_WORKER_ID_LENGTH);
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
  callback: RuntimeLifecycleSupervisorOptions["onOperationalError"]
): void {
  try {
    callback?.("runtime_internal");
  } catch {
    // Observability must not terminate the supervisor loop.
  }
}

const LEASE_COMPLETION_MARGIN_MS = 250;

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

    function finish(result: BoundedOperationResult<T>): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      parentSignal.removeEventListener("abort", abortFromParent);
      resolve(result);
    }
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
