import type { Runtime, RuntimeHandle, RuntimeLifecycleCommand, RuntimeReceipt } from "./contracts";
import {
  RuntimeCommandExecutionError,
  executeRuntimeCommand,
  type RuntimeAuthorityVerifier,
  type RuntimeCommandDispatchCertainty,
  type RuntimeCommandExecutionErrorCode,
} from "./runtime-command-execution";

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
 * command with any accepted receipt. Receipt/follow reconciliation is a separate
 * path outside this supervisor.
 */
export interface RuntimeLifecycleJournal {
  reconcile(options: RuntimeLifecycleReconcileOptions): Promise<void>;
  claim(options: RuntimeLifecycleClaimOptions): Promise<ReadonlyArray<RuntimeLifecycleDelivery>>;
  complete(completion: RuntimeLifecycleCompletion): Promise<void>;
}

/** Resolve only a handle whose binding exactly matches the claimed command. */
export interface RuntimeLifecycleHandleResolver {
  resolve(command: RuntimeLifecycleCommand): Promise<RuntimeHandle | null>;
}

export interface RuntimeLifecycleSupervisorOptions {
  readonly journal: RuntimeLifecycleJournal;
  readonly runtime: Runtime;
  readonly handles: RuntimeLifecycleHandleResolver;
  readonly verifyAuthority: RuntimeAuthorityVerifier;
  readonly workerId: string;
  readonly clock?: () => number;
  readonly claimLimit?: number;
  readonly leaseDurationMs?: number;
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
  private readonly runtime: Runtime;
  private readonly handles: RuntimeLifecycleHandleResolver;
  private readonly verifyAuthority: RuntimeAuthorityVerifier;
  private readonly workerId: string;
  private readonly clock: () => number;
  private readonly claimLimit: number;
  private readonly leaseDurationMs: number;
  private readonly idleDelayMs: number;
  private readonly busyDelayMs: number;
  private readonly errorDelayMs: number;
  private readonly onOperationalError?: (code: "runtime_internal") => void;
  private controller: AbortController | null = null;
  private loopPromise: Promise<void> | null = null;
  private activeRun: Promise<RuntimeLifecycleRunResult> | null = null;

  constructor(options: RuntimeLifecycleSupervisorOptions) {
    if (!isSafeWorkerId(options.workerId)) throw new TypeError("Invalid Runtime worker ID");
    if (
      typeof options.verifyAuthority !== "function" ||
      typeof options.journal?.reconcile !== "function" ||
      typeof options.journal?.claim !== "function" ||
      typeof options.journal?.complete !== "function" ||
      typeof options.handles?.resolve !== "function"
    ) {
      throw new TypeError("Invalid Runtime lifecycle supervisor dependency");
    }
    this.journal = options.journal;
    this.runtime = options.runtime;
    this.handles = options.handles;
    this.verifyAuthority = options.verifyAuthority;
    this.workerId = options.workerId;
    this.clock = options.clock ?? Date.now;
    if (typeof this.clock !== "function") throw new TypeError("Invalid Runtime clock");
    // A delivery has no renewable pre-dispatch lease fence yet. Keep a batch
    // singular so earlier work can never consume a later delivery's lease.
    this.claimLimit = boundedInteger(options.claimLimit ?? 1, 1, 1);
    this.leaseDurationMs = boundedInteger(options.leaseDurationMs ?? 30_000, 1_000, 300_000);
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
    if (!loop) return;
    this.controller?.abort();
    await loop;
  }

  /** Concurrent callers share one batch so a worker cannot claim against itself. */
  runOnce(): Promise<RuntimeLifecycleRunResult> {
    if (this.activeRun) return this.activeRun;
    const run = this.processOneBatch().finally(() => {
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

  private async processOneBatch(): Promise<RuntimeLifecycleRunResult> {
    const reconcileAtMs = sampleClock(this.clock);
    await this.journal.reconcile({ nowMs: reconcileAtMs });
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
      const outcome = await this.executeDelivery(delivery);
      const observedAtMs = sampleClock(this.clock, claimAtMs);
      await this.journal.complete({
        commandId: delivery.command.commandId,
        workerId: this.workerId,
        expectedAttempt: delivery.attempt,
        expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
        observedAtMs,
        outcome,
      });
      if (outcome.kind === "receipt") result.receipts += 1;
      else if (outcome.dispatchCertainty === "not-dispatched") {
        result.failedBeforeDispatch += 1;
      } else {
        result.dispatchUncertain += 1;
      }
    }
    return result;
  }

  private async executeDelivery(
    delivery: RuntimeLifecycleDelivery
  ): Promise<RuntimeLifecycleAttemptOutcome> {
    const handle = await this.handles.resolve(delivery.command);
    if (handle === null) {
      return {
        kind: "failure",
        code: "runtime_handle_unavailable",
        dispatchCertainty: "not-dispatched",
      };
    }
    if (sampleClock(this.clock) >= delivery.leaseExpiresAtMs) {
      return {
        kind: "failure",
        code: "lease_expired_before_dispatch",
        dispatchCertainty: "not-dispatched",
      };
    }

    try {
      const receipt = await executeRuntimeCommand(
        this.runtime,
        handle,
        delivery.command,
        this.verifyAuthority,
        this.clock
      );
      return { kind: "receipt", receipt };
    } catch (error) {
      if (error instanceof RuntimeCommandExecutionError) {
        return {
          kind: "failure",
          code: error.code,
          dispatchCertainty: error.dispatchCertainty,
        };
      }
      return {
        kind: "failure",
        code: "runtime_internal",
        dispatchCertainty: "dispatch-uncertain",
      };
    }
  }
}

export function createRuntimeLifecycleSupervisor(
  options: RuntimeLifecycleSupervisorOptions
): RuntimeLifecycleSupervisor {
  return new RuntimeLifecycleSupervisor(options);
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
