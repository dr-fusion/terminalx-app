import { types as nodeTypes } from "node:util";
import type { RuntimeHandle, RuntimeLifecycleCommand, RuntimeReceipt } from "./contracts";
import type { RuntimeCommandCapability } from "./runtime-command-dispatch";
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
import {
  linkRuntimeAbortSignal,
  runBoundedRuntimeOperation,
  runtimeHealthClockMinimum,
  runtimeAbortableDelay,
  sampleRuntimeHealthClock,
} from "./runtime-supervisor-operation";
import {
  exactRuntimeSupervisorDataRecord as exactDataRecord,
  runtimeSupervisorCommandValidationInstant as commandStructuralValidationInstant,
  runtimeSupervisorDataField as dataField,
  snapshotRuntimeSupervisorPortableData as snapshotPortableData,
} from "./runtime-supervisor-snapshot";
import type { RuntimeManagedSupervisorHealth } from "./runtime-supervisor-root";

const MAX_WORKER_ID_LENGTH = 128;
const DELIVERY_FIELDS = [
  "command",
  "attempt",
  "leaseOwner",
  "leaseExpiresAtMs",
  "priorDispatchCertainty",
] as const;

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
  readonly runtime: RuntimeCommandCapability;
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
  private lastSuccessAtMs: number | null = null;
  private lastErrorAtMs: number | null = null;
  private activeCycleStartedAtMs: number | null = null;
  private failureSinceSuccess = false;

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

  health(): RuntimeManagedSupervisorHealth {
    return Object.freeze({
      lastSuccessAtMs: this.lastSuccessAtMs,
      lastErrorAtMs: this.lastErrorAtMs,
      activeCycleStartedAtMs: this.activeCycleStartedAtMs,
      failureSinceSuccess: this.failureSinceSuccess,
    });
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
    const unlink = linkRuntimeAbortSignal(this.controller?.signal, controller);
    this.activeRunController = controller;
    const run = this.processOneBatch(controller.signal)
      .then(
        (result) => {
          const minimum = runtimeHealthClockMinimum(
            this.activeCycleStartedAtMs,
            this.lastSuccessAtMs,
            this.lastErrorAtMs
          );
          const settledAtMs = sampleRuntimeHealthClock(this.clock, minimum);
          if (settledAtMs === null) {
            this.lastErrorAtMs = minimum;
            this.failureSinceSuccess = true;
          } else {
            this.lastSuccessAtMs = settledAtMs;
            this.failureSinceSuccess = false;
          }
          return result;
        },
        (error: unknown) => {
          const minimum = runtimeHealthClockMinimum(
            this.activeCycleStartedAtMs,
            this.lastSuccessAtMs,
            this.lastErrorAtMs
          );
          this.lastErrorAtMs = sampleRuntimeHealthClock(this.clock, minimum) ?? minimum;
          this.failureSinceSuccess = true;
          throw error;
        }
      )
      .finally(() => {
        unlink();
        this.activeCycleStartedAtMs = null;
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
        await runtimeAbortableDelay(delay, signal);
      } catch {
        reportOperationalError(this.onOperationalError);
        await runtimeAbortableDelay(this.errorDelayMs, signal);
      }
    }
  }

  private async processOneBatch(signal: AbortSignal): Promise<RuntimeLifecycleRunResult> {
    if (signal.aborted) return emptyRunResult();
    const reconcileAtMs = sampleClock(this.clock);
    this.activeCycleStartedAtMs = reconcileAtMs;
    await this.journal.reconcile({ nowMs: reconcileAtMs });
    if (signal.aborted) return emptyRunResult();
    const claimAtMs = sampleClock(this.clock, reconcileAtMs);
    const claimed = await this.journal.claim({
      workerId: this.workerId,
      limit: this.claimLimit,
      leaseDurationMs: this.leaseDurationMs,
      nowMs: claimAtMs,
    });
    const deliveries = snapshotClaimedDeliveries(
      claimed,
      this.workerId,
      claimAtMs,
      this.claimLimit
    );

    const result = {
      claimed: deliveries.length,
      receipts: 0,
      failedBeforeDispatch: 0,
      dispatchUncertain: 0,
    };
    for (const delivery of deliveries) {
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
    const resolved = await runBoundedRuntimeOperation(
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

    const executed = await runBoundedRuntimeOperation(
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

function snapshotClaimedDeliveries(
  value: unknown,
  workerId: string,
  claimedAtMs: number,
  limit: number
): ReadonlyArray<RuntimeLifecycleDelivery> {
  try {
    if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) {
      throw new TypeError();
    }
    if (!Array.isArray(value)) throw new TypeError();
    const keys = Reflect.ownKeys(value);
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (!lengthDescriptor || !("value" in lengthDescriptor)) throw new TypeError();
    const length = lengthDescriptor.value;
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      length > limit ||
      keys.length !== length + 1 ||
      !keys.includes("length")
    ) {
      throw new TypeError();
    }
    const deliveries: RuntimeLifecycleDelivery[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new TypeError();
      }
      deliveries.push(snapshotDelivery(descriptor.value, workerId, claimedAtMs));
    }
    return Object.freeze(deliveries);
  } catch (error) {
    if (error instanceof InvalidRuntimeLifecycleDeliveryError) throw error;
    throw new TypeError("Invalid Runtime lifecycle claim result");
  }
}

class InvalidRuntimeLifecycleDeliveryError extends TypeError {
  constructor() {
    super("Invalid Runtime lifecycle delivery");
    this.name = "InvalidRuntimeLifecycleDeliveryError";
  }
}

function snapshotDelivery(
  value: unknown,
  workerId: string,
  claimedAtMs: number
): RuntimeLifecycleDelivery {
  try {
    const snapshot = snapshotPortableData(value);
    const delivery = exactDataRecord(snapshot, DELIVERY_FIELDS);
    const attempt = dataField(delivery, "attempt");
    const leaseOwner = dataField(delivery, "leaseOwner");
    const leaseExpiresAtMs = dataField(delivery, "leaseExpiresAtMs");
    if (
      !Number.isSafeInteger(attempt) ||
      (attempt as number) < 1 ||
      leaseOwner !== workerId ||
      !Number.isSafeInteger(leaseExpiresAtMs) ||
      (leaseExpiresAtMs as number) <= claimedAtMs ||
      dataField(delivery, "priorDispatchCertainty") !== "not-dispatched"
    ) {
      throw new TypeError();
    }
    const command = snapshotLifecycleCommand(dataField(delivery, "command"), claimedAtMs);
    return Object.freeze({
      command,
      attempt: attempt as number,
      leaseOwner: leaseOwner as string,
      leaseExpiresAtMs: leaseExpiresAtMs as number,
      priorDispatchCertainty: "not-dispatched",
    });
  } catch {
    throw new InvalidRuntimeLifecycleDeliveryError();
  }
}

/**
 * Reuse the executor's exact command snapshot and schema preflight without
 * crossing an authority or Runtime seam. Async functions run synchronously to
 * their first await, so the inert verifier captures the validated snapshot
 * before this helper returns; its deliberate rejection is consumed locally.
 */
function snapshotLifecycleCommand(value: unknown, nowMs: number): RuntimeLifecycleCommand {
  const command = value as RuntimeLifecycleCommand;
  const commandRecord = exactDataRecord(command, Reflect.ownKeys(command) as string[]);
  const binding = dataField(commandRecord, "binding") as RuntimeHandle["binding"];
  const validationAtMs = commandStructuralValidationInstant(commandRecord, nowMs);
  const validationHandle: RuntimeHandle = Object.freeze({
    binding,
    opaqueHandleRef: "supervisor-command-validation",
    capabilities: Object.freeze({
      isolatedExecution: true,
      brokeredCredentials: true,
      proxyOnlyEgress: true,
      checkpoints: true,
      yoloEligible: true,
    }),
  });
  let snapshot: RuntimeLifecycleCommand | undefined;
  const validation = executeCapturedRuntimeCommand(
    () => Promise.reject(new TypeError()),
    validationHandle,
    command,
    (input) => {
      snapshot = input.command;
      return false;
    },
    () => validationAtMs,
    () => false,
    new AbortController().signal
  );
  void validation.catch(() => undefined);
  if (!snapshot) throw new TypeError();
  return snapshot;
}

function validateRenewal(
  delivery: RuntimeLifecycleDelivery,
  value: RuntimeLifecycleRenewal,
  renewedAtMs: number
): RuntimeLifecycleDelivery | null {
  let renewal: Record<string, unknown>;
  try {
    const snapshot = snapshotPortableData(value);
    if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot)) {
      throw new TypeError();
    }
    const kind = dataField(snapshot as Record<string, unknown>, "kind");
    renewal = exactDataRecord(
      snapshot,
      kind === "superseded" ? ["kind"] : ["kind", "leaseExpiresAtMs"]
    );
    if (kind !== "renewed" && kind !== "superseded") throw new TypeError();
  } catch {
    throw new TypeError("Invalid Runtime lifecycle lease renewal");
  }
  if (dataField(renewal, "kind") === "superseded") return null;
  const leaseExpiresAtMs = dataField(renewal, "leaseExpiresAtMs");
  if (
    !Number.isSafeInteger(leaseExpiresAtMs) ||
    (leaseExpiresAtMs as number) < delivery.leaseExpiresAtMs ||
    (leaseExpiresAtMs as number) <= renewedAtMs
  ) {
    throw new TypeError("Invalid Runtime lifecycle lease renewal");
  }
  return Object.freeze({
    command: delivery.command,
    attempt: delivery.attempt,
    leaseOwner: delivery.leaseOwner,
    leaseExpiresAtMs: leaseExpiresAtMs as number,
    priorDispatchCertainty: delivery.priorDispatchCertainty,
  });
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
