import {
  RUNTIME_OUTBOX_ERROR_CODES,
  TEAM_SESSION_SCHEMA_VERSION,
  type CommandResult,
  type RuntimeOutboxClaimOptions,
  type RuntimeOutboxDelivery,
  type RuntimeOutboxErrorCode,
  type SessionCommand,
  type TeamSessions,
} from "../team-sessions";
import { RuntimeEffectError } from "./local-tmux-runtime";
import type { RuntimeManagedSupervisorHealth } from "./runtime-supervisor-root";
import {
  linkRuntimeAbortSignal,
  runBoundedRuntimeOperation,
  runtimeAbortableDelay,
  runtimeHealthClockMinimum,
  sampleRuntimeHealthClock,
} from "./runtime-supervisor-operation";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";

export interface RuntimeOutboxApplier {
  apply(delivery: RuntimeOutboxDelivery, signal: AbortSignal): Promise<void>;
  reconcile(delivery: RuntimeOutboxDelivery, signal: AbortSignal): Promise<void>;
}

export type RuntimeOutboxKernel = Pick<
  TeamSessions,
  "claimRuntimeOutbox" | "markRuntimeOutboxDispatch" | "renewRuntimeOutboxLease" | "dispatch"
>;

export interface RuntimeOutboxWorkerOptions {
  kernel: RuntimeOutboxKernel;
  runtime: RuntimeOutboxApplier;
  workerId: string;
  clock?: () => number;
  claimLimit?: number;
  leaseDurationMs?: number;
  idleDelayMs?: number;
  busyDelayMs?: number;
  errorDelayMs?: number;
  maxTransientAttempts?: number;
  runtimeEffectTimeoutMs?: number;
  leaseHeartbeatIntervalMs?: number;
  onOperationalError?: (code: RuntimeOutboxErrorCode) => void;
}

export interface RuntimeOutboxRunResult {
  claimed: number;
  acknowledged: number;
  retried: number;
  failedPermanently: number;
}

interface RuntimeOutboxLeaseIdentity {
  readonly outboxId: string;
  readonly attempts: number;
  leaseExpiresAtMs: number;
}

export class RuntimeOutboxWorker {
  private readonly kernel: RuntimeOutboxKernel;
  private readonly runtime: RuntimeOutboxApplier;
  private readonly workerId: string;
  private readonly clock: () => number;
  private readonly claimOptions: RuntimeOutboxClaimOptions;
  private readonly idleDelayMs: number;
  private readonly busyDelayMs: number;
  private readonly errorDelayMs: number;
  private readonly maxTransientAttempts: number;
  private readonly leaseDurationMs: number;
  private readonly runtimeEffectTimeoutMs: number;
  private readonly leaseHeartbeatIntervalMs: number;
  private readonly onOperationalError?: (code: RuntimeOutboxErrorCode) => void;
  private controller: AbortController | null = null;
  private loopPromise: Promise<void> | null = null;
  private activeRun: Promise<RuntimeOutboxRunResult> | null = null;
  private activeRunController: AbortController | null = null;
  private lastSuccessAtMs: number | null = null;
  private lastErrorAtMs: number | null = null;
  private activeCycleStartedAtMs: number | null = null;
  private failureSinceSuccess = false;

  constructor(options: RuntimeOutboxWorkerOptions) {
    if (!isSafeIdentifier(options.workerId)) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    this.kernel = options.kernel;
    this.runtime = options.runtime;
    this.workerId = options.workerId;
    this.clock = options.clock ?? Date.now;
    this.leaseDurationMs = boundedInteger(options.leaseDurationMs ?? 30_000, 1_000, 300_000);
    this.claimOptions = {
      workerId: options.workerId,
      // Later deliveries in a batch could expire while an earlier effect is
      // running. Keep assignment work singular so every attempt is renewed
      // before crossing its own point of no return.
      limit: boundedInteger(options.claimLimit ?? 1, 1, 1),
      leaseDurationMs: this.leaseDurationMs,
    };
    this.idleDelayMs = boundedInteger(options.idleDelayMs ?? 250, 1, 60_000);
    this.busyDelayMs = boundedInteger(options.busyDelayMs ?? 10, 1, 60_000);
    this.errorDelayMs = boundedInteger(options.errorDelayMs ?? 1_000, 1, 60_000);
    this.maxTransientAttempts = boundedInteger(options.maxTransientAttempts ?? 5, 1, 100);
    this.runtimeEffectTimeoutMs = boundedInteger(
      options.runtimeEffectTimeoutMs ?? Math.min(120_000, this.leaseDurationMs * 4),
      1,
      300_000
    );
    this.leaseHeartbeatIntervalMs = boundedInteger(
      options.leaseHeartbeatIntervalMs ?? Math.max(10, Math.floor(this.leaseDurationMs / 3)),
      10,
      Math.max(10, Math.floor(this.leaseDurationMs / 2))
    );
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
    const active = this.activeRun;
    this.controller?.abort();
    this.activeRunController?.abort();
    await Promise.allSettled([...(loop ? [loop] : []), ...(active ? [active] : [])]);
  }

  runOnce(): Promise<RuntimeOutboxRunResult> {
    if (this.activeRun) return this.activeRun;
    const controller = new AbortController();
    const unlink = linkRuntimeAbortSignal(this.controller?.signal, controller);
    this.activeRunController = controller;
    this.activeCycleStartedAtMs = sampleRuntimeHealthClock(this.clock);
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
        const delay =
          result.retried > 0
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

  private async processOneBatch(signal: AbortSignal): Promise<RuntimeOutboxRunResult> {
    if (signal.aborted) return emptyRunResult();
    const deliveries = await this.kernel.claimRuntimeOutbox(this.claimOptions);
    if (deliveries.length > 1) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const result: RuntimeOutboxRunResult = {
      claimed: deliveries.length,
      acknowledged: 0,
      retried: 0,
      failedPermanently: 0,
    };
    for (const unsafeDelivery of deliveries) {
      if (signal.aborted) return result;
      // Snapshot lease identity before crossing the adapter boundary. Runtime
      // code must not be able to redirect an acknowledgement or alter retry
      // policy by mutating the delivery object it receives. Inspecting exact
      // data descriptors also rejects accessors and hostile proxies before a
      // lease renewal or dispatch marker can mutate durable state.
      const delivery = snapshotRuntimeOutboxDelivery(unsafeDelivery);
      const dispatchMode = delivery.dispatchMode;
      if (dispatchMode !== "apply" && dispatchMode !== "reconcile") {
        throw new RuntimeEffectError("runtime_invalid_state", false);
      }
      if (
        !isSafeIdentifier(delivery.outboxId) ||
        delivery.leaseOwner !== this.workerId ||
        !Number.isSafeInteger(delivery.attempts) ||
        delivery.attempts < 1 ||
        !Number.isSafeInteger(delivery.leaseExpiresAtMs) ||
        delivery.leaseExpiresAtMs < 1
      ) {
        throw new RuntimeEffectError("runtime_invalid_state", false);
      }
      let leaseIdentity: RuntimeOutboxLeaseIdentity = {
        outboxId: delivery.outboxId,
        attempts: delivery.attempts,
        leaseExpiresAtMs: delivery.leaseExpiresAtMs,
      };
      leaseIdentity = await this.renewExactLease(leaseIdentity);
      if (signal.aborted) return result;
      if (dispatchMode === "apply") {
        // This durable point of no return must complete before the adapter is
        // invoked. A lost lease before this update is safely retryable; any
        // loss after it permanently routes the row through reconciliation.
        await this.kernel.markRuntimeOutboxDispatch({
          outboxId: leaseIdentity.outboxId,
          workerId: this.workerId,
          expectedAttempt: leaseIdentity.attempts,
          expectedLeaseExpiresAtMs: leaseIdentity.leaseExpiresAtMs,
        });
      }
      if (signal.aborted) return result;
      const runtimeDelivery = snapshotRuntimeOutboxDeliveryWithLease(
        delivery,
        leaseIdentity.leaseExpiresAtMs
      );
      const operationController = new AbortController();
      const unlinkOperation = linkRuntimeAbortSignal(signal, operationController);
      const heartbeatController = new AbortController();
      const unlinkHeartbeat = linkRuntimeAbortSignal(signal, heartbeatController);
      const heartbeatState: RuntimeOutboxHeartbeatState = { lost: false };
      const heartbeat = this.renewHeartbeat(
        leaseIdentity,
        operationController,
        heartbeatController.signal,
        heartbeatState
      );
      const executed = await runBoundedRuntimeOperation(
        (operationSignal) =>
          dispatchMode === "reconcile"
            ? this.runtime.reconcile(runtimeDelivery, operationSignal)
            : this.runtime.apply(runtimeDelivery, operationSignal),
        this.runtimeEffectTimeoutMs,
        operationController.signal,
        { abortOnSettlement: true }
      );
      heartbeatController.abort();
      await heartbeat;
      unlinkHeartbeat();
      unlinkOperation();
      if (heartbeatState.lost) throw exactLeaseLossError(heartbeatState.error);
      if (signal.aborted || executed.kind === "aborted") return result;
      const failure =
        executed.kind === "value"
          ? null
          : executed.kind === "error"
            ? safeRuntimeFailure(executed.error)
            : { code: "runtime_timeout" as const, retryable: true };
      const completionAtMs = sampleClock(this.clock);
      if (completionAtMs >= leaseIdentity.leaseExpiresAtMs) {
        throw new RuntimeEffectError("runtime_timeout", true);
      }
      if (!failure) {
        await this.dispatchOutcome(leaseIdentity, "acknowledge");
        result.acknowledged += 1;
        continue;
      }
      // Any error after a fresh dispatch crossed the durable marker is
      // observationally ambiguous, including a nominally permanent adapter
      // error or an exhausted attempt budget. Force at least one separate
      // reconciliation lease before the kernel may terminalize it.
      const retryable =
        dispatchMode === "apply"
          ? true
          : failure.retryable && leaseIdentity.attempts < this.maxTransientAttempts;
      await this.dispatchOutcome(leaseIdentity, "fail", failure.code, retryable);
      if (retryable) result.retried += 1;
      else result.failedPermanently += 1;
    }
    return result;
  }

  private async renewExactLease(
    lease: RuntimeOutboxLeaseIdentity
  ): Promise<RuntimeOutboxLeaseIdentity> {
    const renewedAtMs = sampleClock(this.clock);
    if (renewedAtMs >= lease.leaseExpiresAtMs) {
      throw new RuntimeEffectError("runtime_timeout", true);
    }
    const renewal = await this.kernel.renewRuntimeOutboxLease({
      outboxId: lease.outboxId,
      workerId: this.workerId,
      expectedAttempt: lease.attempts,
      expectedLeaseExpiresAtMs: lease.leaseExpiresAtMs,
      leaseDurationMs: this.leaseDurationMs,
    });
    const finishedAtMs = sampleClock(this.clock);
    const renewedExpiry = snapshotLeaseExpiry(renewal);
    if (
      renewedExpiry < lease.leaseExpiresAtMs ||
      renewedExpiry <= finishedAtMs ||
      renewedExpiry > safeAdd(finishedAtMs, this.leaseDurationMs)
    ) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    // The kernel's returned expiry is the next exact compare-and-swap value.
    // Predicting it from a pre-call clock sample races even ordinary 1 ms
    // clock progress between this process and the durable transaction.
    lease.leaseExpiresAtMs = renewedExpiry;
    return lease;
  }

  private async renewHeartbeat(
    lease: RuntimeOutboxLeaseIdentity,
    operationController: AbortController,
    signal: AbortSignal,
    state: RuntimeOutboxHeartbeatState
  ): Promise<void> {
    while (!signal.aborted && !operationController.signal.aborted) {
      await runtimeAbortableDelay(this.leaseHeartbeatIntervalMs, signal);
      if (signal.aborted || operationController.signal.aborted) return;
      try {
        await this.renewExactLease(lease);
      } catch (error) {
        state.lost = true;
        state.error = error;
        // Abort dispatch synchronously before exposing the renewal error. The
        // LocalTmux adapter checks this signal at every callback/executor edge.
        operationController.abort();
        return;
      }
    }
  }

  private async dispatchOutcome(
    delivery: RuntimeOutboxLeaseIdentity,
    outcome: "acknowledge" | "fail",
    errorCode?: RuntimeOutboxErrorCode,
    retryable?: boolean
  ): Promise<CommandResult> {
    const occurredAtMs = this.clock();
    if (!Number.isSafeInteger(occurredAtMs) || occurredAtMs < 0) {
      throw new RuntimeEffectError("runtime_internal", false);
    }
    const base = {
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: {
        kind: "system" as const,
        userId: this.workerId,
        displayName: "LocalTmux Runtime Worker",
      },
      idempotency: {
        scope: `runtime-worker:${this.workerId}`,
        key: `${delivery.outboxId}:${delivery.attempts}:${delivery.leaseExpiresAtMs}:${outcome}`,
      },
      occurredAtMs,
      outboxId: delivery.outboxId,
      workerId: this.workerId,
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
    };
    const command: SessionCommand =
      outcome === "acknowledge"
        ? { ...base, type: "runtime.outbox.acknowledge" }
        : {
            ...base,
            type: "runtime.outbox.fail",
            retryable: retryable ?? false,
            errorCode: errorCode ?? "runtime_internal",
          };
    return this.kernel.dispatch(command);
  }
}

export function createRuntimeOutboxWorker(
  options: RuntimeOutboxWorkerOptions
): RuntimeOutboxWorker {
  return new RuntimeOutboxWorker(options);
}

function safeRuntimeFailure(error: unknown): {
  code: RuntimeOutboxErrorCode;
  retryable: boolean;
} {
  if (error instanceof RuntimeEffectError && RUNTIME_OUTBOX_ERROR_CODES.includes(error.code)) {
    return { code: error.code, retryable: error.retryable };
  }
  return { code: "runtime_internal", retryable: true };
}

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }
  return value;
}

function isSafeIdentifier(value: string): boolean {
  return value.length > 0 && value.length <= 128 && !/[\0\r\n\t]/.test(value);
}

function reportOperationalError(callback: RuntimeOutboxWorkerOptions["onOperationalError"]): void {
  try {
    callback?.("runtime_internal");
  } catch {
    // Observability must not terminate the worker loop.
  }
}

interface RuntimeOutboxHeartbeatState {
  lost: boolean;
  error?: unknown;
}

const RUNTIME_OUTBOX_DELIVERY_KEYS = Object.freeze([
  "outboxId",
  "sessionId",
  "sessionSequence",
  "attempts",
  "leaseOwner",
  "leaseExpiresAtMs",
  "dispatchMode",
  "kind",
  "payload",
] as const);

function snapshotRuntimeOutboxDelivery(delivery: RuntimeOutboxDelivery): RuntimeOutboxDelivery {
  // Hosted payloads carry a nested immutable Runtime binding. Detach the whole
  // delivery before acquiring the durable dispatch interlock so a caller-owned
  // binding, proxy, or accessor cannot retarget provider work after the lease
  // identity has been accepted.
  let detached: unknown;
  try {
    detached = snapshotRuntimeSupervisorPortableData(delivery);
  } catch (error) {
    if (error instanceof RuntimeEffectError) throw error;
    throw invalidRuntimeClaim();
  }
  const root = snapshotExactDataRecord(detached, RUNTIME_OUTBOX_DELIVERY_KEYS);
  const payload = Object.freeze(
    snapshotExactDataRecordOneOf(root.payload, runtimeOutboxPayloadKeySets(root.kind))
  );
  return Object.freeze({
    outboxId: root.outboxId,
    sessionId: root.sessionId,
    sessionSequence: root.sessionSequence,
    attempts: root.attempts,
    leaseOwner: root.leaseOwner,
    leaseExpiresAtMs: root.leaseExpiresAtMs,
    dispatchMode: root.dispatchMode,
    kind: root.kind,
    payload,
  }) as RuntimeOutboxDelivery;
}

function snapshotRuntimeOutboxDeliveryWithLease(
  delivery: RuntimeOutboxDelivery,
  leaseExpiresAtMs: number
): RuntimeOutboxDelivery {
  return Object.freeze({
    outboxId: delivery.outboxId,
    sessionId: delivery.sessionId,
    sessionSequence: delivery.sessionSequence,
    attempts: delivery.attempts,
    leaseOwner: delivery.leaseOwner,
    leaseExpiresAtMs,
    dispatchMode: delivery.dispatchMode,
    kind: delivery.kind,
    payload: delivery.payload,
  }) as RuntimeOutboxDelivery;
}

function snapshotExactDataRecord(
  value: unknown,
  expectedKeys: readonly string[]
): Record<string, unknown> {
  return snapshotExactDataRecordOneOf(value, [expectedKeys]);
}

function snapshotExactDataRecordOneOf(
  value: unknown,
  expectedKeySets: readonly (readonly string[])[]
): Record<string, unknown> {
  try {
    if (typeof value !== "object" || value === null) throw invalidRuntimeClaim();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw invalidRuntimeClaim();
    const ownKeys = Reflect.ownKeys(value);
    const expectedKeys = expectedKeySets.find(
      (candidate) =>
        ownKeys.length === candidate.length &&
        ownKeys.every((key) => typeof key === "string" && candidate.includes(key))
    );
    if (!expectedKeys) throw invalidRuntimeClaim();
    const snapshot: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of expectedKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) throw invalidRuntimeClaim();
      snapshot[key] = descriptor.value;
    }
    return snapshot;
  } catch (error) {
    if (error instanceof RuntimeEffectError) throw error;
    throw invalidRuntimeClaim();
  }
}

function runtimeOutboxPayloadKeySets(kind: unknown): readonly (readonly string[])[] {
  switch (kind) {
    case "runtime.session.ensure":
      return [
        ["sessionId", "runtimeKind", "tmuxName", "runtimeAuthorizationGeneration"],
        [
          "sessionId",
          "runtimeKind",
          "runtimeAuthorizationGeneration",
          "binding",
          "assignmentPlanRef",
          "assignmentPlanDigest",
        ],
      ];
    case "runtime.authorization.fence":
      return [
        ["sessionId", "reason", "runtimeAuthorizationGeneration"],
        [
          "sessionId",
          "reason",
          "runtimeAuthorizationGeneration",
          "runtimeKind",
          "binding",
          "assignmentPlanRef",
          "assignmentPlanDigest",
        ],
      ];
    case "runtime.session.retire":
      return [
        ["sessionId", "runtimeAuthorizationGeneration"],
        [
          "sessionId",
          "runtimeAuthorizationGeneration",
          "reason",
          "agentRunId",
          "runtimeAssignmentId",
          "runtimeAssignmentGeneration",
          "sandboxId",
          "sandboxGeneration",
        ],
        [
          "sessionId",
          "runtimeAuthorizationGeneration",
          "reason",
          "agentRunId",
          "runtimeAssignmentId",
          "runtimeAssignmentGeneration",
          "sandboxId",
          "sandboxGeneration",
          "runtimeKind",
          "binding",
          "assignmentPlanRef",
          "assignmentPlanDigest",
        ],
      ];
    default:
      throw invalidRuntimeClaim();
  }
}

function invalidRuntimeClaim(): RuntimeEffectError {
  return new RuntimeEffectError("runtime_invalid_state", false);
}

function exactLeaseLossError(error: unknown): Error {
  return error instanceof Error ? error : new RuntimeEffectError("runtime_timeout", true);
}

function snapshotLeaseExpiry(value: unknown): number {
  const record = snapshotExactDataRecord(value, ["leaseExpiresAtMs"]);
  const leaseExpiresAtMs = record.leaseExpiresAtMs;
  if (!Number.isSafeInteger(leaseExpiresAtMs) || (leaseExpiresAtMs as number) < 0) {
    throw invalidRuntimeClaim();
  }
  return leaseExpiresAtMs as number;
}

function emptyRunResult(): RuntimeOutboxRunResult {
  return {
    claimed: 0,
    acknowledged: 0,
    retried: 0,
    failedPermanently: 0,
  };
}

function sampleClock(clock: () => number): number {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RuntimeEffectError("runtime_internal", false);
  }
  return value;
}

function safeAdd(left: number, right: number): number {
  if (
    !Number.isSafeInteger(left) ||
    !Number.isSafeInteger(right) ||
    left < 0 ||
    right < 0 ||
    left > Number.MAX_SAFE_INTEGER - right
  ) {
    throw new RuntimeEffectError("runtime_internal", false);
  }
  return left + right;
}
