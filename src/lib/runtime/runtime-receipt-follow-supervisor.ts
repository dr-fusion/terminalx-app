import type { RuntimeHandle } from "./contracts";
import type { RuntimeReceiptObservationCheckpoint } from "./runtime-receipt-observation";
import type { RuntimeBinding } from "../team-sessions/contracts";
import {
  linkRuntimeAbortSignal,
  runBoundedRuntimeOperation,
  runtimeHealthClockMinimum,
  runtimeAbortableDelay,
  sampleRuntimeHealthClock,
} from "./runtime-supervisor-operation";
import type { RuntimeManagedSupervisorHealth } from "./runtime-supervisor-root";

const MAX_PROTOTYPE_DEPTH = 32;
const MAX_IDENTIFIER_LENGTH = 300;
const MAX_WORKER_ID_LENGTH = 128;
const LEASE_COMPLETION_MARGIN_MS = 250;

type MaybePromise<T> = T | Promise<T>;

export interface RuntimeReceiptFollowClaimOptions {
  readonly workerId: string;
  readonly leaseDurationMs: number;
  readonly nowMs: number;
}

export interface RuntimeReceiptFollowLease {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly issuerKeyId: string;
  readonly publicKeySpkiDigest: string;
  readonly checkpoint: RuntimeReceiptObservationCheckpoint | null;
  readonly attempt: number;
  readonly leaseOwner: string;
  readonly leaseVersion: number;
  readonly leaseExpiresAtMs: number;
}

interface ExactRuntimeReceiptFollowLease {
  readonly runtimeAssignmentId: string;
  readonly runtimeAuthorizationGeneration: number;
  readonly workerId: string;
  readonly expectedLeaseVersion: number;
  readonly expectedLeaseExpiresAtMs: number;
  readonly nowMs: number;
}

export interface RuntimeReceiptFollowRenewalOptions extends ExactRuntimeReceiptFollowLease {
  readonly leaseDurationMs: number;
}

export interface RuntimeReceiptFollowReleaseOptions extends ExactRuntimeReceiptFollowLease {
  readonly reason: "no-event" | "transport-unavailable";
}

export interface RuntimeReceiptFollowSettlementOptions extends ExactRuntimeReceiptFollowLease {
  readonly observation: unknown;
  readonly receivedAtMs: number;
}

/**
 * Narrow durable seam used by the worker. The SQLite implementation may stay
 * synchronous; hosted or test implementations may return Promises.
 */
export interface RuntimeReceiptFollowJournal {
  reconcile(nowMs: number): MaybePromise<number>;
  claim(options: RuntimeReceiptFollowClaimOptions): MaybePromise<RuntimeReceiptFollowLease | null>;
  renew(options: RuntimeReceiptFollowRenewalOptions): MaybePromise<{ leaseExpiresAtMs: number }>;
  release(options: RuntimeReceiptFollowReleaseOptions): MaybePromise<void>;
  settle(options: RuntimeReceiptFollowSettlementOptions): MaybePromise<unknown>;
}

/** Resolve only the exact historical binding carried by the durable stream. */
export interface RuntimeReceiptFollowHandleResolver {
  resolve(lease: RuntimeReceiptFollowLease, signal: AbortSignal): Promise<RuntimeHandle | null>;
}

/**
 * Private receipt-only transport. It intentionally does not reuse the public
 * Runtime event stream: unrelated terminal output must not block durable
 * receipt-cursor progress.
 */
export interface RuntimeReceiptFollowTransport {
  follow(
    handle: RuntimeHandle,
    checkpoint: RuntimeReceiptObservationCheckpoint | null,
    signal: AbortSignal
  ): AsyncIterable<unknown>;
}

export interface RuntimeReceiptFollowSupervisorOptions {
  readonly journal: RuntimeReceiptFollowJournal;
  readonly transport: RuntimeReceiptFollowTransport;
  readonly handles: RuntimeReceiptFollowHandleResolver;
  readonly workerId: string;
  readonly clock?: () => number;
  readonly leaseDurationMs?: number;
  readonly handleResolveTimeoutMs?: number;
  readonly followPollTimeoutMs?: number;
  readonly idleDelayMs?: number;
  readonly busyDelayMs?: number;
  readonly errorDelayMs?: number;
  readonly onOperationalError?: (code: "runtime_receipt_follow_internal") => void;
}

export interface RuntimeReceiptFollowRunResult {
  readonly claimed: number;
  readonly settled: number;
  readonly empty: number;
  readonly transportFailures: number;
}

type CapturedFollow = (
  handle: RuntimeHandle,
  checkpoint: RuntimeReceiptObservationCheckpoint | null,
  signal: AbortSignal
) => AsyncIterable<unknown>;

interface CapturedAsyncIterator {
  next(): Promise<unknown> | unknown;
  close(): void;
}

/** Singular, bounded worker for lifecycle and compensation receipt observations. */
export class RuntimeReceiptFollowSupervisor {
  private readonly journal: RuntimeReceiptFollowJournal;
  private readonly follow: CapturedFollow;
  private readonly handles: RuntimeReceiptFollowHandleResolver;
  private readonly workerId: string;
  private readonly clock: () => number;
  private readonly leaseDurationMs: number;
  private readonly handleResolveTimeoutMs: number;
  private readonly followPollTimeoutMs: number;
  private readonly idleDelayMs: number;
  private readonly busyDelayMs: number;
  private readonly errorDelayMs: number;
  private readonly onOperationalError?: (code: "runtime_receipt_follow_internal") => void;
  private controller: AbortController | null = null;
  private loopPromise: Promise<void> | null = null;
  private activeRun: Promise<RuntimeReceiptFollowRunResult> | null = null;
  private activeRunController: AbortController | null = null;
  private lastSuccessAtMs: number | null = null;
  private lastErrorAtMs: number | null = null;
  private activeCycleStartedAtMs: number | null = null;
  private failureSinceSuccess = false;

  constructor(options: RuntimeReceiptFollowSupervisorOptions) {
    // Capture provider capability before touching the journal. A getter-backed
    // or later-replaced provider method can never become a dispatch capability.
    const follow = captureFollowDataFunction(options?.transport);
    if (!isSafeIdentifier(options?.workerId, MAX_WORKER_ID_LENGTH)) {
      throw new TypeError("Invalid Runtime receipt follow worker ID");
    }
    if (
      typeof options.journal?.reconcile !== "function" ||
      typeof options.journal?.claim !== "function" ||
      typeof options.journal?.renew !== "function" ||
      typeof options.journal?.release !== "function" ||
      typeof options.journal?.settle !== "function" ||
      typeof options.handles?.resolve !== "function"
    ) {
      throw new TypeError("Invalid Runtime receipt follow supervisor dependency");
    }
    this.follow = follow;
    this.journal = options.journal;
    this.handles = options.handles;
    this.workerId = options.workerId;
    this.clock = options.clock ?? Date.now;
    if (typeof this.clock !== "function") throw new TypeError("Invalid Runtime receipt clock");
    this.leaseDurationMs = boundedInteger(options.leaseDurationMs ?? 30_000, 1_000, 300_000);
    const maximumOperationMs = this.leaseDurationMs - 2 * LEASE_COMPLETION_MARGIN_MS;
    this.handleResolveTimeoutMs = boundedInteger(
      options.handleResolveTimeoutMs ?? Math.min(5_000, maximumOperationMs),
      1,
      maximumOperationMs
    );
    this.followPollTimeoutMs = boundedInteger(
      options.followPollTimeoutMs ?? Math.min(20_000, maximumOperationMs),
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
    const loopPromise = this.loop(controller.signal)
      .catch(() => {
        reportOperationalError(this.onOperationalError);
      })
      .finally(() => {
        if (this.controller === controller) this.controller = null;
        if (this.loopPromise === loopPromise) this.loopPromise = null;
      });
    this.loopPromise = loopPromise;
  }

  async stop(): Promise<void> {
    const loop = this.loopPromise;
    const activeRun = this.activeRun;
    const controller = this.controller;
    const activeRunController = this.activeRunController;
    controller?.abort();
    activeRunController?.abort();
    await Promise.allSettled([...(loop ? [loop] : []), ...(activeRun ? [activeRun] : [])]);
  }

  /** Concurrent callers share one poll so one stream lease has one iterator. */
  runOnce(): Promise<RuntimeReceiptFollowRunResult> {
    if (this.activeRun) return this.activeRun;
    const controller = new AbortController();
    const unlink = linkRuntimeAbortSignal(this.controller?.signal, controller);
    this.activeRunController = controller;
    const run = this.processOne(controller.signal)
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
          result.transportFailures > 0
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

  private async processOne(signal: AbortSignal): Promise<RuntimeReceiptFollowRunResult> {
    if (signal.aborted) return emptyRunResult();
    const reconcileAtMs = sampleClock(this.clock);
    this.activeCycleStartedAtMs = reconcileAtMs;
    await this.journal.reconcile(reconcileAtMs);
    if (signal.aborted) return emptyRunResult();
    const claimedAtMs = sampleClock(this.clock, reconcileAtMs);
    const unsafeLease = await this.journal.claim({
      workerId: this.workerId,
      leaseDurationMs: this.leaseDurationMs,
      nowMs: claimedAtMs,
    });
    if (unsafeLease === null) return emptyRunResult();
    let lease = snapshotLease(unsafeLease, this.workerId, claimedAtMs);

    const resolveAtMs = sampleClock(this.clock, claimedAtMs);
    const remainingBeforeResolve = lease.leaseExpiresAtMs - resolveAtMs;
    if (signal.aborted || remainingBeforeResolve <= LEASE_COMPLETION_MARGIN_MS) {
      await this.releaseBestEffort(lease, "transport-unavailable", resolveAtMs);
      return transportFailureResult();
    }
    const resolved = await runBoundedRuntimeOperation(
      (operationSignal) => this.handles.resolve(lease, operationSignal),
      Math.min(this.handleResolveTimeoutMs, remainingBeforeResolve - LEASE_COMPLETION_MARGIN_MS),
      signal,
      { abortOnSettlement: true }
    );
    if (resolved.kind !== "value") {
      const failedAtMs = sampleClock(this.clock, resolveAtMs);
      await this.releaseBestEffort(lease, "transport-unavailable", failedAtMs);
      return transportFailureResult();
    }
    const handle = snapshotExactHandle(resolved.value, lease.binding);
    if (handle === null) {
      const failedAtMs = sampleClock(this.clock, resolveAtMs);
      await this.releaseBestEffort(lease, "transport-unavailable", failedAtMs);
      return transportFailureResult();
    }

    const renewalAtMs = sampleClock(this.clock, resolveAtMs);
    if (signal.aborted || renewalAtMs >= lease.leaseExpiresAtMs - LEASE_COMPLETION_MARGIN_MS) {
      await this.releaseBestEffort(lease, "transport-unavailable", renewalAtMs);
      return transportFailureResult();
    }
    const renewal = await this.journal.renew({
      ...exactLeaseOptions(lease, renewalAtMs),
      leaseDurationMs: this.leaseDurationMs,
    });
    lease = withRenewedExpiry(lease, renewal, renewalAtMs);

    const pollAtMs = sampleClock(this.clock, renewalAtMs);
    const remainingBeforePoll = lease.leaseExpiresAtMs - pollAtMs;
    if (signal.aborted || remainingBeforePoll <= LEASE_COMPLETION_MARGIN_MS) {
      await this.releaseBestEffort(lease, "transport-unavailable", pollAtMs);
      return transportFailureResult();
    }

    const iteratorHolder: { current?: CapturedAsyncIterator } = {};
    const next = await runBoundedRuntimeOperation<unknown>(
      (operationSignal) => {
        const iterator = captureAsyncIterator(
          this.follow(handle, lease.checkpoint, operationSignal)
        );
        iteratorHolder.current = iterator;
        return iterator.next();
      },
      Math.min(this.followPollTimeoutMs, remainingBeforePoll - LEASE_COMPLETION_MARGIN_MS),
      signal,
      { abortOnSettlement: true }
    );
    iteratorHolder.current?.close();
    if (next.kind !== "value") {
      const failedAtMs = sampleClock(this.clock, pollAtMs);
      await this.releaseBestEffort(lease, "transport-unavailable", failedAtMs);
      return transportFailureResult();
    }
    const receivedAtMs = sampleClock(this.clock, pollAtMs);
    if (signal.aborted || receivedAtMs >= lease.leaseExpiresAtMs - LEASE_COMPLETION_MARGIN_MS) {
      await this.releaseBestEffort(lease, "transport-unavailable", receivedAtMs);
      return transportFailureResult();
    }
    let item: ReturnType<typeof snapshotIteratorResult>;
    try {
      item = snapshotIteratorResult(next.value);
    } catch {
      await this.releaseBestEffort(lease, "transport-unavailable", receivedAtMs);
      return transportFailureResult();
    }
    if (item.done) {
      await this.journal.release({
        ...exactLeaseOptions(lease, receivedAtMs),
        reason: "no-event",
      });
      return Object.freeze({ claimed: 1, settled: 0, empty: 1, transportFailures: 0 });
    }

    await this.journal.settle({
      ...exactLeaseOptions(lease, receivedAtMs),
      observation: item.value,
      receivedAtMs,
    });
    return Object.freeze({ claimed: 1, settled: 1, empty: 0, transportFailures: 0 });
  }

  private async releaseBestEffort(
    lease: RuntimeReceiptFollowLease,
    reason: RuntimeReceiptFollowReleaseOptions["reason"],
    nowMs: number
  ): Promise<void> {
    if (nowMs >= lease.leaseExpiresAtMs) return;
    try {
      await this.journal.release({ ...exactLeaseOptions(lease, nowMs), reason });
    } catch {
      // A lost/expired exact lease is recovered by the next reconcile. Never
      // let a cleanup race turn an unavailable transport into accepted truth.
    }
  }
}

export function createRuntimeReceiptFollowSupervisor(
  options: RuntimeReceiptFollowSupervisorOptions
): RuntimeReceiptFollowSupervisor {
  return new RuntimeReceiptFollowSupervisor(options);
}

function captureFollowDataFunction(transport: unknown): CapturedFollow {
  const method = captureDataMethod(transport, "follow");
  return Object.freeze((handle, checkpoint, signal) => {
    const result = Reflect.apply(method, transport, [handle, checkpoint, signal]) as unknown;
    if ((typeof result !== "object" && typeof result !== "function") || result === null) {
      throw new TypeError("Invalid Runtime receipt follow transport");
    }
    return result as AsyncIterable<unknown>;
  });
}

function captureAsyncIterator(iterable: AsyncIterable<unknown>): CapturedAsyncIterator {
  const iteratorFactory = captureDataMethod(iterable, Symbol.asyncIterator);
  const iterator = Reflect.apply(iteratorFactory, iterable, []) as unknown;
  if ((typeof iterator !== "object" && typeof iterator !== "function") || iterator === null) {
    throw new TypeError("Invalid Runtime receipt iterator");
  }
  const next = captureDataMethod(iterator, "next");
  const close = captureDataMethod(iterator, "return");
  let closed = false;
  return Object.freeze({
    next: () => Reflect.apply(next, iterator, []) as Promise<unknown> | unknown,
    close: () => {
      if (closed) return;
      closed = true;
      try {
        const pending = Reflect.apply(close, iterator, []) as unknown;
        try {
          Reflect.apply(Promise.prototype.then, pending, [undefined, () => undefined]);
        } catch {
          // Custom thenables are not invoked during best-effort cleanup.
        }
      } catch {
        // Closing is best effort. The AbortSignal is the authoritative transport fence.
      }
    },
  });
}

function captureDataMethod(target: unknown, key: PropertyKey): (...args: unknown[]) => unknown {
  if ((typeof target !== "object" && typeof target !== "function") || target === null) {
    throw new TypeError("Invalid Runtime receipt follow capability");
  }
  try {
    const visited = new Set<object>();
    let current: object | null = target;
    for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
      if (visited.has(current)) throw new TypeError("Invalid Runtime receipt follow capability");
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        if (!("value" in descriptor) || typeof descriptor.value !== "function") {
          throw new TypeError("Invalid Runtime receipt follow capability");
        }
        return descriptor.value as (...args: unknown[]) => unknown;
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
  } catch {
    throw new TypeError("Invalid Runtime receipt follow capability");
  }
  throw new TypeError("Invalid Runtime receipt follow capability");
}

function snapshotLease(
  value: RuntimeReceiptFollowLease,
  workerId: string,
  claimedAtMs: number
): RuntimeReceiptFollowLease {
  const record = exactDataRecord(value, [
    "binding",
    "runtimeAuthorizationGeneration",
    "issuerKeyId",
    "publicKeySpkiDigest",
    "checkpoint",
    "attempt",
    "leaseOwner",
    "leaseVersion",
    "leaseExpiresAtMs",
  ]);
  const binding = snapshotBinding(dataValue(record, "binding"));
  const checkpointValue = dataValue(record, "checkpoint");
  const checkpoint = checkpointValue === null ? null : snapshotCheckpoint(checkpointValue);
  const leaseOwner = safeIdentifier(dataValue(record, "leaseOwner"), MAX_WORKER_ID_LENGTH);
  const leaseExpiresAtMs = positiveInteger(dataValue(record, "leaseExpiresAtMs"));
  if (leaseOwner !== workerId || leaseExpiresAtMs <= claimedAtMs) {
    throw new TypeError("Invalid Runtime receipt follow lease");
  }
  return deepFreeze({
    binding,
    runtimeAuthorizationGeneration: positiveInteger(
      dataValue(record, "runtimeAuthorizationGeneration")
    ),
    issuerKeyId: safeIdentifier(dataValue(record, "issuerKeyId"), MAX_IDENTIFIER_LENGTH),
    publicKeySpkiDigest: sha256Digest(dataValue(record, "publicKeySpkiDigest")),
    checkpoint,
    attempt: positiveInteger(dataValue(record, "attempt")),
    leaseOwner,
    leaseVersion: positiveInteger(dataValue(record, "leaseVersion")),
    leaseExpiresAtMs,
  });
}

function snapshotExactHandle(
  value: RuntimeHandle | null,
  expected: RuntimeBinding
): RuntimeHandle | null {
  if (value === null) return null;
  try {
    const record = exactDataRecord(value, ["binding", "opaqueHandleRef", "capabilities"]);
    const binding = snapshotBinding(dataValue(record, "binding"));
    if (!sameBinding(binding, expected)) return null;
    const capabilitiesRecord = exactDataRecord(dataValue(record, "capabilities"), [
      "isolatedExecution",
      "brokeredCredentials",
      "proxyOnlyEgress",
      "checkpoints",
      "yoloEligible",
    ]);
    const capabilities = {
      isolatedExecution: booleanValue(dataValue(capabilitiesRecord, "isolatedExecution")),
      brokeredCredentials: booleanValue(dataValue(capabilitiesRecord, "brokeredCredentials")),
      proxyOnlyEgress: booleanValue(dataValue(capabilitiesRecord, "proxyOnlyEgress")),
      checkpoints: booleanValue(dataValue(capabilitiesRecord, "checkpoints")),
      yoloEligible: booleanValue(dataValue(capabilitiesRecord, "yoloEligible")),
    };
    return deepFreeze({
      binding,
      opaqueHandleRef: safeIdentifier(dataValue(record, "opaqueHandleRef"), MAX_IDENTIFIER_LENGTH),
      capabilities,
    });
  } catch {
    return null;
  }
}

function snapshotIteratorResult(value: unknown): {
  readonly done: boolean;
  readonly value: unknown;
} {
  const record = exactDataRecord(value, ["value", "done"]);
  const done = dataValue(record, "done");
  if (typeof done !== "boolean") throw new TypeError("Invalid Runtime receipt iterator result");
  return Object.freeze({ done, value: dataValue(record, "value") });
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const fields = [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ] as const;
  const record = exactDataRecord(value, fields);
  return Object.freeze({
    teamId: safeIdentifier(dataValue(record, "teamId"), MAX_IDENTIFIER_LENGTH),
    projectId: safeIdentifier(dataValue(record, "projectId"), MAX_IDENTIFIER_LENGTH),
    sessionId: safeIdentifier(dataValue(record, "sessionId"), MAX_IDENTIFIER_LENGTH),
    runtimeAssignmentId: safeIdentifier(
      dataValue(record, "runtimeAssignmentId"),
      MAX_IDENTIFIER_LENGTH
    ),
    runtimeAssignmentGeneration: positiveInteger(dataValue(record, "runtimeAssignmentGeneration")),
    sandboxId: safeIdentifier(dataValue(record, "sandboxId"), MAX_IDENTIFIER_LENGTH),
    sandboxGeneration: positiveInteger(dataValue(record, "sandboxGeneration")),
    runtimePrincipalId: safeIdentifier(
      dataValue(record, "runtimePrincipalId"),
      MAX_IDENTIFIER_LENGTH
    ),
  });
}

function snapshotCheckpoint(value: unknown): RuntimeReceiptObservationCheckpoint {
  const record = exactDataRecord(value, ["cursor", "observationDigest"]);
  return Object.freeze({
    cursor: safeIdentifier(dataValue(record, "cursor"), 2_048),
    observationDigest: sha256Digest(dataValue(record, "observationDigest")),
  });
}

function exactLeaseOptions(lease: RuntimeReceiptFollowLease, nowMs: number) {
  return {
    runtimeAssignmentId: lease.binding.runtimeAssignmentId,
    runtimeAuthorizationGeneration: lease.runtimeAuthorizationGeneration,
    workerId: lease.leaseOwner,
    expectedLeaseVersion: lease.leaseVersion,
    expectedLeaseExpiresAtMs: lease.leaseExpiresAtMs,
    nowMs,
  } as const;
}

function withRenewedExpiry(
  lease: RuntimeReceiptFollowLease,
  renewal: { leaseExpiresAtMs: number },
  renewedAtMs: number
): RuntimeReceiptFollowLease {
  const expiry = positiveInteger(
    dataValue(exactDataRecord(renewal, ["leaseExpiresAtMs"]), "leaseExpiresAtMs")
  );
  if (expiry < lease.leaseExpiresAtMs || expiry <= renewedAtMs) {
    throw new TypeError("Invalid Runtime receipt follow renewal");
  }
  return deepFreeze({ ...lease, leaseExpiresAtMs: expiry });
}

function exactDataRecord(
  value: unknown,
  expected: readonly PropertyKey[]
): Record<PropertyKey, unknown> {
  try {
    if ((typeof value !== "object" && typeof value !== "function") || value === null) {
      throw new TypeError("Invalid Runtime receipt follow data");
    }
    const prototype = Object.getPrototypeOf(value) as object | null;
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Invalid Runtime receipt follow data");
    }
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== expected.length ||
      keys.some((key) => !expected.some((candidate) => candidate === key))
    ) {
      throw new TypeError("Invalid Runtime receipt follow data");
    }
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new TypeError("Invalid Runtime receipt follow data");
      }
    }
    return value as Record<PropertyKey, unknown>;
  } catch {
    throw new TypeError("Invalid Runtime receipt follow data");
  }
}

function dataValue(record: Record<PropertyKey, unknown>, key: PropertyKey): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new TypeError("Invalid Runtime receipt follow data");
    }
    return descriptor.value;
  } catch {
    throw new TypeError("Invalid Runtime receipt follow data");
  }
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

function booleanValue(value: unknown): boolean {
  if (typeof value !== "boolean") throw new TypeError("Invalid Runtime receipt handle");
  return value;
}

function safeIdentifier(value: unknown, maximumLength: number): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximumLength ||
    value.trim() !== value ||
    /[\0\r\n\t]/.test(value)
  ) {
    throw new TypeError("Invalid Runtime receipt follow identifier");
  }
  return value;
}

function isSafeIdentifier(value: unknown, maximumLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    value.trim() === value &&
    !/[\0\r\n\t]/.test(value)
  );
}

function sha256Digest(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("Invalid Runtime receipt follow digest");
  }
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new TypeError("Invalid Runtime receipt follow integer");
  }
  return value as number;
}

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError("Invalid Runtime receipt follow supervisor bound");
  }
  return value;
}

function sampleClock(clock: () => number, minimum = 0): number {
  let nowMs: number;
  try {
    nowMs = clock();
  } catch {
    throw new TypeError("Invalid Runtime receipt clock");
  }
  if (!Number.isSafeInteger(nowMs) || nowMs < minimum) {
    throw new TypeError("Invalid Runtime receipt clock");
  }
  return nowMs;
}

function emptyRunResult(): RuntimeReceiptFollowRunResult {
  return Object.freeze({ claimed: 0, settled: 0, empty: 0, transportFailures: 0 });
}

function transportFailureResult(): RuntimeReceiptFollowRunResult {
  return Object.freeze({ claimed: 1, settled: 0, empty: 0, transportFailures: 1 });
}

function reportOperationalError(
  callback: RuntimeReceiptFollowSupervisorOptions["onOperationalError"]
): void {
  try {
    callback?.("runtime_receipt_follow_internal");
  } catch {
    // Observability is never allowed to terminate the supervisor loop.
  }
}

function deepFreeze<T>(value: T): T {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return value;
  if (Object.isFrozen(value)) return value;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor) deepFreeze(descriptor.value);
  }
  return Object.freeze(value);
}
