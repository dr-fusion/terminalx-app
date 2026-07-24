import type { RuntimeWriteStateUpdate } from "./local-tmux-runtime";
import type { RuntimeCompensationMaterializerRunResult } from "./runtime-compensation-materializer";
import type { RuntimeWriteStateRegistry } from "./write-state";

export type RuntimeSupervisorRootState =
  | "created"
  | "starting"
  | "running"
  | "stopping"
  | "stopped"
  | "failed";

export interface RuntimeManagedSupervisor {
  readonly running: boolean;
  start(): void;
  /** One complete reconcile/claim cycle used as the restart barrier. */
  runOnce(): Promise<RuntimeManagedSupervisorRunResult>;
  stop(): Promise<void>;
}

export interface RuntimeManagedSupervisorRunResult {
  /** Number of durable work items claimed by this cycle. */
  readonly claimed: number;
}

export interface RuntimeCompensationMaterializerWorker {
  runOnce(signal?: AbortSignal): Promise<RuntimeCompensationMaterializerRunResult>;
}

export interface RuntimeDurableWriteStateSource {
  read(): ReadonlyArray<RuntimeWriteStateUpdate>;
}

export interface RuntimeSupervisorRootOptions {
  readonly lifecycle: RuntimeManagedSupervisor;
  readonly receiptFollow: RuntimeManagedSupervisor;
  readonly compensation: RuntimeManagedSupervisor;
  readonly materializer: RuntimeCompensationMaterializerWorker;
  readonly writeStateRegistry: RuntimeWriteStateRegistry;
  readonly writeStateSource: RuntimeDurableWriteStateSource;
  readonly clock?: () => number;
  readonly materializerIdleDelayMs?: number;
  readonly materializerBusyDelayMs?: number;
  readonly materializerErrorDelayMs?: number;
  readonly materializerCycleTimeoutMs?: number;
  readonly startupOperationTimeoutMs?: number;
  /** Maximum cycles per worker/materializer before startup fails closed. */
  readonly startupDrainLimit?: number;
  readonly shutdownOperationTimeoutMs?: number;
  readonly readinessStaleAfterMs?: number;
  readonly onOperationalError?: (code: "runtime_supervisor_internal") => void;
}

export interface RuntimeSupervisorRootReadiness {
  readonly ready: boolean;
  readonly state: RuntimeSupervisorRootState;
  readonly durableWriteStateLoaded: boolean;
  readonly lifecycleReconciled: boolean;
  readonly receiptFollowReconciled: boolean;
  readonly compensationReconciled: boolean;
  readonly restartReconciled: boolean;
  readonly lifecycleRunning: boolean;
  readonly receiptFollowRunning: boolean;
  readonly compensationRunning: boolean;
  readonly materializerHealthy: boolean;
  readonly lastMaterializerSuccessAtMs: number | null;
  readonly lastMaterializerErrorAtMs: number | null;
}

interface CapturedManagedSupervisor {
  readonly isRunning: () => boolean;
  readonly start: () => unknown;
  readonly runOnce: () => unknown;
  readonly stop: () => unknown;
}

type BoundedOperationResult<T> =
  | { readonly kind: "value"; readonly value: T }
  | { readonly kind: "error" }
  | { readonly kind: "invalid" }
  | { readonly kind: "timeout" }
  | { readonly kind: "aborted" };

type RootOperationFailureKind = Exclude<BoundedOperationResult<never>["kind"], "value">;

class RootOperationFailure extends Error {
  constructor(readonly kind: RootOperationFailureKind) {
    super("Runtime supervisor operation failed");
    this.name = "RootOperationFailure";
  }
}

const MAX_PROTOTYPE_DEPTH = 16;

/**
 * Production lifecycle owner for the portable Runtime-truth workers.
 *
 * Startup is an explicit fail-closed barrier: install the durable write fence,
 * complete one lifecycle reconciliation, complete one signed-receipt follow
 * reconciliation, materialize stale-effect compensation, and complete one
 * compensation reconciliation before any background loop may report ready.
 */
export class RuntimeSupervisorRoot {
  private readonly lifecycle: CapturedManagedSupervisor;
  private readonly receiptFollow: CapturedManagedSupervisor;
  private readonly compensation: CapturedManagedSupervisor;
  private readonly runMaterializer: (signal: AbortSignal) => unknown;
  private readonly bootstrapWriteState: (
    updates: ReadonlyArray<RuntimeWriteStateUpdate>
  ) => unknown;
  private readonly readWriteState: () => unknown;
  private readonly hasDurableWriteState: () => boolean;
  private readonly clock: () => number;
  private readonly idleDelayMs: number;
  private readonly busyDelayMs: number;
  private readonly errorDelayMs: number;
  private readonly materializerCycleTimeoutMs: number;
  private readonly startupOperationTimeoutMs: number;
  private readonly startupDrainLimit: number;
  private readonly shutdownOperationTimeoutMs: number;
  private readonly readinessStaleAfterMs: number;
  private readonly onOperationalError?: (code: "runtime_supervisor_internal") => void;
  private currentState: RuntimeSupervisorRootState = "created";
  private startPromise: Promise<void> | null = null;
  private stopPromise: Promise<void> | null = null;
  private startupController: AbortController | null = null;
  private materializerController: AbortController | null = null;
  private materializerLoop: Promise<void> | null = null;
  private readonly activeMaterializerSettlements = new Set<Promise<void>>();
  private shutdownWorkersPromise: Promise<boolean> | null = null;
  private lifecycleReconciled = false;
  private receiptFollowReconciled = false;
  private compensationReconciled = false;
  private lastMaterializerSuccessAtMs: number | null = null;
  private lastMaterializerErrorAtMs: number | null = null;
  private materializerFailureSinceSuccess = false;

  constructor(unsafeOptions: RuntimeSupervisorRootOptions) {
    const options = dataRecord(unsafeOptions, "Invalid Runtime supervisor root options");
    this.lifecycle = captureManagedSupervisor(
      requiredDataField(options, "lifecycle", "Invalid Runtime supervisor root dependency")
    );
    this.receiptFollow = captureManagedSupervisor(
      requiredDataField(options, "receiptFollow", "Invalid Runtime supervisor root dependency")
    );
    this.compensation = captureManagedSupervisor(
      requiredDataField(options, "compensation", "Invalid Runtime supervisor root dependency")
    );

    const materializer = requiredDataField(
      options,
      "materializer",
      "Invalid Runtime supervisor root dependency"
    );
    const materializerMethod = captureDataMethod(
      materializer,
      "runOnce",
      "Invalid Runtime supervisor root dependency"
    );
    this.runMaterializer = (signal) => {
      const result = Reflect.apply(materializerMethod, materializer, [signal]);
      this.trackMaterializerSettlement(result);
      return result;
    };

    const writeStateRegistry = requiredDataField(
      options,
      "writeStateRegistry",
      "Invalid Runtime supervisor root dependency"
    );
    const bootstrap = captureDataMethod(
      writeStateRegistry,
      "bootstrap",
      "Invalid Runtime supervisor root dependency"
    );
    this.bootstrapWriteState = (updates) => Reflect.apply(bootstrap, writeStateRegistry, [updates]);
    this.hasDurableWriteState = captureBooleanReader(
      writeStateRegistry,
      "hasDurableSnapshot",
      "Invalid Runtime supervisor root dependency"
    );

    const writeStateSource = requiredDataField(
      options,
      "writeStateSource",
      "Invalid Runtime supervisor root dependency"
    );
    const read = captureDataMethod(
      writeStateSource,
      "read",
      "Invalid Runtime supervisor root dependency"
    );
    this.readWriteState = () => Reflect.apply(read, writeStateSource, []);

    const unsafeClock = optionalDataField(options, "clock");
    if (unsafeClock !== undefined && typeof unsafeClock !== "function") {
      throw new TypeError("Invalid Runtime supervisor clock");
    }
    const capturedClock = (unsafeClock ?? Date.now) as () => unknown;
    this.clock = () => Reflect.apply(capturedClock, undefined, []) as number;

    this.idleDelayMs = bound(
      optionalDataField(options, "materializerIdleDelayMs") ?? 250,
      1,
      60_000
    );
    this.busyDelayMs = bound(
      optionalDataField(options, "materializerBusyDelayMs") ?? 10,
      1,
      60_000
    );
    this.errorDelayMs = bound(
      optionalDataField(options, "materializerErrorDelayMs") ?? 1_000,
      1,
      60_000
    );
    this.materializerCycleTimeoutMs = bound(
      optionalDataField(options, "materializerCycleTimeoutMs") ?? 30_000,
      1,
      300_000
    );
    this.startupOperationTimeoutMs = bound(
      optionalDataField(options, "startupOperationTimeoutMs") ?? 30_000,
      1,
      300_000
    );
    this.startupDrainLimit = bound(
      optionalDataField(options, "startupDrainLimit") ?? 64,
      1,
      10_000
    );
    this.shutdownOperationTimeoutMs = bound(
      optionalDataField(options, "shutdownOperationTimeoutMs") ?? 30_000,
      1,
      300_000
    );
    this.readinessStaleAfterMs = bound(
      optionalDataField(options, "readinessStaleAfterMs") ?? 30_000,
      1_000,
      10 * 60_000
    );

    const unsafeObserver = optionalDataField(options, "onOperationalError");
    if (unsafeObserver !== undefined && typeof unsafeObserver !== "function") {
      throw new TypeError("Invalid Runtime supervisor observer");
    }
    if (unsafeObserver !== undefined) {
      this.onOperationalError = (code) => Reflect.apply(unsafeObserver, undefined, [code]);
    }
  }

  get state(): RuntimeSupervisorRootState {
    return this.currentState;
  }

  /** Concurrent startup callers share one bounded, fail-closed bootstrap. */
  start(): Promise<void> {
    if (this.startPromise) return this.startPromise;
    if (this.currentState === "running") return Promise.resolve();
    if (this.currentState !== "created") {
      return Promise.reject(new TypeError("Runtime supervisor root cannot be restarted"));
    }
    this.currentState = "starting";
    const controller = new AbortController();
    this.startupController = controller;
    const start = this.startInternal(controller.signal).finally(() => {
      if (this.startupController === controller) this.startupController = null;
      if (this.startPromise === start) this.startPromise = null;
    });
    this.startPromise = start;
    return start;
  }

  /** Stop/abort every capability immediately, then bound all shutdown waits. */
  stop(): Promise<void> {
    if (this.stopPromise) return this.stopPromise;
    const stop = this.stopInternal().finally(() => {
      if (this.stopPromise === stop) this.stopPromise = null;
    });
    this.stopPromise = stop;
    return stop;
  }

  readiness(): RuntimeSupervisorRootReadiness {
    const nowMs = safeClockOrNull(this.clock);
    const lifecycleRunning = this.lifecycle.isRunning();
    const receiptFollowRunning = this.receiptFollow.isRunning();
    const compensationRunning = this.compensation.isRunning();
    const durableWriteStateLoaded = this.hasDurableWriteState();
    const restartReconciled =
      this.lifecycleReconciled && this.receiptFollowReconciled && this.compensationReconciled;
    const materializerHealthy =
      nowMs !== null &&
      this.lastMaterializerSuccessAtMs !== null &&
      nowMs >= this.lastMaterializerSuccessAtMs &&
      nowMs - this.lastMaterializerSuccessAtMs <= this.readinessStaleAfterMs &&
      !this.materializerFailureSinceSuccess;
    return Object.freeze({
      ready:
        this.currentState === "running" &&
        durableWriteStateLoaded &&
        restartReconciled &&
        lifecycleRunning &&
        receiptFollowRunning &&
        compensationRunning &&
        materializerHealthy,
      state: this.currentState,
      durableWriteStateLoaded,
      lifecycleReconciled: this.lifecycleReconciled,
      receiptFollowReconciled: this.receiptFollowReconciled,
      compensationReconciled: this.compensationReconciled,
      restartReconciled,
      lifecycleRunning,
      receiptFollowRunning,
      compensationRunning,
      materializerHealthy,
      lastMaterializerSuccessAtMs: this.lastMaterializerSuccessAtMs,
      lastMaterializerErrorAtMs: this.lastMaterializerErrorAtMs,
    });
  }

  private async startInternal(signal: AbortSignal): Promise<void> {
    try {
      this.assertStarting(signal);
      if (this.hasDurableWriteState()) {
        throw new TypeError("Runtime supervisor root requires a fresh write-state registry");
      }
      const snapshot = this.readWriteState();
      this.assertStarting(signal);
      const bootstrapResult = this.bootstrapWriteState(
        snapshot as ReadonlyArray<RuntimeWriteStateUpdate>
      );
      assertSynchronousVoid(bootstrapResult);
      if (!this.hasDurableWriteState()) {
        throw new TypeError("Runtime write-state bootstrap did not install a snapshot");
      }

      await this.primeWorker(this.lifecycle, signal);
      this.lifecycleReconciled = true;
      this.assertStarting(signal);

      await this.primeWorker(this.receiptFollow, signal);
      this.receiptFollowReconciled = true;
      this.assertStarting(signal);

      // Follow settlement may have created a stale-effect incident, so the
      // materializer barrier intentionally follows receipt reconciliation.
      await this.drainMaterializer(signal);
      this.assertStarting(signal);

      await this.primeWorker(this.compensation, signal);
      this.compensationReconciled = true;
      this.assertStarting(signal);

      // Start containment first. The explicit priming barrier above means a
      // synchronous `start()` cannot make readiness outrun reconciliation.
      for (const worker of [this.compensation, this.receiptFollow, this.lifecycle]) {
        assertSynchronousVoid(worker.start());
        if (!worker.isRunning()) throw new TypeError("Runtime worker did not start");
        this.assertStarting(signal);
      }

      const controller = new AbortController();
      this.materializerController = controller;
      const loop = this.loopMaterializer(controller.signal)
        .catch(() => {
          if (!controller.signal.aborted) {
            reportOperationalError(this.onOperationalError);
            this.failRunningRoot();
          }
        })
        .finally(() => {
          if (this.materializerController === controller) this.materializerController = null;
          if (this.materializerLoop === loop) this.materializerLoop = null;
        });
      this.materializerLoop = loop;
      this.assertStarting(signal);
      this.currentState = "running";
    } catch {
      if (this.currentState === "starting") this.currentState = "failed";
      await this.requestWorkersStop();
      throw new TypeError("Runtime supervisor root could not start");
    }
  }

  private async stopInternal(): Promise<void> {
    if (this.currentState === "created" || this.currentState === "stopped") {
      this.currentState = "stopped";
      return;
    }

    this.currentState = "stopping";
    this.startupController?.abort();
    this.materializerController?.abort();
    const startup = this.startPromise;
    const materializerLoop = this.materializerLoop;
    const activeMaterializers = [...this.activeMaterializerSettlements];
    const workersStopped = this.requestWorkersStop();
    const [stopped, startupSettled, loopSettled, materializersSettled] = await Promise.all([
      workersStopped,
      startup ? settleWithin(startup, this.shutdownOperationTimeoutMs) : Promise.resolve(true),
      materializerLoop
        ? settleWithin(materializerLoop, this.shutdownOperationTimeoutMs)
        : Promise.resolve(true),
      settleAllWithin(activeMaterializers, this.shutdownOperationTimeoutMs),
    ]);
    if (!stopped || !startupSettled || !loopSettled || !materializersSettled) {
      this.currentState = "failed";
      throw new TypeError("Runtime supervisor root could not stop");
    }
    this.currentState = "stopped";
  }

  private assertStarting(signal: AbortSignal): void {
    if (signal.aborted || this.currentState !== "starting") {
      throw new TypeError("Runtime supervisor startup was cancelled");
    }
  }

  private async primeWorker(worker: CapturedManagedSupervisor, signal: AbortSignal): Promise<void> {
    for (let cycle = 0; cycle < this.startupDrainLimit; cycle += 1) {
      const result = await boundedNativeOperation(
        worker.runOnce,
        this.startupOperationTimeoutMs,
        signal
      );
      if (result.kind !== "value") throw new RootOperationFailure(result.kind);
      if (snapshotManagedRunResult(result.value).claimed === 0) return;
      this.assertStarting(signal);
    }
    throw new RootOperationFailure("invalid");
  }

  private async drainMaterializer(signal: AbortSignal): Promise<void> {
    for (let cycle = 0; cycle < this.startupDrainLimit; cycle += 1) {
      const result = await this.runMaterializerCycle(signal, this.startupOperationTimeoutMs);
      if (result.found === 0) return;
      this.assertStarting(signal);
    }
    throw new RootOperationFailure("invalid");
  }

  private trackMaterializerSettlement(value: unknown): void {
    const settlement = observeNativeSettlement(value);
    if (settlement === null) return;
    this.activeMaterializerSettlements.add(settlement);
    void settlement.then(() => this.activeMaterializerSettlements.delete(settlement));
  }

  private requestWorkersStop(): Promise<boolean> {
    if (this.shutdownWorkersPromise) return this.shutdownWorkersPromise;
    const pending = this.stopWorkers().finally(() => {
      if (this.shutdownWorkersPromise === pending) this.shutdownWorkersPromise = null;
    });
    this.shutdownWorkersPromise = pending;
    return pending;
  }

  private async stopWorkers(): Promise<boolean> {
    const results = await Promise.all(
      [this.lifecycle, this.compensation, this.receiptFollow].map((worker) =>
        boundedNativeOperation(worker.stop, this.shutdownOperationTimeoutMs)
      )
    );
    return results.every((result) => result.kind === "value" && result.value === undefined);
  }

  private async loopMaterializer(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      let busy = false;
      try {
        const result = await this.runMaterializerCycle(signal, this.materializerCycleTimeoutMs);
        busy = result.found > 0;
      } catch (error) {
        if (signal.aborted || (error instanceof RootOperationFailure && error.kind === "aborted")) {
          return;
        }
        reportOperationalError(this.onOperationalError);
        if (
          error instanceof RootOperationFailure &&
          (error.kind === "timeout" || error.kind === "invalid")
        ) {
          this.failRunningRoot();
          return;
        }
      }
      await abortableDelay(busy ? this.busyDelayMs : this.errorOrIdleDelay(), signal);
    }
  }

  private failRunningRoot(): void {
    if (this.currentState !== "running" && this.currentState !== "starting") return;
    this.currentState = "failed";
    this.startupController?.abort();
    this.materializerController?.abort();
    void this.requestWorkersStop();
  }

  private errorOrIdleDelay(): number {
    return this.lastMaterializerErrorAtMs !== null && this.materializerFailureSinceSuccess
      ? this.errorDelayMs
      : this.idleDelayMs;
  }

  private async runMaterializerCycle(
    signal: AbortSignal,
    timeoutMs: number
  ): Promise<RuntimeCompensationMaterializerRunResult> {
    const outcome = await boundedNativeOperation(
      () => this.runMaterializer(signal),
      timeoutMs,
      signal
    );
    if (outcome.kind !== "value") {
      this.recordMaterializerFailure();
      throw new RootOperationFailure(outcome.kind);
    }
    try {
      const result = snapshotMaterializerResult(outcome.value);
      this.lastMaterializerSuccessAtMs = sampleClock(this.clock);
      this.materializerFailureSinceSuccess = false;
      return result;
    } catch {
      this.recordMaterializerFailure();
      throw new RootOperationFailure("invalid");
    }
  }

  private recordMaterializerFailure(): void {
    this.lastMaterializerErrorAtMs = safeClockOrNull(this.clock) ?? 0;
    this.materializerFailureSinceSuccess = true;
  }
}

export function createRuntimeSupervisorRoot(
  options: RuntimeSupervisorRootOptions
): RuntimeSupervisorRoot {
  return new RuntimeSupervisorRoot(options);
}

function captureManagedSupervisor(value: unknown): CapturedManagedSupervisor {
  const start = captureDataMethod(value, "start", "Invalid Runtime supervisor root dependency");
  const runOnce = captureDataMethod(value, "runOnce", "Invalid Runtime supervisor root dependency");
  const stop = captureDataMethod(value, "stop", "Invalid Runtime supervisor root dependency");
  return Object.freeze({
    isRunning: captureBooleanReader(value, "running", "Invalid Runtime supervisor root dependency"),
    start: () => Reflect.apply(start, value, []),
    runOnce: () => Reflect.apply(runOnce, value, []),
    stop: () => Reflect.apply(stop, value, []),
  });
}

function captureDataMethod(
  target: unknown,
  key: PropertyKey,
  safeMessage: string
): (...args: unknown[]) => unknown {
  if ((typeof target !== "object" && typeof target !== "function") || target === null) {
    throw new TypeError(safeMessage);
  }
  try {
    const visited = new Set<object>();
    let current: object | null = target;
    for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
      if (visited.has(current)) throw new TypeError();
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) throw new TypeError();
        if (typeof descriptor.value !== "function") throw new TypeError();
        return descriptor.value as (...args: unknown[]) => unknown;
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
  } catch {
    throw new TypeError(safeMessage);
  }
  throw new TypeError(safeMessage);
}

function captureBooleanReader(
  target: unknown,
  key: PropertyKey,
  safeMessage: string
): () => boolean {
  if ((typeof target !== "object" && typeof target !== "function") || target === null) {
    throw new TypeError(safeMessage);
  }
  try {
    const visited = new Set<object>();
    let current: object | null = target;
    for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
      if (visited.has(current)) throw new TypeError();
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) {
        if (Object.prototype.hasOwnProperty.call(descriptor, "value")) {
          const owner = current;
          return () => {
            try {
              const latest = Object.getOwnPropertyDescriptor(owner, key);
              return (
                latest !== undefined &&
                Object.prototype.hasOwnProperty.call(latest, "value") &&
                latest.value === true
              );
            } catch {
              return false;
            }
          };
        }
        if (typeof descriptor.get !== "function") throw new TypeError();
        const getter = descriptor.get;
        return () => {
          try {
            return Reflect.apply(getter, target, []) === true;
          } catch {
            return false;
          }
        };
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
  } catch {
    throw new TypeError(safeMessage);
  }
  throw new TypeError(safeMessage);
}

function snapshotManagedRunResult(value: unknown): RuntimeManagedSupervisorRunResult {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) {
    throw new TypeError("Invalid Runtime managed supervisor result");
  }
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, "claimed");
  } catch {
    throw new TypeError("Invalid Runtime managed supervisor result");
  }
  if (
    !descriptor ||
    !descriptor.enumerable ||
    !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
    !Number.isSafeInteger(descriptor.value) ||
    descriptor.value < 0
  ) {
    throw new TypeError("Invalid Runtime managed supervisor result");
  }
  return Object.freeze({ claimed: descriptor.value as number });
}

function snapshotMaterializerResult(value: unknown): RuntimeCompensationMaterializerRunResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Invalid Runtime compensation materializer result");
  }
  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    throw new TypeError("Invalid Runtime compensation materializer result");
  }
  if (keys.length !== 2 || !keys.includes("found") || !keys.includes("created")) {
    throw new TypeError("Invalid Runtime compensation materializer result");
  }
  const found = dataInteger(value, "found");
  const created = dataInteger(value, "created");
  if (created > found || found > 1) {
    throw new TypeError("Invalid Runtime compensation materializer result");
  }
  return Object.freeze({ found, created });
}

function dataInteger(value: object, key: string): number {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, key);
  } catch {
    throw new TypeError("Invalid Runtime compensation materializer result");
  }
  if (
    !descriptor ||
    !descriptor.enumerable ||
    !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
    !Number.isSafeInteger(descriptor.value) ||
    descriptor.value < 0
  ) {
    throw new TypeError("Invalid Runtime compensation materializer result");
  }
  return descriptor.value as number;
}

function dataRecord(value: unknown, safeMessage: string): object {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) {
    throw new TypeError(safeMessage);
  }
  return value;
}

function requiredDataField(value: object, key: string, safeMessage: string): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, key);
  } catch {
    throw new TypeError(safeMessage);
  }
  if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
    throw new TypeError(safeMessage);
  }
  return descriptor.value;
}

function optionalDataField(value: object, key: string): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, key);
  } catch {
    throw new TypeError("Invalid Runtime supervisor root options");
  }
  if (!descriptor) return undefined;
  if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
    throw new TypeError("Invalid Runtime supervisor root options");
  }
  return descriptor.value;
}

function assertSynchronousVoid(value: unknown): void {
  if (value === undefined) return;
  suppressNativePromiseRejection(value);
  throw new TypeError("Invalid Runtime supervisor synchronous result");
}

function suppressNativePromiseRejection(value: unknown): void {
  try {
    Reflect.apply(Promise.prototype.then, value, [undefined, () => undefined]);
  } catch {
    // Custom thenables are deliberately not invoked.
  }
}

function observeNativeSettlement(value: unknown): Promise<void> | null {
  let attached = false;
  const settlement = new Promise<void>((resolve) => {
    try {
      Reflect.apply(Promise.prototype.then, value, [resolve, resolve]);
      attached = true;
    } catch {
      // Custom thenables are deliberately not invoked or tracked as native work.
    }
  });
  return attached ? settlement : null;
}

function boundedNativeOperation<T = unknown>(
  operation: () => unknown,
  timeoutMs: number,
  signal?: AbortSignal
): Promise<BoundedOperationResult<T>> {
  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const finish = (result: BoundedOperationResult<T>): void => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      resolve(result);
    };
    const abort = () => finish({ kind: "aborted" });
    if (signal?.aborted) {
      finish({ kind: "aborted" });
      return;
    }
    signal?.addEventListener("abort", abort, { once: true });
    timer = setTimeout(() => finish({ kind: "timeout" }), timeoutMs);

    let pending: unknown;
    try {
      pending = operation();
    } catch {
      finish({ kind: "error" });
      return;
    }
    try {
      Reflect.apply(Promise.prototype.then, pending, [
        (value: T) => finish({ kind: "value", value }),
        () => finish({ kind: "error" }),
      ]);
    } catch {
      finish({ kind: "invalid" });
    }
  });
}

function settleWithin(promise: Promise<unknown>, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => finish(false), timeoutMs);
    const finish = (result: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    try {
      Reflect.apply(Promise.prototype.then, promise, [() => finish(true), () => finish(true)]);
    } catch {
      finish(false);
    }
  });
}

async function settleAllWithin(
  promises: ReadonlyArray<Promise<unknown>>,
  timeoutMs: number
): Promise<boolean> {
  const results = await Promise.all(promises.map((promise) => settleWithin(promise, timeoutMs)));
  return results.every(Boolean);
}

function bound(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError("Invalid Runtime supervisor root bound");
  }
  return value as number;
}

function sampleClock(clock: () => number): number {
  const value = safeClockOrNull(clock);
  if (value === null) throw new TypeError("Invalid Runtime supervisor clock");
  return value;
}

function safeClockOrNull(clock: () => number): number | null {
  try {
    const value = clock();
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  } catch {
    return null;
  }
}

function reportOperationalError(
  callback: RuntimeSupervisorRootOptions["onOperationalError"]
): void {
  try {
    callback?.("runtime_supervisor_internal");
  } catch {
    // Observability cannot terminate the worker root.
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
