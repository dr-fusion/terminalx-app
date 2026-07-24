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

export interface RuntimeOutboxApplier {
  apply(delivery: RuntimeOutboxDelivery): Promise<void>;
}

export type RuntimeOutboxKernel = Pick<TeamSessions, "claimRuntimeOutbox" | "dispatch">;

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
  onOperationalError?: (code: RuntimeOutboxErrorCode) => void;
}

export interface RuntimeOutboxRunResult {
  claimed: number;
  acknowledged: number;
  retried: number;
  failedPermanently: number;
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
  private readonly onOperationalError?: (code: RuntimeOutboxErrorCode) => void;
  private controller: AbortController | null = null;
  private loopPromise: Promise<void> | null = null;
  private activeRun: Promise<RuntimeOutboxRunResult> | null = null;

  constructor(options: RuntimeOutboxWorkerOptions) {
    if (!isSafeIdentifier(options.workerId)) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    this.kernel = options.kernel;
    this.runtime = options.runtime;
    this.workerId = options.workerId;
    this.clock = options.clock ?? Date.now;
    this.claimOptions = {
      workerId: options.workerId,
      limit: boundedInteger(options.claimLimit ?? 1, 1, 100),
      leaseDurationMs: boundedInteger(options.leaseDurationMs ?? 30_000, 1_000, 300_000),
    };
    this.idleDelayMs = boundedInteger(options.idleDelayMs ?? 250, 1, 60_000);
    this.busyDelayMs = boundedInteger(options.busyDelayMs ?? 10, 1, 60_000);
    this.errorDelayMs = boundedInteger(options.errorDelayMs ?? 1_000, 1, 60_000);
    this.maxTransientAttempts = boundedInteger(options.maxTransientAttempts ?? 5, 1, 100);
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

  runOnce(): Promise<RuntimeOutboxRunResult> {
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
        const delay =
          result.retried > 0
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

  private async processOneBatch(): Promise<RuntimeOutboxRunResult> {
    const deliveries = await this.kernel.claimRuntimeOutbox(this.claimOptions);
    const result: RuntimeOutboxRunResult = {
      claimed: deliveries.length,
      acknowledged: 0,
      retried: 0,
      failedPermanently: 0,
    };
    for (const delivery of deliveries) {
      let failure: ReturnType<typeof safeRuntimeFailure> | null = null;
      try {
        await this.runtime.apply(delivery);
      } catch (error) {
        failure = safeRuntimeFailure(error);
      }
      if (!failure) {
        await this.dispatchOutcome(delivery, "acknowledge");
        result.acknowledged += 1;
        continue;
      }
      const retryable = failure.retryable && delivery.attempts < this.maxTransientAttempts;
      await this.dispatchOutcome(delivery, "fail", failure.code, retryable);
      if (retryable) result.retried += 1;
      else result.failedPermanently += 1;
    }
    return result;
  }

  private async dispatchOutcome(
    delivery: RuntimeOutboxDelivery,
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
        key: `${delivery.outboxId}:${delivery.attempts}:${outcome}`,
      },
      occurredAtMs,
      outboxId: delivery.outboxId,
      workerId: this.workerId,
      expectedAttempt: delivery.attempts,
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
