export type RuntimeBoundedOperationResult<T> =
  | { readonly kind: "value"; readonly value: T }
  | { readonly kind: "error"; readonly error: unknown }
  | { readonly kind: "timeout" }
  | { readonly kind: "aborted" };

interface RunBoundedRuntimeOperationOptions {
  /** Receipt following owns a one-shot poll and closes its operation signal at settlement. */
  readonly abortOnSettlement?: boolean;
}

/**
 * Bound an internal asynchronous capability without assimilating custom thenables.
 * Provider cancellation is advisory; callers still classify a timeout according
 * to whether their durable dispatch interlock has already been crossed.
 */
export function runBoundedRuntimeOperation<T>(
  operation: (signal: AbortSignal) => T,
  timeoutMs: number,
  parentSignal: AbortSignal,
  options: RunBoundedRuntimeOperationOptions = {}
): Promise<RuntimeBoundedOperationResult<Awaited<T>>> {
  return new Promise((resolve) => {
    const controller = new AbortController();
    if (parentSignal.aborted) {
      controller.abort();
      resolve({ kind: "aborted" });
      return;
    }
    let settled = false;
    const finish = (result: RuntimeBoundedOperationResult<Awaited<T>>): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      parentSignal.removeEventListener("abort", abortFromParent);
      if (options.abortOnSettlement === true) controller.abort();
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

    let pending: unknown;
    try {
      pending = operation(controller.signal);
    } catch (error) {
      finish({ kind: "error", error });
      return;
    }
    try {
      Reflect.apply(Promise.prototype.then, pending, [
        (value: Awaited<T>) => finish({ kind: "value", value }),
        (error: unknown) => finish({ kind: "error", error }),
      ]);
    } catch {
      // Never invoke a provider-controlled custom `then` implementation.
      finish({ kind: "error", error: new TypeError("Invalid Runtime asynchronous capability") });
    }
  });
}

export function linkRuntimeAbortSignal(
  source: AbortSignal | undefined,
  target: AbortController
): () => void {
  if (!source) return () => undefined;
  const abort = () => target.abort();
  if (source.aborted) {
    abort();
    return () => undefined;
  }
  source.addEventListener("abort", abort, { once: true });
  return () => source.removeEventListener("abort", abort);
}

export function runtimeAbortableDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
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

/** A broken health clock fails readiness closed without changing worker control flow. */
export function sampleRuntimeHealthClock(clock: () => number, minimum = 0): number | null {
  try {
    const value = clock();
    return Number.isSafeInteger(minimum) &&
      minimum >= 0 &&
      Number.isSafeInteger(value) &&
      value >= minimum
      ? value
      : null;
  } catch {
    return null;
  }
}

export function runtimeHealthClockMinimum(...timestamps: Array<number | null>): number {
  return Math.max(0, ...timestamps.filter((value): value is number => value !== null));
}
