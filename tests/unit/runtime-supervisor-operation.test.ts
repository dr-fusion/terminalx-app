import { describe, expect, it, vi } from "vitest";
import { runBoundedRuntimeOperation } from "@/lib/runtime/runtime-supervisor-operation";

describe("Runtime supervisor bounded operations", () => {
  it("settles a native Promise and optionally closes its operation signal", async () => {
    let operationSignal: AbortSignal | undefined;
    const result = await runBoundedRuntimeOperation(
      async (signal) => {
        operationSignal = signal;
        return "settled" as const;
      },
      100,
      new AbortController().signal,
      { abortOnSettlement: true }
    );

    expect(result).toEqual({ kind: "value", value: "settled" });
    expect(operationSignal?.aborted).toBe(true);
  });

  it("rejects a custom thenable without reading or invoking its then capability", async () => {
    let getterCalls = 0;
    const thenable = Object.defineProperty({}, "then", {
      get() {
        getterCalls += 1;
        throw new Error("provider-private-then-getter");
      },
    });

    const result = await runBoundedRuntimeOperation(
      () => thenable as never,
      100,
      new AbortController().signal
    );

    expect(result.kind).toBe("error");
    expect(getterCalls).toBe(0);
    expect(JSON.stringify(result)).not.toContain("provider-private");
  });

  it("aborts the child operation on timeout and parent cancellation", async () => {
    const timeoutObserver = vi.fn();
    const timedOut = await runBoundedRuntimeOperation(
      (signal) => {
        signal.addEventListener("abort", timeoutObserver, { once: true });
        return new Promise(() => undefined);
      },
      5,
      new AbortController().signal
    );
    expect(timedOut).toEqual({ kind: "timeout" });
    expect(timeoutObserver).toHaveBeenCalledOnce();

    const parent = new AbortController();
    const cancelled = runBoundedRuntimeOperation(
      () => new Promise(() => undefined),
      1_000,
      parent.signal
    );
    parent.abort();
    await expect(cancelled).resolves.toEqual({ kind: "aborted" });
  });
});
