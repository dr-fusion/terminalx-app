import { describe, expect, it, vi } from "vitest";
import {
  RuntimeReceiptFollowSupervisor,
  type RuntimeReceiptFollowJournal,
  type RuntimeReceiptFollowLease,
  type RuntimeReceiptFollowReleaseOptions,
  type RuntimeReceiptFollowSettlementOptions,
  type RuntimeReceiptFollowTransport,
} from "../../src/lib/runtime/runtime-receipt-follow-supervisor";
import type { RuntimeHandle } from "../../src/lib/runtime/contracts";

const BINDING = Object.freeze({
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 2,
  sandboxId: "sandbox-1",
  sandboxGeneration: 3,
  runtimePrincipalId: "principal-1",
});

const CHECKPOINT = Object.freeze({
  cursor: "cursor-7",
  observationDigest: "a".repeat(64),
});

const HANDLE: RuntimeHandle = Object.freeze({
  binding: BINDING,
  opaqueHandleRef: "opaque-handle-1",
  capabilities: Object.freeze({
    isolatedExecution: true,
    brokeredCredentials: true,
    proxyOnlyEgress: true,
    checkpoints: true,
    yoloEligible: false,
  }),
});

function lease(): RuntimeReceiptFollowLease {
  return Object.freeze({
    binding: BINDING,
    runtimeAuthorizationGeneration: 4,
    issuerKeyId: "runtime-key-1",
    publicKeySpkiDigest: "b".repeat(64),
    checkpoint: CHECKPOINT,
    attempt: 1,
    leaseOwner: "worker-1",
    leaseVersion: 5,
    leaseExpiresAtMs: 1_100,
  });
}

class FakeJournal implements RuntimeReceiptFollowJournal {
  readonly reconciled: number[] = [];
  readonly released: RuntimeReceiptFollowReleaseOptions[] = [];
  readonly settled: RuntimeReceiptFollowSettlementOptions[] = [];
  claimed: RuntimeReceiptFollowLease | null = lease();
  settleError: unknown;

  reconcile(nowMs: number): number {
    this.reconciled.push(nowMs);
    return 0;
  }

  claim(): RuntimeReceiptFollowLease | null {
    return this.claimed;
  }

  renew(): { leaseExpiresAtMs: number } {
    return { leaseExpiresAtMs: 1_200 };
  }

  release(options: RuntimeReceiptFollowReleaseOptions): void {
    this.released.push(options);
  }

  settle(options: RuntimeReceiptFollowSettlementOptions): void {
    this.settled.push(options);
    if (this.settleError !== undefined) throw this.settleError;
  }
}

function supervisor(
  journal: FakeJournal,
  transport: RuntimeReceiptFollowTransport,
  overrides: Partial<ConstructorParameters<typeof RuntimeReceiptFollowSupervisor>[0]> = {}
) {
  return new RuntimeReceiptFollowSupervisor({
    journal,
    transport,
    handles: { resolve: async () => HANDLE },
    workerId: "worker-1",
    clock: () => 100,
    leaseDurationMs: 1_000,
    handleResolveTimeoutMs: 50,
    followPollTimeoutMs: 50,
    ...overrides,
  });
}

describe("RuntimeReceiptFollowSupervisor", () => {
  it("records a successful health heartbeat when a long poll cycle settles", async () => {
    let nowMs = 100;
    let releaseReconcile: (() => void) | undefined;
    const journal: RuntimeReceiptFollowJournal = {
      reconcile: () =>
        new Promise<number>((resolve) => {
          releaseReconcile = () => resolve(0);
        }),
      claim: () => null,
      renew: () => ({ leaseExpiresAtMs: 1_200 }),
      release: () => undefined,
      settle: () => undefined,
    };
    const worker = new RuntimeReceiptFollowSupervisor({
      journal,
      transport: {
        async *follow() {
          return;
        },
      },
      handles: { resolve: async () => HANDLE },
      workerId: "worker-1",
      clock: () => nowMs,
      leaseDurationMs: 1_000,
    });

    const running = worker.runOnce();
    expect(worker.health()).toMatchObject({ activeCycleStartedAtMs: 100 });
    nowMs = 40_100;
    releaseReconcile?.();
    await expect(running).resolves.toMatchObject({ claimed: 0 });
    expect(worker.health()).toEqual({
      lastSuccessAtMs: 40_100,
      lastErrorAtMs: null,
      activeCycleStartedAtMs: null,
      failureSinceSuccess: false,
    });
  });

  it("renews one exact lease, polls the receipt-only checkpoint, settles one item, and closes", async () => {
    const journal = new FakeJournal();
    const observation = Object.freeze({ kind: "runtime.lifecycle-receipt-observed" });
    let receivedHandle: RuntimeHandle | undefined;
    let receivedCheckpoint: unknown;
    let receivedSignal: AbortSignal | undefined;
    let closed = 0;
    const transport: RuntimeReceiptFollowTransport = {
      async *follow(handle, checkpoint, signal) {
        receivedHandle = handle;
        receivedCheckpoint = checkpoint;
        receivedSignal = signal;
        try {
          yield observation;
        } finally {
          closed += 1;
        }
      },
    };

    const worker = supervisor(journal, transport);
    await expect(worker.runOnce()).resolves.toEqual({
      claimed: 1,
      settled: 1,
      empty: 0,
      transportFailures: 0,
    });

    expect(receivedHandle).toEqual(HANDLE);
    expect(receivedHandle).not.toBe(HANDLE);
    expect(receivedCheckpoint).toEqual(CHECKPOINT);
    expect(receivedSignal).toBeInstanceOf(AbortSignal);
    expect(receivedSignal?.aborted).toBe(true);
    expect(closed).toBe(1);
    expect(journal.settled).toEqual([
      {
        runtimeAssignmentId: "assignment-1",
        runtimeAuthorizationGeneration: 4,
        workerId: "worker-1",
        expectedLeaseVersion: 5,
        expectedLeaseExpiresAtMs: 1_200,
        nowMs: 100,
        observation,
        receivedAtMs: 100,
      },
    ]);
    expect(journal.released).toEqual([]);
    expect(worker.health()).toEqual({
      lastSuccessAtMs: 100,
      lastErrorAtMs: null,
      activeCycleStartedAtMs: null,
      failureSinceSuccess: false,
    });
  });

  it("captures a data-property transport method before later replacement", async () => {
    const journal = new FakeJournal();
    let originalCalls = 0;
    let replacementCalls = 0;
    const transport = {
      async *follow() {
        originalCalls += 1;
        yield Object.freeze({ kind: "runtime.compensation-receipt-observed" });
      },
    };
    const worker = supervisor(journal, transport);
    transport.follow = async function* replacement() {
      replacementCalls += 1;
    };

    await worker.runOnce();
    expect(originalCalls).toBe(1);
    expect(replacementCalls).toBe(0);
    expect(journal.settled).toHaveLength(1);
  });

  it("rejects accessor-backed and trapping follow capabilities without invoking a getter", () => {
    const journal = new FakeJournal();
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, "follow", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return () => undefined;
      },
    });
    expect(() => supervisor(journal, accessor as RuntimeReceiptFollowTransport)).toThrow(
      "Invalid Runtime receipt follow capability"
    );
    expect(getterCalls).toBe(0);

    const trapping = new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          throw new Error("provider detail");
        },
      }
    );
    expect(() => supervisor(journal, trapping as RuntimeReceiptFollowTransport)).toThrow(
      "Invalid Runtime receipt follow capability"
    );
  });

  it("releases a completed empty poll without advancing settlement", async () => {
    const journal = new FakeJournal();
    const transport: RuntimeReceiptFollowTransport = {
      async *follow() {
        return;
      },
    };

    await expect(supervisor(journal, transport).runOnce()).resolves.toEqual({
      claimed: 1,
      settled: 0,
      empty: 1,
      transportFailures: 0,
    });
    expect(journal.settled).toEqual([]);
    expect(journal.released).toEqual([
      expect.objectContaining({
        expectedLeaseExpiresAtMs: 1_200,
        reason: "no-event",
      }),
    ]);
  });

  it("aborts and closes a timed-out poll before releasing the exact lease", async () => {
    const journal = new FakeJournal();
    let transportSignal: AbortSignal | undefined;
    let closeCalls = 0;
    const transport: RuntimeReceiptFollowTransport = {
      follow(_handle, _checkpoint, signal) {
        transportSignal = signal;
        const iterator: AsyncIterableIterator<unknown> = {
          [Symbol.asyncIterator]() {
            return iterator;
          },
          next() {
            return new Promise<IteratorResult<unknown>>(() => undefined);
          },
          return() {
            closeCalls += 1;
            return Promise.resolve({ value: undefined, done: true });
          },
        };
        return iterator;
      },
    };

    await expect(
      supervisor(journal, transport, { followPollTimeoutMs: 5 }).runOnce()
    ).resolves.toEqual({ claimed: 1, settled: 0, empty: 0, transportFailures: 1 });
    expect(transportSignal?.aborted).toBe(true);
    expect(closeCalls).toBe(1);
    expect(journal.released).toEqual([
      expect.objectContaining({ reason: "transport-unavailable" }),
    ]);
  });

  it("does not settle a poll result when stop wins the resolution race", async () => {
    const journal = new FakeJournal();
    const observation = Object.freeze({ kind: "runtime.lifecycle-receipt-observed" });
    let resolveNext: ((value: IteratorResult<unknown>) => void) | undefined;
    let closeCalls = 0;
    const transport: RuntimeReceiptFollowTransport = {
      follow() {
        const iterator: AsyncIterableIterator<unknown> = {
          [Symbol.asyncIterator]() {
            return iterator;
          },
          next() {
            return new Promise<IteratorResult<unknown>>((resolve) => {
              resolveNext = resolve;
            });
          },
          return() {
            closeCalls += 1;
            return Promise.resolve({ value: undefined, done: true });
          },
        };
        return iterator;
      },
    };
    const worker = supervisor(journal, transport, { followPollTimeoutMs: 500 });
    const run = worker.runOnce();
    await vi.waitFor(() => expect(resolveNext).toBeTypeOf("function"));

    let stopping: Promise<void> | undefined;
    resolveNext?.({ value: observation, done: false });
    queueMicrotask(() => {
      stopping = worker.stop();
    });

    await expect(run).resolves.toEqual({
      claimed: 1,
      settled: 0,
      empty: 0,
      transportFailures: 1,
    });
    await vi.waitFor(() => expect(stopping).toBeInstanceOf(Promise));
    await stopping!;
    expect(closeCalls).toBe(1);
    expect(journal.settled).toEqual([]);
    expect(journal.released).toEqual([
      expect.objectContaining({ reason: "transport-unavailable" }),
    ]);
  });

  it("refuses to settle inside the lease completion margin", async () => {
    const journal = new FakeJournal();
    const readings = [100, 100, 100, 100, 100, 1_190];
    let transportSignal: AbortSignal | undefined;
    const transport: RuntimeReceiptFollowTransport = {
      async *follow(_handle, _checkpoint, signal) {
        transportSignal = signal;
        yield Object.freeze({ kind: "runtime.compensation-receipt-observed" });
      },
    };

    await expect(
      supervisor(journal, transport, {
        clock: () => readings.shift() ?? 1_190,
      }).runOnce()
    ).resolves.toEqual({ claimed: 1, settled: 0, empty: 0, transportFailures: 1 });
    expect(transportSignal?.aborted).toBe(true);
    expect(journal.settled).toEqual([]);
    expect(journal.released).toEqual([
      expect.objectContaining({ nowMs: 1_190, reason: "transport-unavailable" }),
    ]);
  });

  it.each(["accessor", "proxy"] as const)(
    "contains a descriptor-hostile iterator result %s as a transport failure",
    async (kind) => {
      const journal = new FakeJournal();
      let getterCalls = 0;
      const transport: RuntimeReceiptFollowTransport = {
        follow() {
          const iterator: AsyncIterableIterator<unknown> = {
            [Symbol.asyncIterator]() {
              return iterator;
            },
            next() {
              const target = { value: Object.freeze({}), done: false };
              if (kind === "accessor") {
                return Promise.resolve(
                  Object.defineProperty(target, "done", {
                    enumerable: true,
                    get() {
                      getterCalls += 1;
                      throw new Error("provider-secret-result-getter");
                    },
                  }) as unknown as IteratorResult<unknown>
                );
              }
              return Promise.resolve(
                new Proxy(target, {
                  getOwnPropertyDescriptor() {
                    throw new Error("provider-secret-result-proxy");
                  },
                  get(_target, key) {
                    if (key === "then") return undefined;
                    getterCalls += 1;
                    throw new Error("provider-secret-result-get");
                  },
                }) as IteratorResult<unknown>
              );
            },
            return() {
              return Promise.resolve({ value: undefined, done: true });
            },
          };
          return iterator;
        },
      };

      await expect(supervisor(journal, transport).runOnce()).resolves.toEqual({
        claimed: 1,
        settled: 0,
        empty: 0,
        transportFailures: 1,
      });
      expect(getterCalls).toBe(0);
      expect(journal.settled).toEqual([]);
      expect(journal.released).toHaveLength(1);
    }
  );

  it("handles late next and close rejections after timeout without an unhandled rejection", async () => {
    const journal = new FakeJournal();
    let rejectNext: ((reason?: unknown) => void) | undefined;
    let transportSignal: AbortSignal | undefined;
    const transport: RuntimeReceiptFollowTransport = {
      follow(_handle, _checkpoint, signal) {
        transportSignal = signal;
        const iterator: AsyncIterableIterator<unknown> = {
          [Symbol.asyncIterator]() {
            return iterator;
          },
          next() {
            return new Promise<IteratorResult<unknown>>((_resolve, reject) => {
              rejectNext = reject;
            });
          },
          return() {
            return Promise.reject(new Error("provider-secret-close-rejection"));
          },
        };
        return iterator;
      },
    };

    await expect(
      supervisor(journal, transport, { followPollTimeoutMs: 5 }).runOnce()
    ).resolves.toEqual({ claimed: 1, settled: 0, empty: 0, transportFailures: 1 });
    rejectNext?.(new Error("provider-secret-late-next-rejection"));
    await Promise.resolve();
    await Promise.resolve();
    expect(transportSignal?.aborted).toBe(true);
    expect(journal.released).toHaveLength(1);
  });

  it("contains a hostile next thenable without exposing its rejection detail", async () => {
    const journal = new FakeJournal();
    let transportSignal: AbortSignal | undefined;
    const transport: RuntimeReceiptFollowTransport = {
      follow(_handle, _checkpoint, signal) {
        transportSignal = signal;
        const iterator = {
          [Symbol.asyncIterator]() {
            return iterator;
          },
          next() {
            return Object.defineProperty({}, "then", {
              get() {
                throw new Error("provider-secret-thenable-getter");
              },
            });
          },
          return() {
            return Promise.resolve({ value: undefined, done: true });
          },
        };
        return iterator as unknown as AsyncIterable<unknown>;
      },
    };

    await expect(supervisor(journal, transport).runOnce()).resolves.toEqual({
      claimed: 1,
      settled: 0,
      empty: 0,
      transportFailures: 1,
    });
    expect(transportSignal?.aborted).toBe(true);
    expect(journal.settled).toEqual([]);
    expect(journal.released).toHaveLength(1);
  });

  it("never invokes transport for an unavailable or descriptor-hostile historical handle", async () => {
    const journal = new FakeJournal();
    const follow = vi.fn(async function* () {
      yield Object.freeze({});
    });
    let getterCalls = 0;
    const hostileHandle = Object.defineProperty(
      {
        opaqueHandleRef: "hostile",
        capabilities: HANDLE.capabilities,
      },
      "binding",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          return BINDING;
        },
      }
    ) as RuntimeHandle;

    await expect(
      supervisor(journal, { follow }, { handles: { resolve: async () => hostileHandle } }).runOnce()
    ).resolves.toEqual({ claimed: 1, settled: 0, empty: 0, transportFailures: 1 });
    expect(getterCalls).toBe(0);
    expect(follow).not.toHaveBeenCalled();
    expect(journal.released).toHaveLength(1);
  });

  it("propagates settlement failure after closing and never releases it as harmless", async () => {
    const journal = new FakeJournal();
    journal.settleError = new Error("safe journal rejection");
    let closed = 0;
    const transport: RuntimeReceiptFollowTransport = {
      async *follow() {
        try {
          yield Object.freeze({ kind: "runtime.compensation-receipt-observed" });
        } finally {
          closed += 1;
        }
      },
    };

    await expect(supervisor(journal, transport).runOnce()).rejects.toThrow(
      "safe journal rejection"
    );
    expect(closed).toBe(1);
    expect(journal.released).toEqual([]);
  });

  it("shares concurrent runOnce calls and stop aborts the live receipt transport", async () => {
    const journal = new FakeJournal();
    let transportSignal: AbortSignal | undefined;
    let closeCalls = 0;
    const transport: RuntimeReceiptFollowTransport = {
      follow(_handle, _checkpoint, signal) {
        transportSignal = signal;
        const iterator: AsyncIterableIterator<unknown> = {
          [Symbol.asyncIterator]() {
            return iterator;
          },
          next() {
            return new Promise<IteratorResult<unknown>>(() => undefined);
          },
          return() {
            closeCalls += 1;
            return Promise.resolve({ value: undefined, done: true });
          },
        };
        return iterator;
      },
    };
    const worker = supervisor(journal, transport, { followPollTimeoutMs: 500 });
    const first = worker.runOnce();
    const second = worker.runOnce();
    expect(second).toBe(first);
    await vi.waitFor(() => expect(transportSignal).toBeInstanceOf(AbortSignal));
    await worker.stop();

    await expect(first).resolves.toEqual({
      claimed: 1,
      settled: 0,
      empty: 0,
      transportFailures: 1,
    });
    expect(transportSignal?.aborted).toBe(true);
    expect(closeCalls).toBe(1);
  });

  it("keeps start and stop idempotent across an immediate restart", async () => {
    const journal = new FakeJournal();
    journal.claimed = null;
    const worker = supervisor(
      journal,
      {
        async *follow() {
          return;
        },
      },
      { idleDelayMs: 1, busyDelayMs: 1, errorDelayMs: 1 }
    );

    worker.start();
    worker.start();
    expect(worker.running).toBe(true);
    const firstStop = worker.stop();
    worker.start();
    await firstStop;
    expect(worker.running).toBe(false);

    worker.start();
    expect(worker.running).toBe(true);
    await worker.stop();
    expect(worker.running).toBe(false);
  });

  it("maps a hostile renewal result to a stable internal data error", async () => {
    const journal = new FakeJournal();
    journal.renew = () =>
      new Proxy(
        { leaseExpiresAtMs: 1_200 },
        {
          getPrototypeOf() {
            throw new Error("provider-secret-renewal-proxy");
          },
        }
      );
    const transport: RuntimeReceiptFollowTransport = {
      async *follow() {
        yield Object.freeze({});
      },
    };

    await expect(supervisor(journal, transport).runOnce()).rejects.toThrow(
      "Invalid Runtime receipt follow data"
    );
    expect(journal.settled).toEqual([]);
  });
});
