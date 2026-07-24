import { describe, expect, it, vi } from "vitest";
import {
  createRuntimeSupervisorComposition,
  type Runtime,
  type RuntimeCompensationJournal,
  type RuntimeLifecycleJournal,
  type RuntimeReceiptFollowJournal,
  type RuntimeSupervisorKernel,
} from "@/lib/runtime";

const SNAPSHOT = Object.freeze([
  Object.freeze({
    sessionId: "session-1",
    runtimeAuthorizationGeneration: 3,
    state: "active" as const,
  }),
]);

function dependencies() {
  const order: string[] = [];
  const lifecycleJournal: RuntimeLifecycleJournal = {
    reconcile: vi.fn(async () => {
      order.push("lifecycle");
    }),
    claim: vi.fn(async () => []),
    renew: vi.fn(async () => ({ kind: "superseded" as const })),
    complete: vi.fn(async () => undefined),
  };
  const receiptFollowJournal: RuntimeReceiptFollowJournal = {
    reconcile: vi.fn(() => {
      order.push("receipt-follow");
      return 0;
    }),
    claim: vi.fn(() => null),
    renew: vi.fn(() => ({ leaseExpiresAtMs: 1 })),
    release: vi.fn(() => undefined),
    settle: vi.fn(() => undefined),
  };
  const compensationJournal: RuntimeCompensationJournal = {
    reconcile: vi.fn(async () => {
      order.push("compensation");
    }),
    claim: vi.fn(async () => null),
    renew: vi.fn(async () => ({ kind: "expired-before-dispatch" as const })),
    complete: vi.fn(async () => undefined),
  };
  const kernel: RuntimeSupervisorKernel = {
    runtimeWriteStateSnapshotSource: {
      read: vi.fn(() => {
        order.push("snapshot");
        return SNAPSHOT;
      }),
    },
    runtimeLifecycleJournal: lifecycleJournal,
    runtimeReceiptFollowJournal: receiptFollowJournal,
    runtimeCompensationJournal: compensationJournal,
    runtimeCompensationMaterializer: {
      runOnce: vi.fn(async () => {
        order.push("materializer");
        return { found: 0, created: 0 };
      }),
    },
  };
  const runtime: Runtime = {
    ensure: vi.fn(async () => {
      throw new Error("not used");
    }),
    command: vi.fn(async () => {
      throw new Error("not used");
    }),
    follow: vi.fn(async function* () {
      return;
    }),
    retire: vi.fn(async () => undefined),
  };
  return { kernel, runtime, order };
}

function compositionOptions(input: ReturnType<typeof dependencies>) {
  return {
    kernel: input.kernel,
    runtime: input.runtime,
    receiptTransport: {
      follow: async function* () {
        return;
      },
    },
    lifecycleHandles: { resolve: async () => null },
    receiptFollowHandles: { resolve: async () => null },
    compensationHandles: { resolve: async () => null },
    verifyLifecycleAuthority: async () => true,
    verifyLifecycleEnforcementProof: async () => true,
    verifyCompensationAuthority: async () => true,
    verifyCompensationEnforcementProof: async () => true,
    workerIdPrefix: "host-1",
    clock: () => 100,
  };
}

function replaceMethod(target: object, key: PropertyKey, replacement: unknown): void {
  Object.defineProperty(target, key, {
    configurable: true,
    enumerable: true,
    value: replacement,
    writable: true,
  });
}

describe("Runtime supervisor production composition", () => {
  it("boots the complete worker graph only after durable fences and recovery materialization", async () => {
    const input = dependencies();
    const composition = createRuntimeSupervisorComposition(compositionOptions(input));

    expect(
      composition.writeStateRegistry.isWriteAllowed({
        sessionId: "session-1",
        runtimeAuthorizationGeneration: 3,
      })
    ).toBe(false);

    await composition.root.start();
    expect(input.order.slice(0, 5)).toEqual([
      "snapshot",
      "lifecycle",
      "receipt-follow",
      "materializer",
      "compensation",
    ]);
    expect(composition.root.readiness()).toMatchObject({ ready: true, state: "running" });
    expect(
      composition.writeStateRegistry.isWriteAllowed({
        sessionId: "session-1",
        runtimeAuthorizationGeneration: 3,
      })
    ).toBe(true);
    expect(Object.isFrozen(composition)).toBe(true);

    await composition.root.stop();
    expect(composition.root.readiness()).toMatchObject({ ready: false, state: "stopped" });
  });

  it("rejects an incomplete recovery trust group before constructing workers", () => {
    const input = dependencies();
    const missingMaterializer = {
      ...input.kernel,
      runtimeCompensationMaterializer: undefined,
    };
    const missingJournal = {
      ...input.kernel,
      runtimeCompensationJournal: undefined,
    };

    expect(() =>
      createRuntimeSupervisorComposition({
        ...compositionOptions(input),
        kernel: missingMaterializer,
      })
    ).toThrow("requires compensation recovery");
    expect(() =>
      createRuntimeSupervisorComposition({
        ...compositionOptions(input),
        kernel: missingJournal,
      })
    ).toThrow("requires compensation recovery");
  });

  it("wires each worker to its complete trust-group seam and component-scoped worker ID", async () => {
    const input = dependencies();
    const composition = createRuntimeSupervisorComposition(compositionOptions(input));

    await Promise.all([
      composition.lifecycle.runOnce(),
      composition.receiptFollow.runOnce(),
      composition.compensation.runOnce(),
    ]);

    expect(input.kernel.runtimeLifecycleJournal.claim).toHaveBeenCalledWith(
      expect.objectContaining({ workerId: "host-1:lifecycle" })
    );
    expect(input.kernel.runtimeReceiptFollowJournal.claim).toHaveBeenCalledWith(
      expect.objectContaining({ workerId: "host-1:receipt-follow" })
    );
    expect(input.kernel.runtimeCompensationJournal?.claim).toHaveBeenCalledWith(
      expect.objectContaining({ workerId: "host-1:compensation" })
    );
  });

  it("pins source, materializer, and journal data methods against later replacement", async () => {
    const input = dependencies();
    const composition = createRuntimeSupervisorComposition(compositionOptions(input));
    const replacementSnapshot = vi.fn(() => {
      throw new Error("replacement snapshot must not run");
    });
    const replacementMaterializer = vi.fn(async () => {
      throw new Error("replacement materializer must not run");
    });
    const replacementLifecycle = vi.fn(async () => {
      throw new Error("replacement lifecycle must not run");
    });
    const replacementReceiptFollow = vi.fn(() => {
      throw new Error("replacement receipt follow must not run");
    });
    const replacementCompensation = vi.fn(async () => {
      throw new Error("replacement compensation must not run");
    });

    replaceMethod(input.kernel.runtimeWriteStateSnapshotSource, "read", replacementSnapshot);
    replaceMethod(
      input.kernel.runtimeCompensationMaterializer as object,
      "runOnce",
      replacementMaterializer
    );
    replaceMethod(input.kernel.runtimeLifecycleJournal, "reconcile", replacementLifecycle);
    replaceMethod(input.kernel.runtimeReceiptFollowJournal, "reconcile", replacementReceiptFollow);
    replaceMethod(
      input.kernel.runtimeCompensationJournal as object,
      "reconcile",
      replacementCompensation
    );

    await composition.root.start();
    expect(input.order.slice(0, 5)).toEqual([
      "snapshot",
      "lifecycle",
      "receipt-follow",
      "materializer",
      "compensation",
    ]);
    expect(replacementSnapshot).not.toHaveBeenCalled();
    expect(replacementMaterializer).not.toHaveBeenCalled();
    expect(replacementLifecycle).not.toHaveBeenCalled();
    expect(replacementReceiptFollow).not.toHaveBeenCalled();
    expect(replacementCompensation).not.toHaveBeenCalled();
    await composition.root.stop();
  });

  it("rejects accessor-backed and descriptor-hostile dependencies without leaking details", () => {
    const input = dependencies();
    let getterCalls = 0;
    const accessorOptions = compositionOptions(input);
    Object.defineProperty(accessorOptions, "kernel", {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("private provider path");
      },
    });

    expect(() => createRuntimeSupervisorComposition(accessorOptions)).toThrow(
      "Invalid Runtime supervisor composition"
    );
    expect(getterCalls).toBe(0);

    let nestedGetterCalls = 0;
    const nestedAccessorOptions = compositionOptions(input);
    nestedAccessorOptions.receiptTransport = Object.defineProperty({}, "follow", {
      enumerable: true,
      get() {
        nestedGetterCalls += 1;
        throw new Error("private receipt endpoint");
      },
    }) as (typeof nestedAccessorOptions)["receiptTransport"];
    expect(() => createRuntimeSupervisorComposition(nestedAccessorOptions)).toThrow(
      "Invalid Runtime supervisor composition"
    );
    expect(nestedGetterCalls).toBe(0);

    const hostile = new Proxy(compositionOptions(input), {
      getOwnPropertyDescriptor() {
        throw new Error("private worker identity");
      },
    });
    let failure: unknown;
    try {
      createRuntimeSupervisorComposition(hostile);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(TypeError);
    expect((failure as Error).message).toBe("Invalid Runtime supervisor composition");
  });

  it("keeps writes and workers closed when the durable snapshot cannot be loaded", async () => {
    const input = dependencies();
    replaceMethod(input.kernel.runtimeWriteStateSnapshotSource, "read", () => {
      throw new Error("sqlite path and tenant secret");
    });
    const composition = createRuntimeSupervisorComposition(compositionOptions(input));

    let failure: unknown;
    try {
      await composition.root.start();
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(TypeError);
    expect((failure as Error).message).toBe("Runtime supervisor root could not start");
    expect(composition.writeStateRegistry.isBootstrapped).toBe(false);
    expect(input.kernel.runtimeCompensationMaterializer?.runOnce).not.toHaveBeenCalled();
    expect(input.kernel.runtimeLifecycleJournal.reconcile).not.toHaveBeenCalled();
    expect(input.kernel.runtimeReceiptFollowJournal.reconcile).not.toHaveBeenCalled();
    expect(input.kernel.runtimeCompensationJournal?.reconcile).not.toHaveBeenCalled();
  });
});
