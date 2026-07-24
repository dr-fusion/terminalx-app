import { describe, expect, it, vi } from "vitest";
import {
  RuntimeSupervisorRoot,
  createRuntimeWriteStateRegistry,
  type RuntimeManagedSupervisor,
} from "../../src/lib/runtime";

class FakeSupervisor implements RuntimeManagedSupervisor {
  running = false;
  readonly runOnce = vi.fn(async () => ({ claimed: 0 }));
  readonly start = vi.fn(() => {
    this.running = true;
  });
  readonly stop = vi.fn(async () => {
    this.running = false;
  });
}

const SNAPSHOT = Object.freeze([
  Object.freeze({
    sessionId: "session-1",
    runtimeAuthorizationGeneration: 3,
    state: "fenced" as const,
  }),
]);

function dependencies() {
  return {
    lifecycle: new FakeSupervisor(),
    receiptFollow: new FakeSupervisor(),
    compensation: new FakeSupervisor(),
    materializer: { runOnce: vi.fn(async () => ({ found: 0, created: 0 })) },
    writeStateRegistry: createRuntimeWriteStateRegistry({ requireBootstrap: true }),
    writeStateSource: { read: vi.fn(() => SNAPSHOT) },
  };
}

describe("RuntimeSupervisorRoot", () => {
  it("loads durable write state and completes one compensation cycle before readiness", async () => {
    const input = dependencies();
    const order: string[] = [];
    input.writeStateSource.read.mockImplementation(() => {
      order.push("snapshot");
      return SNAPSHOT;
    });
    input.materializer.runOnce.mockImplementation(async () => {
      expect(input.writeStateRegistry.hasDurableSnapshot).toBe(true);
      order.push("materializer");
      return { found: 0, created: 0 };
    });
    for (const [name, worker] of [
      ["lifecycle-reconcile", input.lifecycle],
      ["follow-reconcile", input.receiptFollow],
      ["compensation-reconcile", input.compensation],
    ] as const) {
      worker.runOnce.mockImplementation(async () => {
        order.push(name);
        return { claimed: 0 };
      });
    }
    for (const [name, worker] of [
      ["follow", input.receiptFollow],
      ["lifecycle", input.lifecycle],
      ["compensation", input.compensation],
    ] as const) {
      worker.start.mockImplementation(() => {
        order.push(name);
        worker.running = true;
      });
    }
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      materializerIdleDelayMs: 60_000,
    });

    await root.start();
    expect(order.slice(0, 8)).toEqual([
      "snapshot",
      "lifecycle-reconcile",
      "follow-reconcile",
      "materializer",
      "compensation-reconcile",
      "compensation",
      "follow",
      "lifecycle",
    ]);
    expect(root.readiness()).toEqual({
      ready: true,
      state: "running",
      durableWriteStateLoaded: true,
      lifecycleReconciled: true,
      receiptFollowReconciled: true,
      compensationReconciled: true,
      restartReconciled: true,
      lifecycleRunning: true,
      receiptFollowRunning: true,
      compensationRunning: true,
      materializerHealthy: true,
      lastMaterializerSuccessAtMs: 100,
      lastMaterializerErrorAtMs: null,
    });
    expect(
      input.writeStateRegistry.isWriteAllowed({
        sessionId: "session-1",
        runtimeAuthorizationGeneration: 2,
      })
    ).toBe(false);

    await root.stop();
    expect(root.state).toBe("stopped");
    expect(input.lifecycle.stop).toHaveBeenCalledOnce();
    expect(input.receiptFollow.stop).toHaveBeenCalledOnce();
    expect(input.compensation.stop).toHaveBeenCalledOnce();
  });

  it("shares concurrent startup and refuses to start the same root after stop", async () => {
    const input = dependencies();
    let release: (() => void) | undefined;
    input.materializer.runOnce.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ found: 0, created: 0 });
        })
    );
    const root = new RuntimeSupervisorRoot({ ...input, clock: () => 100 });

    const first = root.start();
    const second = root.start();
    expect(second).toBe(first);
    await vi.waitFor(() => expect(release).toBeTypeOf("function"));
    release?.();
    await first;
    await root.stop();
    await expect(root.start()).rejects.toThrow("cannot be restarted");
  });

  it("fails startup closed when the durable snapshot or initial materializer cycle fails", async () => {
    const snapshotFailure = dependencies();
    snapshotFailure.writeStateSource.read.mockImplementation(() => {
      throw new Error("database filename must stay private");
    });
    const first = new RuntimeSupervisorRoot({ ...snapshotFailure, clock: () => 100 });
    await expect(first.start()).rejects.toThrow("could not start");
    expect(first.state).toBe("failed");
    expect(snapshotFailure.receiptFollow.start).not.toHaveBeenCalled();
    expect(String(await first.start().catch((error: unknown) => error))).not.toContain(
      "database filename"
    );

    const materializerFailure = dependencies();
    materializerFailure.materializer.runOnce.mockRejectedValueOnce(
      new Error("platform signing detail")
    );
    const second = new RuntimeSupervisorRoot({ ...materializerFailure, clock: () => 100 });
    await expect(second.start()).rejects.toThrow("could not start");
    expect(second.state).toBe("failed");
    expect(materializerFailure.lifecycle.start).not.toHaveBeenCalled();
  });

  it("cannot report readiness before every restart reconciliation has completed", async () => {
    const input = dependencies();
    let releaseCompensation: (() => void) | undefined;
    input.compensation.runOnce.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          releaseCompensation = () => resolve({ claimed: 0 });
        })
    );
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      materializerIdleDelayMs: 60_000,
    });

    const startup = root.start();
    await vi.waitFor(() => expect(releaseCompensation).toBeTypeOf("function"));
    expect(root.readiness()).toMatchObject({
      ready: false,
      state: "starting",
      durableWriteStateLoaded: true,
      lifecycleReconciled: true,
      receiptFollowReconciled: true,
      compensationReconciled: false,
      restartReconciled: false,
      lifecycleRunning: false,
      receiptFollowRunning: false,
      compensationRunning: false,
    });
    expect(input.lifecycle.start).not.toHaveBeenCalled();
    expect(input.receiptFollow.start).not.toHaveBeenCalled();
    expect(input.compensation.start).not.toHaveBeenCalled();

    releaseCompensation?.();
    await startup;
    expect(root.readiness()).toMatchObject({
      ready: true,
      restartReconciled: true,
      compensationReconciled: true,
    });
    await root.stop();
  });

  it("drains each startup stage through a final idle reconciliation", async () => {
    const input = dependencies();
    input.lifecycle.runOnce
      .mockResolvedValueOnce({ claimed: 1 })
      .mockResolvedValueOnce({ claimed: 0 });
    input.receiptFollow.runOnce
      .mockResolvedValueOnce({ claimed: 1 })
      .mockResolvedValueOnce({ claimed: 0 });
    input.materializer.runOnce
      .mockResolvedValueOnce({ found: 1, created: 1 })
      .mockResolvedValue({ found: 0, created: 0 });
    input.compensation.runOnce
      .mockImplementationOnce(async () => {
        expect(input.materializer.runOnce).toHaveBeenCalledTimes(2);
        return { claimed: 1 };
      })
      .mockResolvedValueOnce({ claimed: 0 });
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      startupDrainLimit: 3,
      materializerIdleDelayMs: 60_000,
    });

    await root.start();
    expect(input.lifecycle.runOnce).toHaveBeenCalledTimes(2);
    expect(input.receiptFollow.runOnce).toHaveBeenCalledTimes(2);
    expect(input.compensation.runOnce).toHaveBeenCalledTimes(2);
    expect(root.readiness()).toMatchObject({ ready: true, restartReconciled: true });
    await root.stop();
  });

  it("fails closed when the bounded startup drain never reaches idle", async () => {
    const input = dependencies();
    input.lifecycle.runOnce.mockResolvedValue({ claimed: 1 });
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      startupDrainLimit: 3,
    });

    await expect(root.start()).rejects.toThrow("could not start");
    expect(input.lifecycle.runOnce).toHaveBeenCalledTimes(3);
    expect(input.receiptFollow.runOnce).not.toHaveBeenCalled();
    expect(input.materializer.runOnce).not.toHaveBeenCalled();
    expect(input.compensation.runOnce).not.toHaveBeenCalled();
    expect(input.lifecycle.start).not.toHaveBeenCalled();
    expect(root.readiness()).toMatchObject({
      ready: false,
      state: "failed",
      lifecycleReconciled: false,
      restartReconciled: false,
    });
  });

  it("fails closed when compensation materialization exhausts the drain bound", async () => {
    const input = dependencies();
    input.materializer.runOnce.mockResolvedValue({ found: 1, created: 1 });
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      startupDrainLimit: 2,
    });

    await expect(root.start()).rejects.toThrow("could not start");
    expect(input.lifecycle.runOnce).toHaveBeenCalledOnce();
    expect(input.receiptFollow.runOnce).toHaveBeenCalledOnce();
    expect(input.materializer.runOnce).toHaveBeenCalledTimes(2);
    expect(input.compensation.runOnce).not.toHaveBeenCalled();
    expect(input.compensation.start).not.toHaveBeenCalled();
    expect(root.readiness()).toMatchObject({
      ready: false,
      state: "failed",
      compensationReconciled: false,
      restartReconciled: false,
    });
  });

  it("bounds stop-during-start and does not claim a hung materializer stopped", async () => {
    const input = dependencies();
    input.materializer.runOnce.mockImplementationOnce(() => new Promise(() => undefined));
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      startupOperationTimeoutMs: 60_000,
      shutdownOperationTimeoutMs: 100,
    });

    const startup = root.start();
    await vi.waitFor(() => expect(input.materializer.runOnce).toHaveBeenCalledOnce());
    await expect(root.stop()).rejects.toThrow("could not stop");
    await expect(startup).rejects.toThrow("could not start");
    expect(root.state).toBe("failed");
    expect(input.lifecycle.stop).toHaveBeenCalledOnce();
    expect(input.receiptFollow.stop).toHaveBeenCalledOnce();
    expect(input.compensation.stop).toHaveBeenCalledOnce();
  });

  it("bounds a hung startup operation and remains failed closed", async () => {
    const input = dependencies();
    input.materializer.runOnce.mockImplementationOnce(() => new Promise(() => undefined));
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      startupOperationTimeoutMs: 5,
      shutdownOperationTimeoutMs: 100,
    });

    await expect(root.start()).rejects.toThrow("could not start");
    expect(root.state).toBe("failed");
    expect(root.readiness()).toMatchObject({ ready: false, materializerHealthy: false });
    expect(input.lifecycle.start).not.toHaveBeenCalled();
    expect(input.lifecycle.stop).toHaveBeenCalledOnce();
    expect(input.receiptFollow.stop).toHaveBeenCalledOnce();
    expect(input.compensation.stop).toHaveBeenCalledOnce();
  });

  it("calls every worker stop when one throws synchronously and exposes only a safe error", async () => {
    const input = dependencies();
    input.lifecycle.stop.mockImplementation(() => {
      throw new Error("private worker pathname and token");
    });
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      materializerIdleDelayMs: 60_000,
      shutdownOperationTimeoutMs: 100,
    });
    await root.start();

    const error = await root.stop().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(TypeError);
    expect(String(error)).toContain("could not stop");
    expect(String(error)).not.toContain("pathname");
    expect(String(error)).not.toContain("token");
    expect(root.state).toBe("failed");
    expect(input.lifecycle.stop).toHaveBeenCalledOnce();
    expect(input.receiptFollow.stop).toHaveBeenCalledOnce();
    expect(input.compensation.stop).toHaveBeenCalledOnce();
    expect(root.readiness().ready).toBe(false);
  });

  it("fails the running root and stops workers when a materializer cycle hangs", async () => {
    const input = dependencies();
    input.materializer.runOnce
      .mockResolvedValueOnce({ found: 0, created: 0 })
      .mockImplementationOnce(() => new Promise(() => undefined));
    const onOperationalError = vi.fn();
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => 100,
      materializerCycleTimeoutMs: 5,
      shutdownOperationTimeoutMs: 100,
      onOperationalError,
    });

    await root.start();
    await vi.waitFor(() => expect(root.state).toBe("failed"));
    expect(root.readiness()).toMatchObject({ ready: false, materializerHealthy: false });
    expect(onOperationalError).toHaveBeenCalledWith("runtime_supervisor_internal");
    await vi.waitFor(() => expect(input.lifecycle.stop).toHaveBeenCalledOnce());
    expect(input.receiptFollow.stop).toHaveBeenCalledOnce();
    expect(input.compensation.stop).toHaveBeenCalledOnce();
  });

  it("rejects accessor capabilities and custom thenables without invoking them", async () => {
    const accessorInput = dependencies();
    let startGetterReads = 0;
    const accessorWorker = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperties(accessorWorker, {
      running: { enumerable: true, value: false },
      runOnce: { enumerable: true, value: async () => ({ claimed: 0 }) },
      stop: { enumerable: true, value: async () => undefined },
      start: {
        enumerable: true,
        get: () => {
          startGetterReads += 1;
          throw new Error("private accessor detail");
        },
      },
    });
    expect(
      () =>
        new RuntimeSupervisorRoot({
          ...accessorInput,
          lifecycle: accessorWorker as unknown as RuntimeManagedSupervisor,
          clock: () => 100,
        })
    ).toThrow("Invalid Runtime supervisor root dependency");
    expect(startGetterReads).toBe(0);

    const thenableInput = dependencies();
    let thenGetterReads = 0;
    const hostileThenable = Object.defineProperty(Object.create(null), "then", {
      get: () => {
        thenGetterReads += 1;
        throw new Error("private thenable detail");
      },
    });
    thenableInput.materializer.runOnce.mockImplementationOnce(
      () =>
        hostileThenable as unknown as Promise<{
          found: number;
          created: number;
        }>
    );
    const root = new RuntimeSupervisorRoot({ ...thenableInput, clock: () => 100 });
    const error = await root.start().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(TypeError);
    expect(String(error)).toContain("could not start");
    expect(String(error)).not.toContain("thenable detail");
    expect(thenGetterReads).toBe(0);
  });

  it("contains synchronous worker-start failures and stops every capability", async () => {
    const input = dependencies();
    input.compensation.start.mockImplementation(() => {
      throw new Error("private process handle");
    });
    const root = new RuntimeSupervisorRoot({ ...input, clock: () => 100 });

    const error = await root.start().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(TypeError);
    expect(String(error)).toContain("could not start");
    expect(String(error)).not.toContain("process handle");
    expect(root.state).toBe("failed");
    expect(input.lifecycle.stop).toHaveBeenCalledOnce();
    expect(input.receiptFollow.stop).toHaveBeenCalledOnce();
    expect(input.compensation.stop).toHaveBeenCalledOnce();
    expect(input.receiptFollow.start).not.toHaveBeenCalled();
    expect(input.lifecycle.start).not.toHaveBeenCalled();
  });

  it("withdraws readiness on a later materializer error and restores it after recovery", async () => {
    const input = dependencies();
    let nowMs = 100;
    input.materializer.runOnce
      .mockResolvedValueOnce({ found: 0, created: 0 })
      .mockImplementationOnce(async () => {
        nowMs = 200;
        throw new Error("signer unavailable");
      })
      .mockImplementation(async () => {
        nowMs = 300;
        return { found: 0, created: 0 };
      });
    const onOperationalError = vi.fn();
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => nowMs,
      materializerIdleDelayMs: 5,
      materializerErrorDelayMs: 5,
      onOperationalError,
    });

    await root.start();
    await vi.waitFor(() => expect(onOperationalError).toHaveBeenCalledOnce());
    expect(root.readiness()).toMatchObject({
      ready: false,
      materializerHealthy: false,
      lastMaterializerErrorAtMs: 200,
    });
    await vi.waitFor(() =>
      expect(root.readiness()).toMatchObject({
        ready: true,
        materializerHealthy: true,
        lastMaterializerSuccessAtMs: 300,
      })
    );
    await root.stop();
  });

  it("rejects a stale materializer heartbeat even while all worker loops remain alive", async () => {
    const input = dependencies();
    let nowMs = 100;
    const root = new RuntimeSupervisorRoot({
      ...input,
      clock: () => nowMs,
      materializerIdleDelayMs: 60_000,
      readinessStaleAfterMs: 1_000,
    });
    await root.start();
    nowMs = 1_101;
    expect(root.readiness()).toMatchObject({ ready: false, materializerHealthy: false });
    await root.stop();
  });
});
