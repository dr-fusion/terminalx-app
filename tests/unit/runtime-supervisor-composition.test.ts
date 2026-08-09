import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  createRuntimeSupervisorComposition,
  type Runtime,
  type RuntimeCompensationJournal,
  type RuntimeLifecycleJournal,
  type RuntimeOutboxApplier,
  type RuntimeOutboxKernel,
  type RuntimeReceiptFollowJournal,
  type RuntimeSupervisorKernel,
} from "@/lib/runtime";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  createTeamSessionKernel,
  type ActorContext,
  type RuntimeOutboxDelivery,
  type SessionCommand,
} from "@/lib/team-sessions";
import { createTestRuntimeCommandAuthorityIssuer } from "../helpers/runtime-authority";

const SNAPSHOT = Object.freeze([
  Object.freeze({
    sessionId: "session-1",
    runtimeAuthorizationGeneration: 3,
    state: "active" as const,
  }),
]);

function dependencies() {
  const order: string[] = [];
  const assignmentKernel: RuntimeOutboxKernel = {
    claimRuntimeOutbox: vi.fn(async () => {
      order.push("assignment");
      return [];
    }),
    markRuntimeOutboxDispatch: vi.fn(async () => undefined),
    renewRuntimeOutboxLease: vi.fn(async (options) => ({
      leaseExpiresAtMs: Math.max(options.expectedLeaseExpiresAtMs, 30_100),
    })),
    dispatch: vi.fn(async (command: SessionCommand) => ({
      accepted: true as const,
      acceptedSequence: 1,
      commandType: command.type,
      replayed: false as const,
      data: {},
      events: [],
    })),
  };
  const assignmentRuntime: RuntimeOutboxApplier = {
    apply: vi.fn(async () => undefined),
    reconcile: vi.fn(async () => undefined),
  };
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
    runtimeAssignmentKernel: assignmentKernel,
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
  return { kernel, assignmentRuntime, runtime, order };
}

function compositionOptions(input: ReturnType<typeof dependencies>) {
  return {
    kernel: input.kernel,
    assignmentRuntime: input.assignmentRuntime,
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

function assignmentDelivery(
  dispatchMode: RuntimeOutboxDelivery["dispatchMode"],
  outboxId: string
): RuntimeOutboxDelivery {
  return {
    outboxId,
    sessionId: "session-1",
    sessionSequence: 1,
    attempts: 2,
    leaseOwner: "host-1:assignment",
    leaseExpiresAtMs: 1_000,
    dispatchMode,
    kind: "runtime.session.ensure",
    payload: {
      sessionId: "session-1",
      runtimeKind: "local-tmux",
      tmuxName: "session-1",
      runtimeAuthorizationGeneration: 3,
    },
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
    expect(input.order.slice(0, 6)).toEqual([
      "snapshot",
      "assignment",
      "lifecycle",
      "receipt-follow",
      "materializer",
      "compensation",
    ]);
    expect(composition.root.readiness()).toMatchObject({
      ready: true,
      state: "running",
      assignmentReconciled: true,
      assignmentRunning: true,
    });
    expect(
      composition.writeStateRegistry.isWriteAllowed({
        sessionId: "session-1",
        runtimeAuthorizationGeneration: 3,
      })
    ).toBe(true);
    expect(Object.isFrozen(composition)).toBe(true);

    await composition.root.stop();
    expect(composition.root.readiness()).toMatchObject({
      ready: false,
      state: "stopped",
      assignmentRunning: false,
    });
  });

  it("withdraws readiness on a post-start worker failure and restores it after a healthy cycle", async () => {
    const input = dependencies();
    const composition = createRuntimeSupervisorComposition(compositionOptions(input));
    const claim = vi.mocked(input.kernel.runtimeAssignmentKernel.claimRuntimeOutbox);
    await composition.root.start();

    claim.mockRejectedValue(new Error("durable assignment seam unavailable"));
    await vi.waitFor(
      () =>
        expect(composition.root.readiness()).toMatchObject({
          ready: false,
          assignmentRunning: true,
          assignmentHealth: { healthy: false, failureSinceSuccess: true },
        }),
      { timeout: 2_500 }
    );

    claim.mockResolvedValue([]);
    await vi.waitFor(
      () =>
        expect(composition.root.readiness()).toMatchObject({
          ready: true,
          assignmentHealth: { healthy: true, failureSinceSuccess: false },
        }),
      { timeout: 2_500 }
    );
    await composition.root.stop();
  });

  it("boots and drains the real SQLite kernel through the portable composition", async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-runtime-composition-"));
    const now = 2_000_000_000_000;
    const sessionId = "33333333-3333-4333-8333-333333333333";
    const actor: ActorContext = { kind: "human", userId: "alice", displayName: "Alice" };
    const kernel = createTeamSessionKernel({
      filename: path.join(directory, "team-sessions.sqlite"),
      clock: () => now,
      runtimeCommandAuthorityIssuer: createTestRuntimeCommandAuthorityIssuer(),
      runtimeAuthorizationSnapshotSource: {
        resolve: ({ runtimeAuthorizationGeneration }) => ({
          generation: runtimeAuthorizationGeneration,
          networkPolicyRef: "test-network-policy:v1",
          networkPolicyDigest: "c".repeat(64),
          credentialPolicyRef: "test-credential-policy:v1",
          credentialPolicyDigest: "d".repeat(64),
          effectEnforcerPolicyDigest: "e".repeat(64),
        }),
      },
      runtimeEnforcementProofVerifier: () => true,
      runtimeCompensationAuthorityIssuer: {
        issue: () => {
          throw new Error("No compensation incident should be issued");
        },
      },
      runtimeCompensationAuthorityVerifier: () => true,
      runtimeCompensationPolicySource: { resolve: () => undefined },
      runtimeCompensationEnforcementProofVerifier: () => true,
    });
    const assignmentRuntime: RuntimeOutboxApplier = {
      apply: vi.fn(async () => undefined),
      reconcile: vi.fn(async () => undefined),
    };
    const runtime: Runtime = {
      ensure: vi.fn(async () => {
        throw new Error("Runtime ensure must use the assignment adapter");
      }),
      command: vi.fn(async () => {
        throw new Error("No lifecycle command should be dispatched");
      }),
      follow: vi.fn(async function* () {
        return;
      }),
      retire: vi.fn(async () => undefined),
    };
    let commandSequence = 0;
    const dispatch = (input: Record<string, unknown>) => {
      commandSequence += 1;
      return kernel.teamSessions.dispatch({
        ...input,
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor,
        idempotency: {
          scope: "vitest:runtime-supervisor-composition",
          key: `command-${commandSequence}`,
        },
        occurredAtMs: now,
      } as SessionCommand);
    };

    const composition = createRuntimeSupervisorComposition({
      kernel,
      assignmentRuntime,
      runtime,
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
      workerIdPrefix: "sqlite-integration",
      clock: () => now,
    });

    try {
      await dispatch({
        type: "team.create",
        teamId: "11111111-1111-4111-8111-111111111111",
        name: "Acme",
      });
      await dispatch({
        type: "project.create",
        teamId: "11111111-1111-4111-8111-111111111111",
        projectId: "22222222-2222-4222-8222-222222222222",
        name: "Terminal X",
      });
      await dispatch({
        type: "session.start",
        teamId: "11111111-1111-4111-8111-111111111111",
        projectId: "22222222-2222-4222-8222-222222222222",
        sessionId,
        name: "SQLite composition",
        tmuxName: "sqlite-composition",
        steeringPolicy: "shared",
      });

      expect(kernel.runtimeAssignmentKernel).toBe(kernel.teamSessions);
      await composition.root.start();

      expect(assignmentRuntime.apply).toHaveBeenCalledOnce();
      expect(assignmentRuntime.reconcile).not.toHaveBeenCalled();
      await expect(
        kernel.teamSessions.inspect({
          schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
          type: "session.get",
          sessionId,
          actor,
        })
      ).resolves.toMatchObject({
        runtime: { authorizationState: "enforced" },
      });
      expect(composition.root.readiness()).toMatchObject({
        ready: true,
        state: "running",
        durableWriteStateLoaded: true,
        assignmentReconciled: true,
        lifecycleReconciled: true,
        receiptFollowReconciled: true,
        compensationReconciled: true,
        restartReconciled: true,
      });

      await composition.root.stop();
      expect(composition.root.readiness()).toMatchObject({
        ready: false,
        state: "stopped",
        assignmentRunning: false,
        lifecycleRunning: false,
        receiptFollowRunning: false,
        compensationRunning: false,
      });
    } finally {
      await composition.root.stop().catch(() => undefined);
      kernel.teamSessions.close();
      fs.rmSync(directory, { recursive: true, force: true });
    }
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

  it("requires the complete assignment kernel and adapter before constructing workers", () => {
    const input = dependencies();
    const missingKernel = {
      ...input.kernel,
      runtimeAssignmentKernel: undefined,
    } as unknown as RuntimeSupervisorKernel;

    expect(() =>
      createRuntimeSupervisorComposition({
        ...compositionOptions(input),
        kernel: missingKernel,
      })
    ).toThrow("Invalid Runtime supervisor composition");
    expect(() =>
      createRuntimeSupervisorComposition({
        ...compositionOptions(input),
        assignmentRuntime: undefined as unknown as RuntimeOutboxApplier,
      })
    ).toThrow("Invalid Runtime supervisor composition");
  });

  it("wires each worker to its complete trust-group seam and component-scoped worker ID", async () => {
    const input = dependencies();
    const composition = createRuntimeSupervisorComposition(compositionOptions(input));

    await Promise.all([
      composition.assignment.runOnce(),
      composition.lifecycle.runOnce(),
      composition.receiptFollow.runOnce(),
      composition.compensation.runOnce(),
    ]);

    expect(input.kernel.runtimeAssignmentKernel.claimRuntimeOutbox).toHaveBeenCalledWith(
      expect.objectContaining({ workerId: "host-1:assignment" })
    );

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

  it("wires ambiguous assignment attempts only through their durable reconciliation mode", async () => {
    const input = dependencies();
    const reconcileDelivery = assignmentDelivery("reconcile", "outbox-reconcile");
    const applyDelivery = assignmentDelivery("apply", "outbox-apply");
    const claim = vi.mocked(input.kernel.runtimeAssignmentKernel.claimRuntimeOutbox);
    claim.mockResolvedValueOnce([reconcileDelivery]).mockResolvedValueOnce([applyDelivery]);
    const originalApply = vi.mocked(input.assignmentRuntime.apply);
    const originalReconcile = vi.mocked(input.assignmentRuntime.reconcile);
    const replacementApply = vi.fn(async () => {
      throw new Error("replacement assignment apply must not run");
    });
    const replacementReconcile = vi.fn(async () => {
      throw new Error("replacement assignment reconcile must not run");
    });
    const originalRenew = vi.mocked(input.kernel.runtimeAssignmentKernel.renewRuntimeOutboxLease);
    const replacementRenew = vi.fn(async () => {
      throw new Error("replacement assignment renewal must not run");
    });
    const composition = createRuntimeSupervisorComposition(compositionOptions(input));
    replaceMethod(input.assignmentRuntime, "apply", replacementApply);
    replaceMethod(input.assignmentRuntime, "reconcile", replacementReconcile);
    replaceMethod(
      input.kernel.runtimeAssignmentKernel,
      "renewRuntimeOutboxLease",
      replacementRenew
    );

    await expect(composition.assignment.runOnce()).resolves.toMatchObject({
      claimed: 1,
      acknowledged: 1,
    });
    await expect(composition.assignment.runOnce()).resolves.toMatchObject({
      claimed: 1,
      acknowledged: 1,
    });

    expect(originalReconcile).toHaveBeenCalledOnce();
    expect(originalReconcile).toHaveBeenCalledWith(
      expect.objectContaining({
        ...reconcileDelivery,
        leaseExpiresAtMs: 30_100,
      }),
      expect.any(AbortSignal)
    );
    expect(originalApply).toHaveBeenCalledOnce();
    expect(originalApply).toHaveBeenCalledWith(
      expect.objectContaining({
        ...applyDelivery,
        leaseExpiresAtMs: 30_100,
      }),
      expect.any(AbortSignal)
    );
    expect(replacementReconcile).not.toHaveBeenCalled();
    expect(replacementApply).not.toHaveBeenCalled();
    expect(originalRenew).toHaveBeenCalledTimes(2);
    expect(replacementRenew).not.toHaveBeenCalled();
    expect(input.kernel.runtimeAssignmentKernel.markRuntimeOutboxDispatch).toHaveBeenCalledOnce();
    expect(input.kernel.runtimeAssignmentKernel.markRuntimeOutboxDispatch).toHaveBeenCalledWith({
      outboxId: "outbox-apply",
      workerId: "host-1:assignment",
      expectedAttempt: 2,
      expectedLeaseExpiresAtMs: 30_100,
    });
    expect(input.kernel.runtimeAssignmentKernel.dispatch).toHaveBeenCalledTimes(2);
    expect(input.kernel.runtimeAssignmentKernel.dispatch).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        type: "runtime.outbox.acknowledge",
        outboxId: "outbox-reconcile",
        workerId: "host-1:assignment",
        expectedAttempt: 2,
        expectedLeaseExpiresAtMs: 30_100,
      })
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
    const replacementAssignment = vi.fn(async () => {
      throw new Error("replacement assignment claim must not run");
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
      input.kernel.runtimeAssignmentKernel,
      "claimRuntimeOutbox",
      replacementAssignment
    );
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
    expect(input.order.slice(0, 6)).toEqual([
      "snapshot",
      "assignment",
      "lifecycle",
      "receipt-follow",
      "materializer",
      "compensation",
    ]);
    expect(replacementSnapshot).not.toHaveBeenCalled();
    expect(replacementAssignment).not.toHaveBeenCalled();
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

    let assignmentGetterCalls = 0;
    const assignmentAccessorOptions = compositionOptions(input);
    assignmentAccessorOptions.assignmentRuntime = Object.defineProperties(
      {},
      {
        apply: { enumerable: true, value: async () => undefined },
        reconcile: {
          enumerable: true,
          get() {
            assignmentGetterCalls += 1;
            throw new Error("private assignment adapter endpoint");
          },
        },
      }
    ) as (typeof assignmentAccessorOptions)["assignmentRuntime"];
    expect(() => createRuntimeSupervisorComposition(assignmentAccessorOptions)).toThrow(
      "Invalid Runtime supervisor composition"
    );
    expect(assignmentGetterCalls).toBe(0);

    let runtimeProxyTrapCalls = 0;
    const proxiedRuntimeOptions = compositionOptions(input);
    proxiedRuntimeOptions.runtime = new Proxy(input.runtime, {
      getOwnPropertyDescriptor() {
        runtimeProxyTrapCalls += 1;
        throw new Error("private Runtime proxy endpoint");
      },
      getPrototypeOf() {
        runtimeProxyTrapCalls += 1;
        throw new Error("private Runtime proxy prototype");
      },
    });
    expect(() => createRuntimeSupervisorComposition(proxiedRuntimeOptions)).toThrow(
      "Invalid Runtime supervisor composition"
    );
    expect(runtimeProxyTrapCalls).toBe(0);

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
    expect(input.kernel.runtimeAssignmentKernel.claimRuntimeOutbox).not.toHaveBeenCalled();
    expect(input.kernel.runtimeCompensationMaterializer?.runOnce).not.toHaveBeenCalled();
    expect(input.kernel.runtimeLifecycleJournal.reconcile).not.toHaveBeenCalled();
    expect(input.kernel.runtimeReceiptFollowJournal.reconcile).not.toHaveBeenCalled();
    expect(input.kernel.runtimeCompensationJournal?.reconcile).not.toHaveBeenCalled();
  });
});
