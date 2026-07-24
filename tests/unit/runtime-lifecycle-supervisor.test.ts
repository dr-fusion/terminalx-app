import { describe, expect, it, vi } from "vitest";
import {
  RuntimeCommandExecutionError,
  RuntimeLifecycleSupervisor,
  type Runtime,
  type RuntimeHandle,
  type RuntimeLifecycleDelivery,
  type RuntimeLifecycleHandleResolver,
  type RuntimeLifecycleJournal,
  type RuntimeLifecycleCommand,
  type RuntimeReceipt,
} from "@/lib/runtime";

const binding = {
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 3,
  sandboxId: "sandbox-1",
  sandboxGeneration: 4,
  runtimePrincipalId: "principal-1",
} as const;

const command = {
  kind: "run.pause",
  commandId: "command-1",
  binding,
  projectCeilingRevision: "ceiling-1",
  runtimeAuthorizationGeneration: 7,
  requiredEffectEnforcerSetDigest: "b".repeat(64),
  causationId: "cause-1",
  actor: { kind: "human", actorRef: "user-1" },
  issuedAtMs: 50,
  deadlineAtMs: 400,
  authority: {
    issuerKeyId: "runtime-key:v1",
    audience: "runtime",
    claimsDigest: "a".repeat(64),
    issuedAtMs: 40,
    expiresAtMs: 500,
    signature: "signed-envelope",
    issuer: "team-session",
    capability: "run.pause",
  },
  agentRunId: "run-1",
  runPolicyRevision: 2,
  fromRunStateVersion: 8,
  toRunStateVersion: 9,
  reason: "human",
} as const satisfies RuntimeLifecycleCommand;

const handle: RuntimeHandle = {
  binding,
  opaqueHandleRef: "opaque-1",
  capabilities: {
    isolatedExecution: true,
    brokeredCredentials: true,
    proxyOnlyEgress: true,
    checkpoints: true,
    yoloEligible: false,
  },
};

const accepted = {
  commandId: command.commandId,
  binding,
  runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
  outcome: "accepted",
  effectRef: "effect-1",
} as const satisfies RuntimeReceipt;

describe("RuntimeLifecycleSupervisor", () => {
  it("records a successful health heartbeat when a long cycle settles", async () => {
    let nowMs = 100;
    let releaseReconcile: (() => void) | undefined;
    const journal = journalReturning([]);
    vi.mocked(journal.reconcile).mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          releaseReconcile = resolve;
        })
    );
    const supervisor = new RuntimeLifecycleSupervisor({
      journal,
      runtime: runtimeReturning(accepted),
      handles: { resolve: async () => handle },
      verifyAuthority: () => true,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => nowMs,
    });

    const running = supervisor.runOnce();
    expect(supervisor.health()).toMatchObject({ activeCycleStartedAtMs: 100 });
    nowMs = 40_100;
    releaseReconcile?.();
    await expect(running).resolves.toMatchObject({ claimed: 0 });
    expect(supervisor.health()).toEqual({
      lastSuccessAtMs: 40_100,
      lastErrorAtMs: null,
      activeCycleStartedAtMs: null,
      failureSinceSuccess: false,
    });
  });

  it("fails the settlement heartbeat closed when the health clock rolls back", async () => {
    let nowMs = 100;
    let releaseClaim: ((deliveries: ReadonlyArray<RuntimeLifecycleDelivery>) => void) | undefined;
    const journal = journalReturning([]);
    vi.mocked(journal.claim).mockImplementation(
      () =>
        new Promise<ReadonlyArray<RuntimeLifecycleDelivery>>((resolve) => {
          releaseClaim = resolve;
        })
    );
    const supervisor = new RuntimeLifecycleSupervisor({
      journal,
      runtime: runtimeReturning(accepted),
      handles: { resolve: async () => handle },
      verifyAuthority: () => true,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => nowMs,
    });

    const running = supervisor.runOnce();
    await Promise.resolve();
    nowMs = 99;
    releaseClaim?.([]);

    await expect(running).resolves.toMatchObject({ claimed: 0 });
    expect(supervisor.health()).toEqual({
      lastSuccessAtMs: null,
      lastErrorAtMs: 100,
      activeCycleStartedAtMs: null,
      failureSinceSuccess: true,
    });

    vi.mocked(journal.claim).mockResolvedValue([]);
    await expect(supervisor.runOnce()).resolves.toMatchObject({ claimed: 0 });
    expect(supervisor.health()).toMatchObject({
      lastSuccessAtMs: null,
      lastErrorAtMs: 100,
      failureSinceSuccess: true,
    });

    nowMs = 100;
    await expect(supervisor.runOnce()).resolves.toMatchObject({ claimed: 0 });
    expect(supervisor.health()).toMatchObject({
      lastSuccessAtMs: 100,
      lastErrorAtMs: 100,
      failureSinceSuccess: false,
    });
  });

  it("rejects an accessor-backed handle resolver without invoking provider code", () => {
    const journal = journalReturning([delivery()]);
    let getterCalls = 0;
    const handles = Object.defineProperty({}, "resolve", {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("provider-secret-handle-getter");
      },
    }) as RuntimeLifecycleHandleResolver;

    expect(
      () =>
        new RuntimeLifecycleSupervisor({
          journal,
          runtime: runtimeReturning(accepted),
          handles,
          verifyAuthority: () => true,
          verifyEnforcementProof: () => true,
          workerId: "worker-1",
          clock: () => 100,
        })
    ).toThrow("Invalid Runtime handle resolver");
    expect(getterCalls).toBe(0);
    expect(journal.claim).not.toHaveBeenCalled();
  });

  it("rejects a descriptor-hostile resolved handle before the dispatch interlock", async () => {
    const journal = journalReturning([delivery()]);
    const runtime = runtimeReturning(accepted);
    let getterCalls = 0;
    const hostileHandle = Object.defineProperty(
      {
        opaqueHandleRef: "opaque-hostile",
        capabilities: handle.capabilities,
      },
      "binding",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          throw new Error("provider-secret-binding-getter");
        },
      }
    ) as RuntimeHandle;
    const supervisor = new RuntimeLifecycleSupervisor({
      journal,
      runtime,
      handles: { resolve: async () => hostileHandle },
      verifyAuthority: () => true,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => 100,
    });

    await expect(supervisor.runOnce()).resolves.toMatchObject({
      claimed: 1,
      failedBeforeDispatch: 1,
      dispatchUncertain: 0,
    });
    expect(getterCalls).toBe(0);
    expect(journal.renew).not.toHaveBeenCalled();
    expect(runtime.command).not.toHaveBeenCalled();
  });

  it("rejects an accessor-backed Runtime before any journal interlock without invoking it", () => {
    const journal = journalReturning([delivery()]);
    let getterCalls = 0;
    const runtime = {
      ensure: vi.fn(async () => handle),
      get command(): Runtime["command"] {
        getterCalls += 1;
        throw new Error("provider getter must never run");
      },
      follow: vi.fn(async function* () {
        return;
      }),
      retire: vi.fn(async () => undefined),
    } satisfies Runtime;

    let failure: unknown;
    try {
      new RuntimeLifecycleSupervisor({
        journal,
        runtime,
        handles: { resolve: vi.fn(async () => handle) },
        verifyAuthority: () => true,
        verifyEnforcementProof: () => true,
        workerId: "worker-1",
        clock: () => 100,
      });
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(RuntimeCommandExecutionError);
    expect(failure).toMatchObject({
      code: "invalid_input",
      dispatchCertainty: "not-dispatched",
    });
    expect(getterCalls).toBe(0);
    expect(journal.reconcile).not.toHaveBeenCalled();
    expect(journal.claim).not.toHaveBeenCalled();
    expect(journal.renew).not.toHaveBeenCalled();
    expect(journal.complete).not.toHaveBeenCalled();
  });

  it("reconciles, claims, executes, and durably completes an exact leased command", async () => {
    const order: string[] = [];
    const journal = journalReturning([delivery()], order);
    const handles: RuntimeLifecycleHandleResolver = {
      resolve: vi.fn(async (_command, signal) => {
        expect(signal.aborted).toBe(false);
        order.push("resolve");
        return handle;
      }),
    };
    const runtime = runtimeReturning(accepted, order);
    const supervisor = new RuntimeLifecycleSupervisor({
      journal,
      runtime,
      handles,
      verifyAuthority: () => true,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => 100,
    });

    await expect(supervisor.runOnce()).resolves.toEqual({
      claimed: 1,
      receipts: 1,
      failedBeforeDispatch: 0,
      dispatchUncertain: 0,
    });
    expect(order).toEqual(["reconcile", "claim", "resolve", "renew", "runtime", "complete"]);
    expect(handles.resolve).toHaveBeenCalledWith(command, expect.any(AbortSignal));
    expect(runtime.command).toHaveBeenCalledWith(
      expect.objectContaining({ binding }),
      expect.objectContaining({ commandId: command.commandId }),
      expect.any(AbortSignal)
    );
    expect(journal.reconcile).toHaveBeenCalledWith({ nowMs: 100 });
    expect(journal.claim).toHaveBeenCalledWith({
      workerId: "worker-1",
      limit: 1,
      leaseDurationMs: 30_000,
      nowMs: 100,
    });
    expect(journal.complete).toHaveBeenCalledWith({
      commandId: command.commandId,
      workerId: "worker-1",
      expectedAttempt: 1,
      expectedLeaseExpiresAtMs: 30_100,
      observedAtMs: 100,
      outcome: { kind: "receipt", receipt: accepted },
    });
    expect(supervisor.health()).toEqual({
      lastSuccessAtMs: 100,
      lastErrorAtMs: null,
      activeCycleStartedAtMs: null,
      failureSinceSuccess: false,
    });
  });

  it("snapshots an expired command structurally and records the executor's safe failure", async () => {
    const journal = journalReturning([delivery()]);
    const runtime = runtimeReturning(accepted);
    const supervisor = new RuntimeLifecycleSupervisor({
      journal,
      runtime,
      handles: { resolve: vi.fn(async () => handle) },
      verifyAuthority: () => true,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => command.deadlineAtMs,
    });

    await expect(supervisor.runOnce()).resolves.toEqual({
      claimed: 1,
      receipts: 0,
      failedBeforeDispatch: 1,
      dispatchUncertain: 0,
    });
    expect(runtime.command).not.toHaveBeenCalled();
    expect(journal.complete).toHaveBeenCalledWith(
      expect.objectContaining({
        commandId: command.commandId,
        outcome: {
          kind: "failure",
          code: "deadline_expired",
          dispatchCertainty: "not-dispatched",
        },
      })
    );
  });

  it("uses one frozen delivery snapshot through resolve, renewal, dispatch, and completion", async () => {
    const expectedBinding = structuredClone(binding);
    const expectedCommand = structuredClone(command) as RuntimeLifecycleCommand;
    const mutable = structuredClone(delivery()) as unknown as {
      command: {
        commandId: string;
        causationId: string;
        binding: {
          sessionId: string;
          runtimeAssignmentId: string;
          sandboxId: string;
        };
      };
      attempt: number;
      leaseOwner: string;
      leaseExpiresAtMs: number;
    };
    const journal = journalReturning([
      mutable as unknown as RuntimeLifecycleDelivery,
    ]) as RuntimeLifecycleJournal & {
      renew: ReturnType<typeof vi.fn>;
      complete: ReturnType<typeof vi.fn>;
    };
    const exactHandle: RuntimeHandle = { ...handle, binding: expectedBinding };
    const exactReceipt: RuntimeReceipt = {
      ...accepted,
      commandId: expectedCommand.commandId,
      binding: expectedBinding,
    };
    const handles: RuntimeLifecycleHandleResolver = {
      resolve: vi.fn(async (resolvedCommand) => {
        expect(resolvedCommand).toEqual(expectedCommand);
        expect(resolvedCommand).not.toBe(mutable.command);
        expect(Object.isFrozen(resolvedCommand)).toBe(true);
        expect(Object.isFrozen(resolvedCommand.binding)).toBe(true);
        expect(Object.isFrozen(resolvedCommand.authority)).toBe(true);

        mutable.command.commandId = "mutated-during-resolve";
        mutable.command.causationId = "mutated-cause";
        mutable.command.binding.sessionId = "mutated-session";
        mutable.command.binding.runtimeAssignmentId = "mutated-assignment";
        mutable.attempt = 91;
        mutable.leaseOwner = "mutated-worker";
        mutable.leaseExpiresAtMs = 999_999;
        return exactHandle;
      }),
    };
    journal.renew.mockImplementationOnce(async (options) => {
      expect(options).toEqual({
        commandId: expectedCommand.commandId,
        workerId: "worker-1",
        expectedAttempt: 1,
        expectedLeaseExpiresAtMs: 30_100,
        leaseDurationMs: 30_000,
        nowMs: 100,
      });
      mutable.command.commandId = "mutated-during-renewal";
      mutable.command.binding.sandboxId = "mutated-sandbox";
      mutable.attempt = 92;
      return { kind: "renewed" as const, leaseExpiresAtMs: 60_100 };
    });
    const runtime = runtimeReturning(exactReceipt);
    vi.mocked(runtime.command).mockImplementationOnce(async (_runtimeHandle, dispatchedCommand) => {
      expect(dispatchedCommand).toEqual(expectedCommand);
      expect(dispatchedCommand.commandId).toBe(expectedCommand.commandId);
      expect(dispatchedCommand.binding).toEqual(expectedBinding);
      expect(Object.isFrozen(dispatchedCommand)).toBe(true);
      expect(Object.isFrozen(dispatchedCommand.binding)).toBe(true);
      return exactReceipt;
    });
    const supervisor = new RuntimeLifecycleSupervisor({
      journal,
      runtime,
      handles,
      verifyAuthority: ({ command: verifiedCommand }) => {
        expect(verifiedCommand.commandId).toBe(expectedCommand.commandId);
        expect(verifiedCommand.binding).toEqual(expectedBinding);
        return true;
      },
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => 100,
    });

    await expect(supervisor.runOnce()).resolves.toEqual({
      claimed: 1,
      receipts: 1,
      failedBeforeDispatch: 0,
      dispatchUncertain: 0,
    });
    expect(journal.complete).toHaveBeenCalledWith({
      commandId: expectedCommand.commandId,
      workerId: "worker-1",
      expectedAttempt: 1,
      expectedLeaseExpiresAtMs: 60_100,
      observedAtMs: 100,
      outcome: { kind: "receipt", receipt: exactReceipt },
    });
  });

  it("rejects delivery proxies, accessors, and inexact records without invoking getters", async () => {
    let getterCalls = 0;
    const accessorCommand = Object.defineProperty({ ...command }, "binding", {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("journal-secret-binding-getter");
      },
    });
    const missingField = { ...delivery() } as Record<string, unknown>;
    delete missingField.attempt;
    const hostileDeliveries: unknown[] = [
      new Proxy(delivery(), {}),
      { ...delivery(), command: accessorCommand },
      { ...delivery(), unexpected: "field" },
      missingField,
      { ...delivery(), command: { ...command, unexpected: "field" } },
    ];

    for (const hostile of hostileDeliveries) {
      const journal = journalReturning([hostile as RuntimeLifecycleDelivery]);
      const handles = { resolve: vi.fn(async () => handle) };
      const runtime = runtimeReturning(accepted);
      const supervisor = new RuntimeLifecycleSupervisor({
        journal,
        runtime,
        handles,
        verifyAuthority: () => true,
        verifyEnforcementProof: () => true,
        workerId: "worker-1",
        clock: () => 100,
      });

      await expect(supervisor.runOnce()).rejects.toThrow("Invalid Runtime lifecycle delivery");
      expect(handles.resolve).not.toHaveBeenCalled();
      expect(journal.renew).not.toHaveBeenCalled();
      expect(runtime.command).not.toHaveBeenCalled();
      expect(journal.complete).not.toHaveBeenCalled();
    }
    expect(getterCalls).toBe(0);
  });

  it("records a missing exact handle as provably not dispatched", async () => {
    const journal = journalReturning([delivery()]);
    const runtime = runtimeReturning(accepted);
    const verifier = vi.fn(() => true);
    const supervisor = new RuntimeLifecycleSupervisor({
      journal,
      runtime,
      handles: { resolve: vi.fn(async () => null) },
      verifyAuthority: verifier,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => 100,
    });

    await expect(supervisor.runOnce()).resolves.toEqual({
      claimed: 1,
      receipts: 0,
      failedBeforeDispatch: 1,
      dispatchUncertain: 0,
    });
    expect(runtime.command).not.toHaveBeenCalled();
    expect(journal.renew).not.toHaveBeenCalled();
    expect(verifier).not.toHaveBeenCalled();
    expect(journal.complete).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: {
          kind: "failure",
          code: "runtime_handle_unavailable",
          dispatchCertainty: "not-dispatched",
        },
      })
    );
  });

  it("skips Runtime dispatch and completion after renewal durably supersedes stale trust", async () => {
    const journal = journalReturning([delivery()]);
    vi.mocked(journal.renew).mockResolvedValueOnce({ kind: "superseded" });
    const runtime = runtimeReturning(accepted);
    const supervisor = supervisorWith(journal, runtime);

    await expect(supervisor.runOnce()).resolves.toEqual({
      claimed: 1,
      receipts: 0,
      failedBeforeDispatch: 1,
      dispatchUncertain: 0,
    });
    expect(journal.renew).toHaveBeenCalledTimes(1);
    expect(runtime.command).not.toHaveBeenCalled();
    expect(journal.complete).not.toHaveBeenCalled();
  });

  it("actively cancels a timed-out handle lookup before recording a pre-dispatch failure", async () => {
    vi.useFakeTimers();
    try {
      const journal = journalReturning([{ ...delivery(), leaseExpiresAtMs: 400 }]);
      let resolverSignal: AbortSignal | undefined;
      let cancellationObserved = false;
      const handles: RuntimeLifecycleHandleResolver = {
        resolve: vi.fn(
          (_command, signal) =>
            new Promise<RuntimeHandle | null>((_resolve, reject) => {
              resolverSignal = signal;
              signal.addEventListener(
                "abort",
                () => {
                  cancellationObserved = true;
                  reject(new Error("cancelled handle transport"));
                },
                { once: true }
              );
            })
        ),
      };
      const runtime = runtimeReturning(accepted);
      const supervisor = new RuntimeLifecycleSupervisor({
        journal,
        runtime,
        handles,
        verifyAuthority: () => true,
        verifyEnforcementProof: () => true,
        workerId: "worker-1",
        clock: () => 100,
        handleResolveTimeoutMs: 100,
      });

      const running = supervisor.runOnce();
      // The live lease leaves only 50ms after the completion margin, even
      // though the configured resolver timeout is 100ms.
      await vi.advanceTimersByTimeAsync(49);
      expect(cancellationObserved).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await expect(running).resolves.toEqual({
        claimed: 1,
        receipts: 0,
        failedBeforeDispatch: 1,
        dispatchUncertain: 0,
      });
      expect(resolverSignal?.aborted).toBe(true);
      expect(cancellationObserved).toBe(true);
      expect(runtime.command).not.toHaveBeenCalled();
      expect(journal.renew).not.toHaveBeenCalled();
      expect(journal.complete).toHaveBeenCalledWith(
        expect.objectContaining({
          outcome: {
            kind: "failure",
            code: "runtime_handle_unavailable",
            dispatchCertainty: "not-dispatched",
          },
        })
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("records provider and invalid-receipt failures as dispatch uncertain without raw errors", async () => {
    const providerJournal = journalReturning([delivery()]);
    const provider = runtimeReturning(accepted);
    vi.mocked(provider.command).mockRejectedValueOnce(new Error("provider secret material"));
    const providerSupervisor = supervisorWith(providerJournal, provider);

    await expect(providerSupervisor.runOnce()).resolves.toMatchObject({
      dispatchUncertain: 1,
    });
    expect(providerJournal.complete).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: {
          kind: "failure",
          code: "runtime_command_failed",
          dispatchCertainty: "dispatch-uncertain",
        },
      })
    );
    expect(JSON.stringify(vi.mocked(providerJournal.complete).mock.calls)).not.toContain(
      "provider secret material"
    );

    const invalidJournal = journalReturning([delivery()]);
    const invalidReceipt = { ...accepted, commandId: "other-command" } as RuntimeReceipt;
    const invalidSupervisor = supervisorWith(invalidJournal, runtimeReturning(invalidReceipt));
    await expect(invalidSupervisor.runOnce()).resolves.toMatchObject({ dispatchUncertain: 1 });
    expect(invalidJournal.complete).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: {
          kind: "failure",
          code: "invalid_receipt",
          dispatchCertainty: "dispatch-uncertain",
        },
      })
    );
  });

  it("classifies resolver failures before dispatch but preserves journal failures", async () => {
    const resolverJournal = journalReturning([delivery()]);
    const resolverSupervisor = new RuntimeLifecycleSupervisor({
      journal: resolverJournal,
      runtime: runtimeReturning(accepted),
      handles: {
        resolve: vi.fn(async () => {
          throw new Error("database unavailable");
        }),
      },
      verifyAuthority: () => true,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => 100,
    });
    await expect(resolverSupervisor.runOnce()).resolves.toMatchObject({
      failedBeforeDispatch: 1,
      dispatchUncertain: 0,
    });
    expect(resolverJournal.renew).not.toHaveBeenCalled();
    expect(resolverJournal.complete).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: {
          kind: "failure",
          code: "runtime_handle_unavailable",
          dispatchCertainty: "not-dispatched",
        },
      })
    );

    const completionJournal = journalReturning([delivery()]);
    vi.mocked(completionJournal.complete).mockRejectedValueOnce(new Error("lease fence changed"));
    await expect(
      supervisorWith(completionJournal, runtimeReturning(accepted)).runOnce()
    ).rejects.toThrow("lease fence changed");
    expect(completionJournal.complete).toHaveBeenCalledTimes(1);
  });

  it("never dispatches or completes when durable pre-dispatch renewal fails", async () => {
    const journal = journalReturning([delivery()]);
    vi.mocked(journal.renew).mockRejectedValueOnce(new Error("renewal store unavailable"));
    const runtime = runtimeReturning(accepted);

    await expect(supervisorWith(journal, runtime).runOnce()).rejects.toThrow(
      "renewal store unavailable"
    );
    expect(runtime.command).not.toHaveBeenCalled();
    expect(journal.complete).not.toHaveBeenCalled();
  });

  it("serializes concurrent batches and rejects an invalid delivery fence", async () => {
    let releaseClaim: (() => void) | undefined;
    const claimGate = new Promise<void>((resolve) => {
      releaseClaim = resolve;
    });
    const journal = journalReturning([]);
    vi.mocked(journal.claim).mockImplementationOnce(async () => {
      await claimGate;
      return [];
    });
    const supervisor = supervisorWith(journal, runtimeReturning(accepted));

    const first = supervisor.runOnce();
    const second = supervisor.runOnce();
    expect(second).toBe(first);
    releaseClaim?.();
    await expect(first).resolves.toEqual({
      claimed: 0,
      receipts: 0,
      failedBeforeDispatch: 0,
      dispatchUncertain: 0,
    });
    expect(journal.claim).toHaveBeenCalledTimes(1);

    const invalidJournal = journalReturning([{ ...delivery(), leaseOwner: "other-worker" }]);
    await expect(
      supervisorWith(invalidJournal, runtimeReturning(accepted)).runOnce()
    ).rejects.toThrow("Invalid Runtime lifecycle delivery");
    expect(invalidJournal.complete).not.toHaveBeenCalled();
  });

  it("refuses to downgrade prior dispatch ambiguity with a later retry result", async () => {
    const ambiguousJournal = journalReturning([
      {
        ...delivery(),
        leaseExpiresAtMs: 500,
        priorDispatchCertainty: "dispatch-uncertain",
      } as unknown as RuntimeLifecycleDelivery,
    ]);
    const handles = { resolve: vi.fn(async () => null) };
    const runtime = runtimeReturning(accepted);
    const supervisor = new RuntimeLifecycleSupervisor({
      journal: ambiguousJournal,
      runtime,
      handles,
      verifyAuthority: () => true,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
      clock: () => command.deadlineAtMs,
    });

    await expect(supervisor.runOnce()).rejects.toThrow("Invalid Runtime lifecycle delivery");
    expect(handles.resolve).not.toHaveBeenCalled();
    expect(runtime.command).not.toHaveBeenCalled();
    expect(ambiguousJournal.complete).not.toHaveBeenCalled();
  });

  it("starts idempotently, reconciles before claiming, and stops abortably", async () => {
    const journal = journalReturning([]);
    const supervisor = supervisorWith(journal, runtimeReturning(accepted));

    supervisor.start();
    supervisor.start();
    expect(supervisor.running).toBe(true);
    await vi.waitFor(() => expect(journal.claim).toHaveBeenCalledTimes(1));
    expect(vi.mocked(journal.reconcile).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(journal.claim).mock.invocationCallOrder[0]!
    );
    await supervisor.stop();
    expect(supervisor.running).toBe(false);
  });

  it("propagates stop cancellation into an in-flight Runtime transport", async () => {
    const journal = journalReturning([delivery()]);
    const runtime = runtimeReturning(accepted);
    let runtimeSignal: AbortSignal | undefined;
    let commandStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      commandStarted = resolve;
    });
    vi.mocked(runtime.command).mockImplementationOnce(
      (_handle, _command, signal) =>
        new Promise<RuntimeReceipt>((_resolve, reject) => {
          runtimeSignal = signal;
          commandStarted?.();
          signal.addEventListener("abort", () => reject(new Error("Runtime stopped")), {
            once: true,
          });
        })
    );
    const supervisor = supervisorWith(journal, runtime);

    supervisor.start();
    await started;
    await supervisor.stop();

    expect(runtimeSignal?.aborted).toBe(true);
    expect(supervisor.running).toBe(false);
    expect(journal.complete).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: {
          kind: "failure",
          code: "runtime_internal",
          dispatchCertainty: "dispatch-uncertain",
        },
      })
    );
  });

  it("cancels and awaits an in-flight manual runOnce even when its loop was never started", async () => {
    const journal = journalReturning([delivery()]);
    const runtime = runtimeReturning(accepted);
    let runtimeSignal: AbortSignal | undefined;
    let commandStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      commandStarted = resolve;
    });
    vi.mocked(runtime.command).mockImplementationOnce(
      (_handle, _command, signal) =>
        new Promise<RuntimeReceipt>((_resolve, reject) => {
          runtimeSignal = signal;
          commandStarted?.();
          signal.addEventListener("abort", () => reject(new Error("Runtime stopped")), {
            once: true,
          });
        })
    );
    const supervisor = supervisorWith(journal, runtime);

    const run = supervisor.runOnce();
    await started;
    await supervisor.stop();

    expect(runtimeSignal?.aborted).toBe(true);
    await expect(run).resolves.toMatchObject({
      claimed: 1,
      dispatchUncertain: 1,
    });
    expect(journal.complete).toHaveBeenCalledOnce();
    expect(supervisor.running).toBe(false);
  });

  it("bounds a hung Runtime call below the renewed lease and records uncertainty", async () => {
    vi.useFakeTimers();
    try {
      const journal = journalReturning([delivery()]);
      const runtime = runtimeReturning(accepted);
      let runtimeSignal: AbortSignal | undefined;
      let cancellationObserved = false;
      vi.mocked(runtime.command).mockImplementationOnce(
        (_handle, _command, signal) =>
          new Promise<RuntimeReceipt>((_resolve, reject) => {
            runtimeSignal = signal;
            signal.addEventListener(
              "abort",
              () => {
                cancellationObserved = true;
                reject(new Error("cancelled Runtime transport"));
              },
              { once: true }
            );
          })
      );
      const supervisor = new RuntimeLifecycleSupervisor({
        journal,
        runtime,
        handles: { resolve: vi.fn(async () => handle) },
        verifyAuthority: () => true,
        verifyEnforcementProof: () => true,
        workerId: "worker-1",
        clock: () => 100,
        runtimeCommandTimeoutMs: 100,
      });

      const running = supervisor.runOnce();
      await vi.advanceTimersByTimeAsync(100);
      await expect(running).resolves.toEqual({
        claimed: 1,
        receipts: 0,
        failedBeforeDispatch: 0,
        dispatchUncertain: 1,
      });
      expect(runtimeSignal?.aborted).toBe(true);
      expect(cancellationObserved).toBe(true);
      expect(journal.complete).toHaveBeenCalledWith(
        expect.objectContaining({
          expectedLeaseExpiresAtMs: 30_100,
          outcome: {
            kind: "failure",
            code: "runtime_internal",
            dispatchCertainty: "dispatch-uncertain",
          },
        })
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not dispatch later when authority verification resumes after its transport deadline", async () => {
    vi.useFakeTimers();
    try {
      let releaseVerifier: (() => void) | undefined;
      const verifierGate = new Promise<void>((resolve) => {
        releaseVerifier = resolve;
      });
      const journal = journalReturning([delivery()]);
      const runtime = runtimeReturning(accepted);
      const supervisor = new RuntimeLifecycleSupervisor({
        journal,
        runtime,
        handles: { resolve: vi.fn(async () => handle) },
        verifyAuthority: async () => {
          await verifierGate;
          return true;
        },
        verifyEnforcementProof: () => true,
        workerId: "worker-1",
        clock: () => 100,
        runtimeCommandTimeoutMs: 100,
      });

      const running = supervisor.runOnce();
      await vi.advanceTimersByTimeAsync(100);
      await expect(running).resolves.toMatchObject({ dispatchUncertain: 1 });
      expect(runtime.command).not.toHaveBeenCalled();

      releaseVerifier?.();
      await Promise.resolve();
      await Promise.resolve();
      expect(runtime.command).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("validates worker identity and every configured bound", () => {
    const base = {
      journal: journalReturning([]),
      runtime: runtimeReturning(accepted),
      handles: { resolve: vi.fn(async () => handle) },
      verifyAuthority: () => true,
      verifyEnforcementProof: () => true,
      workerId: "worker-1",
    } satisfies ConstructorParameters<typeof RuntimeLifecycleSupervisor>[0];

    expect(() => new RuntimeLifecycleSupervisor({ ...base, workerId: "bad\nworker" })).toThrow(
      "Invalid Runtime worker ID"
    );
    expect(() => new RuntimeLifecycleSupervisor({ ...base, claimLimit: 0 })).toThrow(
      "Invalid Runtime lifecycle supervisor bound"
    );
    expect(() => new RuntimeLifecycleSupervisor({ ...base, claimLimit: 2 })).toThrow(
      "Invalid Runtime lifecycle supervisor bound"
    );
    expect(() => new RuntimeLifecycleSupervisor({ ...base, leaseDurationMs: 999 })).toThrow(
      "Invalid Runtime lifecycle supervisor bound"
    );
    expect(() => new RuntimeLifecycleSupervisor({ ...base, errorDelayMs: 60_001 })).toThrow(
      "Invalid Runtime lifecycle supervisor bound"
    );
    expect(
      () =>
        new RuntimeLifecycleSupervisor({
          ...base,
          leaseDurationMs: 1_000,
          runtimeCommandTimeoutMs: 501,
        })
    ).toThrow("Invalid Runtime lifecycle supervisor bound");
  });
});

function delivery(): RuntimeLifecycleDelivery {
  return {
    command,
    attempt: 1,
    leaseOwner: "worker-1",
    leaseExpiresAtMs: 30_100,
    priorDispatchCertainty: "not-dispatched",
  };
}

function journalReturning(
  deliveries: ReadonlyArray<RuntimeLifecycleDelivery>,
  order?: string[]
): RuntimeLifecycleJournal {
  return {
    reconcile: vi.fn(async () => {
      order?.push("reconcile");
    }),
    claim: vi.fn(async () => {
      order?.push("claim");
      return deliveries;
    }),
    renew: vi.fn(async (options) => {
      order?.push("renew");
      return { kind: "renewed" as const, leaseExpiresAtMs: options.expectedLeaseExpiresAtMs };
    }),
    complete: vi.fn(async () => {
      order?.push("complete");
    }),
  };
}

function runtimeReturning(result: RuntimeReceipt, order?: string[]): Runtime {
  return {
    ensure: vi.fn(async () => handle),
    command: vi.fn(async (_handle, _command, signal) => {
      if (signal.aborted) throw new Error("Runtime command was cancelled");
      order?.push("runtime");
      return result;
    }),
    follow: vi.fn(async function* () {
      return;
    }),
    retire: vi.fn(async () => undefined),
  };
}

function supervisorWith(
  journal: RuntimeLifecycleJournal,
  runtime: Runtime
): RuntimeLifecycleSupervisor {
  return new RuntimeLifecycleSupervisor({
    journal,
    runtime,
    handles: { resolve: vi.fn(async () => handle) },
    verifyAuthority: () => true,
    verifyEnforcementProof: () => true,
    workerId: "worker-1",
    clock: () => 100,
  });
}
