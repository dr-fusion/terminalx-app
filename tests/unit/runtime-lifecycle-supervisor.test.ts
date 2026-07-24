import { describe, expect, it, vi } from "vitest";
import {
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
  it("reconciles, claims, executes, and durably completes an exact leased command", async () => {
    const order: string[] = [];
    const journal = journalReturning([delivery()], order);
    const handles: RuntimeLifecycleHandleResolver = {
      resolve: vi.fn(async () => {
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
      workerId: "worker-1",
      clock: () => 100,
    });

    await expect(supervisor.runOnce()).resolves.toEqual({
      claimed: 1,
      receipts: 1,
      failedBeforeDispatch: 0,
      dispatchUncertain: 0,
    });
    expect(order).toEqual(["reconcile", "claim", "resolve", "runtime", "complete"]);
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
      expectedLeaseExpiresAtMs: 200,
      observedAtMs: 100,
      outcome: { kind: "receipt", receipt: accepted },
    });
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

  it("does not reinterpret resolver or journal failures as Runtime outcomes", async () => {
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
      workerId: "worker-1",
      clock: () => 100,
    });
    await expect(resolverSupervisor.runOnce()).rejects.toThrow("database unavailable");
    expect(resolverJournal.complete).not.toHaveBeenCalled();

    const completionJournal = journalReturning([delivery()]);
    vi.mocked(completionJournal.complete).mockRejectedValueOnce(new Error("lease fence changed"));
    await expect(
      supervisorWith(completionJournal, runtimeReturning(accepted)).runOnce()
    ).rejects.toThrow("lease fence changed");
    expect(completionJournal.complete).toHaveBeenCalledTimes(1);
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

  it("validates worker identity and every configured bound", () => {
    const base = {
      journal: journalReturning([]),
      runtime: runtimeReturning(accepted),
      handles: { resolve: vi.fn(async () => handle) },
      verifyAuthority: () => true,
      workerId: "worker-1",
    } satisfies ConstructorParameters<typeof RuntimeLifecycleSupervisor>[0];

    expect(() => new RuntimeLifecycleSupervisor({ ...base, workerId: "bad\nworker" })).toThrow(
      "Invalid Runtime worker ID"
    );
    expect(() => new RuntimeLifecycleSupervisor({ ...base, claimLimit: 0 })).toThrow(
      "Invalid Runtime lifecycle supervisor bound"
    );
    expect(() => new RuntimeLifecycleSupervisor({ ...base, leaseDurationMs: 999 })).toThrow(
      "Invalid Runtime lifecycle supervisor bound"
    );
    expect(() => new RuntimeLifecycleSupervisor({ ...base, errorDelayMs: 60_001 })).toThrow(
      "Invalid Runtime lifecycle supervisor bound"
    );
  });
});

function delivery(): RuntimeLifecycleDelivery {
  return {
    command,
    attempt: 1,
    leaseOwner: "worker-1",
    leaseExpiresAtMs: 200,
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
    complete: vi.fn(async () => {
      order?.push("complete");
    }),
  };
}

function runtimeReturning(result: RuntimeReceipt, order?: string[]): Runtime {
  return {
    ensure: vi.fn(async () => handle),
    command: vi.fn(async () => {
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
    workerId: "worker-1",
    clock: () => 100,
  });
}
