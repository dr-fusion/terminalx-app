import { describe, expect, it, vi } from "vitest";
import {
  RuntimeCompensationExecutionError,
  createRuntimeCompensationSupervisor,
  digestRuntimeCommandClaims,
  type Runtime,
  type RuntimeCompensationCommand,
  type RuntimeCompensationDelivery,
  type RuntimeCompensationJournal,
  type RuntimeCompensationReceipt,
  type RuntimeHandle,
} from "@/lib/runtime";

const binding = {
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 2,
  sandboxId: "sandbox-1",
  sandboxGeneration: 3,
  runtimePrincipalId: "principal-1",
} as const;

const handle = {
  binding,
  opaqueHandleRef: "historical-handle-1",
  capabilities: {
    isolatedExecution: true,
    brokeredCredentials: true,
    proxyOnlyEgress: true,
    checkpoints: true,
    yoloEligible: false,
  },
} as const satisfies RuntimeHandle;

function compensationCommand(): RuntimeCompensationCommand {
  const claims = {
    kind: "safety.quarantine",
    commandId: "quarantine-command-1",
    compensationId: "compensation-1",
    binding,
    observedRuntimeAuthorizationGeneration: 4,
    source: {
      lifecycleCommandId: "lifecycle-command-1",
      lifecycleCommandClaimsDigest: "a".repeat(64),
      lifecycleReceiptDigest: "b".repeat(64),
      lifecycleEnforcementSubjectDigest: "c".repeat(64),
      lifecycleAggregateProofDigest: "d".repeat(64),
      sourceRequiredEffectEnforcerSetDigest: "e".repeat(64),
    },
    platformSecurityPolicyRevision: "platform-security-policy:v1",
    requiredContainmentEnforcerSetDigest: "f".repeat(64),
    containment: {
      revokeTerminalWrites: true,
      stopProcessExecution: true,
      quarantineRuntime: true,
    },
    safetyFence: 8,
    exactBindingOnly: true,
    advanceBeyondCurrentFences: true,
    reasonRef: "compensation-incident:1",
    causationId: "lifecycle-command-1",
    actor: { kind: "system", actorRef: "platform-security" },
    issuedAtMs: 100,
    deadlineAtMs: 1_000,
  } as const;
  return {
    ...claims,
    authority: {
      issuer: "platform-security",
      issuerKeyId: "platform-security:v1",
      audience: "runtime",
      capability: "safety.quarantine",
      claimsDigest: digestRuntimeCommandClaims(claims),
      issuedAtMs: 100,
      expiresAtMs: 1_000,
      signature: "platform-signature",
    },
  };
}

function acceptedReceipt(command: RuntimeCompensationCommand): RuntimeCompensationReceipt {
  return {
    receiptKind: "runtime.compensation",
    compensationId: command.compensationId,
    commandId: command.commandId,
    binding: command.binding,
    observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
    outcome: "accepted",
    effectRef: "provider-accepted-ref",
  };
}

function delivery(command = compensationCommand()): RuntimeCompensationDelivery {
  return {
    command,
    attempt: 1,
    leaseOwner: "compensation-worker-1",
    leaseExpiresAtMs: 30_200,
    priorDispatchCertainty: "not-dispatched",
  };
}

function journalReturning(next: RuntimeCompensationDelivery | null): RuntimeCompensationJournal & {
  reconcile: ReturnType<typeof vi.fn>;
  claim: ReturnType<typeof vi.fn>;
  renew: ReturnType<typeof vi.fn>;
  complete: ReturnType<typeof vi.fn>;
} {
  return {
    reconcile: vi.fn(async () => undefined),
    claim: vi.fn(async () => next),
    renew: vi.fn(async () => ({ kind: "renewed" as const, leaseExpiresAtMs: 60_200 })),
    complete: vi.fn(async () => undefined),
  };
}

function runtimeWith(
  dispatch: Runtime["command"] = vi.fn(async (_handle, command) =>
    acceptedReceipt(command as RuntimeCompensationCommand)
  )
): Runtime {
  return {
    async ensure() {
      return handle;
    },
    command: dispatch,
    async *follow() {
      return;
    },
    async retire() {},
  };
}

describe("Runtime compensation supervisor", () => {
  it("rejects an accessor-backed handle resolver without invoking provider code", () => {
    const journal = journalReturning(delivery());
    let getterCalls = 0;
    const handles = Object.defineProperty({}, "resolve", {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("provider-secret-handle-getter");
      },
    });

    expect(() =>
      createRuntimeCompensationSupervisor({
        journal,
        runtime: runtimeWith(),
        handles: handles as never,
        verifyAuthority: async () => true,
        verifyEnforcementProof: async () => true,
        workerId: "compensation-worker-1",
        clock: () => 200,
      })
    ).toThrow("Invalid Runtime handle resolver");
    expect(getterCalls).toBe(0);
    expect(journal.claim).not.toHaveBeenCalled();
  });

  it("rejects a descriptor-hostile historical handle before the dispatch interlock", async () => {
    const journal = journalReturning(delivery());
    const dispatch = vi.fn<Runtime["command"]>(async (_handle, command) =>
      acceptedReceipt(command as RuntimeCompensationCommand)
    );
    let getterCalls = 0;
    const hostileHandle = Object.defineProperty(
      {
        opaqueHandleRef: "hostile-handle",
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
    const supervisor = createRuntimeCompensationSupervisor({
      journal,
      runtime: runtimeWith(dispatch),
      handles: { resolve: async () => hostileHandle },
      verifyAuthority: async () => true,
      verifyEnforcementProof: async () => true,
      workerId: "compensation-worker-1",
      clock: () => 200,
    });

    await expect(supervisor.runOnce()).resolves.toMatchObject({
      claimed: 1,
      failedBeforeDispatch: 1,
      dispatchUncertain: 0,
    });
    expect(getterCalls).toBe(0);
    expect(journal.renew).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("rejects a Runtime command accessor before any journal work without invoking it", () => {
    const journal = journalReturning(delivery());
    const shadowedDispatch = vi.fn<Runtime["command"]>(async (_handle, command) =>
      acceptedReceipt(command as RuntimeCompensationCommand)
    );
    const shadowedRuntime = runtimeWith(shadowedDispatch);
    let getterCalls = 0;
    const runtime = Object.create(shadowedRuntime) as Runtime;
    Object.defineProperty(runtime, "command", {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("provider getter must never run");
      },
    });

    let failure: unknown;
    try {
      createRuntimeCompensationSupervisor({
        journal,
        runtime,
        handles: { resolve: async () => handle },
        verifyAuthority: async () => true,
        verifyEnforcementProof: async () => true,
        workerId: "compensation-worker-1",
        clock: () => 200,
      });
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(RuntimeCompensationExecutionError);
    expect(failure).toMatchObject({
      code: "invalid_input",
      dispatchCertainty: "not-dispatched",
    });
    expect(getterCalls).toBe(0);
    expect(shadowedDispatch).not.toHaveBeenCalled();
    expect(journal.reconcile).not.toHaveBeenCalled();
    expect(journal.claim).not.toHaveBeenCalled();
    expect(journal.renew).not.toHaveBeenCalled();
    expect(journal.complete).not.toHaveBeenCalled();
  });

  it("reconciles and remains idle when there is no signed compensation command", async () => {
    const journal = journalReturning(null);
    const supervisor = createRuntimeCompensationSupervisor({
      journal,
      runtime: runtimeWith(),
      handles: { resolve: async () => handle },
      verifyAuthority: async () => true,
      verifyEnforcementProof: async () => true,
      workerId: "compensation-worker-1",
      clock: () => 200,
    });

    await expect(supervisor.runOnce()).resolves.toEqual({
      claimed: 0,
      receipts: 0,
      failedBeforeDispatch: 0,
      dispatchUncertain: 0,
    });
    expect(journal.reconcile).toHaveBeenCalledWith({ nowMs: 200 });
    expect(journal.claim).toHaveBeenCalledOnce();
  });

  it("renews the exact lease before dispatch and completes one receipt", async () => {
    const command = compensationCommand();
    const journal = journalReturning(delivery(command));
    const dispatch = vi.fn<Runtime["command"]>(async () => acceptedReceipt(command));
    const supervisor = createRuntimeCompensationSupervisor({
      journal,
      runtime: runtimeWith(dispatch),
      handles: { resolve: async () => handle },
      verifyAuthority: async () => true,
      verifyEnforcementProof: async () => true,
      workerId: "compensation-worker-1",
      clock: () => 200,
    });

    await expect(supervisor.runOnce()).resolves.toEqual({
      claimed: 1,
      receipts: 1,
      failedBeforeDispatch: 0,
      dispatchUncertain: 0,
    });
    expect(journal.renew).toHaveBeenCalledWith({
      commandId: command.commandId,
      workerId: "compensation-worker-1",
      expectedAttempt: 1,
      expectedLeaseExpiresAtMs: 30_200,
      leaseDurationMs: 30_000,
      nowMs: 200,
    });
    expect(dispatch).toHaveBeenCalledOnce();
    expect(journal.complete).toHaveBeenCalledWith(
      expect.objectContaining({
        commandId: command.commandId,
        expectedAttempt: 1,
        expectedLeaseExpiresAtMs: 60_200,
        outcome: { kind: "receipt", receipt: acceptedReceipt(command) },
      })
    );
  });

  it("rejects a replacement handle before acquiring the dispatch interlock", async () => {
    const journal = journalReturning(delivery());
    const dispatch = vi.fn<Runtime["command"]>(async (_handle, command) =>
      acceptedReceipt(command as RuntimeCompensationCommand)
    );
    const replacement = {
      ...handle,
      binding: { ...binding, sandboxGeneration: binding.sandboxGeneration + 1 },
    };
    const supervisor = createRuntimeCompensationSupervisor({
      journal,
      runtime: runtimeWith(dispatch),
      handles: { resolve: async () => replacement },
      verifyAuthority: async () => true,
      verifyEnforcementProof: async () => true,
      workerId: "compensation-worker-1",
      clock: () => 200,
    });

    await expect(supervisor.runOnce()).resolves.toMatchObject({
      claimed: 1,
      failedBeforeDispatch: 1,
      dispatchUncertain: 0,
    });
    expect(journal.renew).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
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

  it("parks a marker-present timeout as dispatch-uncertain", async () => {
    const journal = journalReturning(delivery());
    const dispatch = vi.fn<Runtime["command"]>(
      async (_handle, _command, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(new Error("provider timeout")), {
            once: true,
          });
        })
    );
    const supervisor = createRuntimeCompensationSupervisor({
      journal,
      runtime: runtimeWith(dispatch),
      handles: { resolve: async () => handle },
      verifyAuthority: async () => true,
      verifyEnforcementProof: async () => true,
      workerId: "compensation-worker-1",
      clock: () => 200,
      runtimeCommandTimeoutMs: 5,
    });

    await expect(supervisor.runOnce()).resolves.toMatchObject({
      claimed: 1,
      failedBeforeDispatch: 0,
      dispatchUncertain: 1,
    });
    expect(journal.renew).toHaveBeenCalledOnce();
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

  it("shares one active runOnce claim across concurrent callers", async () => {
    let release: (() => void) | undefined;
    const journal = journalReturning(null);
    journal.reconcile.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        })
    );
    const supervisor = createRuntimeCompensationSupervisor({
      journal,
      runtime: runtimeWith(),
      handles: { resolve: async () => handle },
      verifyAuthority: async () => true,
      verifyEnforcementProof: async () => true,
      workerId: "compensation-worker-1",
      clock: () => 200,
    });

    const first = supervisor.runOnce();
    const second = supervisor.runOnce();
    expect(second).toBe(first);
    release?.();
    await expect(first).resolves.toMatchObject({ claimed: 0 });
    expect(journal.reconcile).toHaveBeenCalledOnce();
  });

  it("cancels and awaits an in-flight manual runOnce when no background loop exists", async () => {
    const journal = journalReturning(delivery());
    let runtimeSignal: AbortSignal | undefined;
    let commandStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      commandStarted = resolve;
    });
    const dispatch = vi.fn<Runtime["command"]>(
      async (_handle, _command, signal) =>
        new Promise<RuntimeCompensationReceipt>((_resolve, reject) => {
          runtimeSignal = signal;
          commandStarted?.();
          signal.addEventListener("abort", () => reject(new Error("Runtime stopped")), {
            once: true,
          });
        })
    );
    const supervisor = createRuntimeCompensationSupervisor({
      journal,
      runtime: runtimeWith(dispatch),
      handles: { resolve: async () => handle },
      verifyAuthority: async () => true,
      verifyEnforcementProof: async () => true,
      workerId: "compensation-worker-1",
      clock: () => 200,
    });

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
});
