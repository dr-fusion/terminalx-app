import { describe, expect, expectTypeOf, it, vi } from "vitest";
import {
  RuntimeCommandExecutionError,
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  digestNonDuplicateRuntimeReceipt,
  executeRuntimeCommand,
  verifyRuntimeReceiptEnforcementProofSynchronously,
  type NonDuplicateRuntimeReceipt,
  type Runtime,
  type RuntimeAuthorityVerificationInput,
  type RuntimeCommand,
  type RuntimeHandle,
  type RuntimeLifecycleCommand,
  type RuntimePostStartLifecycleCommand,
  type RuntimeReceipt,
} from "@/lib/runtime";
import { digestActionManifest } from "@/lib/runtime/action-policy";
import {
  digestRuntimeEnforcementSubject,
  type RuntimeEnforcementProofVerifier,
} from "@/lib/runtime/runtime-enforcement-proof";

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
} as const satisfies RuntimeCommand;

describe("Runtime command execution", () => {
  it("executes an exact-bound command after required authority verification", async () => {
    const accepted = receipt({ outcome: "accepted", effectRef: "effect-1" });
    const adapter = runtimeReturning(accepted);
    const verifier = vi.fn((_input: RuntimeAuthorityVerificationInput) => true);

    await expect(
      executeRuntimeCommand(adapter, handle, command, verifier, () => 100)
    ).resolves.toEqual(accepted);
    const verification = verifier.mock.calls[0]?.[0];
    expect(verification).toEqual({ handle, command, nowMs: 100 });
    expect(verification?.handle).not.toBe(handle);
    expect(verification?.command).not.toBe(command);
    expect(Object.isFrozen(verification?.command)).toBe(true);
    expect(adapter.command).toHaveBeenCalledWith(
      expect.objectContaining({ binding }),
      expect.objectContaining({ commandId: command.commandId, binding }),
      expect.any(AbortSignal)
    );
  });

  it("captures a non-enumerable Runtime command data-method from its prototype", async () => {
    const dispatch = vi.fn(async () => receipt({ outcome: "accepted", effectRef: "effect-1" }));
    const prototype = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(prototype, "command", {
      value: dispatch,
      enumerable: false,
      writable: true,
      configurable: true,
    });
    const adapter = Object.assign(Object.create(prototype) as object, {
      ensure: vi.fn(async () => handle),
      follow: vi.fn(async function* () {
        return;
      }),
      retire: vi.fn(async () => undefined),
    }) as unknown as Runtime;

    expect(Object.hasOwn(adapter, "command")).toBe(false);
    await expect(
      executeRuntimeCommand(
        adapter,
        handle,
        command,
        () => true,
        () => 100
      )
    ).resolves.toMatchObject({ outcome: "accepted", commandId: command.commandId });
    expect(dispatch).toHaveBeenCalledOnce();
  });

  it("rejects a proxied Runtime capability without invoking its descriptor traps", async () => {
    const target = runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" }));
    let descriptorTrapCalls = 0;
    const proxy = new Proxy(target, {
      getOwnPropertyDescriptor() {
        descriptorTrapCalls += 1;
        throw new Error("provider-secret-runtime-proxy");
      },
    });

    await expect(
      executeRuntimeCommand(
        proxy,
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_input", dispatchCertainty: "not-dispatched" });
    expect(descriptorTrapCalls).toBe(0);
    expect(target.command).not.toHaveBeenCalled();
  });

  it("propagates cancellation to Runtime and never accepts a response after abort", async () => {
    const accepted = receipt({ outcome: "accepted", effectRef: "effect-1" });
    const adapter = runtimeReturning(accepted);
    let receivedSignal: AbortSignal | undefined;
    let releaseProvider: ((receipt: RuntimeReceipt) => void) | undefined;
    vi.mocked(adapter.command).mockImplementationOnce(
      (_handle, _command, signal) =>
        new Promise<RuntimeReceipt>((resolve) => {
          receivedSignal = signal;
          releaseProvider = resolve;
        })
    );
    const controller = new AbortController();

    const execution = executeRuntimeCommand(
      adapter,
      handle,
      command,
      () => true,
      () => 100,
      undefined,
      controller.signal
    );
    await vi.waitFor(() => expect(receivedSignal).toBe(controller.signal));
    controller.abort();
    releaseProvider?.(accepted);

    await expect(execution).rejects.toEqual(
      new RuntimeCommandExecutionError("runtime_command_failed")
    );
    expect(receivedSignal?.aborted).toBe(true);
  });

  it("rejects handle and receipt binding mismatches", async () => {
    const adapter = runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" }));
    const mismatchedHandle = {
      ...handle,
      binding: { ...binding, sandboxGeneration: binding.sandboxGeneration + 1 },
    };

    await expect(
      executeRuntimeCommand(
        adapter,
        mismatchedHandle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "binding_mismatch" });
    expect(adapter.command).not.toHaveBeenCalled();

    const mismatchedReceipt = receipt(
      { outcome: "accepted", effectRef: "effect-1" },
      { ...binding, runtimeAssignmentId: "assignment-other" }
    );
    await expect(
      executeRuntimeCommand(
        runtimeReturning(mismatchedReceipt),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });
  });

  it("fails closed at the deadline without invoking authority or Runtime", async () => {
    const adapter = runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" }));
    const verifier = vi.fn(() => true);

    await expect(
      executeRuntimeCommand(adapter, handle, command, verifier, () => command.deadlineAtMs)
    ).rejects.toMatchObject({ code: "deadline_expired" });
    expect(verifier).not.toHaveBeenCalled();
    expect(adapter.command).not.toHaveBeenCalled();
  });

  it("rejects future-issued input and expiry introduced while authority verification waits", async () => {
    const futureIssued = asPostStart({ ...command, issuedAtMs: 150 });
    const futureAdapter = runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" }));
    await expect(
      executeRuntimeCommand(
        futureAdapter,
        handle,
        futureIssued,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_input" });
    expect(futureAdapter.command).not.toHaveBeenCalled();

    const delayedAdapter = runtimeReturning(
      receipt({ outcome: "accepted", effectRef: "effect-1" })
    );
    const clock = vi.fn().mockReturnValueOnce(100).mockReturnValueOnce(command.deadlineAtMs);
    await expect(
      executeRuntimeCommand(delayedAdapter, handle, command, async () => true, clock)
    ).rejects.toMatchObject({ code: "deadline_expired" });
    expect(clock).toHaveBeenCalledTimes(2);
    expect(delayedAdapter.command).not.toHaveBeenCalled();

    const authorityExpired = asPostStart({
      ...command,
      deadlineAtMs: 600,
      authority: { ...command.authority, expiresAtMs: 300 },
    });
    const authorityClock = vi.fn().mockReturnValueOnce(100).mockReturnValueOnce(300);
    await expect(
      executeRuntimeCommand(
        runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" })),
        handle,
        authorityExpired,
        async () => true,
        authorityClock
      )
    ).rejects.toMatchObject({ code: "invalid_authority" });
  });

  it("isolates dispatch from caller and verifier mutation", async () => {
    const callerCommand = structuredClone(command) as unknown as {
      commandId: string;
      binding: { sandboxId: string };
    };
    const callerHandle = structuredClone(handle) as unknown as {
      binding: { sandboxId: string };
    };
    let releaseVerifier: (() => void) | undefined;
    const verifierGate = new Promise<void>((resolve) => {
      releaseVerifier = resolve;
    });
    let verificationStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      verificationStarted = resolve;
    });
    let verifiedSnapshot: RuntimeLifecycleCommand | undefined;
    const accepted = receipt({ outcome: "accepted", effectRef: "effect-1" });
    const dispatch = vi.fn(async () => accepted);
    const adapter = {
      ensure: vi.fn(async () => handle),
      command: dispatch,
      follow: vi.fn(async function* () {
        return;
      }),
      retire: vi.fn(async () => undefined),
    } satisfies Runtime;

    const execution = executeRuntimeCommand(
      adapter,
      callerHandle as RuntimeHandle,
      callerCommand as RuntimePostStartLifecycleCommand,
      async ({ command: snapshot }) => {
        verifiedSnapshot = snapshot;
        verificationStarted?.();
        await verifierGate;
        expect(Reflect.set(snapshot, "commandId", "verifier-redirect")).toBe(false);
        return true;
      },
      () => 100
    );
    await started;
    callerCommand.commandId = "caller-redirect";
    callerCommand.binding.sandboxId = "caller-sandbox";
    callerHandle.binding.sandboxId = "caller-handle-sandbox";
    releaseVerifier?.();

    await expect(execution).resolves.toEqual(accepted);
    expect(verifiedSnapshot).toMatchObject({
      commandId: command.commandId,
      binding: { sandboxId: binding.sandboxId },
    });
    expect(dispatch).toHaveBeenCalledWith(
      expect.objectContaining({
        binding: expect.objectContaining({ sandboxId: binding.sandboxId }),
      }),
      expect.objectContaining({
        commandId: command.commandId,
        binding: expect.objectContaining({ sandboxId: binding.sandboxId }),
      }),
      expect.any(AbortSignal)
    );
  });

  it("rejects accepted receipts with a conflicting command or authorization generation", async () => {
    const wrongCommand = {
      ...receipt({ outcome: "accepted", effectRef: "effect-1" }),
      commandId: "command-other",
    } satisfies RuntimeReceipt;
    await expect(
      executeRuntimeCommand(
        runtimeReturning(wrongCommand),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });

    const wrongGeneration = {
      ...receipt({ outcome: "accepted", effectRef: "effect-1" }),
      runtimeAuthorizationGeneration: 8,
    } satisfies RuntimeReceipt;
    await expect(
      executeRuntimeCommand(
        runtimeReturning(wrongGeneration),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });
  });

  it("validates exact lifecycle fields, enums, literal true, and positive generations", async () => {
    const missingPolicyRevision = structuredClone(command) as unknown as Record<string, unknown>;
    delete missingPolicyRevision.runPolicyRevision;
    const missingEnforcerSet = structuredClone(command) as unknown as Record<string, unknown>;
    delete missingEnforcerSet.requiredEffectEnforcerSetDigest;
    const { reason: _pauseReason, ...lifecycleBase } = command;
    const invalidCommands: RuntimePostStartLifecycleCommand[] = [
      asPostStart({ ...command, reason: "later" }),
      asPostStart({
        ...lifecycleBase,
        kind: "run.resume",
        authority: { ...command.authority, capability: "run.resume" },
        accountableAssigneePresent: false,
      }),
      asPostStart({
        ...lifecycleBase,
        kind: "run.stop",
        authority: { ...command.authority, capability: "run.stop" },
        reason: "human",
        unexpected: true,
      }),
      asPostStart(missingPolicyRevision),
      asPostStart(missingEnforcerSet),
      asPostStart({ ...command, requiredEffectEnforcerSetDigest: "B".repeat(64) }),
      asPostStart({ ...command, runtimeAuthorizationGeneration: 0 }),
      asPostStart({
        ...command,
        binding: { ...command.binding, runtimeAssignmentGeneration: 0 },
      }),
      asPostStart({ ...command, binding: { ...command.binding, sandboxGeneration: 0 } }),
      asPostStart({ ...command, fromRunStateVersion: 0, toRunStateVersion: 1 }),
    ];

    for (const invalidCommand of invalidCommands) {
      const adapter = runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" }));
      await expect(
        executeRuntimeCommand(
          adapter,
          handle,
          invalidCommand,
          () => true,
          () => 100
        )
      ).rejects.toMatchObject({ code: "invalid_input" });
      expect(adapter.command).not.toHaveBeenCalled();
    }
  });

  it("rejects hostile-cast run.start before authority verification or Runtime dispatch", async () => {
    const verifier = vi.fn((_input: RuntimeAuthorityVerificationInput) => true);
    const adapter = runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-start" }));
    const hostileStart = asPostStart({
      ...command,
      kind: "run.start",
      authority: { ...command.authority, capability: "run.start" },
      policy: { nestedValidationDeferred: true },
    });

    await expect(
      executeRuntimeCommand(adapter, handle, hostileStart, verifier, () => 100)
    ).rejects.toMatchObject({ code: "invalid_input" });
    expect(verifier).not.toHaveBeenCalled();
    expect(adapter.command).not.toHaveBeenCalled();
  });

  it("executes a complete immutable run.start snapshot", async () => {
    const start = startCommand();
    const accepted = receipt({ outcome: "accepted", effectRef: "effect-start" });
    const adapter = runtimeReturning(accepted);
    const verifier = vi.fn((_input: RuntimeAuthorityVerificationInput) => true);

    await expect(
      executeRuntimeCommand(adapter, handle, start, verifier, () => 100)
    ).resolves.toEqual(accepted);
    expect(verifier).toHaveBeenCalledOnce();
    const verified = verifier.mock.calls[0]?.[0].command;
    expect(verified).toMatchObject({ kind: "run.start", policy: start.policy });
    expect(Object.isFrozen(verified)).toBe(true);
    if (verified?.kind === "run.start") {
      expect(Object.isFrozen(verified.policy)).toBe(true);
      expect(Object.isFrozen(verified.policy.initialGoalSet.goals)).toBe(true);
    }
    expect(adapter.command).toHaveBeenCalledOnce();
  });

  it("rejects inconsistent run.start policies and capability claims before dispatch", async () => {
    const start = startCommand();
    const firstGoal = start.policy.initialGoalSet.goals[0]!;
    const invalidStarts: RuntimeLifecycleCommand[] = [
      asLifecycle({
        ...start,
        policy: { ...start.policy, agentRunId: "run-other" },
      }),
      asLifecycle({
        ...start,
        policy: { ...start.policy, binding: { ...binding, sandboxGeneration: 5 } },
      }),
      asLifecycle({
        ...start,
        policy: { ...start.policy, unexpected: true },
      }),
      asLifecycle({
        ...start,
        policy: {
          ...start.policy,
          limits: {
            ...start.policy.limits,
            modelTokens: { kind: "capped", value: -1 },
          },
        },
      }),
      asLifecycle({
        ...start,
        policy: {
          ...start.policy,
          initialGoalSet: {
            ...start.policy.initialGoalSet,
            goals: [{ ...firstGoal, acceptanceCriteria: [] }],
          },
        },
      }),
      asLifecycle({
        ...start,
        policy: { ...start.policy, yoloConfirmationRef: "unexpected-confirmation" },
      }),
      asLifecycle({
        ...start,
        policy: { ...start.policy, mode: "yolo" },
      }),
      asLifecycle({
        ...start,
        runPolicyRevision: 2,
        policy: { ...start.policy, revision: 2 },
      }),
      asLifecycle({
        ...start,
        fromRunStateVersion: 2,
        toRunStateVersion: 3,
      }),
      asLifecycle({
        ...start,
        policy: {
          ...start.policy,
          initialGoalSet: {
            ...start.policy.initialGoalSet,
            revision: 2,
          },
        },
      }),
      asLifecycle({
        ...start,
        policy: {
          ...start.policy,
          initialGoalSet: {
            ...start.policy.initialGoalSet,
            goals: [{ ...firstGoal, version: 2, status: "in-progress" }],
          },
        },
      }),
    ];

    for (const invalidStart of invalidStarts) {
      const verifier = vi.fn(() => true);
      const adapter = runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-start" }));
      await expect(
        executeRuntimeCommand(adapter, handle, invalidStart, verifier, () => 100)
      ).rejects.toMatchObject({
        code: "invalid_input",
        dispatchCertainty: "not-dispatched",
      });
      expect(verifier).not.toHaveBeenCalled();
      expect(adapter.command).not.toHaveBeenCalled();
    }

    const nonIsolated = {
      ...handle,
      capabilities: { ...handle.capabilities, isolatedExecution: false },
    } satisfies RuntimeHandle;
    await expect(
      executeRuntimeCommand(
        runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-start" })),
        nonIsolated,
        start,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({
      code: "invalid_input",
      dispatchCertainty: "not-dispatched",
    });
  });

  it("validates exact-bound YOLO start authorization without exposing grant material", async () => {
    const start = yoloStartCommand();
    if (!start.yoloAuthorization) throw new Error("Expected YOLO authorization fixture");
    const yoloHandle = {
      ...handle,
      capabilities: { ...handle.capabilities, yoloEligible: true },
    } satisfies RuntimeHandle;
    const accepted = receipt({ outcome: "accepted", effectRef: "effect-yolo-start" });

    await expect(
      executeRuntimeCommand(
        runtimeReturning(accepted),
        yoloHandle,
        start,
        () => true,
        () => 100
      )
    ).resolves.toEqual(accepted);

    const { yoloAuthorization: _authorization, ...missingAuthorization } = start;
    const missingAuthorizationAdapter = runtimeReturning(accepted);
    await expect(
      executeRuntimeCommand(
        missingAuthorizationAdapter,
        yoloHandle,
        asLifecycle(missingAuthorization),
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({
      code: "invalid_input",
      dispatchCertainty: "not-dispatched",
    });
    expect(missingAuthorizationAdapter.command).not.toHaveBeenCalled();

    const ineligibleAdapter = runtimeReturning(accepted);
    await expect(
      executeRuntimeCommand(
        ineligibleAdapter,
        handle,
        start,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({
      code: "invalid_input",
      dispatchCertainty: "not-dispatched",
    });
    expect(ineligibleAdapter.command).not.toHaveBeenCalled();

    const tampered = asLifecycle({
      ...start,
      yoloAuthorization: {
        ...start.yoloAuthorization,
        manifest: {
          ...start.yoloAuthorization?.manifest,
          operation: "deployment.replace-production",
        },
      },
    });
    const tamperedAdapter = runtimeReturning(accepted);
    await expect(
      executeRuntimeCommand(
        tamperedAdapter,
        yoloHandle,
        tampered,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({
      code: "invalid_input",
      dispatchCertainty: "not-dispatched",
    });
    expect(tamperedAdapter.command).not.toHaveBeenCalled();

    const overPolicyLimit = asLifecycle({
      ...start,
      policy: {
        ...start.policy,
        limits: {
          ...start.policy.limits,
          outboundBytes: { kind: "capped", value: 0 },
        },
      },
    });
    const underBudgeted = asLifecycle({
      ...start,
      yoloAuthorization: {
        ...start.yoloAuthorization,
        grant: {
          ...start.yoloAuthorization.grant,
          budget: {
            ...start.yoloAuthorization.grant.budget,
            perEffectLimit: {
              ...start.yoloAuthorization.grant.budget.perEffectLimit,
              outboundBytes: 0,
            },
          },
        },
      },
    });
    for (const invalidBudget of [overPolicyLimit, underBudgeted]) {
      const budgetAdapter = runtimeReturning(accepted);
      await expect(
        executeRuntimeCommand(
          budgetAdapter,
          yoloHandle,
          invalidBudget,
          () => true,
          () => 100
        )
      ).rejects.toMatchObject({
        code: "invalid_input",
        dispatchCertainty: "not-dispatched",
      });
      expect(budgetAdapter.command).not.toHaveBeenCalled();
    }
  });

  it("requires a lifecycle enforced receipt to advance the exact Run-state fence", async () => {
    const aggregateEnforcementProof = proof(command.runtimeAuthorizationGeneration);
    const enforced = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof,
    });
    const verifyEnforcementProof = vi.fn<RuntimeEnforcementProofVerifier>(() => true);
    await expect(
      executeRuntimeCommand(
        runtimeReturning(enforced),
        handle,
        command,
        () => true,
        () => 100,
        verifyEnforcementProof
      )
    ).resolves.toEqual(enforced);
    expect(verifyEnforcementProof).toHaveBeenCalledWith({
      subject: {
        version: 1,
        commandId: command.commandId,
        commandClaimsDigest: command.authority.claimsDigest,
        binding,
        runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
        requiredEffectEnforcerSetDigest: command.requiredEffectEnforcerSetDigest,
        effectRefCommitment: commitRuntimeEffectRef("effect-1"),
        enforcedFence: command.toRunStateVersion,
      },
      subjectDigest: aggregateEnforcementProof.enforcementSubjectDigest,
      proof: aggregateEnforcementProof,
    });

    const staleFence = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.fromRunStateVersion,
      aggregateEnforcementProof: proof(
        command.runtimeAuthorizationGeneration,
        "effect-1",
        command.fromRunStateVersion
      ),
    });
    await expect(
      executeRuntimeCommand(
        runtimeReturning(staleFence),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });
  });

  it("always hashes a provider ref even when its text has commitment syntax", async () => {
    const providerRef = commitRuntimeEffectRef("effect-1");
    const aggregateEnforcementProof = proof(command.runtimeAuthorizationGeneration, providerRef);
    const verifyEnforcementProof = vi.fn<RuntimeEnforcementProofVerifier>(() => true);

    await expect(
      executeRuntimeCommand(
        runtimeReturning(
          receipt({
            outcome: "enforced",
            effectRef: providerRef,
            enforcedFence: command.toRunStateVersion,
            aggregateEnforcementProof,
          })
        ),
        handle,
        command,
        () => true,
        () => 100,
        verifyEnforcementProof
      )
    ).resolves.toMatchObject({ effectRef: providerRef });

    expect(verifyEnforcementProof.mock.calls[0]?.[0].subject.effectRefCommitment).toBe(
      commitRuntimeEffectRef(providerRef)
    );
    expect(commitRuntimeEffectRef(providerRef)).not.toBe(providerRef);
  });

  it("fails closed when an enforced result has no trusted proof decision", async () => {
    const enforced = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration),
    });
    const noVerifierRuntime = runtimeReturning(enforced);
    await expect(
      executeRuntimeCommand(
        noVerifierRuntime,
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({
      code: "enforcement_proof_verification_failed",
      dispatchCertainty: "dispatch-uncertain",
    });
    expect(noVerifierRuntime.command).toHaveBeenCalledTimes(1);

    const secret = "enforcer-private-key-material";
    for (const verifier of [() => false, () => Promise.reject(new Error(secret))]) {
      const failure = executeRuntimeCommand(
        runtimeReturning(enforced),
        handle,
        command,
        () => true,
        () => 100,
        verifier
      );
      await expect(failure).rejects.toEqual(
        new RuntimeCommandExecutionError("enforcement_proof_verification_failed")
      );
      await failure.catch((error: unknown) => {
        expect(JSON.stringify(error)).not.toContain(secret);
        expect(String(error)).not.toContain(secret);
      });
    }
  });

  it("does not read or invoke a custom thenable from a synchronous proof verifier", () => {
    const enforced = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration),
    });
    const thenBody = vi.fn();
    const thenGetter = vi.fn(() => thenBody);
    const hostile = {} as Record<string, unknown>;
    Object.defineProperty(hostile, "then", { get: thenGetter });

    expect(() =>
      verifyRuntimeReceiptEnforcementProofSynchronously(command, enforced, (() => hostile) as never)
    ).toThrow(new RuntimeCommandExecutionError("enforcement_proof_verification_failed"));
    expect(thenGetter).not.toHaveBeenCalled();
    expect(thenBody).not.toHaveBeenCalled();
  });

  it("accepts a duplicate only with its complete original receipt and canonical digest", async () => {
    const original = receipt({
      outcome: "enforced",
      effectRef: "effect-original",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration, "effect-original"),
    });
    const duplicate = {
      commandId: command.commandId,
      binding,
      runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
      outcome: "duplicate",
      originalReceipt: original,
      originalReceiptDigest: digestNonDuplicateRuntimeReceipt(original),
    } as const satisfies RuntimeReceipt;

    const verifyEnforcementProof = vi.fn<RuntimeEnforcementProofVerifier>(() => true);
    const result = await executeRuntimeCommand(
      runtimeReturning(duplicate),
      handle,
      command,
      () => true,
      () => 100,
      verifyEnforcementProof
    );
    expect(result).not.toBe(duplicate);
    expect(result).toMatchObject({
      outcome: "duplicate",
      originalReceipt: {
        outcome: "enforced",
        enforcedFence: command.toRunStateVersion,
        aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration, "effect-original"),
      },
    });
    expect(verifyEnforcementProof).toHaveBeenCalledTimes(1);
    expect(verifyEnforcementProof.mock.calls[0]?.[0].subject).toMatchObject({
      commandId: command.commandId,
      effectRefCommitment: commitRuntimeEffectRef("effect-original"),
      enforcedFence: command.toRunStateVersion,
    });

    expectTypeOf(duplicate.originalReceipt).toMatchTypeOf<NonDuplicateRuntimeReceipt>();
  });

  it("rejects non-canonical duplicate digests and conflicting enforcement proofs", async () => {
    const original = receipt({
      outcome: "enforced",
      effectRef: "effect-original",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration, "effect-original"),
    });
    const badDigest = {
      commandId: command.commandId,
      binding,
      runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
      outcome: "duplicate",
      originalReceipt: original,
      originalReceiptDigest: digestNonDuplicateRuntimeReceipt(original).toUpperCase(),
    } as const satisfies RuntimeReceipt;
    await expect(
      executeRuntimeCommand(
        runtimeReturning(badDigest),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });

    const conflictingProof = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration + 1),
    });
    await expect(
      executeRuntimeCommand(
        runtimeReturning(conflictingProof),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });

    const verifier = vi.fn<RuntimeEnforcementProofVerifier>(() => true);
    for (const mismatchedSubjectProof of [
      proof(command.runtimeAuthorizationGeneration, "effect-other"),
      proof(
        command.runtimeAuthorizationGeneration,
        "effect-1",
        command.toRunStateVersion,
        "d".repeat(64)
      ),
    ]) {
      const mismatchedSubject = receipt({
        outcome: "enforced",
        effectRef: "effect-1",
        enforcedFence: command.toRunStateVersion,
        aggregateEnforcementProof: mismatchedSubjectProof,
      });
      await expect(
        executeRuntimeCommand(
          runtimeReturning(mismatchedSubject),
          handle,
          command,
          () => true,
          () => 100,
          verifier
        )
      ).rejects.toMatchObject({ code: "invalid_receipt" });
    }
    expect(verifier).not.toHaveBeenCalled();

    const internallyConflictingProof = proof(command.runtimeAuthorizationGeneration);
    const changedAcknowledgement = {
      ...internallyConflictingProof,
      acknowledgements: [
        {
          ...internallyConflictingProof.acknowledgements[0],
          acknowledgementDigest: "e".repeat(64),
        },
      ],
    };
    const inconsistentReceipt = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: changedAcknowledgement,
    });
    await expect(
      executeRuntimeCommand(
        runtimeReturning(inconsistentReceipt),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });

    const emptyProofReceipt = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: {
        generation: command.runtimeAuthorizationGeneration,
        requiredEffectEnforcerSetDigest: "b".repeat(64),
        enforcementSubjectDigest: digestRuntimeEnforcementSubject({
          version: 1,
          commandId: command.commandId,
          commandClaimsDigest: command.authority.claimsDigest,
          binding,
          runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
          requiredEffectEnforcerSetDigest: command.requiredEffectEnforcerSetDigest,
          effectRefCommitment: commitRuntimeEffectRef("effect-1"),
          enforcedFence: command.toRunStateVersion,
        }),
        acknowledgements: [],
        aggregateProofDigest: "d".repeat(64),
      },
    });
    await expect(
      executeRuntimeCommand(
        runtimeReturning(emptyProofReceipt),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });
  });

  it("returns an immutable receipt snapshot detached from provider mutation", async () => {
    const providerReceipt = receipt({ outcome: "accepted", effectRef: "effect-original" });
    const result = await executeRuntimeCommand(
      runtimeReturning(providerReceipt),
      handle,
      command,
      () => true,
      () => 100
    );
    (providerReceipt as { effectRef: string }).effectRef = "effect-mutated";

    expect(result).toMatchObject({ outcome: "accepted", effectRef: "effect-original" });
    expect(result).not.toBe(providerReceipt);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.binding)).toBe(true);
  });

  it("maps hostile and revoked reflection objects to safe typed errors", async () => {
    const hostileCommand = new Proxy(command, {
      ownKeys() {
        throw new Error("secret command trap");
      },
    });
    await expect(
      executeRuntimeCommand(
        runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" })),
        handle,
        hostileCommand,
        () => true,
        () => 100
      )
    ).rejects.toEqual(new RuntimeCommandExecutionError("invalid_input"));

    const revokedReceipt = Proxy.revocable(
      receipt({ outcome: "accepted", effectRef: "effect-1" }),
      {}
    );
    revokedReceipt.revoke();
    await expect(
      executeRuntimeCommand(
        runtimeReturning(revokedReceipt.proxy),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toEqual(new RuntimeCommandExecutionError("runtime_command_failed"));

    const hostileReceipt = new Proxy(receipt({ outcome: "accepted", effectRef: "effect-1" }), {
      ownKeys() {
        throw new Error("secret receipt trap");
      },
    });
    await expect(
      executeRuntimeCommand(
        runtimeReturning(hostileReceipt),
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toEqual(new RuntimeCommandExecutionError("invalid_receipt"));

    let runtimeGetterCalls = 0;
    const shadowedRuntime = runtimeReturning(
      receipt({ outcome: "accepted", effectRef: "effect-1" })
    );
    const hostileRuntime = Object.create(shadowedRuntime) as Runtime;
    Object.defineProperty(hostileRuntime, "command", {
      configurable: true,
      enumerable: true,
      get() {
        runtimeGetterCalls += 1;
        throw new Error("secret runtime getter");
      },
    });
    const hostileRuntimeFailure = executeRuntimeCommand(
      hostileRuntime,
      handle,
      command,
      () => true,
      () => 100
    );
    await expect(hostileRuntimeFailure).rejects.toMatchObject({
      code: "invalid_input",
      dispatchCertainty: "not-dispatched",
    });
    await expect(hostileRuntimeFailure).rejects.toEqual(
      new RuntimeCommandExecutionError("invalid_input")
    );
    expect(runtimeGetterCalls).toBe(0);
    expect(shadowedRuntime.command).not.toHaveBeenCalled();

    const inheritedGetter = Object.create(hostileRuntime) as Runtime;
    await expect(
      executeRuntimeCommand(
        inheritedGetter,
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toEqual(new RuntimeCommandExecutionError("invalid_input"));
    expect(runtimeGetterCalls).toBe(0);

    const revokedDigestInput = Proxy.revocable(
      receipt({ outcome: "accepted", effectRef: "effect-1" }),
      {}
    );
    revokedDigestInput.revoke();
    expect(() => digestNonDuplicateRuntimeReceipt(revokedDigestInput.proxy)).toThrow(
      new RuntimeCommandExecutionError("invalid_receipt")
    );
  });

  it("maps verifier and provider failures to safe typed errors", async () => {
    const provider = runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" }));
    vi.mocked(provider.command).mockRejectedValueOnce(new Error("secret provider payload"));

    const providerFailure = executeRuntimeCommand(
      provider,
      handle,
      command,
      () => true,
      () => 100
    );
    await expect(providerFailure).rejects.toEqual(
      new RuntimeCommandExecutionError("runtime_command_failed")
    );
    await expect(providerFailure).rejects.toMatchObject({
      dispatchCertainty: "dispatch-uncertain",
    });
    await expect(providerFailure).rejects.not.toHaveProperty("cause");

    const verifierFailure = executeRuntimeCommand(
      runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" })),
      handle,
      command,
      () => {
        throw new Error("secret verifier payload");
      },
      () => 100
    );
    await expect(verifierFailure).rejects.toEqual(
      new RuntimeCommandExecutionError("authority_verification_failed")
    );
    await expect(verifierFailure).rejects.toMatchObject({
      dispatchCertainty: "not-dispatched",
    });
  });
});

function asPostStart(value: unknown): RuntimePostStartLifecycleCommand {
  return value as RuntimePostStartLifecycleCommand;
}

function asLifecycle(value: unknown): RuntimeLifecycleCommand {
  return value as RuntimeLifecycleCommand;
}

function startCommand(): Extract<RuntimeLifecycleCommand, { kind: "run.start" }> {
  const { reason: _reason, ...base } = command;
  return {
    ...base,
    kind: "run.start",
    runPolicyRevision: 1,
    fromRunStateVersion: 1,
    toRunStateVersion: 2,
    authority: { ...command.authority, capability: "run.start" },
    policy: {
      agentRunId: command.agentRunId,
      revision: 1,
      digest: "1".repeat(64),
      policyBodyDigest: "2".repeat(64),
      mode: "autonomous",
      completionPolicy: { kind: "continue-until-all-goals-achieved" },
      scopedExternalPolicyRef: "scoped-policy-1",
      limits: {
        wallClock: { kind: "unconfigured" },
        modelTokens: { kind: "unconfigured" },
        modelSpend: { kind: "unconfigured" },
        outboundBytes: { kind: "unconfigured" },
        actionCounts: {
          local: { kind: "unconfigured" },
          "scoped-external": { kind: "unconfigured" },
          protected: { kind: "unconfigured" },
          forbidden: { kind: "unconfigured" },
        },
      },
      initialGoalSet: {
        goalSetId: "goal-set-1",
        agentRunId: command.agentRunId,
        revision: 1,
        digest: "3".repeat(64),
        goals: [
          {
            goalId: "goal-1",
            position: 1,
            title: "Complete the bounded task",
            acceptanceCriteria: ["The focused tests pass"],
            dependencyGoalIds: [],
            version: 1,
            status: "pending",
          },
        ],
      },
      scopedExternalRules: [],
      projectCeilingRevision: command.projectCeilingRevision,
      projectCeilingDigest: "4".repeat(64),
      binding,
      runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest: command.requiredEffectEnforcerSetDigest,
      createdAtMs: command.issuedAtMs,
    },
  } as const satisfies Extract<RuntimeLifecycleCommand, { kind: "run.start" }>;
}

function yoloStartCommand(): Extract<RuntimeLifecycleCommand, { kind: "run.start" }> {
  const start = startCommand();
  const effect = {
    wallClock: { milliseconds: 1 },
    modelTokens: 0,
    modelSpend: { currency: "USD", minorUnits: 0 },
    outboundBytes: 1,
    actionCounts: {
      local: 0,
      "scoped-external": 0,
      protected: 1,
      forbidden: 0,
    },
  } as const;
  const unsignedManifest = {
    version: 1,
    manifestId: "manifest-1",
    actionClass: "protected",
    provider: "deployment-provider",
    operation: "deployment.create-preview",
    exactTarget: "preview:project-1/session-1",
    actionSchema: {
      schemaId: "deployment-preview-v1",
      schemaVersion: 1,
      schemaDigest: "5".repeat(64),
      canonicalizationProfile: "terminalx-canonical-effect-v1",
      unknownFields: "reject",
    },
    canonicalEffectInputDigest: "6".repeat(64),
    effectIdempotencyKey: "effect-key-1",
    expectedEffect: effect,
    expiresAtMs: 350,
  } as const;
  const manifest = {
    ...unsignedManifest,
    digest: digestActionManifest(unsignedManifest),
  } as const;
  return {
    ...start,
    policy: {
      ...start.policy,
      mode: "yolo",
      yoloConfirmationRef: "yolo-confirmation-1",
    },
    yoloAuthorization: {
      manifest,
      grant: {
        grantId: "grant-1",
        teamId: binding.teamId,
        projectId: binding.projectId,
        sessionId: binding.sessionId,
        agentRunId: command.agentRunId,
        runPolicyRevision: start.runPolicyRevision,
        runtimeAssignmentId: binding.runtimeAssignmentId,
        runtimeAssignmentGeneration: binding.runtimeAssignmentGeneration,
        sandboxId: binding.sandboxId,
        sandboxGeneration: binding.sandboxGeneration,
        runtimePrincipalId: binding.runtimePrincipalId,
        runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
        approvalRequestId: "approval-request-1",
        approvalRequestVersion: 1,
        provider: manifest.provider,
        operation: manifest.operation,
        target: manifest.exactTarget,
        budget: { perEffectLimit: effect, cumulativeLimit: effect },
        usageLedgerRef: "usage-ledger-1",
        issuerActorRef: "user-1",
        issuerApprovalAuthorityRevision: "approval-authority-1",
        expiresAtMs: 350,
        signature: "signed-grant",
        createdAtMs: command.issuedAtMs,
        actionClass: "protected",
        scope: {
          kind: "once",
          manifestDigest: manifest.digest,
          effectIdempotencyKey: manifest.effectIdempotencyKey,
        },
      },
    },
  } as const satisfies Extract<RuntimeLifecycleCommand, { kind: "run.start" }>;
}

type WithoutReceiptBase<Receipt> = Receipt extends NonDuplicateRuntimeReceipt
  ? Omit<Receipt, "commandId" | "binding" | "runtimeAuthorizationGeneration">
  : never;

function receipt(
  outcome: WithoutReceiptBase<NonDuplicateRuntimeReceipt>,
  runtimeBinding: RuntimeHandle["binding"] = binding
): NonDuplicateRuntimeReceipt {
  return {
    commandId: command.commandId,
    binding: runtimeBinding,
    runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
    ...outcome,
  } as NonDuplicateRuntimeReceipt;
}

function proof(
  generation: number,
  effectRef = "effect-1",
  enforcedFence: number = command.toRunStateVersion,
  requiredEffectEnforcerSetDigest = command.requiredEffectEnforcerSetDigest
) {
  const enforcementSubjectDigest = digestRuntimeEnforcementSubject({
    version: 1,
    commandId: command.commandId,
    commandClaimsDigest: command.authority.claimsDigest,
    binding,
    runtimeAuthorizationGeneration: generation,
    requiredEffectEnforcerSetDigest,
    effectRefCommitment: commitRuntimeEffectRef(effectRef),
    enforcedFence,
  });
  const content = {
    generation,
    requiredEffectEnforcerSetDigest,
    enforcementSubjectDigest,
    acknowledgements: [
      {
        enforcerRef: "runtime-enforcer-1",
        enforcerKind: "runtime" as const,
        acknowledgementDigest: "c".repeat(64),
      },
    ],
  } as const;
  return {
    ...content,
    aggregateProofDigest: digestAggregateEnforcementProof(content),
  } as const;
}

function runtimeReturning(result: RuntimeReceipt): Runtime {
  return {
    ensure: vi.fn(async () => handle),
    command: vi.fn(async () => result),
    follow: vi.fn(async function* () {
      return;
    }),
    retire: vi.fn(async () => undefined),
  };
}
