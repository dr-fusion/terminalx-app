import { describe, expect, expectTypeOf, it, vi } from "vitest";
import {
  RuntimeCommandExecutionError,
  digestAggregateEnforcementProof,
  digestNonDuplicateRuntimeReceipt,
  executeRuntimeCommand,
  type NonDuplicateRuntimeReceipt,
  type Runtime,
  type RuntimeAuthorityVerificationInput,
  type RuntimeCommand,
  type RuntimeHandle,
  type RuntimePostStartLifecycleCommand,
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
      expect.objectContaining({ commandId: command.commandId, binding })
    );
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

  it("isolates dispatch from caller, verifier, and Runtime-getter mutation", async () => {
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
    let verifiedSnapshot: RuntimePostStartLifecycleCommand | undefined;
    const accepted = receipt({ outcome: "accepted", effectRef: "effect-1" });
    const dispatch = vi.fn(async () => accepted);
    const adapter = {
      ensure: vi.fn(async () => handle),
      get command() {
        callerCommand.commandId = "getter-redirect";
        callerCommand.binding.sandboxId = "getter-sandbox";
        return dispatch;
      },
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
      })
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

  it("requires a lifecycle enforced receipt to advance the exact Run-state fence", async () => {
    const enforced = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration),
    });
    await expect(
      executeRuntimeCommand(
        runtimeReturning(enforced),
        handle,
        command,
        () => true,
        () => 100
      )
    ).resolves.toEqual(enforced);

    const staleFence = receipt({
      outcome: "enforced",
      effectRef: "effect-1",
      enforcedFence: command.fromRunStateVersion,
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

  it("accepts a duplicate only with its complete original receipt and canonical digest", async () => {
    const original = receipt({
      outcome: "enforced",
      effectRef: "effect-original",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration),
    });
    const duplicate = {
      commandId: command.commandId,
      binding,
      runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
      outcome: "duplicate",
      originalReceipt: original,
      originalReceiptDigest: digestNonDuplicateRuntimeReceipt(original),
    } as const satisfies RuntimeReceipt;

    const result = await executeRuntimeCommand(
      runtimeReturning(duplicate),
      handle,
      command,
      () => true,
      () => 100
    );
    expect(result).not.toBe(duplicate);
    expect(result).toMatchObject({
      outcome: "duplicate",
      originalReceipt: {
        outcome: "enforced",
        enforcedFence: command.toRunStateVersion,
        aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration),
      },
    });

    expectTypeOf(duplicate.originalReceipt).toMatchTypeOf<NonDuplicateRuntimeReceipt>();
  });

  it("rejects non-canonical duplicate digests and conflicting enforcement proofs", async () => {
    const original = receipt({
      outcome: "enforced",
      effectRef: "effect-original",
      enforcedFence: command.toRunStateVersion,
      aggregateEnforcementProof: proof(command.runtimeAuthorizationGeneration),
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

    const hostileRuntime = {
      ...runtimeReturning(receipt({ outcome: "accepted", effectRef: "effect-1" })),
      get command(): Runtime["command"] {
        throw new Error("secret runtime getter");
      },
    };
    await expect(
      executeRuntimeCommand(
        hostileRuntime,
        handle,
        command,
        () => true,
        () => 100
      )
    ).rejects.toEqual(new RuntimeCommandExecutionError("invalid_input"));

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
  });
});

function asPostStart(value: unknown): RuntimePostStartLifecycleCommand {
  return value as RuntimePostStartLifecycleCommand;
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

function proof(generation: number) {
  const content = {
    generation,
    requiredEffectEnforcerSetDigest: "b".repeat(64),
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
