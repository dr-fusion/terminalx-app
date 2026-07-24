import { describe, expect, it, vi } from "vitest";
import {
  RuntimeCompensationExecutionError,
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  digestNonDuplicateRuntimeCompensationReceipt,
  digestRuntimeCommandClaims,
  digestRuntimeCompensationEnforcementSubject,
  executeRuntimeCompensationCommand,
  type AggregateEnforcementProof,
  type NonDuplicateRuntimeCompensationReceipt,
  type Runtime,
  type RuntimeCompensationCommand,
  type RuntimeCompensationEnforcementProofVerifier,
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

function command(overrides: Partial<RuntimeCompensationCommand> = {}): RuntimeCompensationCommand {
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
    ...overrides,
  } as const;
  return {
    ...claims,
    authority: {
      issuer: "platform-security",
      issuerKeyId: "platform-security:v1",
      audience: "runtime",
      capability: "safety.quarantine",
      claimsDigest: digestRuntimeCommandClaims(claims),
      issuedAtMs: claims.issuedAtMs,
      expiresAtMs: claims.deadlineAtMs,
      signature: "platform-signature",
    },
  } as RuntimeCompensationCommand;
}

function receiptFor(
  exactCommand: RuntimeCompensationCommand,
  outcome: "accepted" | "enforced" | "rejected" | "quarantined" = "enforced",
  effectRef = "provider-containment-effect",
  enforcedSafetyFence = exactCommand.safetyFence
): RuntimeCompensationReceipt {
  const base = {
    receiptKind: "runtime.compensation",
    compensationId: exactCommand.compensationId,
    commandId: exactCommand.commandId,
    binding: exactCommand.binding,
    observedRuntimeAuthorizationGeneration: exactCommand.observedRuntimeAuthorizationGeneration,
  } as const;
  if (outcome === "accepted") return { ...base, outcome, effectRef };
  if (outcome === "rejected") {
    return { ...base, outcome, code: "not_ready", safeDetail: "Runtime not ready" };
  }
  if (outcome === "quarantined") {
    return { ...base, outcome, reason: "kill_failure", effectRef };
  }
  const containment = {
    terminalWritesRevoked: true,
    processExecutionStopped: true,
    runtimeQuarantined: true,
  } as const;
  const subject = {
    version: 1,
    purpose: "stale-lifecycle-effect-containment",
    compensationId: exactCommand.compensationId,
    commandId: exactCommand.commandId,
    commandClaimsDigest: exactCommand.authority.claimsDigest,
    binding: exactCommand.binding,
    observedRuntimeAuthorizationGeneration: exactCommand.observedRuntimeAuthorizationGeneration,
    sourceReceiptDigest: exactCommand.source.lifecycleReceiptDigest,
    sourceEnforcementSubjectDigest: exactCommand.source.lifecycleEnforcementSubjectDigest,
    sourceAggregateProofDigest: exactCommand.source.lifecycleAggregateProofDigest,
    requiredContainmentEnforcerSetDigest: exactCommand.requiredContainmentEnforcerSetDigest,
    safetyFence: exactCommand.safetyFence,
    enforcedSafetyFence,
    effectRefCommitment: commitRuntimeEffectRef(effectRef),
    containment,
  } as const;
  const proofPayload = {
    generation: exactCommand.observedRuntimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest: exactCommand.requiredContainmentEnforcerSetDigest,
    enforcementSubjectDigest: digestRuntimeCompensationEnforcementSubject(subject),
    acknowledgements: [
      {
        enforcerRef: "containment-runtime",
        enforcerKind: "runtime" as const,
        acknowledgementDigest: "1".repeat(64),
      },
    ],
  };
  const aggregateEnforcementProof: AggregateEnforcementProof = {
    ...proofPayload,
    aggregateProofDigest: digestAggregateEnforcementProof(proofPayload),
  };
  return {
    ...base,
    outcome,
    effectRef,
    enforcedSafetyFence,
    containment,
    aggregateEnforcementProof,
  };
}

function runtimeReturning(receipt: RuntimeCompensationReceipt) {
  const dispatch = vi.fn<Runtime["command"]>(async () => receipt);
  const runtime: Runtime = {
    async ensure() {
      return handle;
    },
    command: dispatch,
    async *follow() {
      return;
    },
    async retire() {},
  };
  return { runtime, dispatch };
}

describe("Runtime compensation execution", () => {
  it("rejects an accessor-backed Runtime command without invoking it", async () => {
    const exactCommand = command();
    const shadowed = runtimeReturning(receiptFor(exactCommand));
    let getterCalls = 0;
    const runtime = Object.create(shadowed.runtime) as Runtime;
    Object.defineProperty(runtime, "command", {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("provider getter must never run");
      },
    });
    const verifyAuthority = vi.fn(async () => true);
    const verifyProof = vi.fn<RuntimeCompensationEnforcementProofVerifier>(() => true);

    await expect(
      executeRuntimeCompensationCommand(
        runtime,
        handle,
        exactCommand,
        verifyAuthority,
        () => 200,
        verifyProof
      )
    ).rejects.toMatchObject({ code: "invalid_input", dispatchCertainty: "not-dispatched" });
    expect(getterCalls).toBe(0);
    expect(shadowed.dispatch).not.toHaveBeenCalled();
    expect(verifyAuthority).not.toHaveBeenCalled();
    expect(verifyProof).not.toHaveBeenCalled();
  });

  it("dispatches one exact platform command and requires its containment proof", async () => {
    const exactCommand = command();
    const { runtime, dispatch } = runtimeReturning(receiptFor(exactCommand));
    const verifyAuthority = vi.fn(async () => true);
    const verifyProof = vi.fn<RuntimeCompensationEnforcementProofVerifier>(() => true);

    await expect(
      executeRuntimeCompensationCommand(
        runtime,
        handle,
        exactCommand,
        verifyAuthority,
        () => 200,
        verifyProof
      )
    ).resolves.toMatchObject({ outcome: "enforced", compensationId: "compensation-1" });

    expect(verifyAuthority).toHaveBeenCalledTimes(2);
    expect(dispatch).toHaveBeenCalledOnce();
    expect(Object.isFrozen(dispatch.mock.calls[0]?.[0])).toBe(true);
    expect(Object.isFrozen(dispatch.mock.calls[0]?.[1])).toBe(true);
    expect(verifyProof).toHaveBeenCalledOnce();
  });

  it("rejects a Team Session quarantine envelope before dispatch", async () => {
    const exactCommand = command();
    const forged = {
      ...exactCommand,
      authority: { ...exactCommand.authority, issuer: "team-session" },
    } as unknown as RuntimeCompensationCommand;
    const { runtime, dispatch } = runtimeReturning(receiptFor(exactCommand));

    await expect(
      executeRuntimeCompensationCommand(
        runtime,
        handle,
        forged,
        async () => true,
        () => 200,
        () => true
      )
    ).rejects.toMatchObject({ code: "invalid_authority", dispatchCertainty: "not-dispatched" });
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("never redirects containment to a replacement Sandbox", async () => {
    const exactCommand = command();
    const replacementHandle = {
      ...handle,
      binding: { ...binding, sandboxGeneration: binding.sandboxGeneration + 1 },
    };
    const { runtime, dispatch } = runtimeReturning(receiptFor(exactCommand));

    await expect(
      executeRuntimeCompensationCommand(
        runtime,
        replacementHandle,
        exactCommand,
        async () => true,
        () => 200,
        () => true
      )
    ).rejects.toMatchObject({ code: "binding_mismatch", dispatchCertainty: "not-dispatched" });
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("classifies a bad containment proof as dispatch-uncertain", async () => {
    const exactCommand = command();
    const { runtime } = runtimeReturning(receiptFor(exactCommand));

    await expect(
      executeRuntimeCompensationCommand(
        runtime,
        handle,
        exactCommand,
        async () => true,
        () => 200,
        async () => false
      )
    ).rejects.toMatchObject({
      code: "enforcement_proof_verification_failed",
      dispatchCertainty: "dispatch-uncertain",
    });
  });

  it("rejects an older safety fence and proof-binds a safely advanced fence", async () => {
    const exactCommand = command();
    const stale = {
      ...(receiptFor(exactCommand) as Extract<RuntimeCompensationReceipt, { outcome: "enforced" }>),
      enforcedSafetyFence: exactCommand.safetyFence - 1,
    };
    const staleProofVerifier = vi.fn(() => true);

    await expect(
      executeRuntimeCompensationCommand(
        runtimeReturning(stale).runtime,
        handle,
        exactCommand,
        async () => true,
        () => 200,
        staleProofVerifier
      )
    ).rejects.toMatchObject({ code: "invalid_receipt", dispatchCertainty: "dispatch-uncertain" });
    expect(staleProofVerifier).not.toHaveBeenCalled();

    const advanced = receiptFor(
      exactCommand,
      "enforced",
      "provider-containment-effect",
      exactCommand.safetyFence + 1
    );
    await expect(
      executeRuntimeCompensationCommand(
        runtimeReturning(advanced).runtime,
        handle,
        exactCommand,
        async () => true,
        () => 200,
        () => true
      )
    ).resolves.toMatchObject({ enforcedSafetyFence: exactCommand.safetyFence + 1 });
  });

  it("rejects lifecycle-domain proof replay and exact-binding receipt substitution", async () => {
    const exactCommand = command();
    const receipt = receiptFor(exactCommand) as Extract<
      RuntimeCompensationReceipt,
      { outcome: "enforced" }
    >;
    const proof = receipt.aggregateEnforcementProof;
    if (!proof) throw new Error("Expected proof");
    const badReceipt = {
      ...receipt,
      aggregateEnforcementProof: {
        ...proof,
        enforcementSubjectDigest: "0".repeat(64),
      },
    };
    const { runtime } = runtimeReturning(badReceipt);

    await expect(
      executeRuntimeCompensationCommand(
        runtime,
        handle,
        exactCommand,
        async () => true,
        () => 200,
        () => true
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });

    const wrongBinding = {
      ...receipt,
      binding: { ...receipt.binding, sandboxId: "replacement-sandbox" },
    };
    await expect(
      executeRuntimeCompensationCommand(
        runtimeReturning(wrongBinding).runtime,
        handle,
        exactCommand,
        async () => true,
        () => 200,
        () => true
      )
    ).rejects.toMatchObject({ code: "invalid_receipt" });
  });

  it("retains accepted as non-enforced and validates exact duplicate originals", async () => {
    const exactCommand = command();
    const accepted = receiptFor(exactCommand, "accepted") as NonDuplicateRuntimeCompensationReceipt;
    const verifyProof = vi.fn<RuntimeCompensationEnforcementProofVerifier>(() => true);
    await expect(
      executeRuntimeCompensationCommand(
        runtimeReturning(accepted).runtime,
        handle,
        exactCommand,
        async () => true,
        () => 200,
        verifyProof
      )
    ).resolves.toEqual(accepted);
    expect(verifyProof).not.toHaveBeenCalled();

    const duplicate = {
      receiptKind: "runtime.compensation",
      compensationId: exactCommand.compensationId,
      commandId: exactCommand.commandId,
      binding: exactCommand.binding,
      observedRuntimeAuthorizationGeneration: exactCommand.observedRuntimeAuthorizationGeneration,
      outcome: "duplicate",
      originalReceipt: accepted,
      originalReceiptDigest: digestNonDuplicateRuntimeCompensationReceipt(accepted),
    } as const satisfies RuntimeCompensationReceipt;
    await expect(
      executeRuntimeCompensationCommand(
        runtimeReturning(duplicate).runtime,
        handle,
        exactCommand,
        async () => true,
        () => 200,
        verifyProof
      )
    ).resolves.toEqual(duplicate);
  });

  it("does not dispatch after abort or an authority recheck failure", async () => {
    const exactCommand = command();
    const { runtime, dispatch } = runtimeReturning(receiptFor(exactCommand));
    const controller = new AbortController();
    controller.abort();
    await expect(
      executeRuntimeCompensationCommand(
        runtime,
        handle,
        exactCommand,
        async () => true,
        () => 200,
        () => true,
        controller.signal
      )
    ).rejects.toBeInstanceOf(RuntimeCompensationExecutionError);
    expect(dispatch).not.toHaveBeenCalled();

    const verifyAuthority = vi.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    await expect(
      executeRuntimeCompensationCommand(
        runtime,
        handle,
        exactCommand,
        verifyAuthority,
        () => 200,
        () => true
      )
    ).rejects.toMatchObject({
      code: "authority_verification_failed",
      dispatchCertainty: "not-dispatched",
    });
    expect(dispatch).not.toHaveBeenCalled();
  });
});
