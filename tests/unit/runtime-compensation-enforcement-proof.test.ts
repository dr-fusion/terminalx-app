import { describe, expect, it, vi } from "vitest";
import {
  RuntimeCompensationEnforcementProofError,
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  digestRuntimeCompensationEnforcementSubject,
  digestRuntimeEnforcementSubject,
  verifyRuntimeCompensationEnforcementProof,
  type AggregateEnforcementProof,
  type RuntimeCompensationEnforcementProofVerifier,
  type RuntimeCompensationEnforcementSubject,
} from "@/lib/runtime";
import { verifyRuntimeCompensationEnforcementProofSynchronously } from "@/lib/runtime/runtime-compensation-enforcement-proof";

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

const subject = {
  version: 1,
  purpose: "stale-lifecycle-effect-containment",
  compensationId: "compensation-1",
  commandId: "quarantine-command-1",
  commandClaimsDigest: "a".repeat(64),
  binding,
  observedRuntimeAuthorizationGeneration: 4,
  safetyFence: 8,
  enforcedSafetyFence: 9,
  sourceReceiptDigest: "b".repeat(64),
  sourceEnforcementSubjectDigest: "c".repeat(64),
  sourceAggregateProofDigest: "d".repeat(64),
  requiredContainmentEnforcerSetDigest: "e".repeat(64),
  effectRefCommitment: commitRuntimeEffectRef("provider-containment-effect"),
  containment: {
    terminalWritesRevoked: true,
    processExecutionStopped: true,
    runtimeQuarantined: true,
  },
} as const satisfies RuntimeCompensationEnforcementSubject;

function proofFor(
  exactSubject: RuntimeCompensationEnforcementSubject = subject
): AggregateEnforcementProof {
  const payload = {
    generation: exactSubject.observedRuntimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest: exactSubject.requiredContainmentEnforcerSetDigest,
    enforcementSubjectDigest: digestRuntimeCompensationEnforcementSubject(exactSubject),
    acknowledgements: [
      {
        enforcerRef: "containment-runtime",
        enforcerKind: "runtime" as const,
        acknowledgementDigest: "f".repeat(64),
      },
      {
        enforcerRef: "terminal-write-revoker",
        enforcerKind: "other-effect-enforcer" as const,
        acknowledgementDigest: "1".repeat(64),
      },
    ],
  };
  return { ...payload, aggregateProofDigest: digestAggregateEnforcementProof(payload) };
}

describe("Runtime compensation enforcement proof", () => {
  it("binds a trusted aggregate proof to every exact containment field", async () => {
    const verifier = vi.fn<RuntimeCompensationEnforcementProofVerifier>(() => true);

    await expect(
      verifyRuntimeCompensationEnforcementProof(subject, proofFor(), verifier)
    ).resolves.toBeUndefined();
    expect(verifier).toHaveBeenCalledOnce();
    expect(verifier.mock.calls[0]?.[0]).toMatchObject({
      subject,
      subjectDigest: digestRuntimeCompensationEnforcementSubject(subject),
    });

    const mutations: RuntimeCompensationEnforcementSubject[] = [
      { ...subject, compensationId: "compensation-2" },
      { ...subject, commandId: "quarantine-command-2" },
      { ...subject, commandClaimsDigest: "0".repeat(64) },
      { ...subject, binding: { ...binding, sandboxGeneration: 4 } },
      { ...subject, observedRuntimeAuthorizationGeneration: 5 },
      { ...subject, safetyFence: 9 },
      { ...subject, enforcedSafetyFence: 10 },
      { ...subject, sourceReceiptDigest: "0".repeat(64) },
      { ...subject, sourceEnforcementSubjectDigest: "0".repeat(64) },
      { ...subject, sourceAggregateProofDigest: "0".repeat(64) },
      { ...subject, requiredContainmentEnforcerSetDigest: "0".repeat(64) },
      { ...subject, effectRefCommitment: commitRuntimeEffectRef("another-effect") },
    ];
    for (const mutation of mutations) {
      await expect(
        verifyRuntimeCompensationEnforcementProof(mutation, proofFor(), verifier)
      ).rejects.toMatchObject({ code: "invalid_proof" });
    }
  });

  it("uses a distinct domain so a lifecycle proof cannot be replayed", async () => {
    const lifecycleDigest = digestRuntimeEnforcementSubject({
      version: 1,
      commandId: subject.commandId,
      commandClaimsDigest: subject.commandClaimsDigest,
      binding,
      runtimeAuthorizationGeneration: subject.observedRuntimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest: subject.requiredContainmentEnforcerSetDigest,
      effectRefCommitment: subject.effectRefCommitment,
      enforcedFence: subject.observedRuntimeAuthorizationGeneration,
    });
    expect(lifecycleDigest).not.toBe(digestRuntimeCompensationEnforcementSubject(subject));

    const payload = {
      generation: subject.observedRuntimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest: subject.requiredContainmentEnforcerSetDigest,
      enforcementSubjectDigest: lifecycleDigest,
      acknowledgements: proofFor().acknowledgements,
    };
    const replay = {
      ...payload,
      aggregateProofDigest: digestAggregateEnforcementProof(payload),
    };
    await expect(
      verifyRuntimeCompensationEnforcementProof(subject, replay, () => true)
    ).rejects.toMatchObject({ code: "invalid_proof" });
  });

  it("fails closed on false, throwing, or asynchronous synchronous verifiers", async () => {
    await expect(
      verifyRuntimeCompensationEnforcementProof(subject, proofFor(), () => false)
    ).rejects.toMatchObject({ code: "verification_failed" });
    await expect(
      verifyRuntimeCompensationEnforcementProof(subject, proofFor(), () => {
        throw new Error("secret verifier detail");
      })
    ).rejects.toMatchObject({ code: "verification_failed" });

    expect(() =>
      verifyRuntimeCompensationEnforcementProofSynchronously(subject, proofFor(), (() =>
        Promise.resolve(true)) as never)
    ).toThrow(RuntimeCompensationEnforcementProofError);
  });

  it("does not read or invoke a custom thenable from a synchronous proof verifier", () => {
    const thenBody = vi.fn();
    const thenGetter = vi.fn(() => thenBody);
    const hostile = {} as Record<string, unknown>;
    Object.defineProperty(hostile, "then", { get: thenGetter });

    expect(() =>
      verifyRuntimeCompensationEnforcementProofSynchronously(
        subject,
        proofFor(),
        (() => hostile) as never
      )
    ).toThrow(RuntimeCompensationEnforcementProofError);
    expect(thenGetter).not.toHaveBeenCalled();
    expect(thenBody).not.toHaveBeenCalled();
  });

  it("rejects malformed subjects without exposing their values", () => {
    expect(() =>
      digestRuntimeCompensationEnforcementSubject({
        ...subject,
        containment: { ...subject.containment, runtimeQuarantined: false },
      } as unknown as RuntimeCompensationEnforcementSubject)
    ).toThrow(expect.objectContaining({ code: "invalid_subject" }));
    expect(() =>
      digestRuntimeCompensationEnforcementSubject({
        ...subject,
        safetyFence: 10,
        enforcedSafetyFence: 9,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_subject" }));
  });
});
