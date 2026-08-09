import { describe, expect, it, vi } from "vitest";
import {
  RuntimeEnforcementProofError,
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  digestRuntimeEnforcementSubject,
  snapshotPersistedRuntimeEffectRefCommitment,
  verifyRuntimeEnforcementProof,
  type RuntimeEnforcementProofVerifier,
  type RuntimeEnforcementSubject,
} from "@/lib/runtime/runtime-enforcement-proof";
import type { AggregateEnforcementProof } from "@/lib/runtime/contracts";

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

const subject = {
  version: 1,
  commandId: "command-1",
  commandClaimsDigest: "a".repeat(64),
  binding,
  runtimeAuthorizationGeneration: 7,
  requiredEffectEnforcerSetDigest: "b".repeat(64),
  effectRefCommitment: commitRuntimeEffectRef("effect-1"),
  enforcedFence: 9,
} as const satisfies RuntimeEnforcementSubject;

describe("Runtime enforcement proof boundary", () => {
  it("separates raw provider refs from trusted persisted commitments", () => {
    const firstCommitment = commitRuntimeEffectRef("effect-1");
    const syntaxCollisionCommitment = commitRuntimeEffectRef(firstCommitment);

    expect(syntaxCollisionCommitment).not.toBe(firstCommitment);
    expect(snapshotPersistedRuntimeEffectRefCommitment(firstCommitment)).toBe(firstCommitment);
    expect(() => snapshotPersistedRuntimeEffectRefCommitment("effect-1")).toThrowError(
      new RuntimeEnforcementProofError("invalid_subject")
    );
  });

  it("domain-separates the exact signed-command enforcement subject", () => {
    expect(digestRuntimeEnforcementSubject(subject)).toBe(
      "07da86a3182f2479455c36a80c44065973a5be66ca463823afd911cabb4e6e12"
    );
  });

  it("rejects non-exact subjects through a safe error surface", () => {
    const secret = "provider-secret-value";
    const invalid = {
      version: 1,
      commandId: "command-1",
      commandClaimsDigest: "a".repeat(64),
      binding,
      runtimeAuthorizationGeneration: 7,
      requiredEffectEnforcerSetDigest: "b".repeat(64),
      effectRefCommitment: commitRuntimeEffectRef("effect-1"),
      enforcedFence: 9,
      [secret]: true,
    } as unknown as RuntimeEnforcementSubject;

    expect(() => digestRuntimeEnforcementSubject(invalid)).toThrowError(
      new RuntimeEnforcementProofError("invalid_subject")
    );
    try {
      digestRuntimeEnforcementSubject(invalid);
    } catch (error) {
      expect(JSON.stringify(error)).not.toContain(secret);
      expect(String(error)).not.toContain(secret);
    }
  });

  it("passes only exact subject-bound proof snapshots to the injected verifier", async () => {
    const proof = validProof();
    const verifier = vi.fn<RuntimeEnforcementProofVerifier>(() => true);

    await expect(verifyRuntimeEnforcementProof(subject, proof, verifier)).resolves.toBeUndefined();
    const input = verifier.mock.calls[0]?.[0];
    expect(input).toEqual({
      subject,
      subjectDigest: proof.enforcementSubjectDigest,
      proof,
    });
    expect(input?.subject).not.toBe(subject);
    expect(input?.proof).not.toBe(proof);
    expect(Object.isFrozen(input)).toBe(true);
    expect(Object.isFrozen(input?.subject.binding)).toBe(true);
    expect(Object.isFrozen(input?.proof.acknowledgements[0])).toBe(true);
  });

  it("rejects replayed enforcer identities and acknowledgement digests", async () => {
    const { aggregateProofDigest: _aggregateProofDigest, ...validPayload } = validProof();
    const duplicateRefPayload = {
      ...validPayload,
      acknowledgements: [
        {
          enforcerRef: "runtime-enforcer-1",
          enforcerKind: "runtime" as const,
          acknowledgementDigest: "c".repeat(64),
        },
        {
          enforcerRef: "runtime-enforcer-1",
          enforcerKind: "credential-proxy" as const,
          acknowledgementDigest: "d".repeat(64),
        },
      ],
    };
    const duplicateRef = {
      ...duplicateRefPayload,
      aggregateProofDigest: "0".repeat(64),
    } satisfies AggregateEnforcementProof;
    const duplicateAcknowledgementPayload = {
      ...validPayload,
      acknowledgements: [
        {
          enforcerRef: "credential-enforcer-1",
          enforcerKind: "credential-proxy" as const,
          acknowledgementDigest: "c".repeat(64),
        },
        {
          enforcerRef: "runtime-enforcer-1",
          enforcerKind: "runtime" as const,
          acknowledgementDigest: "c".repeat(64),
        },
      ],
    };
    const duplicateAcknowledgement = {
      ...duplicateAcknowledgementPayload,
      aggregateProofDigest: "0".repeat(64),
    } satisfies AggregateEnforcementProof;
    const verifier = vi.fn<RuntimeEnforcementProofVerifier>(() => true);

    for (const proof of [duplicateRef, duplicateAcknowledgement]) {
      await expect(verifyRuntimeEnforcementProof(subject, proof, verifier)).rejects.toEqual(
        new RuntimeEnforcementProofError("invalid_proof")
      );
    }
    expect(verifier).not.toHaveBeenCalled();
  });

  it("snapshots acknowledgement arrays without invoking value getters", async () => {
    let getterInvoked = false;
    const proof = validProof();
    const acknowledgements = new Proxy([...proof.acknowledgements], {
      get() {
        getterInvoked = true;
        throw new Error("secret acknowledgement getter");
      },
    });

    await expect(
      verifyRuntimeEnforcementProof(subject, { ...proof, acknowledgements }, () => true)
    ).resolves.toBeUndefined();
    expect(getterInvoked).toBe(false);
  });
});

function validProof(): AggregateEnforcementProof {
  const payload = {
    generation: 7,
    requiredEffectEnforcerSetDigest: "b".repeat(64),
    enforcementSubjectDigest: "07da86a3182f2479455c36a80c44065973a5be66ca463823afd911cabb4e6e12",
    acknowledgements: [
      {
        enforcerRef: "runtime-enforcer-1",
        enforcerKind: "runtime" as const,
        acknowledgementDigest: "c".repeat(64),
      },
    ],
  };
  return { ...payload, aggregateProofDigest: digestAggregateEnforcementProof(payload) };
}
