import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  APPROVAL_PROVENANCE_KIND,
  digestApprovalCapability,
  digestApprovalProvenance,
  signApprovalProvenance,
  snapshotApprovalProvenancePayload,
  verifyApprovalProvenance,
  type ApprovalProvenancePayload,
} from "@/lib/runtime/approval-provenance";

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

function payload(overrides: Partial<ApprovalProvenancePayload> = {}): ApprovalProvenancePayload {
  return {
    schema: 1,
    kind: APPROVAL_PROVENANCE_KIND,
    signingKeyId: "approval-key-1",
    grantId: "grant-1",
    approvalRequestId: "approval-1",
    approvalRequestVersion: 1,
    grantStateVersion: 1,
    actorKind: "human",
    actorRef: "user-1",
    actionClass: "protected",
    capabilityDigest: "a".repeat(64),
    policyDigest: "b".repeat(64),
    budgetDigest: "c".repeat(64),
    binding,
    runtimeAuthorizationGeneration: 4,
    issuedAtMs: 1_000,
    expiresAtMs: 2_000,
    ...overrides,
  };
}

describe("approval provenance signing", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  it("signs and verifies an immutable approval snapshot", () => {
    const proof = signApprovalProvenance(payload(), privateKey);
    const verified = verifyApprovalProvenance(proof, publicKey);
    expect(verified).not.toBeNull();
    expect(verified?.grantId).toBe("grant-1");
    expect(verified?.actionClass).toBe("protected");
  });

  it("fails closed when the payload is tampered after signing", () => {
    const proof = signApprovalProvenance(payload(), privateKey);
    const tampered = {
      ...proof,
      payload: { ...proof.payload, budgetDigest: "d".repeat(64) },
    };
    expect(verifyApprovalProvenance(tampered, publicKey)).toBeNull();
  });

  it("fails closed for a foreign signing key", () => {
    const proof = signApprovalProvenance(payload(), privateKey);
    const foreign = generateKeyPairSync("ed25519");
    expect(verifyApprovalProvenance(proof, foreign.publicKey)).toBeNull();
  });

  it("rejects an out-of-order validity window and non-digest fields", () => {
    expect(() =>
      snapshotApprovalProvenancePayload(payload({ issuedAtMs: 2_000, expiresAtMs: 2_000 }))
    ).toThrow();
    expect(() => snapshotApprovalProvenancePayload(payload({ policyDigest: "short" }))).toThrow();
  });

  it("produces a stable digest that changes with any capability field", () => {
    const base = digestApprovalCapability({
      actionClass: "scoped-external",
      provider: "github",
      operation: "pull-request.create",
      target: "repo/main",
      scopeKind: "run",
      scopeDigest: "e".repeat(64),
    });
    expect(base).toBe(
      digestApprovalCapability({
        actionClass: "scoped-external",
        provider: "github",
        operation: "pull-request.create",
        target: "repo/main",
        scopeKind: "run",
        scopeDigest: "e".repeat(64),
      })
    );
    const changed = digestApprovalCapability({
      actionClass: "scoped-external",
      provider: "github",
      operation: "pull-request.create",
      target: "repo/other",
      scopeKind: "run",
      scopeDigest: "e".repeat(64),
    });
    expect(changed).not.toBe(base);
  });

  it("digests the whole signed payload deterministically", () => {
    expect(digestApprovalProvenance(payload())).toBe(digestApprovalProvenance(payload()));
    expect(digestApprovalProvenance(payload())).not.toBe(
      digestApprovalProvenance(payload({ grantId: "grant-2" }))
    );
  });
});
