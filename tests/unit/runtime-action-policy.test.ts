import { describe, expect, it } from "vitest";
import {
  ACTION_MANIFEST_CANONICALIZATION_PROFILE,
  applyRuntimeReclassification,
  canonicalizeActionManifest,
  classifyAction,
  digestActionManifest,
  matchesV1RunGrant,
  verifyActionManifestDigest,
  type ActionClassificationInput,
  type ActionManifest,
  type BoundedRunTarget,
  type RuntimeActionCandidate,
  type V1RunGrant,
} from "@/lib/runtime/action-policy";

const SESSION_ID = "session-one";
const RUN_ID = "run-one";
const SHA256_A = "a".repeat(64);
const SHA256_B = "b".repeat(64);

function manifest(overrides: Partial<ActionManifest> = {}): ActionManifest {
  return {
    version: 1,
    manifestId: "manifest-one",
    actionClass: "scoped-external",
    provider: "github",
    operation: "git.push",
    exactTarget: { branch: "terminalx/session-one", repositoryId: "repo-one" },
    actionSchema: {
      schemaId: "terminalx.git.push",
      schemaVersion: 1,
      schemaDigest: SHA256_A,
      canonicalizationProfile: ACTION_MANIFEST_CANONICALIZATION_PROFILE,
      unknownFields: "reject",
    },
    canonicalEffectInputDigest: SHA256_B,
    effectIdempotencyKey: "effect-one",
    commitSha: "1a2b3c4d",
    expectedEffect: { remoteRef: "refs/heads/terminalx/session-one" },
    expiresAtMs: 2_000_000_000_000,
    ...overrides,
  };
}

function policy(overrides: Partial<ActionClassificationInput> = {}): ActionClassificationInput {
  return {
    sessionId: SESSION_ID,
    targetSessionId: SESSION_ID,
    executionBoundary: "sandbox",
    effectScope: "external",
    targetProtection: "unprotected",
    secretHandling: "none",
    killSwitch: "preserve",
    audit: "preserve",
    operation: "git.push",
    ...overrides,
  };
}

function grant(
  eligibleUse: V1RunGrant["scope"]["eligibleUse"],
  targetPattern: BoundedRunTarget,
  overrides: Partial<V1RunGrant["scope"]> = {}
): V1RunGrant {
  return {
    version: 1,
    sessionId: SESSION_ID,
    runId: RUN_ID,
    scope: {
      kind: "run",
      actionClass: "scoped-external",
      provider: "github",
      operation: "git.push",
      eligibleUse,
      targetPattern,
      ...overrides,
    },
  };
}

function candidate(
  exactTarget: BoundedRunTarget,
  overrides: Partial<RuntimeActionCandidate> = {}
): RuntimeActionCandidate {
  return {
    sessionId: SESSION_ID,
    runId: RUN_ID,
    actionClass: "scoped-external",
    provider: "github",
    operation: "git.push",
    exactTarget,
    policy: policy(),
    ...overrides,
  };
}

describe("runtime action policy", () => {
  it("serializes a manifest canonically and hashes exactly those bytes", () => {
    const first = manifest({
      exactTarget: { repositoryId: "repo-one", nested: { z: 2, a: 1 }, branch: "tx/one" },
      expectedEffect: { updated: true, refs: ["b", "a"] },
    });
    const reordered = manifest({
      exactTarget: { branch: "tx/one", nested: { a: 1, z: 2 }, repositoryId: "repo-one" },
      expectedEffect: { refs: ["b", "a"], updated: true },
      digest: "f".repeat(64),
    });

    const canonical = canonicalizeActionManifest(first);
    expect(canonicalizeActionManifest(reordered)).toBe(canonical);
    expect(canonical).not.toContain('"digest"');
    expect(digestActionManifest(first)).toMatch(/^[a-f0-9]{64}$/);
    expect(digestActionManifest(reordered)).toBe(digestActionManifest(first));
    expect(verifyActionManifestDigest({ ...first, digest: digestActionManifest(first) })).toBe(
      true
    );
    expect(verifyActionManifestDigest({ ...first, digest: "0".repeat(64) })).toBe(false);
    expect(verifyActionManifestDigest({ ...first, digest: "malformed" })).toBe(false);
    expect(digestActionManifest(manifest())).toBe(
      "11aa2bd0e83103b68ef35b249484a96fcd016998ad05eefbfe2d1efaf9d79fad"
    );
  });

  it("rejects ambiguous or unbound manifest input instead of hashing it", () => {
    expect(() =>
      canonicalizeActionManifest({ ...manifest(), extra: "not-digested" } as ActionManifest)
    ).toThrowError(expect.objectContaining({ code: "invalid-manifest" }));
    expect(() =>
      canonicalizeActionManifest({
        ...manifest(),
        expectedEffect: { value: Number.NaN },
      })
    ).toThrowError(expect.objectContaining({ code: "invalid-manifest" }));
    expect(() =>
      canonicalizeActionManifest({
        ...manifest(),
        actionSchema: { ...manifest().actionSchema, unknownFields: "allow" as "reject" },
      })
    ).toThrowError(expect.objectContaining({ code: "invalid-manifest" }));
  });

  it("bounds manifest depth, nodes, collections, strings, and total canonical bytes", () => {
    let tooDeep: unknown = "leaf";
    for (let depth = 0; depth < 18; depth += 1) tooDeep = { nested: tooDeep };

    const tooManyNodes: Record<string, unknown> = {};
    for (let index = 0; index < 900; index += 1) {
      tooManyNodes[`entry-${index}`] = [1, 2, 3, 4];
    }

    const invalidValues = [
      tooDeep,
      tooManyNodes,
      Array.from({ length: 1_025 }, (_, index) => index),
      "x".repeat(16 * 1_024 + 1),
      Array.from({ length: 32 }, () => "x".repeat(10_000)),
    ];
    for (const exactTarget of invalidValues) {
      expect(() => canonicalizeActionManifest(manifest({ exactTarget }))).toThrowError(
        expect.objectContaining({ code: "invalid-manifest" })
      );
    }
    expect(() =>
      canonicalizeActionManifest(
        manifest({ expectedEffect: { summary: "x".repeat(16 * 1_024 + 1) } })
      )
    ).toThrowError(expect.objectContaining({ code: "invalid-manifest" }));
  });

  it("rejects accessor-backed canonical data without invoking the accessor", () => {
    let accessorReads = 0;
    const exactTarget = { repositoryId: "repo-one" };
    Object.defineProperty(exactTarget, "branch", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return "terminalx/session-one";
      },
    });

    expect(() => canonicalizeActionManifest(manifest({ exactTarget }))).toThrowError(
      expect.objectContaining({ code: "invalid-manifest" })
    );
    expect(accessorReads).toBe(0);
  });

  it("classifies local, scoped external, protected and production effects", () => {
    expect(classifyAction(policy({ effectScope: "local" }))).toBe("local");
    expect(classifyAction(policy())).toBe("scoped-external");
    expect(classifyAction(policy({ targetProtection: "protected" }))).toBe("protected");
    expect(classifyAction(policy({ targetProtection: "production" }))).toBe("protected");
  });

  it.each([
    ["host", policy({ executionBoundary: "host" })],
    ["control plane", policy({ executionBoundary: "control-plane" })],
    ["cross-session", policy({ targetSessionId: "session-two" })],
    ["secret reveal", policy({ secretHandling: "reveal" })],
    ["kill switch disable", policy({ killSwitch: "disable" })],
    ["audit disable", policy({ audit: "disable" })],
    ["forbidden operation", policy({ operation: "runtime.kill-switch.disable" })],
  ])("forbids %s actions", (_label, input) => {
    expect(classifyAction(input)).toBe("forbidden");
  });

  it("allows runtime classification to stay equal or become stricter, never weaker", () => {
    expect(applyRuntimeReclassification("local", "local")).toBe("local");
    expect(applyRuntimeReclassification("local", "scoped-external")).toBe("scoped-external");
    expect(applyRuntimeReclassification("protected", "forbidden")).toBe("forbidden");
    expect(() => applyRuntimeReclassification("protected", "scoped-external")).toThrowError(
      expect.objectContaining({ code: "classification-downgrade" })
    );
  });

  it("fails closed on unknown and accessor-backed classification facts", () => {
    expect(classifyAction({ ...policy(), unexpected: true } as ActionClassificationInput)).toBe(
      "forbidden"
    );

    let accessorReads = 0;
    const accessorPolicy = { ...policy() };
    Object.defineProperty(accessorPolicy, "operation", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return "git.push";
      },
    });
    expect(classifyAction(accessorPolicy)).toBe("forbidden");
    expect(accessorReads).toBe(0);
  });

  it("bounds a push grant to this Session's exact branch", () => {
    const target = {
      kind: "session-branch",
      repositoryId: "repo-one",
      branch: "terminalx/session-one",
      owningSessionId: SESSION_ID,
    } as const;
    const runGrant = grant("session_branch_push", target);

    expect(matchesV1RunGrant(runGrant, candidate(target))).toBe(true);
    expect(matchesV1RunGrant(runGrant, candidate({ ...target, branch: "main" }))).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, candidate({ ...target, owningSessionId: "session-two" }))
    ).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, candidate({ ...target, unexpected: true } as BoundedRunTarget))
    ).toBe(false);
  });

  it("bounds a grant to updates on the same draft pull request", () => {
    const target = {
      kind: "draft-pull-request",
      repositoryId: "repo-one",
      pullRequestId: "pr-42",
      sourceSessionId: SESSION_ID,
      draft: true,
    } as const;
    const runGrant = grant("draft_pull_request_update", target, {
      operation: "pull-request.update-draft",
    });
    const action = candidate(target, {
      operation: "pull-request.update-draft",
      policy: policy({ operation: "pull-request.update-draft" }),
    });

    expect(matchesV1RunGrant(runGrant, action)).toBe(true);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        exactTarget: { ...target, pullRequestId: "pr-43" },
      })
    ).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        exactTarget: { ...target, unexpected: true } as BoundedRunTarget,
      })
    ).toBe(false);
  });

  it("bounds a grant to one named ephemeral preview", () => {
    const target = {
      kind: "ephemeral-preview",
      projectId: "project-one",
      previewName: "session-one-preview",
      owningSessionId: SESSION_ID,
      ephemeral: true,
      production: false,
    } as const;
    const runGrant = grant("ephemeral_preview_update", target, {
      provider: "vercel",
      operation: "preview.update",
    });
    const action = candidate(target, {
      provider: "vercel",
      operation: "preview.update",
      policy: policy({ operation: "preview.update" }),
    });

    expect(matchesV1RunGrant(runGrant, action)).toBe(true);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        exactTarget: { ...target, previewName: "another-preview" },
      })
    ).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        exactTarget: { ...target, unexpected: true } as BoundedRunTarget,
      })
    ).toBe(false);
  });

  it("requires the same credential and exact non-production target", () => {
    const target = {
      kind: "nonproduction-target",
      targetId: "staging-cluster-one",
      environment: "staging",
      production: false,
    } as const;
    const runGrant = grant("same_credential_nonproduction_target", target, {
      provider: "cloud-provider",
      operation: "deployment.update",
      credentialRef: "op://engineering/staging/deployer",
    });
    const action = candidate(target, {
      provider: "cloud-provider",
      operation: "deployment.update",
      credentialRef: "op://engineering/staging/deployer",
      policy: policy({ secretHandling: "reference", operation: "deployment.update" }),
    });

    expect(matchesV1RunGrant(runGrant, action)).toBe(true);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        credentialRef: "op://engineering/production/deployer",
      })
    ).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        exactTarget: { ...target, targetId: "production-cluster" },
        policy: policy({ targetProtection: "production" }),
      })
    ).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        exactTarget: { ...target, unexpected: true } as BoundedRunTarget,
      })
    ).toBe(false);
  });

  it("never extends a v1 run grant to a protected action", () => {
    const target = {
      kind: "session-branch",
      repositoryId: "repo-one",
      branch: "terminalx/session-one",
      owningSessionId: SESSION_ID,
    } as const;
    const scopedGrant = grant("session_branch_push", target);
    const protectedGrant = grant("session_branch_push", target, {
      actionClass: "protected" as "scoped-external",
    });
    const protectedAction = candidate(target, {
      actionClass: "protected",
      policy: policy({ targetProtection: "protected" }),
    });

    expect(matchesV1RunGrant(protectedGrant, protectedAction)).toBe(false);
    expect(matchesV1RunGrant(scopedGrant, protectedAction)).toBe(false);
    expect(matchesV1RunGrant(protectedGrant, candidate(target, { actionClass: "protected" }))).toBe(
      false
    );
  });

  it("binds trusted classification facts to the action's exact operation", () => {
    const target = {
      kind: "session-branch",
      repositoryId: "repo-one",
      branch: "terminalx/session-one",
      owningSessionId: SESSION_ID,
    } as const;
    const runGrant = grant("session_branch_push", target);

    expect(
      matchesV1RunGrant(runGrant, candidate(target, { policy: policy({ operation: "git.fetch" }) }))
    ).toBe(false);
  });

  it("fails closed on unknown or accessor-backed grant and action fields", () => {
    const target = {
      kind: "session-branch",
      repositoryId: "repo-one",
      branch: "terminalx/session-one",
      owningSessionId: SESSION_ID,
    } as const;
    const runGrant = grant("session_branch_push", target);
    const action = candidate(target);

    expect(matchesV1RunGrant({ ...runGrant, unexpected: true } as V1RunGrant, action)).toBe(false);
    expect(
      matchesV1RunGrant(
        { ...runGrant, scope: { ...runGrant.scope, unexpected: true } } as V1RunGrant,
        action
      )
    ).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        unexpected: true,
      } as RuntimeActionCandidate)
    ).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        policy: { ...action.policy, unexpected: true } as ActionClassificationInput,
      })
    ).toBe(false);

    const hiddenAction = { ...action };
    Object.defineProperty(hiddenAction, "unexpected", { value: true, enumerable: false });
    expect(matchesV1RunGrant(runGrant, hiddenAction)).toBe(false);

    let accessorReads = 0;
    const accessorGrant = { ...runGrant };
    Object.defineProperty(accessorGrant, "runId", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return RUN_ID;
      },
    });
    expect(matchesV1RunGrant(accessorGrant, action)).toBe(false);

    const accessorAction = { ...action };
    Object.defineProperty(accessorAction, "operation", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return "git.push";
      },
    });
    expect(matchesV1RunGrant(runGrant, accessorAction)).toBe(false);

    const accessorTarget = { ...target };
    Object.defineProperty(accessorTarget, "branch", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return target.branch;
      },
    });
    expect(matchesV1RunGrant(runGrant, candidate(accessorTarget as BoundedRunTarget))).toBe(false);
    expect(accessorReads).toBe(0);
  });

  it("never lets a run grant cross its run, Session, class, or forbidden policy", () => {
    const target = {
      kind: "session-branch",
      repositoryId: "repo-one",
      branch: "terminalx/session-one",
      owningSessionId: SESSION_ID,
    } as const;
    const runGrant = grant("session_branch_push", target);
    const action = candidate(target);

    expect(matchesV1RunGrant(runGrant, { ...action, runId: "run-two" })).toBe(false);
    expect(matchesV1RunGrant(runGrant, { ...action, sessionId: "session-two" })).toBe(false);
    expect(matchesV1RunGrant(runGrant, { ...action, actionClass: "protected" })).toBe(false);
    expect(
      matchesV1RunGrant(runGrant, {
        ...action,
        policy: policy({ audit: "disable" }),
      })
    ).toBe(false);
  });
});
