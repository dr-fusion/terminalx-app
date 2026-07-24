import { describe, expect, it } from "vitest";
import type { GoalDefinition, RunPolicyDraft } from "@/lib/team-sessions/contracts";
import {
  assertValidRunPolicyCommit,
  digestRunPolicyDraft,
  isRunPolicyWidening,
  validateInitialGoals,
} from "@/lib/team-sessions/run-policy";

const unconfigured = { kind: "unconfigured" } as const;

function policy(overrides: Partial<RunPolicyDraft> = {}): RunPolicyDraft {
  return {
    mode: "autonomous",
    completionPolicy: { kind: "continue-until-all-goals-achieved" },
    scopedExternalPolicyRef: "project-policy:1",
    limits: {
      wallClock: unconfigured,
      modelTokens: unconfigured,
      modelSpend: unconfigured,
      outboundBytes: unconfigured,
      actionCounts: {
        local: unconfigured,
        "scoped-external": unconfigured,
        protected: unconfigured,
        forbidden: unconfigured,
      },
    },
    ...overrides,
  };
}

const context = {
  sessionName: "Investigate checkout latency",
  yoloEligible: false,
  projectCeilingRevision: "ceiling:1",
  runtimeAssignmentGeneration: 1,
  sandboxId: "sandbox:1",
  sandboxGeneration: 1,
  runtimeAuthorizationGeneration: 1,
} as const;

function commit(runPolicy: RunPolicyDraft = policy()) {
  return {
    policy: runPolicy,
    policyDigest: digestRunPolicyDraft(runPolicy),
    expectedProjectCeilingRevision: context.projectCeilingRevision,
    expectedRuntimeAssignmentGeneration: context.runtimeAssignmentGeneration,
    expectedSandboxGeneration: context.sandboxGeneration,
    expectedRuntimeAuthorizationGeneration: context.runtimeAuthorizationGeneration,
  };
}

describe("Team Session Run policy", () => {
  it("accepts explicit unconfigured user caps without treating them as infinite resources", () => {
    expect(() => assertValidRunPolicyCommit(commit(), context)).not.toThrow();
  });

  it("rejects a digest mismatch and every stale generation fence", () => {
    expect(() =>
      assertValidRunPolicyCommit({ ...commit(), policyDigest: "0".repeat(64) }, context)
    ).toThrow(/digest/);
    expect(() =>
      assertValidRunPolicyCommit(
        { ...commit(), expectedRuntimeAuthorizationGeneration: 2 },
        context
      )
    ).toThrow(/Authorization/);
  });

  it("requires every committed policy field and rejects unknown input", () => {
    const missingFence = { ...commit() } as Record<string, unknown>;
    delete missingFence.expectedSandboxGeneration;
    expect(() =>
      assertValidRunPolicyCommit(missingFence as unknown as ReturnType<typeof commit>, context)
    ).toThrow(/missing expectedSandboxGeneration/);

    expect(() => digestRunPolicyDraft({ ...policy(), unexpected: true } as RunPolicyDraft)).toThrow(
      /unknown field/
    );

    const missingLimit = { ...policy().limits } as Record<string, unknown>;
    delete missingLimit.outboundBytes;
    expect(() =>
      digestRunPolicyDraft(policy({ limits: missingLimit as unknown as RunPolicyDraft["limits"] }))
    ).toThrow(/missing outboundBytes/);
  });

  it("keeps continue-until-all-goals-achieved out of supervised mode", () => {
    const supervised = policy({ mode: "supervised" });
    expect(() => digestRunPolicyDraft(supervised)).toThrow(/Supervised/);
  });

  it("rejects YOLO on a trusted-host Runtime even with a well-shaped confirmation", () => {
    const yolo = policy({ mode: "yolo" });
    expect(() =>
      assertValidRunPolicyCommit(
        {
          ...commit(yolo),
          yoloConfirmation: {
            challengeId: "challenge:1",
            challengeVersion: 1,
            policyDigest: digestRunPolicyDraft(yolo),
            warningDigest: "1".repeat(64),
            sessionNameRevision: 1,
            typedSessionName: context.sessionName,
            projectCeilingRevision: context.projectCeilingRevision,
            sourceRevision: "source:1",
            sandboxId: context.sandboxId,
            sandboxGeneration: context.sandboxGeneration,
            sandboxProfileDigest: "2".repeat(64),
            runtimeAssignmentGeneration: context.runtimeAssignmentGeneration,
            runtimeAuthorizationGeneration: context.runtimeAuthorizationGeneration,
            credentialPolicyDigest: "3".repeat(64),
            networkPolicyDigest: "4".repeat(64),
            limitsDigest: "5".repeat(64),
          },
        },
        context
      )
    ).toThrow(/not eligible/);
  });

  it("validates ordered, unique, acyclic goals with explicit acceptance criteria", () => {
    const goals: GoalDefinition[] = [
      {
        goalId: "goal:diagnose",
        position: 1,
        title: "Find the bottleneck",
        acceptanceCriteria: ["A trace identifies the slow span"],
        dependencyGoalIds: [],
      },
      {
        goalId: "goal:fix",
        position: 2,
        title: "Apply the bounded fix",
        acceptanceCriteria: ["Focused tests pass"],
        dependencyGoalIds: ["goal:diagnose"],
      },
    ];
    expect(() => validateInitialGoals(goals)).not.toThrow();
    expect(() =>
      validateInitialGoals([{ ...goals[0]!, dependencyGoalIds: ["goal:fix"] }, goals[1]!])
    ).toThrow(/cycle/);
  });

  it("classifies higher modes, removed caps, and external-policy changes as widening", () => {
    const capped = policy({
      mode: "supervised",
      completionPolicy: { kind: "stop-after-directed-work" },
      limits: {
        ...policy().limits,
        modelTokens: { kind: "capped", value: 10_000 },
      },
    });
    expect(isRunPolicyWidening(capped, policy())).toBe(true);
    expect(
      isRunPolicyWidening(policy(), policy({ scopedExternalPolicyRef: "project-policy:2" }))
    ).toBe(true);
    expect(
      isRunPolicyWidening(
        policy({ limits: { ...policy().limits, modelTokens: { kind: "capped", value: 10_000 } } }),
        policy({ limits: { ...policy().limits, modelTokens: { kind: "capped", value: 5_000 } } })
      )
    ).toBe(false);
  });
});
