import { describe, expect, expectTypeOf, it } from "vitest";
import { projectPublicSessionRunState } from "@/lib/team-sessions/public-run-state";
import type {
  SessionDetailView,
  PublicSessionRunStateView,
  SessionResponsibility,
  SessionRunStateView,
} from "@/lib/team-sessions";
import type { TeamSessionRunState } from "@/types/team-session";

const SESSION_ID = "33333333-3333-4333-8333-333333333333";

describe("public Team Session Run state projection", () => {
  it("keeps the server and browser safe contracts structurally aligned", () => {
    expectTypeOf<PublicSessionRunStateView>().toEqualTypeOf<TeamSessionRunState>();
  });

  it("represents the no-Run state without advertising a gated mutation", () => {
    const projected = projectPublicSessionRunState(sessionFixture(["assignee"]), null);

    expect(projected).toMatchObject({
      sessionId: SESSION_ID,
      asOfSequence: 17,
      runStateRevision: 4,
      start: { available: false, reason: "run-mutations-unavailable" },
      currentRun: null,
      attentionRequests: [],
      approvalRequests: [],
      activeGrants: [],
      grantReviews: [],
    });
    expect(projected.capabilities).toEqual({
      startRun: false,
      reviseRunPolicy: false,
      pauseRun: false,
      resumeRun: false,
      stopRun: false,
      emergencyStopRun: false,
      editGoals: false,
      reviewGoalEvidence: false,
      resolveFinalReview: false,
      viewActionCenter: false,
      resolveAttention: false,
      resolveApprovals: false,
      revokeRunGrants: false,
      resolveGrantReviews: false,
    });

    const observer = projectPublicSessionRunState(sessionFixture([]), null);
    expect(observer.start).toEqual({ available: false, reason: "not-session-manager" });
    expect(observer.capabilities.startRun).toBe(false);
  });

  it("projects bounded goals, evidence and policy summaries without internal bindings or refs", () => {
    const internal = runFixture() as SessionRunStateView & Record<string, unknown>;
    internal.runtimeAssignmentId = "runtime-assignment-secret";
    internal.sandboxId = "sandbox-secret";
    internal.runtimePrincipalId = "runtime-principal-secret";
    internal.credentialRef = "one-password://production";
    const projected = projectPublicSessionRunState(
      sessionFixture(["assignee", "steerer"]),
      internal
    );

    expect(projected.currentRun).toMatchObject({
      agentRunId: "run-1",
      lifecycle: "active",
      stateVersion: 3,
      mode: "autonomous",
      completionPolicy: "continue-until-all-goals-achieved",
      runPolicyRevision: 2,
      goalSetRevision: 3,
      finalReviewVersion: 1,
      requiresPolicyRebind: false,
      attentionSummary: {
        openCount: 2,
        blockingCount: 1,
        independentAuthorizedWorkMayContinue: false,
      },
      policySummary: {
        limits: {
          wallClock: { kind: "capped", value: { milliseconds: 60_000 } },
          modelTokens: { kind: "unconfigured" },
        },
      },
      goals: [
        {
          goalId: "goal-1",
          evidenceTotalCount: 1,
          evidence: [
            {
              evidenceId: "evidence-1",
              status: "proposed",
              createdAtMs: 100,
            },
          ],
        },
      ],
    });
    expect(projected.start).toEqual({ available: false, reason: "mutable-run-exists" });
    expect(Object.values(projected.capabilities)).toEqual(
      Array(Object.keys(projected.capabilities).length).fill(false)
    );

    const serialized = JSON.stringify(projected);
    for (const forbidden of [
      "runtime-assignment-secret",
      "sandbox-secret",
      "runtime-principal-secret",
      "one-password://production",
      "artifact://private/provider-payload",
      "evidence-digest-private",
      "runtimeAssignmentGeneration",
      "sandboxGeneration",
      "runtimeAuthorizationGeneration",
      "credentialRef",
      "evidenceRef",
      "evidenceDigest",
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it("omits evidence that is not bound to the exact current Run, Goal Set, and Goal version", () => {
    const run = runFixture();
    const currentEvidence = run.goals[0]?.evidence[0];
    if (!currentEvidence) throw new Error("Expected evidence fixture");
    const projected = projectPublicSessionRunState(sessionFixture(["assignee"]), {
      ...run,
      goals: [
        {
          ...run.goals[0]!,
          evidence: [
            currentEvidence,
            { ...currentEvidence, evidenceId: "other-run", agentRunId: "run-2" },
            { ...currentEvidence, evidenceId: "old-set", goalSetRevision: 2 },
            { ...currentEvidence, evidenceId: "other-goal", goalId: "goal-2" },
            { ...currentEvidence, evidenceId: "old-version", goalVersion: 1 },
          ],
        },
      ],
    });

    expect(projected.currentRun?.goals[0]).toMatchObject({
      evidenceTotalCount: 1,
      evidence: [{ evidenceId: "evidence-1" }],
    });
  });

  it("fails closed on malformed policy data without interpolating the unsafe value", () => {
    const run = runFixture();
    const malformed = {
      ...run,
      limits: {
        ...run.limits,
        modelSpend: {
          kind: "capped",
          value: { currency: "private-key-material", minorUnits: 5 },
        },
      },
    } as SessionRunStateView;

    expect(() => projectPublicSessionRunState(sessionFixture(["assignee"]), malformed)).toThrow(
      "Invalid internal Currency"
    );
    try {
      projectPublicSessionRunState(sessionFixture(["assignee"]), malformed);
    } catch (error) {
      expect(String(error)).not.toContain("private-key-material");
    }
  });

  it("reports a stale policy binding without advertising kernel-only recovery actions", () => {
    const run = {
      ...runFixture(),
      lifecycle: "paused" as const,
      policyRuntimeBindingCurrent: false,
    };
    const projected = projectPublicSessionRunState(sessionFixture(["assignee"]), run);

    expect(projected.currentRun).toMatchObject({
      lifecycle: "paused",
      requiresPolicyRebind: true,
      sandboxState: "ready",
    });
    expect(Object.values(projected.capabilities).every((value) => value === false)).toBe(true);
  });
});

function sessionFixture(responsibilities: SessionResponsibility[]): SessionDetailView {
  const alice = {
    participantId: "participant-alice",
    userId: "alice",
    displayName: "Alice",
  };
  const manager = responsibilities.includes("assignee") || responsibilities.includes("supervisor");
  return {
    sessionId: SESSION_ID,
    teamId: "team-1",
    projectId: "project-1",
    name: "Checkout latency",
    status: "active",
    steeringPolicy: "shared",
    runtime: {
      kind: "local-tmux",
      isolation: "trusted-shared-host",
      yoloEligible: false,
      authorizationGeneration: 7,
      authorizationState: "enforced",
    },
    responsibilities: {
      ...(responsibilities.includes("assignee") ? { assignee: alice } : {}),
      supervisors: responsibilities.includes("supervisor") ? [alice] : [],
      steerers: responsibilities.includes("steerer") ? [alice] : [],
    },
    viewer: {
      ...alice,
      membershipRole: "member",
      responsibilities,
      basis: {
        participantVersion: 1,
        teamMembershipVersion: 1,
        projectAccessVersion: 1,
        responsibilityVersions: Object.fromEntries(
          responsibilities.map((responsibility) => [responsibility, 1])
        ),
        accessRevision: 2,
        assigneeRevision: 2,
        supervisionRevision: 1,
        steeringRevision: 3,
        controlRevision: 1,
        controlEpoch: 1,
        runtimeAuthorizationGeneration: 7,
        runStateRevision: 4,
        latestSequence: 17,
      },
      capabilities: {
        addComment: true,
        addSuggestion: true,
        resolveSuggestion: true,
        enqueueDirective: responsibilities.includes("steerer"),
        observeTerminal: true,
        mutateTerminal: false,
        createInvitation: manager,
        revokeInvitation: manager,
        manageShares: manager,
        manageParticipants: manager,
        manageSupervisors: manager,
        manageSteerers: manager,
        transferControl: manager,
        releaseControl: false,
        offerHandoff: manager,
        acceptHandoff: false,
        cancelHandoff: manager,
        claimAssignee: false,
      },
    },
    latestSequence: 17,
    createdAtMs: 50,
    participants: [],
    shares: [],
    openHandoffs: [],
  };
}

function runFixture(): SessionRunStateView {
  const unconfigured = { kind: "unconfigured" } as const;
  return {
    agentRunId: "run-1",
    lifecycle: "active",
    stateVersion: 3,
    pendingLifecycleOperation: null,
    attention: {
      openRequestIds: ["attention-1", "attention-2"],
      blockingRequestIds: ["attention-1"],
      independentAuthorizedWorkMayContinue: false,
    },
    limitStatus: "within-configured-limits",
    sandboxState: "ready",
    finalReviewState: "not-ready",
    mode: "autonomous",
    runPolicyRevision: 2,
    goalSetRevision: 3,
    finalReviewVersion: 1,
    policyRuntimeBindingCurrent: true,
    limits: {
      wallClock: { kind: "capped", value: { milliseconds: 60_000 } },
      modelTokens: unconfigured,
      modelSpend: { kind: "capped", value: { currency: "USD", minorUnits: 1_500 } },
      outboundBytes: unconfigured,
      actionCounts: {
        local: unconfigured,
        "scoped-external": { kind: "capped", value: 10 },
        protected: { kind: "capped", value: 0 },
        forbidden: { kind: "capped", value: 0 },
      },
    },
    runtimeAssignmentGeneration: 9,
    sandboxGeneration: 12,
    runtimeAuthorizationGeneration: 7,
    completionPolicy: "continue-until-all-goals-achieved",
    goals: [
      {
        goalId: "goal-1",
        position: 1,
        title: "Find the bottleneck",
        acceptanceCriteria: ["A trace identifies the slow span"],
        dependencyGoalIds: [],
        version: 2,
        status: "in-progress",
        evidence: [
          {
            evidenceId: "evidence-1",
            agentRunId: "run-1",
            goalSetRevision: 3,
            goalId: "goal-1",
            goalVersion: 2,
            evidenceRef: "artifact://private/provider-payload",
            evidenceDigest: "evidence-digest-private",
            status: "proposed",
            createdAtMs: 100,
          },
        ],
      },
    ],
  };
}
