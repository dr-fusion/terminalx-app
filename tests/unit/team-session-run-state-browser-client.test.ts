import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fetchTeamSessionRunState,
  parseTeamSessionRunState,
} from "@/lib/team-sessions/browser-client";

const SESSION_ID = "33333333-3333-4333-8333-333333333333";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Team Session Run state browser boundary", () => {
  it("fetches the no-store Run state endpoint and accepts currentRun null", async () => {
    const fixture = noRunFixture();
    const fetchMock = vi.fn(async () => Response.json({ runState: fixture }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchTeamSessionRunState(SESSION_ID)).resolves.toEqual(fixture);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/team-sessions/sessions/${SESSION_ID}/run-state`,
      expect.objectContaining({
        method: "GET",
        cache: "no-store",
        credentials: "same-origin",
      })
    );
  });

  it("strictly parses bounded safe Run, Goal, and evidence state", () => {
    const fixture = activeRunFixture();
    expect(parseTeamSessionRunState(fixture, SESSION_ID)).toEqual(fixture);
  });

  it.each([
    [
      "Runtime assignment",
      (fixture: ReturnType<typeof activeRunFixture>) => {
        Object.assign(fixture.currentRun!, { runtimeAssignmentId: "runtime-private" });
      },
    ],
    [
      "Sandbox id",
      (fixture: ReturnType<typeof activeRunFixture>) => {
        Object.assign(fixture.currentRun!, { sandboxId: "sandbox-private" });
      },
    ],
    [
      "raw artifact reference",
      (fixture: ReturnType<typeof activeRunFixture>) => {
        Object.assign(fixture.currentRun!.goals[0]!.evidence[0]!, {
          artifactRef: "artifact://provider/private",
        });
      },
    ],
  ])("rejects an unexpected %s field at any depth", (_label, mutate) => {
    const fixture = activeRunFixture();
    mutate(fixture);
    expect(() => parseTeamSessionRunState(fixture, SESSION_ID)).toThrowError(
      expect.objectContaining({ code: "invalid-response" })
    );
  });

  it.each(["attentionRequests", "approvalRequests", "activeGrants", "grantReviews"] as const)(
    "rejects gated %s cards before parsing them",
    (field) => {
      const fixture = activeRunFixture();
      fixture[field] = [{ privateProviderPayload: "must-not-cross-the-boundary" }] as never;
      expect(() => parseTeamSessionRunState(fixture, SESSION_ID)).toThrowError(
        expect.objectContaining({ code: "invalid-response" })
      );
    }
  );

  it("rejects browser actions while Run mutations remain release-gated", () => {
    const advertisedCapability = activeRunFixture();
    advertisedCapability.capabilities.pauseRun = true;
    expect(() => parseTeamSessionRunState(advertisedCapability, SESSION_ID)).toThrowError(
      expect.objectContaining({ code: "invalid-response" })
    );

    const advertisedStart = noRunFixture();
    advertisedStart.capabilities.startRun = true;
    (advertisedStart.start as { available: boolean }).available = true;
    (advertisedStart.start as { reason: string }).reason = "available";
    expect(() => parseTeamSessionRunState(advertisedStart, SESSION_ID)).toThrowError(
      expect.objectContaining({ code: "invalid-response" })
    );
  });

  it("rejects oversized Goal Sets", () => {
    const tooManyGoals = activeRunFixture();
    tooManyGoals.currentRun!.goals = Array.from(
      { length: 101 },
      () => tooManyGoals.currentRun!.goals[0]!
    );
    expect(() => parseTeamSessionRunState(tooManyGoals, SESSION_ID)).toThrowError(
      expect.objectContaining({ code: "invalid-response" })
    );
  });

  it("requires meaningful Goals", () => {
    const noGoals = activeRunFixture();
    noGoals.currentRun!.goals = [];
    expect(() => parseTeamSessionRunState(noGoals, SESSION_ID)).toThrowError(
      expect.objectContaining({ code: "invalid-response" })
    );

    const noCriteria = activeRunFixture();
    noCriteria.currentRun!.goals[0]!.acceptanceCriteria = [];
    expect(() => parseTeamSessionRunState(noCriteria, SESSION_ID)).toThrowError(
      expect.objectContaining({ code: "invalid-response" })
    );
  });
});

function noRunFixture() {
  return {
    sessionId: SESSION_ID,
    asOfSequence: 12,
    runStateRevision: 3,
    capabilities: {
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
    },
    start: { available: false, reason: "run-mutations-unavailable" as const },
    currentRun: null,
    attentionRequests: [],
    approvalRequests: [],
    activeGrants: [],
    grantReviews: [],
  };
}

function activeRunFixture() {
  const fixture = noRunFixture();
  return {
    ...fixture,
    capabilities: { ...fixture.capabilities },
    start: { available: false, reason: "mutable-run-exists" as const },
    currentRun: {
      agentRunId: "run-1",
      lifecycle: "active" as const,
      stateVersion: 2,
      mode: "autonomous" as const,
      completionPolicy: "continue-until-all-goals-achieved" as const,
      runPolicyRevision: 2,
      goalSetRevision: 2,
      finalReviewVersion: 1,
      finalReviewState: "not-ready" as const,
      requiresPolicyRebind: false,
      sandboxState: "ready" as const,
      limitStatus: "warning-75-percent" as const,
      attentionSummary: {
        openCount: 1,
        blockingCount: 1,
        independentAuthorizedWorkMayContinue: false,
      },
      policySummary: {
        mode: "autonomous" as const,
        completionPolicy: "continue-until-all-goals-achieved" as const,
        limits: {
          wallClock: { kind: "capped" as const, value: { milliseconds: 60_000 } },
          modelTokens: { kind: "unconfigured" as const },
          modelSpend: {
            kind: "capped" as const,
            value: { currency: "USD", minorUnits: 2_500 },
          },
          outboundBytes: { kind: "unconfigured" as const },
          actionCounts: {
            local: { kind: "unconfigured" as const },
            "scoped-external": { kind: "capped" as const, value: 10 },
            protected: { kind: "capped" as const, value: 1 },
            forbidden: { kind: "capped" as const, value: 0 },
          },
        },
      },
      goals: [
        {
          goalId: "goal-1",
          position: 1,
          title: "Find the bottleneck",
          acceptanceCriteria: ["A trace identifies the slow span"],
          dependencyGoalIds: [],
          version: 2,
          status: "in-progress" as const,
          evidenceTotalCount: 1,
          evidence: [
            {
              evidenceId: "evidence-1",
              status: "proposed" as const,
              createdAtMs: 100,
            },
          ],
        },
      ],
    },
  };
}
