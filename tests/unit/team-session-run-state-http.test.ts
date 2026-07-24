import { describe, expect, it, vi } from "vitest";
import type { RequestActor } from "@/lib/request-actor";
import type { PublicSessionRunStateView, TeamSessions } from "@/lib/team-sessions";
import { handleSessionRunState, type TeamSessionHttpDependencies } from "@/lib/team-sessions/http";

const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ALICE: RequestActor = {
  kind: "human",
  userId: "alice",
  username: "alice",
  displayName: "Alice",
  legacyRole: "user",
};

describe("Team Session Run state HTTP adapter", () => {
  it("returns a private no-store actor-scoped projection", async () => {
    const inspect = vi.fn(async (query: { type: string; actor: unknown }) => {
      if (query.type === "session.public-run-state") return runStateFixture();
      throw new Error("Unexpected query");
    });
    const response = await handleSessionRunState(getRequest(), SESSION_ID, {
      teamSessions: { inspect } as unknown as TeamSessions,
      resolveActor: async () => ALICE,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    expect(response.headers.get("vary")).toBe("Cookie, Authorization");
    expect(await response.json()).toEqual({
      runState: expect.objectContaining({
        sessionId: SESSION_ID,
        asOfSequence: 12,
        runStateRevision: 3,
        start: { available: false, reason: "run-mutations-unavailable" },
        currentRun: null,
        attentionRequests: [],
        approvalRequests: [],
        activeGrants: [],
        grantReviews: [],
      }),
    });
    expect(inspect).toHaveBeenCalledTimes(1);
    expect(inspect).toHaveBeenCalledWith({
      schemaVersion: 1,
      type: "session.public-run-state",
      actor: { kind: "human", userId: ALICE.userId, displayName: ALICE.displayName },
      sessionId: SESSION_ID,
    });
  });

  it("uses the same unavailable response for missing or unauthorized Sessions", async () => {
    const inspect = vi.fn(async () => null);
    const response = await handleSessionRunState(getRequest(), SESSION_ID, {
      teamSessions: { inspect } as unknown as TeamSessions,
      resolveActor: async () => ALICE,
    });

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      error: { code: "resource-unavailable", message: "Resource is unavailable" },
    });
    expect(inspect).toHaveBeenCalledTimes(1);
  });

  it("requires a freshly verified actor", async () => {
    const inspect = vi.fn();
    const dependencies: TeamSessionHttpDependencies = {
      teamSessions: { inspect } as unknown as TeamSessions,
      resolveActor: async () => null,
    };
    const response = await handleSessionRunState(getRequest(), SESSION_ID, dependencies);

    expect(response.status).toBe(401);
    expect(inspect).not.toHaveBeenCalled();
  });
});

function getRequest(): Request {
  return new Request(`https://terminalx.test/api/team-sessions/sessions/${SESSION_ID}/run-state`, {
    method: "GET",
  });
}

function runStateFixture(): PublicSessionRunStateView {
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
    start: { available: false, reason: "run-mutations-unavailable" },
    currentRun: null,
    attentionRequests: [],
    approvalRequests: [],
    activeGrants: [],
    grantReviews: [],
  };
}
