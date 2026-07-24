import { describe, expect, it } from "vitest";
import { shouldRefreshTeamSessionAdmission } from "@/components/team-sessions/admission-refresh";
import type { TeamSessionEvent } from "@/types/team-session";

describe("Team Session admission refresh signal", () => {
  it("refreshes from anonymous public admission activity without inspecting private data", () => {
    expect(
      shouldRefreshTeamSessionAdmission(
        [event(4, "comment.added"), event(5, "session.activity")],
        4
      )
    ).toBe(true);
    expect(shouldRefreshTeamSessionAdmission([event(5, "session.activity")], 5)).toBe(false);
  });

  it("ignores new conversation events but refreshes after a public Participant transition", () => {
    expect(shouldRefreshTeamSessionAdmission([event(6, "suggestion.added")], 5)).toBe(false);
    expect(shouldRefreshTeamSessionAdmission([event(6, "session.participant.joined")], 5)).toBe(
      true
    );
  });
});

function event(sequence: number, type: string): TeamSessionEvent {
  return {
    schemaVersion: 1,
    eventId: `event-${sequence}`,
    sessionId: "session-1",
    sequence,
    type,
    occurredAtMs: 1_000 + sequence,
    actor: { kind: "system", userId: "session-system", displayName: "Session system" },
    sourceAdapter: "internal",
    payload: {},
  };
}
