import { describe, expect, it } from "vitest";
import {
  isPendingTeamSessionAdmission,
  parseRedeemedTeamSessionInvitation,
  teamSessionJoinPath,
} from "@/components/team-sessions/invitation-join";
import type { TeamSessionCommandResult } from "@/types/team-session";
import { HttpError } from "@/lib/team-sessions/browser-client";

function result(data: Record<string, unknown>): TeamSessionCommandResult {
  return {
    accepted: true,
    commandType: "session.invitation.redeem",
    replayed: false,
    data,
    events: [],
  };
}

describe("team Session invitation join", () => {
  it("keeps only the non-secret admission receipt needed after redemption", () => {
    const invitation = parseRedeemedTeamSessionInvitation(
      result({
        invitationId: "invitation-1",
        sessionId: "session-1",
        membershipRole: "guest",
        teamId: "team-1",
        participantGranted: false,
      })
    );

    expect(invitation).toEqual({
      invitationId: "invitation-1",
      sessionId: "session-1",
      membershipRole: "guest",
    });
    expect(teamSessionJoinPath(invitation)).toBe(
      "/team-sessions/join?sessionId=session-1&invitationId=invitation-1"
    );
  });

  it("rejects incomplete and mismatched receipts", () => {
    expect(() => parseRedeemedTeamSessionInvitation(result({ sessionId: "session-1" }))).toThrow(
      "incomplete invitation receipt"
    );
    expect(() =>
      parseRedeemedTeamSessionInvitation({
        ...result({
          invitationId: "invitation-1",
          sessionId: "session-1",
          membershipRole: "member",
        }),
        commandType: "session.join",
      })
    ).toThrow("wrong invitation receipt");
  });

  it("treats the non-enumerating authorization response as pending admission", () => {
    expect(
      isPendingTeamSessionAdmission(
        new HttpError(404, "resource-unavailable", "Resource is unavailable")
      )
    ).toBe(true);
    expect(isPendingTeamSessionAdmission(new HttpError(409, "state-conflict", "Conflict"))).toBe(
      false
    );
  });
});
