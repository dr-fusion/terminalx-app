import type { TeamSessionCommandResult } from "@/types/team-session";
import { HttpError } from "@/lib/team-sessions/browser-client";

export interface RedeemedTeamSessionInvitation {
  invitationId: string;
  sessionId: string;
  membershipRole: "member" | "guest";
}

export function parseRedeemedTeamSessionInvitation(
  result: TeamSessionCommandResult
): RedeemedTeamSessionInvitation {
  if (result.commandType !== "session.invitation.redeem") {
    throw new Error("Server returned the wrong invitation receipt");
  }
  const { invitationId, sessionId, membershipRole } = result.data;
  if (
    typeof invitationId !== "string" ||
    invitationId.length === 0 ||
    typeof sessionId !== "string" ||
    sessionId.length === 0 ||
    (membershipRole !== "member" && membershipRole !== "guest")
  ) {
    throw new Error("Server returned an incomplete invitation receipt");
  }
  return { invitationId, sessionId, membershipRole };
}

export function teamSessionJoinPath(
  invitation: Pick<RedeemedTeamSessionInvitation, "sessionId" | "invitationId">
): string {
  const query = new URLSearchParams({
    sessionId: invitation.sessionId,
    invitationId: invitation.invitationId,
  });
  return `/team-sessions/join?${query.toString()}`;
}

/** Session authorization is deliberately non-enumerating, so pending access is a 404. */
export function isPendingTeamSessionAdmission(cause: unknown): boolean {
  return cause instanceof HttpError && (cause.status === 403 || cause.status === 404);
}
