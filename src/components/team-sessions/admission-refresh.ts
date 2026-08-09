import type { TeamSessionEvent } from "@/types/team-session";

const ADMISSION_REFRESH_EVENT_TYPES = new Set([
  // The public boundary intentionally collapses all invitation, membership,
  // share, Project Access, and access-revision events to this anonymous type.
  "session.activity",
  "session.ended",
  "session.participant.granted",
  "session.participant.joined",
  "session.participant.revoked",
]);

export function shouldRefreshTeamSessionAdmission(
  events: TeamSessionEvent[],
  afterSequence: number
): boolean {
  return events.some(
    (event) => event.sequence > afterSequence && ADMISSION_REFRESH_EVENT_TYPES.has(event.type)
  );
}
