/**
 * Browser-safe contracts for the canonical multiplayer Session APIs.
 *
 * Keep this module free of imports from the server kernel. In particular, the
 * browser must never learn tmux names, command idempotency scopes, raw
 * invitation/token records, revoked access rows, or Runtime/provider errors.
 * The minimal active-invitation view below is a separate actor-scoped manager
 * contract and never travels over the shared event stream.
 */

export const TEAM_SESSION_PUBLIC_SCHEMA_VERSION = 1 as const;

export type TeamRole = "owner" | "admin" | "member" | "guest";
export type ProjectRole = "maintainer" | "contributor";
export type SteeringPolicy = "single" | "shared";
export type TeamSessionStatus = "active" | "awaiting_assignee" | "ended";
export type TeamSessionResponsibility = "assignee" | "supervisor" | "steerer" | "controller";

export interface TeamSessionIdentity {
  participantId: string;
  userId: string;
  displayName: string;
}

export interface TeamSessionParticipant extends TeamSessionIdentity {
  membershipRole: TeamRole;
  observer: boolean;
  responsibilities: TeamSessionResponsibility[];
  responsibilityVersions: Partial<Record<TeamSessionResponsibility, number>>;
  joinedAtMs: number;
  version: number;
}

export interface TeamSessionViewerBasis {
  participantVersion: number;
  teamMembershipVersion: number;
  projectAccessVersion?: number;
  responsibilityVersions: Partial<Record<TeamSessionResponsibility, number>>;
  accessRevision: number;
  assigneeRevision: number;
  supervisionRevision: number;
  steeringRevision: number;
  controlRevision: number;
  controlEpoch: number;
  runtimeAuthorizationGeneration: number;
  latestSequence: number;
}

export interface TeamSessionViewerCapabilities {
  addComment: boolean;
  addSuggestion: boolean;
  resolveSuggestion: boolean;
  enqueueDirective: boolean;
  observeTerminal: boolean;
  mutateTerminal: boolean;
  createInvitation: boolean;
  revokeInvitation: boolean;
  manageShares: boolean;
  manageParticipants: boolean;
  manageSupervisors: boolean;
  manageSteerers: boolean;
  transferControl: boolean;
  releaseControl: boolean;
  offerHandoff: boolean;
  acceptHandoff: boolean;
  cancelHandoff: boolean;
  claimAssignee: boolean;
}

export interface TeamSessionViewer extends TeamSessionIdentity {
  membershipRole: TeamRole;
  responsibilities: TeamSessionResponsibility[];
  basis: TeamSessionViewerBasis;
  capabilities: TeamSessionViewerCapabilities;
}

export interface TeamSessionRuntime {
  kind: "local-tmux";
  isolation: "trusted-shared-host";
  yoloEligible: false;
  authorizationGeneration: number;
  authorizationState: "enforced" | "pending" | "quarantined";
}

export interface TeamSessionResponsibilities {
  assignee?: TeamSessionIdentity;
  supervisors: TeamSessionIdentity[];
  steerers: TeamSessionIdentity[];
  controller?: TeamSessionIdentity;
}

export interface TeamSessionInboxItem {
  sessionId: string;
  teamId: string;
  projectId: string;
  name: string;
  status: TeamSessionStatus;
  steeringPolicy: SteeringPolicy;
  runtime: TeamSessionRuntime;
  responsibilities: TeamSessionResponsibilities;
  viewer: TeamSessionViewer;
  latestSequence: number;
  createdAtMs: number;
}

export interface TeamSessionShare {
  userId: string;
  displayName: string;
  version: number;
  createdAtMs: number;
}

export interface TeamSessionOpenHandoff {
  handoffId: string;
  offererUserId: string;
  recipientParticipantId: string;
  recipientUserId: string;
  offeredUnder: "assignee" | "supervisor";
  version: number;
  contextSequence: number;
  expiresAtMs: number;
  createdAtMs: number;
  briefing: {
    summary: string;
    blockers: string[];
    artifactRefs: string[];
  };
}

export interface TeamSessionDetail extends TeamSessionInboxItem {
  participants: TeamSessionParticipant[];
  /** Present only when the viewer is the Assignee or a Supervisor. */
  shares: TeamSessionShare[];
  /** Open Handoffs are scoped to Session managers and relevant participants. */
  openHandoffs: TeamSessionOpenHandoff[];
}

export interface TeamSessionActiveInvitation {
  invitationId: string;
  membershipRole: "member" | "guest";
  version: number;
  expiresAtMs: number;
}

export interface TeamSessionGuestAccessCandidate {
  invitationId: string;
  userId: string;
  displayName: string;
  membershipRole: "guest";
  requiredGrant: "session-share";
}

export interface TeamSessionMemberAccessCandidate {
  invitationId: string;
  userId: string;
  displayName: string;
  membershipRole: "member";
  requiredGrant: "project-access";
  expectedProjectAccessVersion: number;
}

/** Private, actor-scoped manager projection. Never publish this over Session events. */
export interface TeamSessionAdmission {
  sessionId: string;
  accessRevision: number;
  capabilities: {
    canRevokeInvitations: boolean;
    canGrantGuestShare: boolean;
    canGrantProjectAccess: boolean;
  };
  activeInvitations: TeamSessionActiveInvitation[];
  accessCandidates: Array<TeamSessionGuestAccessCandidate | TeamSessionMemberAccessCandidate>;
}

export type TeamSessionProjectVisibility = "content" | "administration" | "session-only";

export interface TeamSessionProject {
  projectId: string;
  name: string;
  createdAtMs: number;
  visibility: TeamSessionProjectVisibility;
  viewerAccess?: {
    role: ProjectRole;
    version: number;
  };
  capabilities: {
    viewContent: boolean;
    startSession: boolean;
    manageAccess: boolean;
  };
}

export interface TeamSessionTeam {
  teamId: string;
  name: string;
  createdAtMs: number;
  viewerMembership: {
    role: TeamRole;
    version: number;
  };
  capabilities: {
    createProject: boolean;
    manageMemberships: boolean;
  };
  projects: TeamSessionProject[];
}

export interface TeamSessionDiscovery {
  teams: TeamSessionTeam[];
}

export type TeamSessionEventSourceAdapter = "web" | "slack" | "telegram" | "runtime" | "internal";

export interface TeamSessionEventActor {
  kind: "human" | "system";
  userId: string;
  displayName: string;
}

/**
 * Canonical, redacted Session event. `sequence` is gap-free within one
 * Session and is the only ordering cursor exposed to the browser.
 */
export interface TeamSessionEvent {
  schemaVersion: typeof TEAM_SESSION_PUBLIC_SCHEMA_VERSION;
  eventId: string;
  sessionId: string;
  sequence: number;
  type: string;
  occurredAtMs: number;
  actor: TeamSessionEventActor;
  sourceAdapter: TeamSessionEventSourceAdapter;
  payload: Record<string, unknown>;
}

interface TeamSessionCommandBase {
  /** Informational source time only; server authorization uses the kernel clock. */
  occurredAtMs?: number;
}

export type TeamSessionCommandBody = TeamSessionCommandBase &
  (
    | { type: "team.create"; name: string }
    | { type: "project.create"; teamId: string; name: string; sourceRef?: string }
    | {
        type: "team.membership.grant";
        teamId: string;
        userId: string;
        role: TeamRole;
        expectedMembershipVersion: number;
      }
    | {
        type: "team.membership.revoke";
        teamId: string;
        userId: string;
        expectedMembershipVersion: number;
      }
    | {
        type: "project.access.grant";
        projectId: string;
        userId: string;
        role: ProjectRole;
        expectedAccessVersion: number;
      }
    | {
        type: "project.access.revoke";
        projectId: string;
        userId: string;
        expectedAccessVersion: number;
      }
    | {
        type: "session.start";
        teamId: string;
        projectId: string;
        name: string;
        steeringPolicy?: SteeringPolicy;
      }
    | {
        type: "session.invitation.create";
        sessionId: string;
        membershipRole: "member" | "guest";
        expiresAtMs: number;
        expectedAccessRevision: number;
      }
    | {
        type: "session.invitation.revoke";
        sessionId: string;
        invitationId: string;
        expectedInvitationVersion: number;
      }
    | { type: "session.invitation.redeem"; token: string }
    | { type: "session.join"; sessionId: string; invitationId?: string }
    | {
        type: "session.share.create";
        sessionId: string;
        userId: string;
        expectedAccessRevision: number;
      }
    | {
        type: "session.share.revoke";
        sessionId: string;
        userId: string;
        expectedShareVersion: number;
      }
    | {
        type: "session.participant.grant";
        sessionId: string;
        userId: string;
        expectedParticipantVersion: number;
        expectedAccessRevision: number;
      }
    | {
        type: "session.participant.revoke";
        sessionId: string;
        userId: string;
        expectedParticipantVersion: number;
      }
    | {
        type: "session.responsibility.grant";
        sessionId: string;
        userId: string;
        responsibility: "supervisor";
        expectedSupervisionRevision: number;
        expectedParticipantVersion: number;
      }
    | {
        type: "session.responsibility.grant";
        sessionId: string;
        userId: string;
        responsibility: "steerer";
        expectedSteeringRevision: number;
        expectedParticipantVersion: number;
      }
    | {
        type: "session.responsibility.revoke";
        sessionId: string;
        userId: string;
        responsibility: "supervisor";
        expectedSupervisionRevision: number;
      }
    | {
        type: "session.responsibility.revoke";
        sessionId: string;
        userId: string;
        responsibility: "steerer";
        expectedSteeringRevision: number;
        expectedControlRevision: number;
        expectedControlEpoch: number;
      }
    | {
        type: "session.control.transfer";
        sessionId: string;
        userId: string;
        expectedControlRevision: number;
        expectedControlEpoch: number;
        expectedParticipantVersion: number;
      }
    | {
        type: "session.control.release";
        sessionId: string;
        expectedControlRevision: number;
        expectedControlEpoch: number;
      }
    | {
        type: "session.assignee.claim";
        sessionId: string;
        expectedAssigneeRevision: number;
        expectedAccessRevision: number;
      }
    | {
        type: "session.handoff.offer";
        sessionId: string;
        recipientParticipantId: string;
        expectedAssigneeRevision: number;
        expectedRecipientParticipantVersion: number;
        expectedOffererResponsibilityVersion: number;
        expiresAtMs?: number;
        briefing?: {
          summary: string;
          blockers?: string[];
          artifactRefs?: string[];
        };
      }
    | {
        type: "session.handoff.accept";
        sessionId: string;
        handoffId: string;
        expectedHandoffVersion: number;
      }
    | {
        type: "session.handoff.cancel";
        sessionId: string;
        handoffId: string;
        expectedHandoffVersion: number;
      }
    | { type: "comment.add"; sessionId: string; body: string }
    | { type: "suggestion.add"; sessionId: string; body: string }
    | {
        type: "suggestion.resolve";
        sessionId: string;
        suggestionId: string;
        resolution: "accept" | "reject";
        expectedSuggestionVersion: number;
        expectedSteeringRevision: number;
        editedBody?: never;
      }
    | {
        type: "suggestion.resolve";
        sessionId: string;
        suggestionId: string;
        resolution: "accept-edited";
        editedBody: string;
        expectedSuggestionVersion: number;
        expectedSteeringRevision: number;
      }
    | {
        type: "directive.enqueue";
        sessionId: string;
        body: string;
        expectedSteeringRevision: number;
      }
  );

export interface TeamSessionCommandResult {
  accepted: true;
  commandType: TeamSessionCommandBody["type"];
  replayed: boolean;
  /** Safe command receipt data; invitation creation may contain its one-time token. */
  data: Record<string, unknown>;
  events: TeamSessionEvent[];
}

export type TeamSessionEventConnectionState =
  | "idle"
  | "connecting"
  | "syncing"
  | "live"
  | "reconnecting";
