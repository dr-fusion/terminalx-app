export const TEAM_SESSION_SCHEMA_VERSION = 1 as const;

export type TeamRole = "owner" | "admin" | "member" | "guest";
export type ProjectRole = "maintainer" | "contributor";
export type SteeringPolicy = "single" | "shared";
export type SessionResponsibility = "assignee" | "supervisor" | "steerer" | "controller";
export type TerminalAction = "observe" | "input" | "resize" | "interrupt";

/** Safe, kernel-owned Runtime failure classes. Raw adapter errors must never enter commands. */
export const RUNTIME_OUTBOX_ERROR_CODES = [
  "runtime_unavailable",
  "runtime_timeout",
  "runtime_conflict",
  "runtime_permission_denied",
  "runtime_invalid_state",
  "runtime_internal",
] as const;
export type RuntimeOutboxErrorCode = (typeof RUNTIME_OUTBOX_ERROR_CODES)[number];

export interface ActorContext {
  kind: "human" | "system";
  userId: string;
  displayName: string;
}

export interface CommandIdempotency {
  /** Adapter/source namespace, for example `web:user-1` or `telegram:bot-7`. */
  scope: string;
  /** Stable source event or request identifier within the scope. */
  key: string;
}

interface CommandBase {
  schemaVersion: typeof TEAM_SESSION_SCHEMA_VERSION;
  actor: ActorContext;
  idempotency: CommandIdempotency;
  /** Informational source time only; authorization and persistence use the kernel clock. */
  occurredAtMs?: number;
}

export type SessionCommand =
  | (CommandBase & {
      type: "team.create";
      teamId?: string;
      name: string;
    })
  | (CommandBase & {
      type: "project.create";
      teamId: string;
      projectId?: string;
      name: string;
      sourceRef?: string;
    })
  | (CommandBase & {
      type: "team.membership.grant";
      teamId: string;
      userId: string;
      role: TeamRole;
      expectedMembershipVersion: number;
    })
  | (CommandBase & {
      type: "project.access.grant";
      projectId: string;
      userId: string;
      role: ProjectRole;
      expectedAccessVersion: number;
    })
  | (CommandBase & {
      type: "project.access.revoke";
      projectId: string;
      userId: string;
      expectedAccessVersion: number;
    })
  | (CommandBase & {
      type: "team.membership.revoke";
      teamId: string;
      userId: string;
      expectedMembershipVersion: number;
    })
  | (CommandBase & {
      type: "session.start";
      teamId: string;
      projectId: string;
      /** Canonical lowercase RFC 4122 UUID v4 when supplied. */
      sessionId?: string;
      name: string;
      tmuxName: string;
      steeringPolicy?: SteeringPolicy;
    })
  | (CommandBase & {
      type: "session.invitation.create";
      sessionId: string;
      membershipRole: "member" | "guest";
      expiresAtMs: number;
      expectedAccessRevision: number;
    })
  | (CommandBase & {
      type: "session.invitation.revoke";
      sessionId: string;
      invitationId: string;
      expectedInvitationVersion: number;
    })
  | (CommandBase & {
      type: "session.invitation.redeem";
      token: string;
    })
  | (CommandBase & {
      type: "session.join";
      sessionId: string;
      invitationId?: string;
    })
  | (CommandBase & {
      type: "session.share.create";
      sessionId: string;
      userId: string;
      expectedAccessRevision: number;
    })
  | (CommandBase & {
      type: "session.share.revoke";
      sessionId: string;
      userId: string;
      expectedShareVersion: number;
    })
  | (CommandBase & {
      type: "session.participant.grant";
      sessionId: string;
      userId: string;
      expectedParticipantVersion: number;
      expectedAccessRevision: number;
    })
  | (CommandBase & {
      type: "session.participant.revoke";
      sessionId: string;
      userId: string;
      expectedParticipantVersion: number;
    })
  | (CommandBase & {
      type: "session.responsibility.grant";
      sessionId: string;
      userId: string;
      responsibility: "supervisor";
      expectedSupervisionRevision: number;
      expectedParticipantVersion: number;
    })
  | (CommandBase & {
      type: "session.responsibility.grant";
      sessionId: string;
      userId: string;
      responsibility: "steerer";
      expectedSteeringRevision: number;
      expectedParticipantVersion: number;
    })
  | (CommandBase & {
      type: "session.responsibility.revoke";
      sessionId: string;
      userId: string;
      responsibility: "supervisor";
      expectedSupervisionRevision: number;
    })
  | (CommandBase & {
      type: "session.responsibility.revoke";
      sessionId: string;
      userId: string;
      responsibility: "steerer";
      expectedSteeringRevision: number;
      expectedControlRevision: number;
      expectedControlEpoch: number;
    })
  | (CommandBase & {
      type: "session.control.transfer";
      sessionId: string;
      userId: string;
      expectedControlRevision: number;
      expectedControlEpoch: number;
      expectedParticipantVersion: number;
    })
  | (CommandBase & {
      type: "session.control.release";
      sessionId: string;
      expectedControlRevision: number;
      expectedControlEpoch: number;
    })
  | (CommandBase & {
      type: "session.assignee.claim";
      sessionId: string;
      expectedAssigneeRevision: number;
      expectedAccessRevision: number;
    })
  | (CommandBase & {
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
    })
  | (CommandBase & {
      type: "session.handoff.accept";
      sessionId: string;
      handoffId: string;
      expectedHandoffVersion: number;
    })
  | (CommandBase & {
      type: "session.handoff.cancel";
      sessionId: string;
      handoffId: string;
      expectedHandoffVersion: number;
    })
  | (CommandBase & {
      type: "comment.add";
      sessionId: string;
      body: string;
    })
  | (CommandBase & {
      type: "suggestion.add";
      sessionId: string;
      body: string;
    })
  | (CommandBase & {
      type: "suggestion.resolve";
      sessionId: string;
      suggestionId: string;
      resolution: "accept" | "reject";
      expectedSuggestionVersion: number;
      expectedSteeringRevision: number;
      editedBody?: never;
    })
  | (CommandBase & {
      type: "suggestion.resolve";
      sessionId: string;
      suggestionId: string;
      resolution: "accept-edited";
      editedBody: string;
      expectedSuggestionVersion: number;
      expectedSteeringRevision: number;
    })
  | (CommandBase & {
      type: "directive.enqueue";
      sessionId: string;
      body: string;
      expectedSteeringRevision: number;
    })
  | (CommandBase & {
      type: "runtime.outbox.acknowledge";
      outboxId: string;
      workerId: string;
      expectedAttempt: number;
    })
  | (CommandBase & {
      type: "runtime.outbox.fail";
      outboxId: string;
      workerId: string;
      expectedAttempt: number;
      retryable: boolean;
      /** Closed, safe class only; raw Runtime errors and output never enter the kernel ledger. */
      errorCode: RuntimeOutboxErrorCode;
    });

export interface CommandResult {
  accepted: true;
  /** Monotonic order of every accepted kernel mutation, including non-Session mutations. */
  acceptedSequence: number;
  commandType: SessionCommand["type"];
  replayed: boolean;
  /** Command-specific identifiers and safe projection data. */
  data: Record<string, unknown>;
  /** Canonical Session events appended by this command, in sequence order. */
  events: SessionEvent[];
}

interface QueryBase {
  schemaVersion: typeof TEAM_SESSION_SCHEMA_VERSION;
  actor: ActorContext;
}

export interface SessionGetQuery extends QueryBase {
  type: "session.get";
  sessionId: string;
}

export interface SessionListQuery extends QueryBase {
  type: "session.list";
  teamId?: string;
}

/** Public, actor-scoped Team and Project navigation in one read snapshot. */
export interface WorkspaceDiscoveryQuery extends QueryBase {
  type: "workspace.discovery";
}

/** Public inbox projection. Internal Runtime callers continue to use session.list. */
export interface SessionInboxQuery extends QueryBase {
  type: "session.inbox";
  teamId?: string;
}

/** Public Session projection. Internal Runtime callers continue to use session.get. */
export interface SessionDetailQuery extends QueryBase {
  type: "session.detail";
  sessionId: string;
}

export interface SessionEventsQuery extends QueryBase {
  type: "session.events";
  sessionId: string;
  afterSequence?: number;
  limit?: number;
}

export interface SessionTerminalAuthorizationQuery extends QueryBase {
  type: "session.terminal-authorization";
  sessionId: string;
  action: TerminalAction;
  expectedControlEpoch?: number;
  expectedRuntimeAuthorizationGeneration?: number;
}

export interface SessionAdmissionQuery extends QueryBase {
  type: "session.admission";
  sessionId: string;
}

export interface TeamAccessQuery extends QueryBase {
  type: "team.access";
  teamId: string;
}

export interface ProjectAccessQuery extends QueryBase {
  type: "project.access";
  projectId: string;
}

export type SessionQuery =
  | SessionGetQuery
  | SessionListQuery
  | WorkspaceDiscoveryQuery
  | SessionInboxQuery
  | SessionDetailQuery
  | SessionEventsQuery
  | SessionTerminalAuthorizationQuery
  | SessionAdmissionQuery
  | TeamAccessQuery
  | ProjectAccessQuery;

export interface SessionEvent {
  schemaVersion: typeof TEAM_SESSION_SCHEMA_VERSION;
  eventId: string;
  sessionId: string;
  sequence: number;
  type: string;
  occurredAtMs: number;
  actor: ActorContext;
  source: CommandIdempotency;
  payload: Record<string, unknown>;
}

export interface SessionParticipantView {
  participantId: string;
  userId: string;
  membershipRole: TeamRole;
  active: boolean;
  observer: boolean;
  responsibilities: SessionResponsibility[];
  responsibilityVersions: Partial<Record<SessionResponsibility, number>>;
  joinedAtMs: number;
  version: number;
  revokedAtMs?: number;
}

export interface SessionShareView {
  userId: string;
  status: "active" | "revoked";
  version: number;
  createdAtMs: number;
  revokedAtMs?: number;
}

export interface SessionInvitationView {
  invitationId: string;
  membershipRole: "member" | "guest";
  status: "active" | "redeemed" | "revoked";
  version: number;
  expiresAtMs: number;
  createdByUserId: string;
  createdAtMs: number;
  redeemedByUserId?: string;
  redeemedAtMs?: number;
  revokedAtMs?: number;
}

export interface SessionAdmissionView {
  sessionId: string;
  teamId: string;
  projectId: string;
  accessRevision: number;
  invitations: SessionInvitationView[];
}

export interface SessionHandoffView {
  handoffId: string;
  offererUserId: string;
  recipientParticipantId: string;
  recipientUserId: string;
  offeredUnder: "assignee" | "supervisor";
  status: "offered" | "accepted" | "cancelled" | "expired";
  version: number;
  baseAssigneeRevision: number;
  contextSequence: number;
  expiresAtMs: number;
  createdAtMs: number;
  resolvedAtMs?: number;
  resolvedByUserId?: string;
  cancellationReason?: string;
  briefing: {
    summary: string;
    blockers: string[];
    artifactRefs: string[];
  };
}

export type RuntimeOutboxKind =
  | "runtime.session.ensure"
  | "runtime.session.retire"
  | "runtime.authorization.fence";

export interface RuntimeOutboxClaimOptions {
  workerId: string;
  limit?: number;
  leaseDurationMs?: number;
}

interface RuntimeOutboxDeliveryBase {
  outboxId: string;
  sessionId: string;
  sessionSequence: number;
  attempts: number;
  leaseOwner: string;
  leaseExpiresAtMs: number;
}

export type RuntimeOutboxDelivery = RuntimeOutboxDeliveryBase &
  (
    | {
        kind: "runtime.session.ensure";
        payload: {
          sessionId: string;
          runtimeKind: "local-tmux";
          tmuxName: string;
          runtimeAuthorizationGeneration: number;
        };
      }
    | {
        kind: "runtime.authorization.fence";
        payload: {
          sessionId: string;
          reason: "assignee-loss";
          runtimeAuthorizationGeneration: number;
        };
      }
    | {
        kind: "runtime.session.retire";
        payload: {
          sessionId: string;
          runtimeAuthorizationGeneration: number;
        };
      }
  );

export interface TeamMembershipView {
  userId: string;
  role: TeamRole;
  status: "active" | "revoked";
  version: number;
  createdAtMs: number;
  revokedAtMs?: number;
}

export interface TeamAccessView {
  teamId: string;
  name: string;
  memberships: TeamMembershipView[];
}

export interface ProjectAccessEntryView {
  userId: string;
  role: ProjectRole;
  status: "active" | "revoked";
  version: number;
  createdAtMs: number;
  revokedAtMs?: number;
}

export interface ProjectAccessView {
  projectId: string;
  teamId: string;
  name: string;
  access: ProjectAccessEntryView[];
}

export type WorkspaceProjectVisibility = "content" | "administration" | "session-only";

export interface WorkspaceProjectView {
  projectId: string;
  name: string;
  createdAtMs: number;
  visibility: WorkspaceProjectVisibility;
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

export interface WorkspaceTeamView {
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
  projects: WorkspaceProjectView[];
}

export interface WorkspaceDiscoveryView {
  teams: WorkspaceTeamView[];
}

export interface PublicSessionIdentityView {
  participantId: string;
  userId: string;
  displayName: string;
}

export interface PublicSessionParticipantView extends PublicSessionIdentityView {
  membershipRole: TeamRole;
  observer: boolean;
  responsibilities: SessionResponsibility[];
  responsibilityVersions: Partial<Record<SessionResponsibility, number>>;
  joinedAtMs: number;
  version: number;
}

export interface SessionViewerBasis {
  participantVersion: number;
  teamMembershipVersion: number;
  projectAccessVersion?: number;
  responsibilityVersions: Partial<Record<SessionResponsibility, number>>;
  accessRevision: number;
  assigneeRevision: number;
  supervisionRevision: number;
  steeringRevision: number;
  controlRevision: number;
  controlEpoch: number;
  runtimeAuthorizationGeneration: number;
  latestSequence: number;
}

/**
 * Actor-scoped UI hints computed from the same kernel predicates as dispatch.
 * Target-dependent transitions still reauthorize atomically when dispatched.
 */
export interface SessionViewerCapabilities {
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

export interface SessionViewerView extends PublicSessionIdentityView {
  membershipRole: TeamRole;
  responsibilities: SessionResponsibility[];
  basis: SessionViewerBasis;
  capabilities: SessionViewerCapabilities;
}

export interface PublicSessionRuntimeView {
  kind: "local-tmux";
  isolation: "trusted-shared-host";
  yoloEligible: false;
  authorizationGeneration: number;
  authorizationState: "enforced" | "pending" | "quarantined";
}

export interface PublicSessionResponsibilityView {
  assignee?: PublicSessionIdentityView;
  supervisors: PublicSessionIdentityView[];
  steerers: PublicSessionIdentityView[];
  controller?: PublicSessionIdentityView;
}

export interface SessionInboxItemView {
  sessionId: string;
  teamId: string;
  projectId: string;
  name: string;
  status: "active" | "awaiting_assignee" | "ended";
  steeringPolicy: SteeringPolicy;
  runtime: PublicSessionRuntimeView;
  responsibilities: PublicSessionResponsibilityView;
  viewer: SessionViewerView;
  latestSequence: number;
  createdAtMs: number;
}

export interface PublicSessionShareView {
  userId: string;
  displayName: string;
  version: number;
  createdAtMs: number;
}

export interface PublicOpenHandoffView {
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

export interface SessionDetailView extends SessionInboxItemView {
  participants: PublicSessionParticipantView[];
  /** Active shares are visible only to the Assignee or a Supervisor. */
  shares: PublicSessionShareView[];
  /** Only open Handoffs relevant to the viewer or a Session manager are projected. */
  openHandoffs: PublicOpenHandoffView[];
}

export interface SessionView {
  sessionId: string;
  teamId: string;
  projectId: string;
  name: string;
  status: "active" | "awaiting_assignee" | "ended";
  steeringPolicy: SteeringPolicy;
  accessRevision: number;
  assigneeRevision: number;
  supervisionRevision: number;
  steeringRevision: number;
  controlRevision: number;
  controlEpoch: number;
  runtime: {
    kind: "local-tmux";
    isolation: "trusted-shared-host";
    tmuxName: string;
    yoloEligible: false;
    authorizationGeneration: number;
    authorizationState: "enforced" | "pending" | "quarantined";
  };
  participants: SessionParticipantView[];
  shares: SessionShareView[];
  invitations: SessionInvitationView[];
  handoffs: SessionHandoffView[];
  latestSequence: number;
  createdAtMs: number;
}

export interface TerminalAuthorization {
  sessionId: string;
  action: TerminalAction;
  allowed: boolean;
  reason?:
    | "not-authorized"
    | "stale-control-epoch"
    | "stale-runtime-authorization-generation"
    | "session-not-active"
    | "runtime-authorization-pending"
    | "runtime-authorization-quarantined";
  participantId?: string;
  controlEpoch: number;
  runtimeAuthorizationGeneration: number;
}

export interface FollowSessionOptions {
  sessionId: string;
  afterSequence: number;
  actor: ActorContext;
  signal?: AbortSignal;
  pollIntervalMs?: number;
}

export interface TeamSessions {
  dispatch(command: SessionCommand): Promise<CommandResult>;
  inspect(query: SessionGetQuery): Promise<SessionView | null>;
  inspect(query: SessionListQuery): Promise<SessionView[]>;
  inspect(query: WorkspaceDiscoveryQuery): Promise<WorkspaceDiscoveryView>;
  inspect(query: SessionInboxQuery): Promise<SessionInboxItemView[]>;
  inspect(query: SessionDetailQuery): Promise<SessionDetailView | null>;
  inspect(query: SessionEventsQuery): Promise<SessionEvent[]>;
  inspect(query: SessionTerminalAuthorizationQuery): Promise<TerminalAuthorization>;
  inspect(query: SessionAdmissionQuery): Promise<SessionAdmissionView>;
  inspect(query: TeamAccessQuery): Promise<TeamAccessView>;
  inspect(query: ProjectAccessQuery): Promise<ProjectAccessView>;
  /**
   * Hold an immediate SQLite transaction across the final authorization read
   * and one synchronous terminal effect. This gives control transfers and
   * terminal mutations a single total order, including across processes that
   * share the canonical database.
   */
  performTerminalMutation(query: SessionTerminalAuthorizationQuery, mutation: () => void): void;
  follow(options: FollowSessionOptions): AsyncIterable<SessionEvent>;
  claimRuntimeOutbox(options: RuntimeOutboxClaimOptions): Promise<RuntimeOutboxDelivery[]>;
  close(): void;
}

export type TeamSessionErrorCode =
  | "invalid-command"
  | "not-found"
  | "not-authorized"
  | "conflict"
  | "stale-revision"
  | "idempotency-conflict"
  | "invitation-expired"
  | "invitation-revoked"
  | "invitation-used";

export class TeamSessionError extends Error {
  constructor(
    readonly code: TeamSessionErrorCode,
    message: string
  ) {
    super(message);
    this.name = "TeamSessionError";
  }
}
