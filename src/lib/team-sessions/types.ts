import type * as Phase4Contracts from "./contracts";

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
      expectedLeaseExpiresAtMs: number;
    })
  | (CommandBase & {
      type: "runtime.outbox.fail";
      outboxId: string;
      workerId: string;
      expectedAttempt: number;
      expectedLeaseExpiresAtMs: number;
      retryable: boolean;
      /** Closed, safe class only; raw Runtime errors and output never enter the kernel ledger. */
      errorCode: RuntimeOutboxErrorCode;
    })
  | (CommandBase & Phase4Contracts.AgentRunCommandPayload);

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

/**
 * Browser-safe Run state composed with Session authority in one kernel read
 * transaction. Keep the internal Runtime-facing `session.run-state` query
 * separate so HTTP never has to join independently authorized snapshots.
 */
export interface PublicSessionRunStateQuery extends QueryBase {
  type: "session.public-run-state";
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
  | PublicSessionRunStateQuery
  | SessionEventsQuery
  | SessionTerminalAuthorizationQuery
  | SessionAdmissionQuery
  | TeamAccessQuery
  | ProjectAccessQuery
  | Phase4Contracts.SessionRunStateQuery;

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
  accessRevision: number;
  capabilities: {
    canRevokeInvitations: boolean;
    canGrantGuestShare: boolean;
    canGrantProjectAccess: boolean;
  };
  activeInvitations: Array<{
    invitationId: string;
    membershipRole: "member" | "guest";
    version: number;
    expiresAtMs: number;
  }>;
  accessCandidates: Array<
    | {
        invitationId: string;
        userId: string;
        displayName: string;
        membershipRole: "guest";
        requiredGrant: "session-share";
      }
    | {
        invitationId: string;
        userId: string;
        displayName: string;
        membershipRole: "member";
        requiredGrant: "project-access";
        expectedProjectAccessVersion: number;
      }
  >;
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

export interface RuntimeOutboxDispatchInterlockOptions {
  outboxId: string;
  workerId: string;
  expectedAttempt: number;
  expectedLeaseExpiresAtMs: number;
}

export interface RuntimeOutboxLeaseRenewalOptions {
  outboxId: string;
  workerId: string;
  expectedAttempt: number;
  expectedLeaseExpiresAtMs: number;
  leaseDurationMs: number;
}

export interface RuntimeOutboxLeaseRenewal {
  leaseExpiresAtMs: number;
}

export type RuntimeOutboxDispatchMode = "apply" | "reconcile";

interface RuntimeOutboxDeliveryBase {
  outboxId: string;
  sessionId: string;
  sessionSequence: number;
  attempts: number;
  leaseOwner: string;
  leaseExpiresAtMs: number;
  /**
   * Once an attempt has crossed the durable dispatch interlock, every later
   * owner must reconcile adapter state. A reconciler must never call the
   * ordinary apply path, even when the original lease has expired.
   */
  dispatchMode: RuntimeOutboxDispatchMode;
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
          reason: "assignee-loss" | "emergency-stop";
          runtimeAuthorizationGeneration: number;
        };
      }
    | {
        kind: "runtime.session.retire";
        payload: {
          sessionId: string;
          runtimeAuthorizationGeneration: number;
          reason: "emergency-stop";
          agentRunId: string;
          runtimeAssignmentId: string;
          runtimeAssignmentGeneration: number;
          sandboxId: string;
          sandboxGeneration: number;
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
  runStateRevision: number;
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

export type PublicSessionRunStartReason =
  | "available"
  | "not-session-manager"
  | "session-not-active"
  | "runtime-not-ready"
  | "mutable-run-exists"
  | "run-mutations-unavailable";

export interface PublicSessionRunStartAvailability {
  available: boolean;
  reason: PublicSessionRunStartReason;
}

/**
 * Actor-scoped browser actions. Phase 4 keeps every value false until the
 * corresponding HTTP mutation and exact-bound Runtime enforcement ship
 * together; kernel-only authority must not be advertised as an available UI
 * action.
 */
export interface PublicSessionRunCapabilities {
  startRun: boolean;
  reviseRunPolicy: boolean;
  pauseRun: boolean;
  resumeRun: boolean;
  stopRun: boolean;
  emergencyStopRun: boolean;
  editGoals: boolean;
  reviewGoalEvidence: boolean;
  resolveFinalReview: boolean;
  viewActionCenter: boolean;
  resolveAttention: boolean;
  resolveApprovals: boolean;
  revokeRunGrants: boolean;
  resolveGrantReviews: boolean;
}

export type PublicSessionRunLimit<T> = { kind: "unconfigured" } | { kind: "capped"; value: T };

export interface PublicSessionRunMoney {
  currency: string;
  minorUnits: number;
}

export interface PublicSessionRunLimitsSummary {
  wallClock: PublicSessionRunLimit<{ milliseconds: number }>;
  modelTokens: PublicSessionRunLimit<number>;
  modelSpend: PublicSessionRunLimit<PublicSessionRunMoney>;
  outboundBytes: PublicSessionRunLimit<number>;
  actionCounts: {
    local: PublicSessionRunLimit<number>;
    "scoped-external": PublicSessionRunLimit<number>;
    protected: PublicSessionRunLimit<number>;
    forbidden: PublicSessionRunLimit<number>;
  };
}

export interface PublicSessionGoalEvidenceSummary {
  evidenceId: string;
  status: "proposed" | "validated" | "more-work-requested";
  createdAtMs: number;
  reviewedAtMs?: number;
}

export interface PublicSessionRunGoalView {
  goalId: string;
  position: number;
  title: string;
  acceptanceCriteria: string[];
  dependencyGoalIds: string[];
  version: number;
  status: "pending" | "in-progress" | "blocked" | "provisionally-achieved" | "validated";
  evidenceTotalCount: number;
  evidence: PublicSessionGoalEvidenceSummary[];
}

export interface PublicSessionAgentRunView {
  agentRunId: string;
  lifecycle: Phase4Contracts.AgentRunLifecycle;
  stateVersion: number;
  pendingOperation: {
    kind: "start" | "pause" | "resume" | "stop";
    status: "queued" | "awaiting-runtime" | "compensating";
    requestedAtMs: number;
  } | null;
  mode: Phase4Contracts.AgentRunMode;
  completionPolicy: Phase4Contracts.CompletionPolicy["kind"];
  runPolicyRevision: number;
  goalSetRevision: number;
  finalReviewVersion: number;
  finalReviewState: "not-ready" | "open" | "accepted";
  requiresPolicyRebind: boolean;
  sandboxState:
    | "provisioning"
    | "ready"
    | "checkpointing"
    | "recovering"
    | "quarantined"
    | "retired"
    | "failed";
  limitStatus:
    | "accounting-unavailable"
    | "within-configured-limits"
    | "warning-75-percent"
    | "approaching-90-percent"
    | "configured-limit-reached";
  attentionSummary: {
    openCount: number;
    blockingCount: number;
    independentAuthorizedWorkMayContinue: boolean;
  };
  policySummary: {
    mode: Phase4Contracts.AgentRunMode;
    completionPolicy: Phase4Contracts.CompletionPolicy["kind"];
    limits: PublicSessionRunLimitsSummary;
  };
  goals: PublicSessionRunGoalView[];
}

export interface PublicSessionActionEffectSummary {
  wallClockMilliseconds: number;
  modelTokens: number;
  modelSpend: PublicSessionRunMoney;
  outboundBytes: number;
  actionCounts: {
    local: number;
    "scoped-external": number;
    protected: number;
    forbidden: number;
  };
}

export interface PublicSessionApprovalView {
  approvalRequestId: string;
  version: number;
  status: Phase4Contracts.ApprovalRequestStatus;
  expiresAtMs: number;
  displayDigest: string;
  actionClass: Phase4Contracts.ApprovableActionClass;
  provider: string;
  operation: string;
  exactTarget: string;
  expectedEffect: PublicSessionActionEffectSummary;
  reason: string;
  risk: string;
  allowedResolutions: Array<"approve-once" | "approve-for-run" | "deny">;
  runApprovalPattern?: {
    eligibleUse: Phase4Contracts.EligibleRunGrantUse;
    provider: string;
    operation: string;
    targetPattern: string;
    displayDigest: string;
  };
}

export interface PublicSessionAttentionView {
  attentionRequestId: string;
  version: number;
  deadlineAtMs: number;
  status: Phase4Contracts.AttentionRequestStatus;
  reason: string;
  risk: string;
  independentAuthorizedWorkMayContinue: boolean;
  linkedApproval: boolean;
  proposal:
    | { kind: "action-review" }
    | {
        kind: "structured-decision";
        options: Array<{ optionId: string; label: string; description: string }>;
      };
  allowedResolutions: Array<"deny-proposed-action" | "supersede-with-directive" | "answer">;
  answerOptionIds: string[];
}

export interface PublicSessionGrantView {
  grantId: string;
  version: number;
  status: Phase4Contracts.ActionGrantStatus;
  actionClass: Phase4Contracts.ApprovableActionClass;
  provider: string;
  operation: string;
  exactTarget: string;
  scope: "once" | "run";
  expiresAtMs: number;
  allowedActions: Array<"revoke">;
}

export interface PublicSessionGrantCandidateView {
  grantId: string;
  actionClass: Phase4Contracts.ApprovableActionClass;
  provider: string;
  operation: string;
  exactTarget: string;
  scope: "once" | "run";
}

export interface PublicSessionGrantReviewView {
  grantReviewId: string;
  version: number;
  reason: Phase4Contracts.GrantReviewReason;
  status: Phase4Contracts.GrantReviewStatus;
  safeDefault: "revoke-all";
  deliberatelyRevokedCount: number;
  reissuableCandidates: PublicSessionGrantCandidateView[];
  allowedActions: {
    revokeAll: boolean;
    reissueCandidateGrantIds: string[];
  };
}

/**
 * Browser-safe Run projection. It intentionally omits Runtime assignment,
 * Sandbox and principal identifiers, authorization generations, credential
 * references, signatures, ledgers, raw artifact references and provider
 * payloads.
 */
export interface PublicSessionRunStateView {
  sessionId: string;
  asOfSequence: number;
  runStateRevision: number;
  capabilities: PublicSessionRunCapabilities;
  start: PublicSessionRunStartAvailability;
  currentRun: PublicSessionAgentRunView | null;
  attentionRequests: PublicSessionAttentionView[];
  approvalRequests: PublicSessionApprovalView[];
  activeGrants: PublicSessionGrantView[];
  grantReviews: PublicSessionGrantReviewView[];
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
  runStateRevision: number;
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
  inspect(query: PublicSessionRunStateQuery): Promise<PublicSessionRunStateView | null>;
  inspect(query: SessionEventsQuery): Promise<SessionEvent[]>;
  inspect(query: SessionTerminalAuthorizationQuery): Promise<TerminalAuthorization>;
  inspect(query: SessionAdmissionQuery): Promise<SessionAdmissionView>;
  inspect(query: TeamAccessQuery): Promise<TeamAccessView>;
  inspect(query: ProjectAccessQuery): Promise<ProjectAccessView>;
  inspect(
    query: Phase4Contracts.SessionRunStateQuery
  ): Promise<Phase4Contracts.SessionRunStateView | null>;
  /**
   * Hold an immediate SQLite transaction across the final authorization read
   * and one synchronous terminal effect. This gives control transfers and
   * terminal mutations a single total order, including across processes that
   * share the canonical database.
   */
  performTerminalMutation(query: SessionTerminalAuthorizationQuery, mutation: () => void): void;
  follow(options: FollowSessionOptions): AsyncIterable<SessionEvent>;
  claimRuntimeOutbox(options: RuntimeOutboxClaimOptions): Promise<RuntimeOutboxDelivery[]>;
  markRuntimeOutboxDispatch(options: RuntimeOutboxDispatchInterlockOptions): Promise<void>;
  renewRuntimeOutboxLease(
    options: RuntimeOutboxLeaseRenewalOptions
  ): Promise<RuntimeOutboxLeaseRenewal>;
  runtimeEnsureState(input: {
    sessionId: string;
    tmuxName: string;
    runtimeAuthorizationGeneration: number;
  }): "pending" | "enforced" | "stale";
  isCurrentRuntimeBinding(input: {
    sessionId: string;
    runtimeAuthorizationGeneration: number;
    emergencyStop?: {
      agentRunId: string;
      runtimeAssignmentId: string;
      runtimeAssignmentGeneration: number;
      sandboxId: string;
      sandboxGeneration: number;
    };
  }): boolean;
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

// Phase 4 portable contracts are re-exported here so existing type-only imports
// from `team-sessions/types` continue to have one stable Interface.
export type {
  ActionClass,
  ActionControlCommandPayload,
  ActionControlSessionCommand,
  ActionGrant,
  ActionGrantBudget,
  ActionGrantStatus,
  ActionManifest,
  ActionSchemaRef,
  AgentRun,
  AgentRunCommandPayload,
  AgentRunLifecycle,
  AgentRunMode,
  AgentRunPolicySnapshot,
  AgentRunSessionCommand,
  ApprovalRequest,
  ApprovalRequestStatus,
  ApprovableActionClass,
  AttentionRequest,
  AttentionRequestStatus,
  CompletionPolicy,
  DirectiveAttributionInput,
  Duration,
  EligibleRunGrantUse,
  GoalDefinition,
  GoalEvidence,
  GoalItem,
  GoalSet,
  GoalStatus,
  GrantReview,
  GrantReviewReason,
  GrantReviewStatus,
  Money,
  ResourceEffect,
  RunActionPattern,
  RunLimit,
  RunLimits,
  RunPolicyCommit,
  RunPolicyDraft,
  RunPolicyRevision,
  RuntimeBinding,
  ScopedExternalRule,
  SessionRunStateQuery,
  SessionRunStateView,
  YoloConfirmation,
} from "./contracts";
