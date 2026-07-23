import type {
  ProjectRole,
  SteeringPolicy,
  TeamRole,
  TeamSessionAdmission,
  TeamSessionCommandBody,
  TeamSessionCommandResult,
  TeamSessionDetail,
  TeamSessionDiscovery,
  TeamSessionEvent,
  TeamSessionEventActor,
  TeamSessionIdentity,
  TeamSessionInboxItem,
  TeamSessionOpenHandoff,
  TeamSessionParticipant,
  TeamSessionProject,
  TeamSessionResponsibility,
  TeamSessionResponsibilities,
  TeamSessionRuntime,
  TeamSessionShare,
  TeamSessionStatus,
  TeamSessionTeam,
  TeamSessionViewer,
  TeamSessionViewerBasis,
  TeamSessionViewerCapabilities,
} from "@/types/team-session";

const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~:-]{0,127}$/;
const EVENT_TOP_LEVEL_FIELDS = [
  "schemaVersion",
  "eventId",
  "sessionId",
  "sequence",
  "type",
  "occurredAtMs",
  "actor",
  "sourceAdapter",
  "payload",
] as const;
const EVENT_PAYLOAD_MAX_DEPTH = 16;
const EVENT_PAYLOAD_MAX_ENTRIES = 1_000;
const JSON_MAX_DEPTH = 32;
const JSON_MAX_ENTRIES = 2_000;
const REDACTED_VALUE = "[redacted]";

export class HttpError extends Error {
  override readonly name = "HttpError";

  constructor(
    readonly status: number,
    readonly code: string,
    message: string
  ) {
    super(message);
  }

  get retryable(): boolean {
    return this.status === 408 || this.status === 429 || this.status >= 500;
  }
}

export interface TeamSessionFetchOptions {
  signal?: AbortSignal;
}

export interface TeamSessionInboxFetchOptions extends TeamSessionFetchOptions {
  teamId?: string;
}

export interface TeamSessionEventFetchOptions extends TeamSessionFetchOptions {
  afterSequence?: number;
  limit?: number;
}

export interface TeamSessionCommandOptions extends TeamSessionFetchOptions {
  /** Reuse this value when retrying the same user intent. */
  idempotencyKey?: string;
}

export async function fetchTeamSessionDiscovery(
  options: TeamSessionFetchOptions = {}
): Promise<TeamSessionDiscovery> {
  const body = await requestJson("/api/team-sessions/discovery", {
    method: "GET",
    signal: options.signal,
  });
  const envelope = requireRecord(body, "discovery response");
  requireExactFields(envelope, ["discovery"], "discovery response");
  return parseDiscovery(envelope.discovery);
}

export async function fetchTeamSessionInbox(
  options: TeamSessionInboxFetchOptions = {}
): Promise<TeamSessionInboxItem[]> {
  const query = new URLSearchParams();
  if (options.teamId !== undefined) {
    query.set("teamId", requireIdentifier(options.teamId, "Team id"));
  }
  const suffix = query.size === 0 ? "" : `?${query.toString()}`;
  const body = await requestJson(`/api/team-sessions${suffix}`, {
    method: "GET",
    signal: options.signal,
  });
  const envelope = requireRecord(body, "Session inbox response");
  requireExactFields(envelope, ["sessions"], "Session inbox response");
  return requireArray(envelope.sessions, "Session inbox").map((session) => parseInboxItem(session));
}

export async function fetchTeamSessionDetail(
  sessionId: string,
  options: TeamSessionFetchOptions = {}
): Promise<TeamSessionDetail> {
  const body = await requestJson(
    `/api/team-sessions/sessions/${encodeURIComponent(requireIdentifier(sessionId, "Session id"))}`,
    { method: "GET", signal: options.signal }
  );
  const envelope = requireRecord(body, "Session detail response");
  requireExactFields(envelope, ["session"], "Session detail response");
  return parseSessionDetail(envelope.session);
}

export async function fetchTeamSessionAdmission(
  sessionId: string,
  options: TeamSessionFetchOptions = {}
): Promise<TeamSessionAdmission> {
  const normalizedSessionId = requireIdentifier(sessionId, "Session id");
  const body = await requestJson(
    `/api/team-sessions/sessions/${encodeURIComponent(normalizedSessionId)}/admission`,
    { method: "GET", signal: options.signal }
  );
  const envelope = requireRecord(body, "Session admission response");
  requireExactFields(envelope, ["admission"], "Session admission response");
  return parseSessionAdmission(envelope.admission, normalizedSessionId);
}

export async function fetchTeamSessionEvents(
  sessionId: string,
  options: TeamSessionEventFetchOptions = {}
): Promise<TeamSessionEvent[]> {
  const query = new URLSearchParams();
  if (options.afterSequence !== undefined) {
    query.set(
      "afterSequence",
      String(requireSafeInteger(options.afterSequence, "afterSequence", 0))
    );
  }
  if (options.limit !== undefined) {
    query.set("limit", String(requireSafeInteger(options.limit, "limit", 1, 1_000)));
  }
  const suffix = query.size === 0 ? "" : `?${query.toString()}`;
  const body = await requestJson(
    `/api/team-sessions/sessions/${encodeURIComponent(requireIdentifier(sessionId, "Session id"))}/events${suffix}`,
    { method: "GET", signal: options.signal }
  );
  const envelope = requireRecord(body, "Session events response");
  requireExactFields(envelope, ["events"], "Session events response");
  return requireArray(envelope.events, "Session events").map((event) =>
    parseTeamSessionEvent(event, sessionId)
  );
}

export async function submitTeamSessionCommand(
  command: TeamSessionCommandBody,
  options: TeamSessionCommandOptions = {}
): Promise<TeamSessionCommandResult> {
  const idempotencyKey = options.idempotencyKey ?? createTeamSessionIdempotencyKey();
  if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) {
    throw new TypeError("Idempotency key is invalid");
  }

  const body = await requestJson("/api/team-sessions/commands", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify(command),
    signal: options.signal,
  });
  const envelope = requireRecord(body, "command response");
  requireExactFields(envelope, ["result"], "command response");
  return parseCommandResult(envelope.result, command.type);
}

export function createTeamSessionIdempotencyKey(): string {
  const cryptoObject = globalThis.crypto;
  if (typeof cryptoObject?.randomUUID === "function") {
    return `web:${cryptoObject.randomUUID()}`;
  }
  if (typeof cryptoObject?.getRandomValues === "function") {
    const bytes = cryptoObject.getRandomValues(new Uint8Array(16));
    const random = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `web:${random}`;
  }
  throw new Error("Secure random idempotency keys are unavailable");
}

/** Strictly parse the shared HTTP/WebSocket public event boundary. */
export function parseTeamSessionEvent(
  value: unknown,
  expectedSessionId?: string
): TeamSessionEvent {
  const event = requireRecord(value, "Session event");
  requireExactFields(event, EVENT_TOP_LEVEL_FIELDS, "Session event");
  const sessionId = requireString(event.sessionId, "Session event sessionId");
  if (expectedSessionId !== undefined && sessionId !== expectedSessionId) {
    throw invalidResponse("Session event belongs to another Session");
  }

  return {
    schemaVersion: requireLiteral(event.schemaVersion, 1, "Session event schemaVersion"),
    eventId: requireString(event.eventId, "Session event eventId"),
    sessionId,
    sequence: requireSafeInteger(event.sequence, "Session event sequence", 1),
    type: requireString(event.type, "Session event type"),
    occurredAtMs: requireSafeInteger(event.occurredAtMs, "Session event occurredAtMs", 0),
    actor: parseEventActor(event.actor),
    sourceAdapter: requireEnum(
      event.sourceAdapter,
      ["web", "slack", "telegram", "runtime", "internal"] as const,
      "Session event sourceAdapter"
    ),
    payload: cloneEventPayload(event.payload),
  };
}

async function requestJson(path: string, init: RequestInit): Promise<unknown> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  const response = await fetch(path, {
    ...init,
    headers,
    cache: "no-store",
    credentials: "same-origin",
  });

  let body: unknown;
  try {
    body = await response.json();
  } catch (cause) {
    if (init.signal?.aborted || isAbortError(cause)) throw cause;
    throw new HttpError(response.status, "invalid-response", "Server returned an invalid response");
  }
  if (!response.ok) {
    const problem = parseProblem(body);
    throw new HttpError(
      response.status,
      problem?.code ?? "http-error",
      problem?.message ?? `Request failed (${response.status})`
    );
  }
  return body;
}

function parseProblem(value: unknown): { code: string; message: string } | null {
  if (!isRecord(value) || !isRecord(value.error)) return null;
  const { code, message } = value.error;
  return typeof code === "string" && typeof message === "string" ? { code, message } : null;
}

function parseDiscovery(value: unknown): TeamSessionDiscovery {
  const discovery = requireRecord(value, "discovery");
  requireExactFields(discovery, ["teams"], "discovery");
  return {
    teams: requireArray(discovery.teams, "discovery teams").map(parseTeam),
  };
}

function parseTeam(value: unknown): TeamSessionTeam {
  const team = requireRecord(value, "Team");
  requireExactFields(
    team,
    ["teamId", "name", "createdAtMs", "viewerMembership", "capabilities", "projects"],
    "Team"
  );
  const viewerMembership = requireRecord(team.viewerMembership, "Team viewer membership");
  requireExactFields(viewerMembership, ["role", "version"], "Team viewer membership");
  const capabilities = requireRecord(team.capabilities, "Team capabilities");
  requireExactFields(capabilities, ["createProject", "manageMemberships"], "Team capabilities");
  return {
    teamId: requireString(team.teamId, "Team id"),
    name: requireString(team.name, "Team name"),
    createdAtMs: requireSafeInteger(team.createdAtMs, "Team createdAtMs", 0),
    viewerMembership: {
      role: requireTeamRole(viewerMembership.role, "Team membership role"),
      version: requireSafeInteger(viewerMembership.version, "Team membership version", 1),
    },
    capabilities: {
      createProject: requireBoolean(capabilities.createProject, "createProject capability"),
      manageMemberships: requireBoolean(
        capabilities.manageMemberships,
        "manageMemberships capability"
      ),
    },
    projects: requireArray(team.projects, "Team projects").map(parseProject),
  };
}

function parseProject(value: unknown): TeamSessionProject {
  const project = requireRecord(value, "Project");
  requireExactFields(
    project,
    ["projectId", "name", "createdAtMs", "visibility", "capabilities"],
    "Project",
    ["viewerAccess"]
  );
  const capabilities = requireRecord(project.capabilities, "Project capabilities");
  requireExactFields(
    capabilities,
    ["viewContent", "startSession", "manageAccess"],
    "Project capabilities"
  );
  let viewerAccess: TeamSessionProject["viewerAccess"];
  if (project.viewerAccess !== undefined) {
    const access = requireRecord(project.viewerAccess, "Project viewer access");
    requireExactFields(access, ["role", "version"], "Project viewer access");
    viewerAccess = {
      role: requireProjectRole(access.role, "Project viewer role"),
      version: requireSafeInteger(access.version, "Project viewer access version", 1),
    };
  }
  return {
    projectId: requireString(project.projectId, "Project id"),
    name: requireString(project.name, "Project name"),
    createdAtMs: requireSafeInteger(project.createdAtMs, "Project createdAtMs", 0),
    visibility: requireEnum(
      project.visibility,
      ["content", "administration", "session-only"] as const,
      "Project visibility"
    ),
    ...(viewerAccess === undefined ? {} : { viewerAccess }),
    capabilities: {
      viewContent: requireBoolean(capabilities.viewContent, "viewContent capability"),
      startSession: requireBoolean(capabilities.startSession, "startSession capability"),
      manageAccess: requireBoolean(capabilities.manageAccess, "manageAccess capability"),
    },
  };
}

function parseInboxItem(value: unknown, detail = false): TeamSessionInboxItem {
  const session = requireRecord(value, "Session");
  requireExactFields(
    session,
    [
      "sessionId",
      "teamId",
      "projectId",
      "name",
      "status",
      "steeringPolicy",
      "runtime",
      "responsibilities",
      "viewer",
      "latestSequence",
      "createdAtMs",
    ],
    "Session",
    detail ? ["participants", "shares", "openHandoffs"] : []
  );
  return {
    sessionId: requireString(session.sessionId, "Session id"),
    teamId: requireString(session.teamId, "Session teamId"),
    projectId: requireString(session.projectId, "Session projectId"),
    name: requireString(session.name, "Session name"),
    status: requireEnum(
      session.status,
      ["active", "awaiting_assignee", "ended"] as const satisfies readonly TeamSessionStatus[],
      "Session status"
    ),
    steeringPolicy: requireEnum(
      session.steeringPolicy,
      ["single", "shared"] as const satisfies readonly SteeringPolicy[],
      "Session steering policy"
    ),
    runtime: parseRuntime(session.runtime),
    responsibilities: parseResponsibilities(session.responsibilities),
    viewer: parseViewer(session.viewer),
    latestSequence: requireSafeInteger(session.latestSequence, "Session latestSequence", 0),
    createdAtMs: requireSafeInteger(session.createdAtMs, "Session createdAtMs", 0),
  };
}

function parseSessionDetail(value: unknown): TeamSessionDetail {
  const session = requireRecord(value, "Session detail");
  const inbox = parseInboxItem(session, true);
  return {
    ...inbox,
    participants: requireArray(session.participants, "Session participants").map(parseParticipant),
    shares: requireArray(session.shares, "Session shares").map(parseShare),
    openHandoffs: requireArray(session.openHandoffs, "Session open Handoffs").map(parseOpenHandoff),
  };
}

function parseSessionAdmission(value: unknown, expectedSessionId: string): TeamSessionAdmission {
  const admission = requireRecord(value, "Session admission");
  requireExactFields(
    admission,
    ["sessionId", "accessRevision", "capabilities", "activeInvitations", "accessCandidates"],
    "Session admission"
  );
  const sessionId = requireString(admission.sessionId, "Session admission session id");
  if (sessionId !== expectedSessionId) {
    throw invalidResponse("Session admission belongs to another Session");
  }
  const capabilities = requireRecord(admission.capabilities, "Session admission capabilities");
  requireExactFields(
    capabilities,
    ["canRevokeInvitations", "canGrantGuestShare", "canGrantProjectAccess"],
    "Session admission capabilities"
  );
  return {
    sessionId,
    accessRevision: requireSafeInteger(admission.accessRevision, "Session access revision", 1),
    capabilities: {
      canRevokeInvitations: requireBoolean(
        capabilities.canRevokeInvitations,
        "Invitation revocation capability"
      ),
      canGrantGuestShare: requireBoolean(capabilities.canGrantGuestShare, "Guest share capability"),
      canGrantProjectAccess: requireBoolean(
        capabilities.canGrantProjectAccess,
        "Project access capability"
      ),
    },
    activeInvitations: requireArray(admission.activeInvitations, "Active Session invitations").map(
      (value) => {
        const invitation = requireRecord(value, "Active Session invitation");
        requireExactFields(
          invitation,
          ["invitationId", "membershipRole", "version", "expiresAtMs"],
          "Active Session invitation"
        );
        return {
          invitationId: requireString(invitation.invitationId, "Invitation id"),
          membershipRole: requireEnum(
            invitation.membershipRole,
            ["member", "guest"] as const,
            "Invitation membership role"
          ),
          version: requireSafeInteger(invitation.version, "Invitation version", 1),
          expiresAtMs: requireSafeInteger(invitation.expiresAtMs, "Invitation expiresAtMs", 0),
        };
      }
    ),
    accessCandidates: requireArray(admission.accessCandidates, "Session access candidates").map(
      (value) => {
        const candidate = requireRecord(value, "Session access candidate");
        const membershipRole = requireEnum(
          candidate.membershipRole,
          ["member", "guest"] as const,
          "Access candidate membership role"
        );
        const common = {
          invitationId: requireString(candidate.invitationId, "Access candidate invitation id"),
          userId: requireString(candidate.userId, "Access candidate user id"),
          displayName: requireString(candidate.displayName, "Access candidate display name", true),
        };
        if (membershipRole === "guest") {
          requireExactFields(
            candidate,
            ["invitationId", "userId", "displayName", "membershipRole", "requiredGrant"],
            "Guest access candidate"
          );
          return {
            ...common,
            membershipRole,
            requiredGrant: requireLiteral(
              candidate.requiredGrant,
              "session-share",
              "Guest access requirement"
            ),
          };
        }
        requireExactFields(
          candidate,
          [
            "invitationId",
            "userId",
            "displayName",
            "membershipRole",
            "requiredGrant",
            "expectedProjectAccessVersion",
          ],
          "Member access candidate"
        );
        return {
          ...common,
          membershipRole,
          requiredGrant: requireLiteral(
            candidate.requiredGrant,
            "project-access",
            "Member access requirement"
          ),
          expectedProjectAccessVersion: requireSafeInteger(
            candidate.expectedProjectAccessVersion,
            "Expected Project access version",
            0
          ),
        };
      }
    ),
  };
}

function parseRuntime(value: unknown): TeamSessionRuntime {
  const runtime = requireRecord(value, "Session Runtime");
  requireExactFields(
    runtime,
    ["kind", "isolation", "yoloEligible", "authorizationGeneration", "authorizationState"],
    "Session Runtime"
  );
  return {
    kind: requireLiteral(runtime.kind, "local-tmux", "Runtime kind"),
    isolation: requireLiteral(runtime.isolation, "trusted-shared-host", "Runtime isolation"),
    yoloEligible: requireLiteral(runtime.yoloEligible, false, "Runtime YOLO eligibility"),
    authorizationGeneration: requireSafeInteger(
      runtime.authorizationGeneration,
      "Runtime authorization generation",
      1
    ),
    authorizationState: requireEnum(
      runtime.authorizationState,
      ["enforced", "pending", "quarantined"] as const,
      "Runtime authorization state"
    ),
  };
}

function parseResponsibilities(value: unknown): TeamSessionResponsibilities {
  const responsibilities = requireRecord(value, "Session responsibilities");
  requireExactFields(responsibilities, ["supervisors", "steerers"], "Session responsibilities", [
    "assignee",
    "controller",
  ]);
  return {
    ...(responsibilities.assignee === undefined
      ? {}
      : { assignee: parseIdentity(responsibilities.assignee) }),
    supervisors: requireArray(responsibilities.supervisors, "Session supervisors").map(
      parseIdentity
    ),
    steerers: requireArray(responsibilities.steerers, "Session steerers").map(parseIdentity),
    ...(responsibilities.controller === undefined
      ? {}
      : { controller: parseIdentity(responsibilities.controller) }),
  };
}

function parseIdentity(value: unknown): TeamSessionIdentity {
  const identity = requireRecord(value, "Session identity");
  requireExactFields(identity, ["participantId", "userId", "displayName"], "Session identity");
  return {
    participantId: requireString(identity.participantId, "Participant id"),
    userId: requireString(identity.userId, "Participant user id"),
    displayName: requireString(identity.displayName, "Participant display name", true),
  };
}

function parseParticipant(value: unknown): TeamSessionParticipant {
  const participant = requireRecord(value, "Session participant");
  requireExactFields(
    participant,
    [
      "participantId",
      "userId",
      "displayName",
      "membershipRole",
      "observer",
      "responsibilities",
      "responsibilityVersions",
      "joinedAtMs",
      "version",
    ],
    "Session participant"
  );
  return {
    ...parseIdentity({
      participantId: participant.participantId,
      userId: participant.userId,
      displayName: participant.displayName,
    }),
    membershipRole: requireTeamRole(participant.membershipRole, "Participant membership role"),
    observer: requireBoolean(participant.observer, "Participant observer flag"),
    responsibilities: parseResponsibilityList(participant.responsibilities),
    responsibilityVersions: parseResponsibilityVersions(participant.responsibilityVersions),
    joinedAtMs: requireSafeInteger(participant.joinedAtMs, "Participant joinedAtMs", 0),
    version: requireSafeInteger(participant.version, "Participant version", 1),
  };
}

function parseShare(value: unknown): TeamSessionShare {
  const share = requireRecord(value, "Session share");
  requireExactFields(share, ["userId", "displayName", "version", "createdAtMs"], "Session share");
  return {
    userId: requireString(share.userId, "Share user id"),
    displayName: requireString(share.displayName, "Share display name", true),
    version: requireSafeInteger(share.version, "Share version", 1),
    createdAtMs: requireSafeInteger(share.createdAtMs, "Share createdAtMs", 0),
  };
}

function parseOpenHandoff(value: unknown): TeamSessionOpenHandoff {
  const handoff = requireRecord(value, "Session Handoff");
  requireExactFields(
    handoff,
    [
      "handoffId",
      "offererUserId",
      "recipientParticipantId",
      "recipientUserId",
      "offeredUnder",
      "version",
      "contextSequence",
      "expiresAtMs",
      "createdAtMs",
      "briefing",
    ],
    "Session Handoff"
  );
  const briefing = requireRecord(handoff.briefing, "Handoff briefing");
  requireExactFields(briefing, ["summary", "blockers", "artifactRefs"], "Handoff briefing");
  return {
    handoffId: requireString(handoff.handoffId, "Handoff id"),
    offererUserId: requireString(handoff.offererUserId, "Handoff offerer user id"),
    recipientParticipantId: requireString(
      handoff.recipientParticipantId,
      "Handoff recipient participant id"
    ),
    recipientUserId: requireString(handoff.recipientUserId, "Handoff recipient user id"),
    offeredUnder: requireEnum(
      handoff.offeredUnder,
      ["assignee", "supervisor"] as const,
      "Handoff offerer responsibility"
    ),
    version: requireSafeInteger(handoff.version, "Handoff version", 1),
    contextSequence: requireSafeInteger(handoff.contextSequence, "Handoff context sequence", 0),
    expiresAtMs: requireSafeInteger(handoff.expiresAtMs, "Handoff expiresAtMs", 0),
    createdAtMs: requireSafeInteger(handoff.createdAtMs, "Handoff createdAtMs", 0),
    briefing: {
      summary: requireString(briefing.summary, "Handoff summary", true),
      blockers: parseStringArray(briefing.blockers, "Handoff blockers"),
      artifactRefs: parseStringArray(briefing.artifactRefs, "Handoff artifact refs"),
    },
  };
}

function parseViewer(value: unknown): TeamSessionViewer {
  const viewer = requireRecord(value, "Session viewer");
  requireExactFields(
    viewer,
    [
      "participantId",
      "userId",
      "displayName",
      "membershipRole",
      "responsibilities",
      "basis",
      "capabilities",
    ],
    "Session viewer"
  );
  return {
    ...parseIdentity({
      participantId: viewer.participantId,
      userId: viewer.userId,
      displayName: viewer.displayName,
    }),
    membershipRole: requireTeamRole(viewer.membershipRole, "Viewer membership role"),
    responsibilities: parseResponsibilityList(viewer.responsibilities),
    basis: parseViewerBasis(viewer.basis),
    capabilities: parseViewerCapabilities(viewer.capabilities),
  };
}

function parseViewerBasis(value: unknown): TeamSessionViewerBasis {
  const basis = requireRecord(value, "Session viewer basis");
  requireExactFields(
    basis,
    [
      "participantVersion",
      "teamMembershipVersion",
      "responsibilityVersions",
      "accessRevision",
      "assigneeRevision",
      "supervisionRevision",
      "steeringRevision",
      "controlRevision",
      "controlEpoch",
      "runtimeAuthorizationGeneration",
      "latestSequence",
    ],
    "Session viewer basis",
    ["projectAccessVersion"]
  );
  return {
    participantVersion: requireSafeInteger(
      basis.participantVersion,
      "Viewer participant version",
      1
    ),
    teamMembershipVersion: requireSafeInteger(
      basis.teamMembershipVersion,
      "Viewer Team membership version",
      1
    ),
    ...(basis.projectAccessVersion === undefined
      ? {}
      : {
          projectAccessVersion: requireSafeInteger(
            basis.projectAccessVersion,
            "Viewer Project access version",
            1
          ),
        }),
    responsibilityVersions: parseResponsibilityVersions(basis.responsibilityVersions),
    accessRevision: requireSafeInteger(basis.accessRevision, "Session access revision", 0),
    assigneeRevision: requireSafeInteger(basis.assigneeRevision, "Session assignee revision", 0),
    supervisionRevision: requireSafeInteger(
      basis.supervisionRevision,
      "Session supervision revision",
      0
    ),
    steeringRevision: requireSafeInteger(basis.steeringRevision, "Session steering revision", 0),
    controlRevision: requireSafeInteger(basis.controlRevision, "Session control revision", 0),
    controlEpoch: requireSafeInteger(basis.controlEpoch, "Session control epoch", 0),
    runtimeAuthorizationGeneration: requireSafeInteger(
      basis.runtimeAuthorizationGeneration,
      "Runtime authorization generation",
      1
    ),
    latestSequence: requireSafeInteger(basis.latestSequence, "Viewer latest sequence", 0),
  };
}

function parseViewerCapabilities(value: unknown): TeamSessionViewerCapabilities {
  const capabilities = requireRecord(value, "Session viewer capabilities");
  const fields = [
    "addComment",
    "addSuggestion",
    "resolveSuggestion",
    "enqueueDirective",
    "observeTerminal",
    "mutateTerminal",
    "createInvitation",
    "revokeInvitation",
    "manageShares",
    "manageParticipants",
    "manageSupervisors",
    "manageSteerers",
    "transferControl",
    "releaseControl",
    "offerHandoff",
    "acceptHandoff",
    "cancelHandoff",
    "claimAssignee",
  ] as const satisfies readonly (keyof TeamSessionViewerCapabilities)[];
  requireExactFields(capabilities, fields, "Session viewer capabilities");
  return Object.fromEntries(
    fields.map((field) => [field, requireBoolean(capabilities[field], `${field} capability`)])
  ) as unknown as TeamSessionViewerCapabilities;
}

function parseCommandResult(
  value: unknown,
  expectedCommandType: TeamSessionCommandBody["type"]
): TeamSessionCommandResult {
  const result = requireRecord(value, "command result");
  requireExactFields(
    result,
    ["accepted", "commandType", "replayed", "data", "events"],
    "command result"
  );
  const commandType = requireString(result.commandType, "command result type");
  if (commandType !== expectedCommandType) {
    throw invalidResponse("Command receipt type does not match the submitted command");
  }
  const data = cloneJsonRecord(result.data, "command result data");
  assertSensitiveValuesRedacted(
    data,
    "command result data",
    expectedCommandType === "session.invitation.create"
      ? new Set(["invitationToken", "invitationTokenUnavailable"])
      : undefined
  );
  return {
    accepted: requireLiteral(result.accepted, true, "command accepted flag"),
    commandType: expectedCommandType,
    replayed: requireBoolean(result.replayed, "command replayed flag"),
    data,
    events: requireArray(result.events, "command events").map((event) =>
      parseTeamSessionEvent(event)
    ),
  };
}

function parseEventActor(value: unknown): TeamSessionEventActor {
  const actor = requireRecord(value, "Session event actor");
  requireExactFields(actor, ["kind", "userId", "displayName"], "Session event actor");
  return {
    kind: requireEnum(actor.kind, ["human", "system"] as const, "Session event actor kind"),
    userId: requireString(actor.userId, "Session event actor user id"),
    displayName: requireString(actor.displayName, "Session event actor display name", true),
  };
}

function cloneEventPayload(value: unknown): Record<string, unknown> {
  const budget = { remaining: EVENT_PAYLOAD_MAX_ENTRIES };
  const cloned = cloneJson(value, 0, EVENT_PAYLOAD_MAX_DEPTH, budget, true);
  if (!isRecord(cloned)) throw invalidResponse("Session event payload is invalid");
  return cloned;
}

function cloneJsonRecord(value: unknown, label: string): Record<string, unknown> {
  const cloned = cloneJson(value, 0, JSON_MAX_DEPTH, { remaining: JSON_MAX_ENTRIES }, false);
  if (!isRecord(cloned)) throw invalidResponse(`${label} is invalid`);
  return cloned;
}

function cloneJson(
  value: unknown,
  depth: number,
  maximumDepth: number,
  budget: { remaining: number },
  requireRedaction: boolean
): unknown {
  if (depth > maximumDepth) {
    if (requireRedaction && value === REDACTED_VALUE) return value;
    throw invalidResponse("Public JSON exceeds its depth limit");
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    const result: unknown[] = [];
    for (const entry of value) {
      consumeJsonBudget(budget);
      result.push(cloneJson(entry, depth + 1, maximumDepth, budget, requireRedaction));
    }
    return result;
  }
  if (!isRecord(value)) throw invalidResponse("Public JSON contains an invalid value");

  const result: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    consumeJsonBudget(budget);
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      throw invalidResponse("Public JSON contains an unsafe field");
    }
    if (requireRedaction && isSensitiveFieldName(key) && entry !== REDACTED_VALUE) {
      throw invalidResponse("Session event contains unredacted sensitive data");
    }
    result[key] = cloneJson(entry, depth + 1, maximumDepth, budget, requireRedaction);
  }
  return result;
}

function assertSensitiveValuesRedacted(
  value: unknown,
  label: string,
  allowedUnredactedFields: ReadonlySet<string> = new Set()
): void {
  const queue: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let entries = 0;
  while (queue.length > 0) {
    const current = queue.pop();
    if (!current) break;
    if (Array.isArray(current.value)) {
      entries += current.value.length;
      queue.push(...current.value.map((entry) => ({ value: entry, depth: current.depth + 1 })));
      continue;
    }
    if (!isRecord(current.value)) continue;
    const pairs = Object.entries(current.value);
    entries += pairs.length;
    if (entries > JSON_MAX_ENTRIES) throw invalidResponse(`${label} has too many entries`);
    for (const [key, entry] of pairs) {
      if (
        isSensitiveFieldName(key) &&
        entry !== REDACTED_VALUE &&
        !(current.depth === 0 && allowedUnredactedFields.has(key))
      ) {
        throw invalidResponse(`${label} contains unredacted sensitive data`);
      }
      queue.push({ value: entry, depth: current.depth + 1 });
    }
  }
}

function consumeJsonBudget(budget: { remaining: number }): void {
  if (budget.remaining === 0) throw invalidResponse("Public JSON exceeds its entry limit");
  budget.remaining -= 1;
}

function isSensitiveFieldName(key: string): boolean {
  const normalized = key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .toLowerCase();
  return (
    normalized === "authorization" ||
    /(?:^|_)(?:token|secret|password|passphrase|private_key|api_key|access_key|encryption_key|signing_key|key_material|ssh_key|mnemonic|seed_phrase|recovery_phrase|credential|cookie|bearer|authorization_header|authorization_token)(?:_|$)/.test(
      normalized
    )
  );
}

function parseResponsibilityList(value: unknown): TeamSessionResponsibility[] {
  return requireArray(value, "Session responsibilities").map((responsibility) =>
    requireEnum(
      responsibility,
      ["assignee", "supervisor", "steerer", "controller"] as const,
      "Session responsibility"
    )
  );
}

function parseResponsibilityVersions(
  value: unknown
): Partial<Record<TeamSessionResponsibility, number>> {
  const versions = requireRecord(value, "Session responsibility versions");
  const allowed = ["assignee", "supervisor", "steerer", "controller"] as const;
  requireExactFields(versions, [], "Session responsibility versions", allowed);
  return Object.fromEntries(
    Object.entries(versions).map(([responsibility, version]) => [
      responsibility,
      requireSafeInteger(version, `${responsibility} responsibility version`, 1),
    ])
  );
}

function parseStringArray(value: unknown, label: string): string[] {
  return requireArray(value, label).map((entry) => requireString(entry, label, true));
}

function requireTeamRole(value: unknown, label: string): TeamRole {
  return requireEnum(value, ["owner", "admin", "member", "guest"] as const, label);
}

function requireProjectRole(value: unknown, label: string): ProjectRole {
  return requireEnum(value, ["maintainer", "contributor"] as const, label);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw invalidResponse(`${label} is invalid`);
  return value;
}

function requireArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw invalidResponse(`${label} is invalid`);
  return value;
}

function requireString(value: unknown, label: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) {
    throw invalidResponse(`${label} is invalid`);
  }
  return value;
}

function requireIdentifier(value: string, label: string): string {
  if (
    value.length === 0 ||
    value.length > 300 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw invalidResponse(`${label} is invalid`);
  return value;
}

function requireSafeInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw invalidResponse(`${label} is invalid`);
  }
  return value as number;
}

function requireEnum<const Values extends readonly string[]>(
  value: unknown,
  allowed: Values,
  label: string
): Values[number] {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    throw invalidResponse(`${label} is invalid`);
  }
  return value as Values[number];
}

function requireLiteral<const Value extends string | number | boolean>(
  value: unknown,
  expected: Value,
  label: string
): Value {
  if (value !== expected) throw invalidResponse(`${label} is invalid`);
  return expected;
}

function requireExactFields(
  value: Record<string, unknown>,
  required: readonly string[],
  label: string,
  optional: readonly string[] = []
): void {
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((field) => !Object.hasOwn(value, field)) ||
    Object.keys(value).some((field) => !allowed.has(field))
  ) {
    throw invalidResponse(`${label} has an unexpected shape`);
  }
}

function invalidResponse(message: string): HttpError {
  return new HttpError(200, "invalid-response", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isAbortError(cause: unknown): boolean {
  return isRecord(cause) && cause.name === "AbortError";
}
