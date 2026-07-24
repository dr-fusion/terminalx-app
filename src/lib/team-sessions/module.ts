import * as crypto from "crypto";
import * as path from "path";
import type Database from "better-sqlite3";
import { openTeamSessionDatabase } from "./sqlite";
import { isValidTmuxSessionName } from "../tmux";
import { projectPublicSessionRunState } from "./public-run-state";
import type { RuntimeAuthorizationSnapshot, RuntimeLifecycleCommand } from "../runtime/contracts";
import type { RuntimeCommandAuthorityIssuer } from "../runtime/runtime-command-authority";
import {
  createRuntimeCompensationMaterializer,
  type RuntimeCompensationAuthorityIssuer,
  type RuntimeCompensationCommandAuthorityVerifier,
  type RuntimeCompensationMaterializer,
  type RuntimeCompensationPolicySource,
} from "../runtime/runtime-compensation-materializer";
import type { RuntimeCompensationJournal } from "../runtime/runtime-compensation-supervisor";
import type { SynchronousRuntimeCompensationEnforcementProofVerifier } from "../runtime/runtime-compensation-enforcement-proof";
import type { SynchronousRuntimeEnforcementProofVerifier } from "../runtime/runtime-enforcement-proof";
import type { RuntimeLifecycleJournal } from "../runtime/runtime-lifecycle-supervisor";
import {
  createSqliteRuntimeCompensationJournal,
  type SqliteRuntimeCompensationJournal,
} from "./sqlite-runtime-compensation-journal";
import {
  createSqliteRuntimeLifecycleJournal,
  type SqliteRuntimeLifecycleJournal,
} from "./sqlite-runtime-lifecycle-journal";
import {
  createSqliteRuntimeReceiptFollowJournal,
  type SqliteRuntimeReceiptFollowJournal,
} from "./sqlite-runtime-receipt-follow-journal";
import {
  createSqliteRuntimeWriteStateSnapshotSource,
  type RuntimeWriteStateSnapshotSource,
} from "./sqlite-runtime-write-state-source";
import {
  assertValidRunPolicyCommit,
  isRunPolicyWidening,
  validateInitialGoals,
} from "./run-policy";
import {
  RUNTIME_OUTBOX_ERROR_CODES,
  TEAM_SESSION_SCHEMA_VERSION,
  TeamSessionError,
  type ActorContext,
  type CommandResult,
  type FollowSessionOptions,
  type ProjectRole,
  type ProjectAccessQuery,
  type ProjectAccessView,
  type PublicOpenHandoffView,
  type PublicSessionIdentityView,
  type PublicSessionParticipantView,
  type PublicSessionResponsibilityView,
  type PublicSessionRunStateQuery,
  type PublicSessionRunStateView,
  type PublicSessionShareView,
  type RuntimeOutboxClaimOptions,
  type RuntimeOutboxDelivery,
  type RuntimeOutboxKind,
  type SessionCommand,
  type SessionAdmissionQuery,
  type SessionAdmissionView,
  type SessionDetailQuery,
  type SessionDetailView,
  type SessionEvent,
  type SessionEventsQuery,
  type SessionGetQuery,
  type SessionInboxItemView,
  type SessionInboxQuery,
  type SessionListQuery,
  type SessionParticipantView,
  type SessionResponsibility,
  type SessionRunStateQuery,
  type SessionRunStateView,
  type SessionTerminalAuthorizationQuery,
  type SessionView,
  type SessionViewerCapabilities,
  type SessionViewerView,
  type TeamRole,
  type TeamAccessQuery,
  type TeamAccessView,
  type TeamSessions,
  type TerminalAuthorization,
  type WorkspaceDiscoveryQuery,
  type WorkspaceDiscoveryView,
  type WorkspaceProjectView,
  type AgentRunLifecycle,
  type AgentRunPolicySnapshot,
  type GoalDefinition,
  type GoalEvidence,
  type GoalItem,
  type GoalSet,
  type RunPolicyDraft,
  type RuntimeBinding,
} from "./types";

type SqlValue = string | number | null;
type SqlRow = Record<string, SqlValue>;

export interface CreateTeamSessionsOptions {
  filename?: string;
  clock?: () => number;
  idGenerator?: () => string;
  invitationTokenGenerator?: () => string;
  /** Required before any ordinary Runtime-backed Run lifecycle intent is accepted. */
  runtimeCommandAuthorityIssuer?: RuntimeCommandAuthorityIssuer;
  /**
   * Trusted, control-plane-owned Runtime authorization state. Runtime/provider
   * payloads must never implement this seam.
   */
  runtimeAuthorizationSnapshotSource?: RuntimeAuthorizationSnapshotSource;
  /**
   * Synchronously authenticates every effect-enforcer acknowledgement before
   * the SQLite journal may change lifecycle truth.
   */
  runtimeEnforcementProofVerifier?: SynchronousRuntimeEnforcementProofVerifier;
  runtimeLifecycleCommandTtlMs?: number;
  /** Separately pinned platform-security signer; it may issue only quarantine commands. */
  runtimeCompensationAuthorityIssuer?: RuntimeCompensationAuthorityIssuer;
  /** Synchronous pinned-key verifier shared by materialization and durable dispatch. */
  runtimeCompensationAuthorityVerifier?: RuntimeCompensationCommandAuthorityVerifier;
  /** Control-plane-owned containment policy; Runtime/provider data cannot implement this seam. */
  runtimeCompensationPolicySource?: RuntimeCompensationPolicySource;
  /** Synchronously authenticates every containment-enforcer acknowledgement. */
  runtimeCompensationEnforcementProofVerifier?: SynchronousRuntimeCompensationEnforcementProofVerifier;
}

export interface RuntimeAuthorizationSnapshotQuery {
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
}

/** Synchronous because authorization is captured inside the command transaction. */
export interface RuntimeAuthorizationSnapshotSource {
  resolve(query: RuntimeAuthorizationSnapshotQuery): RuntimeAuthorizationSnapshot | undefined;
}

/** Security-sensitive composition result used only by the Runtime worker root. */
export interface TeamSessionKernel {
  readonly teamSessions: TeamSessions;
  /** Private restart seam used before Runtime transports accept mutations. */
  readonly runtimeWriteStateSnapshotSource: RuntimeWriteStateSnapshotSource;
  readonly runtimeLifecycleJournal: RuntimeLifecycleJournal;
  /** Private worker seam; never project this journal through HTTP or browser state. */
  readonly runtimeReceiptFollowJournal: SqliteRuntimeReceiptFollowJournal;
  /** Private platform-security worker seam; absent unless its complete trust group is configured. */
  readonly runtimeCompensationJournal?: RuntimeCompensationJournal;
  /** Private signer worker seam; absent unless its complete trust group is configured. */
  readonly runtimeCompensationMaterializer?: RuntimeCompensationMaterializer;
}

const ROLE_RANK: Record<TeamRole, number> = {
  guest: 0,
  member: 1,
  admin: 2,
  owner: 3,
};

const RESPONSIBILITY_ORDER: SessionResponsibility[] = [
  "assignee",
  "supervisor",
  "steerer",
  "controller",
];

const DEFAULT_HANDOFF_TTL_MS = 24 * 60 * 60 * 1_000;
const MAX_CONVERSATION_BODY_BYTES = 16 * 1_024;
const MAX_PENDING_DIRECTIVES_PER_AUTHOR = 64;
const MAX_PENDING_DIRECTIVES_PER_SESSION = 256;
const DEFAULT_RUNTIME_LIFECYCLE_COMMAND_TTL_MS = 30_000;
const MAX_RUNTIME_LIFECYCLE_COMMAND_TTL_MS = 5 * 60_000;
const SHA256_DIGEST = /^[0-9a-f]{64}$/;
const RUNTIME_AUTHORIZATION_SNAPSHOT_FIELDS = [
  "credentialPolicyDigest",
  "credentialPolicyRef",
  "effectEnforcerSetDigest",
  "generation",
  "networkPolicyDigest",
  "networkPolicyRef",
] as const;
const LOCAL_TMUX_PROJECT_CEILING_REVISION = "local-tmux-ceiling:v1";
const LOCAL_TMUX_PROJECT_CEILING_DIGEST = sha256(
  "terminalx:local-tmux:trusted-shared-host:no-yolo:v1"
);

type ConversationIdentityKind = "comment" | "suggestion" | "resolution" | "directive";

interface MutableGoalItem {
  goalId: string;
  position: number;
  title: string;
  acceptanceCriteria: string[];
  dependencyGoalIds: string[];
  version: number;
  status: GoalItem["status"];
}

interface AssigneeLossRunTransition {
  agentRunId: string;
  lifecycle: "pausing" | "paused" | "agent-work-finished";
  stateVersion: number;
  sandboxState: "recovering" | "quarantined";
  invalidatedGrantCount: number;
  runStateRevision: number;
}

type RuntimeOutboxPayload<K extends RuntimeOutboxKind> = Extract<
  RuntimeOutboxDelivery,
  { kind: K }
>["payload"];

export function createTeamSessions(options: CreateTeamSessionsOptions = {}): TeamSessions {
  return new SqliteTeamSessions(options);
}

export function createTeamSessionKernel(
  options: CreateTeamSessionsOptions = {}
): TeamSessionKernel {
  const teamSessions = new SqliteTeamSessions(options);
  const runtimeCompensationJournal = teamSessions.runtimeCompensationJournalForSupervisor();
  const runtimeCompensationMaterializer = teamSessions.runtimeCompensationMaterializerForWorker();
  return Object.freeze({
    teamSessions,
    runtimeWriteStateSnapshotSource: teamSessions.runtimeWriteStateSnapshotSourceForKernel(),
    runtimeLifecycleJournal: teamSessions.runtimeJournalForSupervisor(),
    runtimeReceiptFollowJournal: teamSessions.runtimeReceiptFollowJournalForSupervisor(),
    ...(runtimeCompensationJournal === undefined ? {} : { runtimeCompensationJournal }),
    ...(runtimeCompensationMaterializer === undefined ? {} : { runtimeCompensationMaterializer }),
  });
}

class SqliteTeamSessions implements TeamSessions {
  private readonly database: ReturnType<typeof openTeamSessionDatabase>;
  private readonly db: Database.Database;
  private readonly clock: () => number;
  private readonly idGenerator: () => string;
  private readonly invitationTokenGenerator: () => string;
  private readonly runtimeCommandAuthorityIssuer?: RuntimeCommandAuthorityIssuer;
  private readonly runtimeAuthorizationSnapshotSource?: RuntimeAuthorizationSnapshotSource;
  private readonly runtimeEnforcementProofVerifier?: SynchronousRuntimeEnforcementProofVerifier;
  private readonly runtimeLifecycleCommandTtlMs: number;
  private readonly runtimeWriteStateSnapshotSource: RuntimeWriteStateSnapshotSource;
  private readonly runtimeLifecycle: SqliteRuntimeLifecycleJournal;
  private readonly runtimeReceiptFollow: SqliteRuntimeReceiptFollowJournal;
  private readonly runtimeCompensation?: SqliteRuntimeCompensationJournal;
  private readonly runtimeCompensationMaterializer?: RuntimeCompensationMaterializer;
  private closed = false;

  constructor(options: CreateTeamSessionsOptions) {
    const runtimeSecurityComponentCount = [
      options.runtimeCommandAuthorityIssuer,
      options.runtimeAuthorizationSnapshotSource,
      options.runtimeEnforcementProofVerifier,
    ].filter((component) => component !== undefined).length;
    if (runtimeSecurityComponentCount !== 0 && runtimeSecurityComponentCount !== 3) {
      throw new TypeError(
        "Runtime lifecycle authority, authorization snapshots, and enforcement proof verification must be configured together"
      );
    }
    const runtimeCompensationSecurityComponentCount = [
      options.runtimeCompensationAuthorityIssuer,
      options.runtimeCompensationAuthorityVerifier,
      options.runtimeCompensationPolicySource,
      options.runtimeCompensationEnforcementProofVerifier,
    ].filter((component) => component !== undefined).length;
    if (
      runtimeCompensationSecurityComponentCount !== 0 &&
      runtimeCompensationSecurityComponentCount !== 4
    ) {
      throw new TypeError(
        "Runtime compensation authority, policy, and enforcement proof verification must be configured together"
      );
    }
    if (runtimeCompensationSecurityComponentCount === 4 && runtimeSecurityComponentCount !== 3) {
      throw new TypeError(
        "Runtime compensation requires the complete Runtime lifecycle security configuration"
      );
    }
    if (
      options.runtimeAuthorizationSnapshotSource !== undefined &&
      typeof options.runtimeAuthorizationSnapshotSource.resolve !== "function"
    ) {
      throw new TypeError("Runtime Authorization snapshot source is invalid");
    }
    if (
      options.runtimeEnforcementProofVerifier !== undefined &&
      typeof options.runtimeEnforcementProofVerifier !== "function"
    ) {
      throw new TypeError("Runtime enforcement proof verifier is invalid");
    }
    this.database = openTeamSessionDatabase({
      filename:
        options.filename ??
        process.env.TERMINALX_TEAM_SESSION_DB_PATH ??
        path.join(process.cwd(), "data", "team-sessions.sqlite"),
    });
    this.db = this.database.db;
    this.clock = options.clock ?? Date.now;
    this.idGenerator = options.idGenerator ?? crypto.randomUUID;
    this.invitationTokenGenerator =
      options.invitationTokenGenerator ?? (() => crypto.randomBytes(32).toString("base64url"));
    this.runtimeCommandAuthorityIssuer = options.runtimeCommandAuthorityIssuer;
    this.runtimeAuthorizationSnapshotSource = options.runtimeAuthorizationSnapshotSource;
    this.runtimeEnforcementProofVerifier = options.runtimeEnforcementProofVerifier;
    this.runtimeLifecycleCommandTtlMs = boundedIntegerOption(
      options.runtimeLifecycleCommandTtlMs ?? DEFAULT_RUNTIME_LIFECYCLE_COMMAND_TTL_MS,
      1,
      MAX_RUNTIME_LIFECYCLE_COMMAND_TTL_MS,
      "Runtime lifecycle command TTL"
    );
    this.runtimeWriteStateSnapshotSource = createSqliteRuntimeWriteStateSnapshotSource({
      db: this.db,
    });
    this.runtimeLifecycle = createSqliteRuntimeLifecycleJournal({
      db: this.db,
      idGenerator: () => this.nextId("runtime-journal"),
      ...(this.runtimeEnforcementProofVerifier === undefined
        ? {}
        : { verifyEnforcementProof: this.runtimeEnforcementProofVerifier }),
    });
    if (
      options.runtimeCompensationAuthorityIssuer !== undefined &&
      options.runtimeCompensationAuthorityVerifier !== undefined &&
      options.runtimeCompensationPolicySource !== undefined &&
      options.runtimeCompensationEnforcementProofVerifier !== undefined
    ) {
      this.runtimeCompensation = createSqliteRuntimeCompensationJournal({
        db: this.db,
        idGenerator: () => this.nextId("runtime-compensation-journal"),
        verifyAuthority: options.runtimeCompensationAuthorityVerifier,
        verifyEnforcementProof: options.runtimeCompensationEnforcementProofVerifier,
      });
      this.runtimeCompensationMaterializer = createRuntimeCompensationMaterializer({
        journal: this.runtimeCompensation,
        authorityIssuer: options.runtimeCompensationAuthorityIssuer,
        verifyAuthority: options.runtimeCompensationAuthorityVerifier,
        policySource: options.runtimeCompensationPolicySource,
        idGenerator: () => this.nextId("runtime-compensation-command"),
        clock: this.clock,
      });
    }
    const runtimeCompensation = this.runtimeCompensation;
    this.runtimeReceiptFollow = createSqliteRuntimeReceiptFollowJournal({
      db: this.db,
      idGenerator: () => this.nextId("runtime-follow-event"),
      settleVerifiedReceiptInTransaction: (input) =>
        this.runtimeLifecycle.settleVerifiedReceiptInTransaction(input),
      ...(runtimeCompensation === undefined
        ? {}
        : {
            settleVerifiedCompensationReceiptInTransaction: (input) =>
              runtimeCompensation.settleVerifiedReceiptInTransaction(input),
          }),
    });
  }

  runtimeJournalForSupervisor(): RuntimeLifecycleJournal {
    return this.runtimeLifecycle;
  }

  runtimeWriteStateSnapshotSourceForKernel(): RuntimeWriteStateSnapshotSource {
    return this.runtimeWriteStateSnapshotSource;
  }

  runtimeReceiptFollowJournalForSupervisor(): SqliteRuntimeReceiptFollowJournal {
    return this.runtimeReceiptFollow;
  }

  runtimeCompensationJournalForSupervisor(): SqliteRuntimeCompensationJournal | undefined {
    return this.runtimeCompensation;
  }

  runtimeCompensationMaterializerForWorker(): RuntimeCompensationMaterializer | undefined {
    return this.runtimeCompensationMaterializer;
  }

  async dispatch(command: SessionCommand): Promise<CommandResult> {
    this.assertOpen();
    validateCommandEnvelope(command);
    const payloadDigest = commandDigest(command);
    const apply = this.db.transaction(() => {
      const replay = this.commandReplay(command, payloadDigest);
      if (replay) return replay;

      // A source may report when it observed a command, but only the kernel's
      // clock is authoritative for expiry checks and canonical timestamps.
      const now = this.clock();
      if (!Number.isSafeInteger(now) || now < 0) {
        throw new TeamSessionError("invalid-command", "Invalid command time");
      }
      const acceptedSequence = this.allocateAcceptedSequence();
      const result = { ...this.applyCommand(command, now), acceptedSequence };
      const stored = sanitizeResultForPersistence(result);
      this.db
        .prepare(
          `INSERT INTO accepted_commands (
             source_scope, source_key, payload_digest, command_type,
             accepted_sequence,
             actor_kind, actor_user_id, actor_display_name, payload_json,
             result_json, secret_result, accepted_at_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          command.idempotency.scope,
          command.idempotency.key,
          payloadDigest,
          command.type,
          acceptedSequence,
          command.actor.kind,
          command.actor.userId,
          command.actor.displayName,
          JSON.stringify(commandAuditPayload(command)),
          JSON.stringify(stored),
          result.data.invitationToken ? 1 : 0,
          now
        );
      return this.projectCommandResultForActor(result, command.actor);
    });

    try {
      return apply.immediate();
    } catch (error) {
      if (error instanceof TeamSessionError) throw error;
      if (isConstraintError(error)) {
        throw new TeamSessionError("conflict", "The requested transition conflicts with state");
      }
      throw error;
    }
  }

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
  inspect(query: SessionRunStateQuery): Promise<SessionRunStateView | null>;
  async inspect(
    query:
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
      | SessionRunStateQuery
  ): Promise<
    | SessionView
    | null
    | SessionView[]
    | WorkspaceDiscoveryView
    | SessionInboxItemView[]
    | SessionDetailView
    | PublicSessionRunStateView
    | SessionEvent[]
    | TerminalAuthorization
    | SessionAdmissionView
    | TeamAccessView
    | ProjectAccessView
    | SessionRunStateView
  > {
    this.assertOpen();
    if (!query || typeof query !== "object") {
      throw new TeamSessionError("invalid-command", "Invalid query");
    }
    validateQueryActor(query.actor);
    if (query.actor.kind !== "human") deny();
    if (query.schemaVersion !== TEAM_SESSION_SCHEMA_VERSION) {
      throw new TeamSessionError("invalid-command", "Unsupported query schema version");
    }
    validateQuery(query);

    const readSnapshot = this.db.transaction(() => {
      switch (query.type) {
        case "session.get":
          return this.hasSessionAccess(query.sessionId, query.actor.userId)
            ? this.projectSession(query.sessionId)
            : null;
        case "session.list":
          return this.listVisibleSessions(query.actor.userId, query.teamId);
        case "workspace.discovery":
          return this.projectWorkspaceDiscovery(query.actor.userId);
        case "session.inbox":
          return this.listPublicSessions(
            query.actor.userId,
            query.teamId,
            this.publicProjectionTime()
          );
        case "session.detail":
          return this.hasSessionAccess(query.sessionId, query.actor.userId)
            ? this.projectPublicSessionDetail(
                query.sessionId,
                query.actor.userId,
                this.publicProjectionTime()
              )
            : null;
        case "session.public-run-state": {
          if (!this.hasSessionAccess(query.sessionId, query.actor.userId)) return null;
          const session = this.projectPublicSessionDetail(
            query.sessionId,
            query.actor.userId,
            this.publicProjectionTime()
          );
          return projectPublicSessionRunState(
            session,
            this.projectSessionRunState(query.sessionId)
          );
        }
        case "session.events":
          if (!this.hasSessionAccess(query.sessionId, query.actor.userId)) return [];
          return this.readEvents(
            query.sessionId,
            Math.max(0, query.afterSequence ?? 0),
            clamp(query.limit ?? 200, 1, 1000)
          );
        case "session.terminal-authorization":
          return this.terminalAuthorization(query);
        case "session.admission":
          return this.projectSessionAdmission(query.sessionId, query.actor.userId);
        case "team.access":
          return this.projectTeamAccess(query.teamId, query.actor.userId);
        case "project.access":
          return this.projectProjectAccess(query.projectId, query.actor.userId);
        case "session.run-state":
          return this.hasSessionAccess(query.sessionId, query.actor.userId)
            ? this.projectSessionRunState(query.sessionId)
            : null;
      }
    });
    return readSnapshot();
  }

  performTerminalMutation(query: SessionTerminalAuthorizationQuery, mutation: () => void): void {
    this.assertOpen();
    if (!query || typeof query !== "object" || typeof mutation !== "function") {
      throw new TeamSessionError("invalid-command", "Invalid terminal mutation");
    }
    validateQueryActor(query.actor);
    if (query.actor.kind !== "human") deny();
    if (query.schemaVersion !== TEAM_SESSION_SCHEMA_VERSION) {
      throw new TeamSessionError("invalid-command", "Unsupported query schema version");
    }
    validateQuery(query);
    if (query.action === "observe") {
      throw new TeamSessionError("invalid-command", "Observe is not a terminal mutation");
    }

    const apply = this.db.transaction(() => {
      if (!this.terminalAuthorization(query).allowed) deny();
      // The gateway is a trusted in-process adapter. Requiring an actual
      // undefined result catches an accidentally async effect whose
      // continuation would otherwise escape this authorization transaction.
      if (mutation() !== undefined) {
        throw new TeamSessionError("invalid-command", "Terminal mutation must be synchronous");
      }
    });
    apply.immediate();
  }

  async *follow(options: FollowSessionOptions): AsyncIterable<SessionEvent> {
    this.assertOpen();
    validateQueryActor(options.actor);
    if (options.actor.kind !== "human") deny();
    requiredIdentifier(options.sessionId, "Session id");
    if (!Number.isSafeInteger(options.afterSequence) || options.afterSequence < 0) {
      throw new TeamSessionError("invalid-command", "Invalid event sequence");
    }
    if (
      options.pollIntervalMs !== undefined &&
      (!Number.isSafeInteger(options.pollIntervalMs) ||
        options.pollIntervalMs < 10 ||
        options.pollIntervalMs > 5_000)
    ) {
      throw new TeamSessionError("invalid-command", "Invalid follow poll interval");
    }
    let cursor = Math.max(0, options.afterSequence);
    const interval = clamp(options.pollIntervalMs ?? 100, 10, 5_000);
    while (!this.closed && !options.signal?.aborted) {
      const readBatch = this.db.transaction(() => {
        if (!this.hasSessionAccess(options.sessionId, options.actor.userId)) return null;
        return this.readEvents(options.sessionId, cursor, 500);
      });
      const events = readBatch();
      if (events === null) return;
      if (events.length > 0) {
        for (const event of events) {
          if (this.closed || options.signal?.aborted) return;
          if (!this.hasSessionAccess(options.sessionId, options.actor.userId)) return;
          cursor = event.sequence;
          yield event;
        }
        continue;
      }
      await abortableDelay(interval, options.signal);
    }
  }

  async claimRuntimeOutbox(options: RuntimeOutboxClaimOptions): Promise<RuntimeOutboxDelivery[]> {
    this.assertOpen();
    const workerId = requiredIdentifier(options.workerId, "Runtime worker id");
    const limit = options.limit ?? 10;
    const leaseDurationMs = options.leaseDurationMs ?? 30_000;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new TeamSessionError("invalid-command", "Runtime outbox claim limit is invalid");
    }
    if (
      !Number.isSafeInteger(leaseDurationMs) ||
      leaseDurationMs < 1_000 ||
      leaseDurationMs > 300_000
    ) {
      throw new TeamSessionError("invalid-command", "Runtime outbox lease duration is invalid");
    }
    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < 0 || now + leaseDurationMs > Number.MAX_SAFE_INTEGER) {
      throw new TeamSessionError("invalid-command", "Invalid Runtime outbox claim time");
    }
    const claim = this.db.transaction(() => {
      this.db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'pending', lease_owner = NULL, lease_expires_at_ms = NULL
           WHERE status = 'processing' AND lease_expires_at_ms <= ?`
        )
        .run(now);
      const rows = this.db
        .prepare(
          `SELECT candidate.* FROM runtime_outbox candidate
           WHERE candidate.status = 'pending'
             AND NOT EXISTS (
               SELECT 1 FROM runtime_outbox earlier
               WHERE earlier.session_id = candidate.session_id
                 AND earlier.status NOT IN ('delivered', 'superseded')
                 AND (
                   earlier.session_sequence < candidate.session_sequence OR
                   (earlier.session_sequence = candidate.session_sequence AND earlier.id < candidate.id)
                 )
             )
           ORDER BY candidate.created_at_ms ASC, candidate.session_id ASC,
                    candidate.session_sequence ASC, candidate.id ASC
           LIMIT ?`
        )
        .all(limit) as SqlRow[];
      const leaseExpiresAtMs = now + leaseDurationMs;
      const deliveries: RuntimeOutboxDelivery[] = [];
      for (const row of rows) {
        const updated = this.db
          .prepare(
            `UPDATE runtime_outbox
             SET status = 'processing', attempts = attempts + 1,
                 lease_owner = ?, lease_expires_at_ms = ?
             WHERE id = ? AND status = 'pending'
             RETURNING attempts`
          )
          .get(workerId, leaseExpiresAtMs, row.id) as SqlRow | undefined;
        if (!updated) continue;
        deliveries.push(
          projectRuntimeOutboxDelivery(row, updated.attempts as number, workerId, leaseExpiresAtMs)
        );
      }
      return deliveries;
    });
    return claim.immediate();
  }

  runtimeEnsureState(input: {
    sessionId: string;
    tmuxName: string;
    runtimeAuthorizationGeneration: number;
  }): "pending" | "enforced" | "stale" {
    this.assertOpen();
    const sessionId = requiredCanonicalSessionId(input?.sessionId, "Session id");
    const tmuxName = requiredText(input?.tmuxName, "tmux Session name", 160);
    const generation = requiredRevision(
      input?.runtimeAuthorizationGeneration,
      "Runtime Authorization"
    );
    const current = this.db
      .prepare(
        `SELECT runtime_authorization_state FROM sessions
         WHERE id = ? AND status = 'active'
           AND runtime_kind = 'local-tmux' AND isolation = 'trusted-shared-host'
           AND tmux_name = ? AND runtime_authorization_generation = ?`
      )
      .get(sessionId, tmuxName, generation) as SqlRow | undefined;
    if (current?.runtime_authorization_state === "pending") return "pending";
    if (current?.runtime_authorization_state === "enforced") return "enforced";
    return "stale";
  }

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
  }): boolean {
    this.assertOpen();
    const sessionId = requiredIdentifier(input?.sessionId, "Session id");
    const generation = requiredRevision(
      input?.runtimeAuthorizationGeneration,
      "Runtime Authorization"
    );
    if (input.emergencyStop) {
      const emergency = input.emergencyStop;
      const agentRunId = requiredIdentifier(emergency.agentRunId, "Emergency-stop Agent Run id");
      const runtimeAssignmentId = requiredIdentifier(
        emergency.runtimeAssignmentId,
        "Runtime Assignment id"
      );
      const runtimeAssignmentGeneration = requiredRevision(
        emergency.runtimeAssignmentGeneration,
        "Runtime Assignment"
      );
      const sandboxId = requiredIdentifier(emergency.sandboxId, "Sandbox id");
      const sandboxGeneration = requiredRevision(emergency.sandboxGeneration, "Sandbox generation");
      return Boolean(
        this.db
          .prepare(
            `SELECT 1 FROM sessions session
             JOIN runtime_assignments assignment ON assignment.session_id = session.id
             JOIN agent_runs run
               ON run.session_id = session.id AND run.runtime_assignment_id = assignment.id
             WHERE session.id = ?
               AND session.runtime_authorization_generation >= ?
               AND assignment.id = ? AND assignment.generation = ?
               AND assignment.sandbox_id = ? AND assignment.sandbox_generation = ?
               AND assignment.status = 'quarantined'
               AND run.id = ? AND run.lifecycle = 'pausing'
               AND run.runtime_authorization_generation >= ?`
          )
          .get(
            sessionId,
            generation,
            runtimeAssignmentId,
            runtimeAssignmentGeneration,
            sandboxId,
            sandboxGeneration,
            agentRunId,
            generation
          )
      );
    }
    // No non-emergency retire producer exists in Phase 4, and that legacy
    // payload does not carry an exact Runtime Assignment/Sandbox identity.
    // Keep it fail closed until the destructive request is fully bound.
    return false;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.database.close();
  }

  private applyCommand(command: SessionCommand, now: number): CommandResult {
    switch (command.type) {
      case "team.create":
        return this.createTeam(command, now);
      case "project.create":
        return this.createProject(command, now);
      case "team.membership.grant":
        return this.grantMembership(command, now);
      case "project.access.grant":
        return this.grantProjectAccess(command, now);
      case "project.access.revoke":
        return this.revokeProjectAccess(command, now);
      case "team.membership.revoke":
        return this.revokeMembership(command, now);
      case "session.start":
        return this.startSession(command, now);
      case "session.invitation.create":
        return this.createInvitation(command, now);
      case "session.invitation.revoke":
        return this.revokeInvitation(command, now);
      case "session.invitation.redeem":
        return this.redeemInvitation(command, now);
      case "session.join":
        return this.joinSession(command, now);
      case "session.share.create":
        return this.createShare(command, now);
      case "session.share.revoke":
        return this.revokeShare(command, now);
      case "session.participant.grant":
        return this.grantParticipant(command, now);
      case "session.participant.revoke":
        return this.revokeParticipant(command, now);
      case "session.responsibility.grant":
        return this.grantResponsibility(command, now);
      case "session.responsibility.revoke":
        return this.revokeResponsibility(command, now);
      case "session.control.transfer":
        return this.transferControl(command, now);
      case "session.control.release":
        return this.releaseControl(command, now);
      case "session.assignee.claim":
        return this.claimAssignee(command, now);
      case "session.handoff.offer":
        return this.offerHandoff(command, now);
      case "session.handoff.accept":
        return this.acceptHandoff(command, now);
      case "session.handoff.cancel":
        return this.cancelHandoff(command, now);
      case "comment.add":
        return this.addComment(command, now);
      case "suggestion.add":
        return this.addSuggestion(command, now);
      case "suggestion.resolve":
        return this.resolveSuggestion(command, now);
      case "directive.enqueue":
        return this.enqueueDirective(command, now);
      case "run.start":
        return this.startAgentRun(command, now);
      case "run.policy.revise":
        return this.reviseAgentRunPolicy(command, now);
      case "run.pause":
        return this.pauseAgentRun(command, now);
      case "run.resume":
        return this.resumeAgentRun(command, now);
      case "run.stop":
        return this.stopAgentRun(command, now);
      case "run.emergency-stop":
        return this.emergencyStopAgentRun(command, now);
      case "goal.add":
        return this.addRunGoal(command, now);
      case "goal.criteria.strengthen":
        return this.strengthenRunGoalCriteria(command, now);
      case "goal.dependency.add":
        return this.addRunGoalDependency(command, now);
      case "goal.reorder":
        return this.reorderRunGoal(command, now);
      case "goal.evidence.review":
        return this.reviewRunGoalEvidence(command, now);
      case "run.final-review.resolve":
        return this.resolveAgentRunFinalReview(command, now);
      case "runtime.outbox.acknowledge":
        return this.acknowledgeRuntimeOutbox(command, now);
      case "runtime.outbox.fail":
        return this.failRuntimeOutbox(command, now);
    }
  }

  private createTeam(
    command: Extract<SessionCommand, { type: "team.create" }>,
    now: number
  ): CommandResult {
    const teamId = command.teamId || this.nextId("team");
    const name = requiredText(command.name, "Team name", 120);
    this.db
      .prepare("INSERT INTO teams (id, name, created_at_ms) VALUES (?, ?, ?)")
      .run(teamId, name, now);
    this.db
      .prepare(
        `INSERT INTO team_memberships
           (team_id, user_id, role, status, version, created_at_ms)
         VALUES (?, ?, 'owner', 'active', 1, ?)`
      )
      .run(teamId, command.actor.userId, now);
    return result(command, { teamId, ownerUserId: command.actor.userId });
  }

  private createProject(
    command: Extract<SessionCommand, { type: "project.create" }>,
    now: number
  ): CommandResult {
    this.requireTeamAdministrator(command.teamId, command.actor.userId);
    const projectId = command.projectId || this.nextId("project");
    const name = requiredText(command.name, "Project name", 120);
    this.db
      .prepare(
        `INSERT INTO projects (id, team_id, name, source_ref, created_at_ms)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(projectId, command.teamId, name, optionalText(command.sourceRef, 500), now);
    this.upsertProjectAccess(projectId, command.actor.userId, "maintainer", now);
    return result(command, {
      projectId,
      teamId: command.teamId,
      creatorProjectRole: "maintainer",
    });
  }

  private grantMembership(
    command: Extract<SessionCommand, { type: "team.membership.grant" }>,
    now: number
  ): CommandResult {
    const actorMembership = this.activeMembership(command.teamId, command.actor.userId);
    if (!actorMembership) deny();
    const target = this.membership(command.teamId, command.userId);

    if (actorMembership.role === "admin") {
      if (command.role !== "member" && command.role !== "guest") deny();
      if (target?.status === "active" && (target.role === "owner" || target.role === "admin")) {
        deny();
      }
    } else if (actorMembership.role !== "owner") {
      deny();
    }

    assertExpectedVersion(
      (target?.version as number | undefined) ?? 0,
      command.expectedMembershipVersion,
      "Team Membership"
    );

    if (
      target?.status === "active" &&
      target.role === "owner" &&
      command.role !== "owner" &&
      this.activeMembershipCount(command.teamId, "owner") <= 1
    ) {
      throw new TeamSessionError("conflict", "A Team must retain at least one Owner");
    }
    if (target?.status === "active" && target.role === command.role) {
      throw new TeamSessionError("conflict", "The Team Membership already has that role");
    }

    const previousRole = target?.status === "active" ? (target.role as TeamRole) : undefined;
    this.setMembership(command.teamId, command.userId, command.role, now);
    const crossesMembershipClass =
      previousRole !== undefined && (previousRole === "guest") !== (command.role === "guest");
    const changesSessionAdministration =
      command.role === "owner" ||
      command.role === "admin" ||
      previousRole === "owner" ||
      previousRole === "admin";
    const accessRows =
      crossesMembershipClass || changesSessionAdministration
        ? this.advanceTeamAccessRevisions(command.teamId)
        : [];

    const events = this.appendAccessRevisionEvents(
      accessRows,
      command,
      now,
      "team-membership-changed",
      { teamId: command.teamId }
    );
    if (previousRole && (previousRole === "guest") !== (command.role === "guest")) {
      this.recordUserRevocations(accessRows, command.userId, "team.membership.role.changed", now);
      this.db
        .prepare(
          `UPDATE project_access
           SET status = 'revoked', version = version + 1, revoked_at_ms = ?
           WHERE user_id = ? AND status = 'active'
             AND project_id IN (SELECT id FROM projects WHERE team_id = ?)`
        )
        .run(now, command.userId, command.teamId);
      this.db
        .prepare(
          `UPDATE session_shares
           SET status = 'revoked', version = version + 1, revoked_at_ms = ?
           WHERE user_id = ? AND status = 'active'
             AND session_id IN (SELECT id FROM sessions WHERE team_id = ?)`
        )
        .run(now, command.userId, command.teamId);
      events.push(
        ...this.revokeAcrossSessions(
          `SELECT s.id FROM sessions s
           JOIN session_participants p ON p.session_id = s.id
           WHERE s.team_id = ? AND p.user_id = ? AND p.status = 'active'`,
          [command.teamId, command.userId],
          command.userId,
          command,
          now,
          "team.membership.role.changed",
          {
            teamId: command.teamId,
            userId: command.userId,
            previousRole,
            role: command.role,
          }
        )
      );
    }

    return result(
      command,
      {
        teamId: command.teamId,
        userId: command.userId,
        role: command.role,
        membershipVersion: this.membership(command.teamId, command.userId)?.version,
        ...(previousRole ? { previousRole } : {}),
      },
      events
    );
  }

  private grantProjectAccess(
    command: Extract<SessionCommand, { type: "project.access.grant" }>,
    now: number
  ): CommandResult {
    const project = this.requireProject(command.projectId);
    this.requireProjectAdministrator(project, command.actor.userId);
    const target = this.activeMembership(project.team_id as string, command.userId);
    if (!target || target.role === "guest") deny();
    const storedAccess = this.projectAccess(command.projectId, command.userId);
    assertExpectedVersion(
      (storedAccess?.version as number | undefined) ?? 0,
      command.expectedAccessVersion,
      "Project Access"
    );
    const existing = storedAccess?.status === "active" ? storedAccess : undefined;
    if (existing?.role === command.role) {
      throw new TeamSessionError("conflict", "Project Access already has that role");
    }
    this.upsertProjectAccess(command.projectId, command.userId, command.role, now);
    const changesProjectAdministration =
      command.role === "maintainer" || existing?.role === "maintainer";
    const accessRows = changesProjectAdministration
      ? this.advanceProjectAccessRevisions(command.projectId)
      : [];
    const events = this.appendAccessRevisionEvents(
      accessRows,
      command,
      now,
      "project-access-changed",
      { projectId: command.projectId }
    );
    return result(
      command,
      {
        projectId: command.projectId,
        userId: command.userId,
        role: command.role,
        accessVersion: this.projectAccess(command.projectId, command.userId)?.version,
      },
      events
    );
  }

  private revokeProjectAccess(
    command: Extract<SessionCommand, { type: "project.access.revoke" }>,
    now: number
  ): CommandResult {
    const project = this.requireProject(command.projectId);
    this.requireProjectAdministrator(project, command.actor.userId);
    const targetAccess = this.activeProjectAccess(command.projectId, command.userId);
    if (!targetAccess) deny();
    assertExpectedVersion(
      targetAccess.version as number,
      command.expectedAccessVersion,
      "Project Access"
    );
    const updated = this.db
      .prepare(
        `UPDATE project_access
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE project_id = ? AND user_id = ? AND status = 'active'`
      )
      .run(now, command.projectId, command.userId);
    if (updated.changes === 0) deny();
    const accessRows = this.advanceProjectAccessRevisions(command.projectId);
    this.recordUserRevocations(accessRows, command.userId, "project.access.revoked", now);
    const events = this.appendAccessRevisionEvents(
      accessRows,
      command,
      now,
      "project-access-revoked",
      { projectId: command.projectId }
    );
    events.push(
      ...this.revokeAcrossSessions(
        `SELECT s.id FROM sessions s
       JOIN session_participants p ON p.session_id = s.id
       JOIN team_memberships m
         ON m.team_id = s.team_id AND m.user_id = p.user_id
          AND m.status = 'active' AND m.role <> 'guest'
       WHERE s.project_id = ? AND p.user_id = ? AND p.status = 'active'`,
        [command.projectId, command.userId],
        command.userId,
        command,
        now,
        "project.access.revoked",
        { projectId: command.projectId, userId: command.userId }
      )
    );
    return result(command, { projectId: command.projectId, userId: command.userId }, events);
  }

  private revokeMembership(
    command: Extract<SessionCommand, { type: "team.membership.revoke" }>,
    now: number
  ): CommandResult {
    const actorMembership = this.activeMembership(command.teamId, command.actor.userId);
    if (
      !actorMembership ||
      (actorMembership.role !== "owner" && actorMembership.role !== "admin")
    ) {
      deny();
    }
    const target = this.activeMembership(command.teamId, command.userId);
    if (!target) deny();
    assertExpectedVersion(
      target.version as number,
      command.expectedMembershipVersion,
      "Team Membership"
    );
    if (actorMembership.role === "admin" && (target.role === "owner" || target.role === "admin")) {
      deny();
    }
    if (target.role === "owner") {
      if (this.activeMembershipCount(command.teamId, "owner") <= 1) {
        throw new TeamSessionError("conflict", "A Team must retain at least one Owner");
      }
    }
    this.db
      .prepare(
        `UPDATE team_memberships
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE team_id = ? AND user_id = ? AND status = 'active'`
      )
      .run(now, command.teamId, command.userId);
    this.db
      .prepare(
        `UPDATE project_access
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE user_id = ? AND status = 'active'
           AND project_id IN (SELECT id FROM projects WHERE team_id = ?)`
      )
      .run(now, command.userId, command.teamId);
    const accessRows = this.advanceTeamAccessRevisions(command.teamId);
    this.recordUserRevocations(accessRows, command.userId, "team.membership.revoked", now);
    this.db
      .prepare(
        `UPDATE session_shares
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE user_id = ? AND status = 'active'
           AND session_id IN (SELECT id FROM sessions WHERE team_id = ?)`
      )
      .run(now, command.userId, command.teamId);
    const events = this.appendAccessRevisionEvents(
      accessRows,
      command,
      now,
      "team-membership-revoked",
      { teamId: command.teamId }
    );
    events.push(
      ...this.revokeAcrossSessions(
        `SELECT s.id FROM sessions s
       JOIN session_participants p ON p.session_id = s.id
       WHERE s.team_id = ? AND p.user_id = ? AND p.status = 'active'`,
        [command.teamId, command.userId],
        command.userId,
        command,
        now,
        "team.membership.revoked",
        { teamId: command.teamId, userId: command.userId }
      )
    );
    return result(command, { teamId: command.teamId, userId: command.userId }, events);
  }

  private startSession(
    command: Extract<SessionCommand, { type: "session.start" }>,
    now: number
  ): CommandResult {
    const project = this.requireProject(command.projectId);
    if (project.team_id !== command.teamId) deny();
    const membership = this.activeMembership(command.teamId, command.actor.userId);
    if (!membership || membership.role === "guest") deny();
    if (!this.activeProjectAccess(command.projectId, command.actor.userId)) deny();

    const sessionId = requiredCanonicalSessionId(
      command.sessionId ?? this.nextId("session"),
      "Session id"
    );
    const name = requiredText(command.name, "Session name", 160);
    const tmuxName = command.tmuxName;
    const policy = command.steeringPolicy ?? "single";
    this.db
      .prepare(
        `INSERT INTO sessions (
           id, team_id, project_id, name, status, steering_policy,
           access_revision, assignee_revision, supervision_revision,
           steering_revision, control_revision, control_epoch,
           runtime_authorization_generation, runtime_authorization_state,
           next_sequence, runtime_kind,
           isolation, tmux_name, yolo_eligible, created_at_ms
         ) VALUES (?, ?, ?, ?, 'active', ?, 1, 1, 1, 1, 1, 1, 1, 'pending', 1,
                   'local-tmux', 'trusted-shared-host', ?, 0, ?)`
      )
      .run(sessionId, command.teamId, command.projectId, name, policy, tmuxName, now);
    this.upsertParticipant(sessionId, command.actor.userId, now);
    for (const responsibility of RESPONSIBILITY_ORDER) {
      this.upsertResponsibility(sessionId, command.actor.userId, responsibility, now);
    }
    const event = this.appendEvent(sessionId, command, now, "session.started", {
      sessionId,
      teamId: command.teamId,
      projectId: command.projectId,
      starterUserId: command.actor.userId,
      steeringPolicy: policy,
      runtimeKind: "local-tmux",
      isolation: "trusted-shared-host",
      yoloEligible: false,
      runtimeAuthorizationGeneration: 1,
      runtimeAuthorizationState: "pending",
    });
    const outboxId = this.nextId("outbox");
    const runtimeEnsurePayload: RuntimeOutboxPayload<"runtime.session.ensure"> = {
      sessionId,
      runtimeKind: "local-tmux",
      tmuxName,
      runtimeAuthorizationGeneration: 1,
    };
    this.db
      .prepare(
        `INSERT INTO runtime_outbox
           (id, session_id, session_sequence, kind, payload_json, status, attempts, created_at_ms)
         VALUES (?, ?, ?, 'runtime.session.ensure', ?, 'pending', 0, ?)`
      )
      .run(outboxId, sessionId, event.sequence, JSON.stringify(runtimeEnsurePayload), now);
    return result(command, { sessionId, runtimeOutboxId: outboxId }, [event]);
  }

  private createInvitation(
    command: Extract<SessionCommand, { type: "session.invitation.create" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireTeamAdministrator(session.team_id as string, command.actor.userId);
    if (session.status === "ended") {
      throw new TeamSessionError("conflict", "An ended Session cannot create an Invitation");
    }
    assertExpectedRevision(
      session.access_revision as number,
      command.expectedAccessRevision,
      "Session Access"
    );
    if (!Number.isSafeInteger(command.expiresAtMs) || command.expiresAtMs <= now) {
      throw new TeamSessionError("invalid-command", "Invitation expiry must be in the future");
    }
    const invitationId = this.nextId("invitation");
    const invitationToken = requiredText(
      this.invitationTokenGenerator(),
      "Invitation token",
      1_000
    );
    const tokenDigest = sha256(invitationToken);
    const accessRevision = this.advanceAccessRevision(command.sessionId);
    this.db
      .prepare(
        `INSERT INTO session_invitations (
           id, session_id, team_id, project_id, membership_role, token_digest,
           status, version, created_access_revision, expires_at_ms,
           created_by_user_id, created_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, 'active', 1, ?, ?, ?, ?)`
      )
      .run(
        invitationId,
        command.sessionId,
        session.team_id,
        session.project_id,
        command.membershipRole,
        tokenDigest,
        accessRevision,
        command.expiresAtMs,
        command.actor.userId,
        now
      );
    const event = this.appendEvent(command.sessionId, command, now, "session.invitation.created", {
      invitationId,
      membershipRole: command.membershipRole,
      expiresAtMs: command.expiresAtMs,
      invitationVersion: 1,
      accessRevision,
    });
    return result(
      command,
      {
        invitationId,
        sessionId: command.sessionId,
        invitationToken,
        invitationVersion: 1,
        accessRevision,
      },
      [event]
    );
  }

  private revokeInvitation(
    command: Extract<SessionCommand, { type: "session.invitation.revoke" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireTeamAdministrator(session.team_id as string, command.actor.userId);
    const invitation = this.db
      .prepare(
        `SELECT * FROM session_invitations
         WHERE id = ? AND session_id = ? AND status = 'active'`
      )
      .get(command.invitationId, command.sessionId) as SqlRow | undefined;
    if (!invitation) deny();
    assertExpectedVersion(
      invitation.version as number,
      command.expectedInvitationVersion,
      "Invitation"
    );
    const updated = this.db
      .prepare(
        `UPDATE session_invitations
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE id = ? AND session_id = ? AND status = 'active'`
      )
      .run(now, command.invitationId, command.sessionId);
    if (updated.changes === 0) deny();
    const accessRevision = this.advanceAccessRevision(command.sessionId);
    const event = this.appendEvent(command.sessionId, command, now, "session.invitation.revoked", {
      invitationId: command.invitationId,
      invitationVersion: (invitation.version as number) + 1,
      accessRevision,
    });
    return result(
      command,
      {
        invitationId: command.invitationId,
        invitationVersion: (invitation.version as number) + 1,
        accessRevision,
      },
      [event]
    );
  }

  private redeemInvitation(
    command: Extract<SessionCommand, { type: "session.invitation.redeem" }>,
    now: number
  ): CommandResult {
    if (command.actor.kind !== "human") deny();
    const token = requiredText(command.token, "Invitation token", 1_000);
    const invitation = this.db
      .prepare("SELECT * FROM session_invitations WHERE token_digest = ?")
      .get(sha256(token)) as SqlRow | undefined;
    if (!invitation) deny();
    if (invitation.status === "revoked") {
      throw new TeamSessionError("invitation-revoked", "Invitation is no longer active");
    }
    if (invitation.status === "redeemed") {
      throw new TeamSessionError("invitation-used", "Invitation has already been redeemed");
    }
    if ((invitation.expires_at_ms as number) <= now) {
      throw new TeamSessionError("invitation-expired", "Invitation has expired");
    }

    const teamId = invitation.team_id as string;
    const sessionId = invitation.session_id as string;
    if (this.requireSession(sessionId).status === "ended") {
      throw new TeamSessionError("conflict", "An ended Session cannot redeem an Invitation");
    }
    const membershipRole = invitation.membership_role as "member" | "guest";
    const storedMembership = this.membership(teamId, command.actor.userId);
    const currentMembership = storedMembership?.status === "active" ? storedMembership : undefined;
    if (
      currentMembership &&
      (currentMembership.role === "guest") !== (membershipRole === "guest")
    ) {
      throw new TeamSessionError(
        "conflict",
        "Invitation cannot change an active Team Membership class"
      );
    }
    const revocation = this.db
      .prepare(
        `SELECT last_access_revision FROM session_user_revocations
         WHERE session_id = ? AND user_id = ?`
      )
      .get(sessionId, command.actor.userId) as SqlRow | undefined;
    if (
      revocation &&
      (revocation.last_access_revision as number) > (invitation.created_access_revision as number)
    ) {
      throw new TeamSessionError(
        "invitation-revoked",
        "Invitation predates an access or participation revocation"
      );
    }
    const membershipChanged = !currentMembership;
    const effectiveMembershipRole = this.upsertMembership(
      teamId,
      command.actor.userId,
      membershipRole,
      now
    );
    const events: SessionEvent[] = [];
    // The invite changes Team Membership, but Membership alone is not Session
    // access. Only the invitation's own Session revision advances here;
    // independent Project Access or Guest Share commands advance their scope.
    const sessionAccessRevision = this.advanceAccessRevision(sessionId);
    if (membershipChanged) {
      events.push(
        this.appendEvent(
          sessionId,
          command,
          now,
          storedMembership ? "team.membership.reinstated" : "team.membership.joined",
          {
            teamId,
            userId: command.actor.userId,
            role: effectiveMembershipRole,
            invitationId: invitation.id,
            accessRevision: sessionAccessRevision,
            ...(storedMembership ? { previousRole: storedMembership.role } : {}),
          }
        )
      );
    }
    this.db
      .prepare(
        `UPDATE session_invitations
         SET status = 'redeemed', version = version + 1,
             redeemed_by_user_id = ?, redeemed_at_ms = ?
         WHERE id = ? AND status = 'active'`
      )
      .run(command.actor.userId, now, invitation.id);
    events.push(
      this.appendEvent(sessionId, command, now, "session.invitation.redeemed", {
        invitationId: invitation.id,
        userId: command.actor.userId,
        invitationVersion: (invitation.version as number) + 1,
        membershipRole: effectiveMembershipRole,
        projectAccessGranted: false,
        sessionShareGranted: false,
        participantGranted: false,
        accessRevision: sessionAccessRevision,
      })
    );
    return result(
      command,
      {
        invitationId: invitation.id,
        invitationVersion: (invitation.version as number) + 1,
        teamId,
        sessionId,
        membershipRole: effectiveMembershipRole,
        projectAccessGranted: false,
        sessionShareGranted: false,
        participantGranted: false,
        accessRevision: sessionAccessRevision,
      },
      events
    );
  }

  private joinSession(
    command: Extract<SessionCommand, { type: "session.join" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    if (!this.hasUnderlyingSessionAccess(command.sessionId, command.actor.userId)) deny();
    if (session.status === "ended") {
      throw new TeamSessionError("conflict", "An ended Session cannot admit a Participant");
    }
    const storedParticipant = this.participant(command.sessionId, command.actor.userId);
    if (storedParticipant) {
      if (storedParticipant.status === "active") {
        throw new TeamSessionError("conflict", "User is already an active Session Participant");
      }
      // A revoked Participant needs a deliberate manager re-admission. A new
      // share or Project Access grant must never resurrect participation.
      deny();
    }
    if (command.invitationId !== undefined) {
      const invitation = this.db
        .prepare(
          `SELECT 1 FROM session_invitations
           WHERE id = ? AND session_id = ? AND status = 'redeemed'
             AND redeemed_by_user_id = ?`
        )
        .get(command.invitationId, command.sessionId, command.actor.userId);
      if (!invitation) deny();
    }
    const participantId = this.upsertParticipant(command.sessionId, command.actor.userId, now);
    const accessRevision = this.advanceAccessRevision(command.sessionId);
    const participant = this.participant(command.sessionId, command.actor.userId);
    const event = this.appendEvent(command.sessionId, command, now, "session.participant.joined", {
      participantId,
      userId: command.actor.userId,
      observer: true,
      participantVersion: participant?.version,
      accessRevision,
      ...(command.invitationId === undefined ? {} : { invitationId: command.invitationId }),
    });
    return result(
      command,
      {
        sessionId: command.sessionId,
        participantId,
        participantVersion: participant?.version,
        accessRevision,
      },
      [event]
    );
  }

  private createShare(
    command: Extract<SessionCommand, { type: "session.share.create" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    if (session.status === "ended") {
      throw new TeamSessionError("conflict", "An ended Session cannot create a Session Share");
    }
    assertExpectedRevision(
      session.access_revision as number,
      command.expectedAccessRevision,
      "Session Access"
    );
    const membership = this.activeMembership(session.team_id as string, command.userId);
    if (!membership || membership.role !== "guest") deny();
    if (
      this.db
        .prepare(
          `SELECT 1 FROM session_shares
           WHERE session_id = ? AND user_id = ? AND status = 'active'`
        )
        .get(command.sessionId, command.userId)
    ) {
      throw new TeamSessionError("conflict", "Session Share is already active");
    }
    this.upsertShare(command.sessionId, command.userId, now);
    const share = this.share(command.sessionId, command.userId);
    const accessRevision = this.advanceAccessRevision(command.sessionId);
    const event = this.appendEvent(command.sessionId, command, now, "session.share.created", {
      userId: command.userId,
      shareVersion: share?.version,
      accessRevision,
    });
    return result(
      command,
      {
        sessionId: command.sessionId,
        userId: command.userId,
        shareVersion: share?.version,
        accessRevision,
      },
      [event]
    );
  }

  private revokeShare(
    command: Extract<SessionCommand, { type: "session.share.revoke" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    const share = this.share(command.sessionId, command.userId);
    if (share?.status !== "active") deny();
    assertExpectedVersion(share.version as number, command.expectedShareVersion, "Session Share");
    const updated = this.db
      .prepare(
        `UPDATE session_shares
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE session_id = ? AND user_id = ? AND status = 'active'`
      )
      .run(now, command.sessionId, command.userId);
    if (updated.changes === 0) deny();
    const accessRevision = this.advanceAccessRevision(command.sessionId);
    this.recordUserRevocations(
      [{ id: command.sessionId, access_revision: accessRevision }],
      command.userId,
      "session.share.revoked",
      now
    );
    const targetMembership = this.activeMembership(session.team_id as string, command.userId);
    const events =
      targetMembership?.role === "guest"
        ? this.revokeOneParticipant(
            command.sessionId,
            command.userId,
            command,
            now,
            "session.share.revoked",
            { userId: command.userId, accessRevision }
          )
        : [];
    if (events.length === 0) {
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.share.revoked", {
          userId: command.userId,
          accessRevision,
        })
      );
    }
    return result(
      command,
      {
        sessionId: command.sessionId,
        userId: command.userId,
        shareVersion: (share.version as number) + 1,
        accessRevision,
      },
      events
    );
  }

  private grantParticipant(
    command: Extract<SessionCommand, { type: "session.participant.grant" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    if (session.status === "ended") {
      throw new TeamSessionError("conflict", "An ended Session cannot admit a Participant");
    }
    assertExpectedRevision(
      session.access_revision as number,
      command.expectedAccessRevision,
      "Session Access"
    );
    if (!this.hasUnderlyingSessionAccess(command.sessionId, command.userId)) deny();
    const storedParticipant = this.participant(command.sessionId, command.userId);
    assertExpectedVersion(
      (storedParticipant?.version as number | undefined) ?? 0,
      command.expectedParticipantVersion,
      "Session Participant"
    );
    if (storedParticipant?.status === "active") {
      throw new TeamSessionError("conflict", "User is already an active Session Participant");
    }
    const participantId = this.upsertParticipant(command.sessionId, command.userId, now);
    const participant = this.participant(command.sessionId, command.userId);
    const accessRevision = this.advanceAccessRevision(command.sessionId);
    const event = this.appendEvent(command.sessionId, command, now, "session.participant.granted", {
      participantId,
      userId: command.userId,
      observer: true,
      participantVersion: participant?.version,
      accessRevision,
    });
    return result(
      command,
      {
        sessionId: command.sessionId,
        participantId,
        participantVersion: participant?.version,
        accessRevision,
      },
      [event]
    );
  }

  private revokeParticipant(
    command: Extract<SessionCommand, { type: "session.participant.revoke" }>,
    now: number
  ): CommandResult {
    this.requireSession(command.sessionId);
    const self = command.actor.userId === command.userId;
    if (!self) this.requireSessionManager(command.sessionId, command.actor.userId);
    const participant = this.activeParticipant(command.sessionId, command.userId);
    if (!participant) deny();
    assertExpectedVersion(
      participant.version as number,
      command.expectedParticipantVersion,
      "Session Participant"
    );
    if (!self && this.hasResponsibility(command.sessionId, command.userId, "assignee")) {
      throw new TeamSessionError("conflict", "Use Handoff or higher-scope revocation for Assignee");
    }
    const accessRevision = this.advanceAccessRevision(command.sessionId);
    this.recordUserRevocations(
      [{ id: command.sessionId, access_revision: accessRevision }],
      command.userId,
      "session.participant.revoked",
      now
    );
    const events = this.revokeOneParticipant(
      command.sessionId,
      command.userId,
      command,
      now,
      "session.participant.revoked",
      { userId: command.userId, accessRevision }
    );
    if (events.length === 0) deny();
    return result(
      command,
      {
        sessionId: command.sessionId,
        userId: command.userId,
        participantVersion: (participant.version as number) + 1,
        accessRevision,
      },
      events
    );
  }

  private grantResponsibility(
    command: Extract<SessionCommand, { type: "session.responsibility.grant" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    if (command.responsibility === "supervisor") {
      if (!this.hasResponsibility(command.sessionId, command.actor.userId, "assignee")) deny();
      if (session.status === "ended") {
        throw new TeamSessionError("conflict", "An ended Session cannot grant responsibility");
      }
      assertExpectedRevision(
        session.supervision_revision as number,
        command.expectedSupervisionRevision,
        "Supervision"
      );
    } else {
      this.requireSessionManager(command.sessionId, command.actor.userId);
      if (session.status === "ended") {
        throw new TeamSessionError("conflict", "An ended Session cannot grant responsibility");
      }
      assertExpectedRevision(
        session.steering_revision as number,
        command.expectedSteeringRevision,
        "Steering"
      );
      if (session.steering_policy !== "shared") {
        throw new TeamSessionError(
          "conflict",
          "Additional Steerers require the shared Steering Policy"
        );
      }
    }
    if (!this.hasSessionAccess(command.sessionId, command.userId)) deny();
    const participant = this.activeParticipant(command.sessionId, command.userId);
    if (!participant) deny();
    assertExpectedVersion(
      participant.version as number,
      command.expectedParticipantVersion,
      "Session Participant"
    );
    if (this.hasResponsibility(command.sessionId, command.userId, command.responsibility)) {
      throw new TeamSessionError("conflict", "Participant already holds that responsibility");
    }
    this.upsertResponsibility(command.sessionId, command.userId, command.responsibility, now);
    const revision =
      command.responsibility === "supervisor"
        ? this.advanceSupervisionRevision(command.sessionId)
        : this.advanceSteeringRevision(command.sessionId);
    const revisionPayload =
      command.responsibility === "supervisor"
        ? { supervisionRevision: revision }
        : { steeringRevision: revision };
    const event = this.appendEvent(
      command.sessionId,
      command,
      now,
      "session.responsibility.granted",
      {
        userId: command.userId,
        responsibility: command.responsibility,
        ...revisionPayload,
      }
    );
    return result(
      command,
      { sessionId: command.sessionId, userId: command.userId, ...revisionPayload },
      [event]
    );
  }

  private revokeResponsibility(
    command: Extract<SessionCommand, { type: "session.responsibility.revoke" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    if (command.responsibility === "supervisor") {
      if (!this.hasResponsibility(command.sessionId, command.actor.userId, "assignee")) deny();
      assertExpectedRevision(
        session.supervision_revision as number,
        command.expectedSupervisionRevision,
        "Supervision"
      );
      if (this.hasResponsibility(command.sessionId, command.userId, "assignee")) {
        throw new TeamSessionError("conflict", "The Assignee must remain a Supervisor");
      }
      const count = this.activeResponsibilityCount(command.sessionId, "supervisor");
      if (count <= 1) {
        throw new TeamSessionError("conflict", "A Session must retain a Supervisor");
      }
    } else if (command.responsibility === "steerer") {
      this.requireSessionManager(command.sessionId, command.actor.userId);
      assertExpectedRevision(
        session.steering_revision as number,
        command.expectedSteeringRevision,
        "Steering"
      );
      assertExpectedRevision(
        session.control_revision as number,
        command.expectedControlRevision,
        "Control"
      );
      assertExpectedRevision(
        session.control_epoch as number,
        command.expectedControlEpoch,
        "Control fencing epoch"
      );
    }
    const wasController = this.hasResponsibility(command.sessionId, command.userId, "controller");
    const updated = this.db
      .prepare(
        `UPDATE session_responsibilities
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE session_id = ? AND user_id = ? AND kind = ? AND status = 'active'`
      )
      .run(now, command.sessionId, command.userId, command.responsibility);
    if (updated.changes === 0) deny();
    const revision =
      command.responsibility === "steerer"
        ? this.advanceSteeringRevision(command.sessionId)
        : this.advanceSupervisionRevision(command.sessionId);
    let controlReleased = false;
    if (command.responsibility === "steerer" && wasController) {
      this.db
        .prepare(
          `UPDATE session_responsibilities
           SET status = 'revoked', version = version + 1, revoked_at_ms = ?
           WHERE session_id = ? AND user_id = ? AND kind = 'controller' AND status = 'active'`
        )
        .run(now, command.sessionId, command.userId);
      controlReleased = true;
    }
    if (controlReleased) {
      this.advanceControlFence(command.sessionId);
    }
    const revisionPayload =
      command.responsibility === "steerer"
        ? { steeringRevision: revision }
        : { supervisionRevision: revision };
    const cancelledHandoffs =
      command.responsibility === "supervisor"
        ? this.cancelHandoffsOfferedBy(
            command.sessionId,
            command.userId,
            now,
            command.actor.userId,
            "supervisor-revoked"
          )
        : [];
    const events = [
      this.appendEvent(command.sessionId, command, now, "session.responsibility.revoked", {
        userId: command.userId,
        responsibility: command.responsibility,
        controlReleased,
        ...revisionPayload,
        ...(controlReleased ? this.controlProjection(command.sessionId) : {}),
      }),
    ];
    if (command.responsibility === "steerer") {
      events.push(
        ...this.appendQueuedDirectiveCancellationEvents(
          command.sessionId,
          command,
          now,
          command.userId,
          "steerer-revoked"
        )
      );
    }
    if (controlReleased) {
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.control.released", {
          previousControllerUserId: command.userId,
          reason: "steerer-revoked",
          ...this.controlProjection(command.sessionId),
        })
      );
    }
    events.push(
      ...this.appendHandoffCancellationEvents(command.sessionId, command, now, cancelledHandoffs)
    );
    return result(
      command,
      {
        sessionId: command.sessionId,
        userId: command.userId,
        ...revisionPayload,
        ...(controlReleased ? this.controlProjection(command.sessionId) : {}),
      },
      events
    );
  }

  private transferControl(
    command: Extract<SessionCommand, { type: "session.control.transfer" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    const currentController = this.activeResponsibilityHolder(command.sessionId, "controller");
    const actorIsManager = this.isSessionManager(command.sessionId, command.actor.userId);
    const actorHasControl = currentController?.user_id === command.actor.userId;
    if (!actorHasControl && !actorIsManager) deny();
    if (session.status !== "active") {
      throw new TeamSessionError("conflict", "Control requires an active Session");
    }
    if (!this.hasSessionAccess(command.sessionId, command.userId)) deny();
    const participant = this.activeParticipant(command.sessionId, command.userId);
    if (!participant) deny();
    assertExpectedVersion(
      participant.version as number,
      command.expectedParticipantVersion,
      "Session Participant"
    );
    assertExpectedRevision(
      session.control_revision as number,
      command.expectedControlRevision,
      "Control"
    );
    assertExpectedRevision(
      session.control_epoch as number,
      command.expectedControlEpoch,
      "Control fencing epoch"
    );
    if (currentController?.user_id === command.userId) {
      throw new TeamSessionError("conflict", "Participant already holds the Control Lease");
    }
    const targetWasSteerer = this.hasResponsibility(command.sessionId, command.userId, "steerer");
    if (session.steering_policy === "shared" && !targetWasSteerer && !actorIsManager) {
      deny();
    }

    const removedSteerers =
      session.steering_policy === "single"
        ? (this.db
            .prepare(
              `SELECT user_id FROM session_responsibilities
               WHERE session_id = ? AND kind = 'steerer' AND status = 'active'
                 AND user_id <> ?
               ORDER BY user_id ASC`
            )
            .all(command.sessionId, command.userId) as SqlRow[])
        : [];
    if (removedSteerers.length > 0) {
      this.db
        .prepare(
          `UPDATE session_responsibilities
           SET status = 'revoked', version = version + 1, revoked_at_ms = ?
           WHERE session_id = ? AND kind = 'steerer' AND status = 'active'
             AND user_id <> ?`
        )
        .run(now, command.sessionId, command.userId);
    }
    if (!targetWasSteerer) {
      this.upsertResponsibility(command.sessionId, command.userId, "steerer", now);
    }
    const steeringChanged = removedSteerers.length > 0 || !targetWasSteerer;
    const steeringRevision = steeringChanged
      ? this.advanceSteeringRevision(command.sessionId)
      : (session.steering_revision as number);
    const events: SessionEvent[] = [];
    for (const removed of removedSteerers) {
      const removedUserId = removed.user_id as string;
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.responsibility.revoked", {
          userId: removedUserId,
          responsibility: "steerer",
          reason: "single-policy-control-transfer",
          steeringRevision,
        }),
        ...this.appendQueuedDirectiveCancellationEvents(
          command.sessionId,
          command,
          now,
          removedUserId,
          "single-policy-control-transfer"
        )
      );
    }
    if (!targetWasSteerer) {
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.responsibility.granted", {
          userId: command.userId,
          responsibility: "steerer",
          reason: "controller-requires-steerer",
          steeringRevision,
        })
      );
    }
    this.db
      .prepare(
        `UPDATE session_responsibilities
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE session_id = ? AND kind = 'controller' AND status = 'active'`
      )
      .run(now, command.sessionId);
    this.advanceControlFence(
      command.sessionId,
      command.expectedControlRevision,
      command.expectedControlEpoch
    );
    this.upsertResponsibility(command.sessionId, command.userId, "controller", now);
    const control = this.controlProjection(command.sessionId);
    events.push(
      this.appendEvent(command.sessionId, command, now, "session.control.transferred", {
        previousControllerUserId: currentController?.user_id ?? null,
        controllerUserId: command.userId,
        steeringRevision,
        ...control,
      })
    );
    return result(
      command,
      {
        sessionId: command.sessionId,
        controllerUserId: command.userId,
        steeringRevision,
        ...control,
      },
      events
    );
  }

  private releaseControl(
    command: Extract<SessionCommand, { type: "session.control.release" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    const currentController = this.activeResponsibilityHolder(command.sessionId, "controller");
    if (!currentController || currentController.user_id !== command.actor.userId) deny();
    assertExpectedRevision(
      session.control_revision as number,
      command.expectedControlRevision,
      "Control"
    );
    assertExpectedRevision(
      session.control_epoch as number,
      command.expectedControlEpoch,
      "Control fencing epoch"
    );
    this.db
      .prepare(
        `UPDATE session_responsibilities
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE session_id = ? AND user_id = ? AND kind = 'controller' AND status = 'active'`
      )
      .run(now, command.sessionId, command.actor.userId);
    let steeringRevision = session.steering_revision as number;
    const events: SessionEvent[] = [];
    if (
      session.steering_policy === "single" &&
      this.hasResponsibility(command.sessionId, command.actor.userId, "steerer")
    ) {
      this.db
        .prepare(
          `UPDATE session_responsibilities
           SET status = 'revoked', version = version + 1, revoked_at_ms = ?
           WHERE session_id = ? AND user_id = ? AND kind = 'steerer' AND status = 'active'`
        )
        .run(now, command.sessionId, command.actor.userId);
      steeringRevision = this.advanceSteeringRevision(command.sessionId);
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.responsibility.revoked", {
          userId: command.actor.userId,
          responsibility: "steerer",
          reason: "single-policy-control-release",
          steeringRevision,
        }),
        ...this.appendQueuedDirectiveCancellationEvents(
          command.sessionId,
          command,
          now,
          command.actor.userId,
          "single-policy-control-release"
        )
      );
    }
    this.advanceControlFence(
      command.sessionId,
      command.expectedControlRevision,
      command.expectedControlEpoch
    );
    const control = this.controlProjection(command.sessionId);
    events.push(
      this.appendEvent(command.sessionId, command, now, "session.control.released", {
        previousControllerUserId: command.actor.userId,
        reason: "controller-released",
        steeringRevision,
        ...control,
      })
    );
    return result(command, { sessionId: command.sessionId, steeringRevision, ...control }, events);
  }

  private claimAssignee(
    command: Extract<SessionCommand, { type: "session.assignee.claim" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    if (!this.hasSessionAccess(command.sessionId, command.actor.userId)) deny();
    const membership = this.activeMembership(session.team_id as string, command.actor.userId);
    if (!membership || membership.role === "guest") deny();
    if (!this.activeProjectAccess(session.project_id as string, command.actor.userId)) deny();
    const participant = this.activeParticipant(command.sessionId, command.actor.userId);
    if (!participant) deny();
    assertExpectedRevision(
      session.assignee_revision as number,
      command.expectedAssigneeRevision,
      "Assignee"
    );
    assertExpectedRevision(
      session.access_revision as number,
      command.expectedAccessRevision,
      "Session Access"
    );
    if (session.status !== "awaiting_assignee") {
      throw new TeamSessionError("conflict", "Session is not Awaiting Assignee");
    }
    if (this.activeResponsibilityHolder(command.sessionId, "assignee")) {
      throw new TeamSessionError("conflict", "Session already has an Assignee");
    }

    const wasSupervisor = this.hasResponsibility(
      command.sessionId,
      command.actor.userId,
      "supervisor"
    );
    this.upsertResponsibility(command.sessionId, command.actor.userId, "assignee", now);
    if (!wasSupervisor) {
      this.upsertResponsibility(command.sessionId, command.actor.userId, "supervisor", now);
    }
    const assigneeRevision = this.advanceAssigneeRevision(command.sessionId);
    const supervisionRevision = wasSupervisor
      ? (session.supervision_revision as number)
      : this.advanceSupervisionRevision(command.sessionId);
    this.db.prepare("UPDATE sessions SET status = 'active' WHERE id = ?").run(command.sessionId);
    const cancelled = this.cancelOfferedHandoffs(
      command.sessionId,
      now,
      command.actor.userId,
      "assignee-claimed"
    );
    const events: SessionEvent[] = [
      this.appendEvent(command.sessionId, command, now, "session.responsibility.granted", {
        userId: command.actor.userId,
        responsibility: "assignee",
        assigneeRevision,
      }),
    ];
    if (!wasSupervisor) {
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.responsibility.granted", {
          userId: command.actor.userId,
          responsibility: "supervisor",
          supervisionRevision,
        })
      );
    }
    events.push(
      ...this.appendHandoffCancellationEvents(command.sessionId, command, now, cancelled),
      this.appendEvent(command.sessionId, command, now, "session.assignee.claimed", {
        assigneeUserId: command.actor.userId,
        participantId: participant.id,
        assigneeRevision,
        supervisionRevision,
        runtimeAuthorizationGeneration: session.runtime_authorization_generation,
        runtimeAuthorizationState: session.runtime_authorization_state,
      })
    );
    return result(
      command,
      {
        sessionId: command.sessionId,
        assigneeUserId: command.actor.userId,
        assigneeRevision,
        supervisionRevision,
        runtimeAuthorizationGeneration: session.runtime_authorization_generation,
        runtimeAuthorizationState: session.runtime_authorization_state,
      },
      events
    );
  }

  private offerHandoff(
    command: Extract<SessionCommand, { type: "session.handoff.offer" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    if (!this.hasSessionAccess(command.sessionId, command.actor.userId)) deny();
    const offeredUnder = this.hasResponsibility(command.sessionId, command.actor.userId, "assignee")
      ? "assignee"
      : this.hasResponsibility(command.sessionId, command.actor.userId, "supervisor")
        ? "supervisor"
        : undefined;
    if (!offeredUnder) deny();
    const authority = this.responsibility(command.sessionId, command.actor.userId, offeredUnder);
    if (!authority || authority.status !== "active") deny();
    if (session.status === "ended") {
      throw new TeamSessionError("conflict", "An ended Session cannot create a Handoff");
    }
    assertExpectedRevision(
      session.assignee_revision as number,
      command.expectedAssigneeRevision,
      "Assignee"
    );
    assertExpectedVersion(
      authority.version as number,
      command.expectedOffererResponsibilityVersion,
      "Handoff authority"
    );
    const recipient = this.activeParticipantById(command.sessionId, command.recipientParticipantId);
    if (!recipient || !this.hasSessionAccess(command.sessionId, recipient.user_id as string)) {
      deny();
    }
    assertExpectedVersion(
      recipient.version as number,
      command.expectedRecipientParticipantVersion,
      "Handoff recipient Participant"
    );
    if (recipient.user_id === command.actor.userId) {
      throw new TeamSessionError("conflict", "Handoff recipient must be another Participant");
    }
    if (this.hasResponsibility(command.sessionId, recipient.user_id as string, "assignee")) {
      throw new TeamSessionError("conflict", "Recipient is already the Assignee");
    }
    const expiresAtMs = command.expiresAtMs ?? now + DEFAULT_HANDOFF_TTL_MS;
    if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= now) {
      throw new TeamSessionError("invalid-command", "Handoff expiry must be in the future");
    }
    const handoffId = this.nextId("handoff");
    const contextSequence = (session.next_sequence as number) - 1;
    const briefing = normalizeHandoffBriefing(command.briefing, contextSequence);
    this.db
      .prepare(
        `INSERT INTO session_handoffs (
           id, session_id, offerer_user_id, recipient_participant_id,
           recipient_user_id, offered_under_kind, offered_under_version,
           recipient_participant_version, base_assignee_revision, context_sequence,
           status, version, expires_at_ms, briefing_json, created_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'offered', 1, ?, ?, ?)`
      )
      .run(
        handoffId,
        command.sessionId,
        command.actor.userId,
        recipient.id,
        recipient.user_id,
        offeredUnder,
        authority.version,
        recipient.version,
        session.assignee_revision,
        contextSequence,
        expiresAtMs,
        JSON.stringify(briefing),
        now
      );
    const event = this.appendEvent(command.sessionId, command, now, "session.handoff.offered", {
      handoffId,
      offererUserId: command.actor.userId,
      recipientParticipantId: recipient.id,
      recipientUserId: recipient.user_id,
      offeredUnder,
      handoffVersion: 1,
      baseAssigneeRevision: session.assignee_revision,
      contextSequence,
      expiresAtMs,
      briefing,
    });
    return result(
      command,
      {
        sessionId: command.sessionId,
        handoffId,
        handoffVersion: 1,
        expiresAtMs,
      },
      [event]
    );
  }

  private acceptHandoff(
    command: Extract<SessionCommand, { type: "session.handoff.accept" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    const handoff = this.handoff(command.sessionId, command.handoffId);
    if (!handoff) deny();
    if (handoff.recipient_user_id !== command.actor.userId) deny();
    if (!this.hasSessionAccess(command.sessionId, command.actor.userId)) deny();
    if (session.status === "ended") {
      throw new TeamSessionError("conflict", "An ended Session cannot accept a Handoff");
    }
    assertExpectedVersion(handoff.version as number, command.expectedHandoffVersion, "Handoff");
    if (handoff.status !== "offered") {
      throw new TeamSessionError("conflict", "Handoff is no longer open");
    }
    if ((handoff.expires_at_ms as number) <= now) {
      const expired = this.db
        .prepare(
          `UPDATE session_handoffs
           SET status = 'expired', version = version + 1,
               resolved_at_ms = ?, resolved_by_user_id = ?, cancellation_reason = 'expired'
           WHERE id = ? AND session_id = ? AND status = 'offered' AND version = ?`
        )
        .run(
          now,
          command.actor.userId,
          command.handoffId,
          command.sessionId,
          command.expectedHandoffVersion
        );
      if (expired.changes !== 1) {
        throw new TeamSessionError("stale-revision", "Handoff was resolved concurrently");
      }
      const event = this.appendEvent(command.sessionId, command, now, "session.handoff.expired", {
        handoffId: command.handoffId,
        handoffVersion: (handoff.version as number) + 1,
        expiresAtMs: handoff.expires_at_ms,
      });
      return result(
        command,
        {
          sessionId: command.sessionId,
          handoffId: command.handoffId,
          handoffVersion: (handoff.version as number) + 1,
          handoffAccepted: false,
          reason: "expired",
        },
        [event]
      );
    }
    assertExpectedRevision(
      session.assignee_revision as number,
      handoff.base_assignee_revision as number,
      "Assignee"
    );
    const authority = this.responsibility(
      command.sessionId,
      handoff.offerer_user_id as string,
      handoff.offered_under_kind as "assignee" | "supervisor"
    );
    if (
      !authority ||
      authority.status !== "active" ||
      authority.version !== handoff.offered_under_version
    ) {
      throw new TeamSessionError("stale-revision", "Handoff authority changed");
    }
    const recipient = this.activeParticipantById(
      command.sessionId,
      handoff.recipient_participant_id as string
    );
    if (
      !recipient ||
      recipient.user_id !== command.actor.userId ||
      recipient.version !== handoff.recipient_participant_version
    ) {
      throw new TeamSessionError("stale-revision", "Handoff recipient admission changed");
    }

    const previousAssignee = this.activeResponsibilityHolder(command.sessionId, "assignee");
    const previousController = this.activeResponsibilityHolder(command.sessionId, "controller");
    if (previousAssignee?.user_id === command.actor.userId) {
      throw new TeamSessionError("conflict", "Recipient is already the Assignee");
    }
    if (previousAssignee) {
      this.revokeResponsibilityRow(
        command.sessionId,
        previousAssignee.user_id as string,
        "assignee",
        now
      );
    }
    this.upsertResponsibility(command.sessionId, command.actor.userId, "assignee", now);
    const wasSupervisor = this.hasResponsibility(
      command.sessionId,
      command.actor.userId,
      "supervisor"
    );
    if (!wasSupervisor) {
      this.upsertResponsibility(command.sessionId, command.actor.userId, "supervisor", now);
    }

    const removedSteerers =
      session.steering_policy === "single"
        ? (this.db
            .prepare(
              `SELECT user_id FROM session_responsibilities
               WHERE session_id = ? AND kind = 'steerer' AND status = 'active'
                 AND user_id <> ? ORDER BY user_id ASC`
            )
            .all(command.sessionId, command.actor.userId) as SqlRow[])
        : [];
    for (const removed of removedSteerers) {
      this.revokeResponsibilityRow(command.sessionId, removed.user_id as string, "steerer", now);
    }
    const wasSteerer = this.hasResponsibility(command.sessionId, command.actor.userId, "steerer");
    if (!wasSteerer) {
      this.upsertResponsibility(command.sessionId, command.actor.userId, "steerer", now);
    }
    if (previousController?.user_id !== command.actor.userId && previousController) {
      this.revokeResponsibilityRow(
        command.sessionId,
        previousController.user_id as string,
        "controller",
        now
      );
    }
    if (previousController?.user_id !== command.actor.userId) {
      this.upsertResponsibility(command.sessionId, command.actor.userId, "controller", now);
    }

    const assigneeRevision = this.advanceAssigneeRevision(command.sessionId);
    const supervisionRevision = wasSupervisor
      ? (session.supervision_revision as number)
      : this.advanceSupervisionRevision(command.sessionId);
    const steeringChanged = removedSteerers.length > 0 || !wasSteerer;
    const steeringRevision = steeringChanged
      ? this.advanceSteeringRevision(command.sessionId)
      : (session.steering_revision as number);
    this.advanceControlFence(command.sessionId);
    const control = this.controlProjection(command.sessionId);
    this.db.prepare("UPDATE sessions SET status = 'active' WHERE id = ?").run(command.sessionId);
    const updated = this.db
      .prepare(
        `UPDATE session_handoffs
         SET status = 'accepted', version = version + 1,
             resolved_at_ms = ?, resolved_by_user_id = ?, cancellation_reason = NULL
         WHERE id = ? AND session_id = ? AND status = 'offered' AND version = ?`
      )
      .run(
        now,
        command.actor.userId,
        command.handoffId,
        command.sessionId,
        command.expectedHandoffVersion
      );
    if (updated.changes !== 1) {
      throw new TeamSessionError("stale-revision", "Handoff was resolved concurrently");
    }
    const cancelled = this.cancelOfferedHandoffs(
      command.sessionId,
      now,
      command.actor.userId,
      "superseded-by-accepted-handoff",
      command.handoffId
    );
    const events: SessionEvent[] = [];
    if (previousAssignee) {
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.responsibility.revoked", {
          userId: previousAssignee.user_id,
          responsibility: "assignee",
          reason: "handoff-accepted",
          assigneeRevision,
        })
      );
    }
    events.push(
      this.appendEvent(command.sessionId, command, now, "session.responsibility.granted", {
        userId: command.actor.userId,
        responsibility: "assignee",
        reason: "handoff-accepted",
        assigneeRevision,
      })
    );
    if (!wasSupervisor) {
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.responsibility.granted", {
          userId: command.actor.userId,
          responsibility: "supervisor",
          reason: "handoff-accepted",
          supervisionRevision,
        })
      );
    }
    for (const removed of removedSteerers) {
      const removedUserId = removed.user_id as string;
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.responsibility.revoked", {
          userId: removedUserId,
          responsibility: "steerer",
          reason: "single-policy-handoff",
          steeringRevision,
        }),
        ...this.appendQueuedDirectiveCancellationEvents(
          command.sessionId,
          command,
          now,
          removedUserId,
          "single-policy-handoff"
        )
      );
    }
    if (!wasSteerer) {
      events.push(
        this.appendEvent(command.sessionId, command, now, "session.responsibility.granted", {
          userId: command.actor.userId,
          responsibility: "steerer",
          reason: "handoff-accepted",
          steeringRevision,
        })
      );
    }
    events.push(
      this.appendEvent(command.sessionId, command, now, "session.control.transferred", {
        previousControllerUserId: previousController?.user_id ?? null,
        controllerUserId: command.actor.userId,
        reason: "handoff-accepted",
        steeringRevision,
        ...control,
      }),
      ...this.appendHandoffCancellationEvents(command.sessionId, command, now, cancelled),
      this.appendEvent(command.sessionId, command, now, "session.handoff.accepted", {
        handoffId: command.handoffId,
        handoffVersion: (handoff.version as number) + 1,
        previousAssigneeUserId: previousAssignee?.user_id ?? null,
        assigneeUserId: command.actor.userId,
        assigneeRevision,
        supervisionRevision,
        steeringRevision,
        ...control,
      })
    );
    return result(
      command,
      {
        sessionId: command.sessionId,
        handoffId: command.handoffId,
        handoffVersion: (handoff.version as number) + 1,
        assigneeUserId: command.actor.userId,
        assigneeRevision,
        supervisionRevision,
        steeringRevision,
        ...control,
      },
      events
    );
  }

  private cancelHandoff(
    command: Extract<SessionCommand, { type: "session.handoff.cancel" }>,
    now: number
  ): CommandResult {
    this.requireSession(command.sessionId);
    const handoff = this.handoff(command.sessionId, command.handoffId);
    if (!handoff) deny();
    if (!this.hasSessionAccess(command.sessionId, command.actor.userId)) deny();
    const authorized =
      handoff.offerer_user_id === command.actor.userId ||
      handoff.recipient_user_id === command.actor.userId ||
      this.hasResponsibility(command.sessionId, command.actor.userId, "assignee") ||
      this.hasResponsibility(command.sessionId, command.actor.userId, "supervisor");
    if (!authorized) deny();
    assertExpectedVersion(handoff.version as number, command.expectedHandoffVersion, "Handoff");
    if (handoff.status !== "offered") {
      throw new TeamSessionError("conflict", "Handoff is no longer open");
    }
    const resolution = (handoff.expires_at_ms as number) <= now ? "expired" : "cancelled";
    const updated = this.db
      .prepare(
        `UPDATE session_handoffs
         SET status = ?, version = version + 1,
             resolved_at_ms = ?, resolved_by_user_id = ?, cancellation_reason = ?
         WHERE id = ? AND session_id = ? AND status = 'offered' AND version = ?`
      )
      .run(
        resolution,
        now,
        command.actor.userId,
        resolution,
        command.handoffId,
        command.sessionId,
        command.expectedHandoffVersion
      );
    if (updated.changes !== 1) {
      throw new TeamSessionError("stale-revision", "Handoff was resolved concurrently");
    }
    const event = this.appendEvent(
      command.sessionId,
      command,
      now,
      resolution === "expired" ? "session.handoff.expired" : "session.handoff.cancelled",
      {
        handoffId: command.handoffId,
        handoffVersion: (handoff.version as number) + 1,
        reason: resolution,
        resolvedByUserId: command.actor.userId,
      }
    );
    return result(
      command,
      {
        sessionId: command.sessionId,
        handoffId: command.handoffId,
        handoffVersion: (handoff.version as number) + 1,
        reason: resolution,
      },
      [event]
    );
  }

  private addComment(
    command: Extract<SessionCommand, { type: "comment.add" }>,
    now: number
  ): CommandResult {
    this.requireConversationParticipant(command.sessionId, command.actor.userId);
    const body = requiredConversationBody(command.body, "Comment body");
    const commentId = this.reserveConversationIdentity(command.sessionId, "comment", now);
    const event = this.appendEvent(command.sessionId, command, now, "comment.added", {
      commentId,
      body,
    });
    this.bindConversationIdentity(commentId, command.sessionId, "comment", event.sequence);
    return result(command, { sessionId: command.sessionId, commentId, sequence: event.sequence }, [
      event,
    ]);
  }

  private addSuggestion(
    command: Extract<SessionCommand, { type: "suggestion.add" }>,
    now: number
  ): CommandResult {
    const session = this.requireConversationParticipant(command.sessionId, command.actor.userId);
    if (session.status === "ended") {
      throw new TeamSessionError("conflict", "An ended Session cannot add Suggestions");
    }
    const body = requiredConversationBody(command.body, "Suggestion body");
    const suggestionId = this.reserveConversationIdentity(command.sessionId, "suggestion", now);
    const event = this.appendEvent(command.sessionId, command, now, "suggestion.added", {
      suggestionId,
      suggestionVersion: 1,
      body,
    });
    this.bindConversationIdentity(suggestionId, command.sessionId, "suggestion", event.sequence);
    return result(
      command,
      {
        sessionId: command.sessionId,
        suggestionId,
        suggestionVersion: 1,
        sequence: event.sequence,
      },
      [event]
    );
  }

  private resolveSuggestion(
    command: Extract<SessionCommand, { type: "suggestion.resolve" }>,
    now: number
  ): CommandResult {
    const session = this.requireDirectiveAuthority(
      command.sessionId,
      command.actor.userId,
      command.expectedSteeringRevision
    );
    const suggestion = this.requireSuggestionEvent(command.sessionId, command.suggestionId);
    const previousResolution = this.suggestionResolutionEvent(
      command.sessionId,
      command.suggestionId
    );
    const currentVersion = previousResolution?.suggestionVersion ?? 1;
    assertExpectedVersion(currentVersion, command.expectedSuggestionVersion, "Suggestion");
    if (previousResolution) {
      throw new TeamSessionError("conflict", "Suggestion is already resolved");
    }

    const accepted = command.resolution !== "reject";
    const directiveBody =
      command.resolution === "accept-edited"
        ? requiredConversationBody(command.editedBody, "Edited Directive body")
        : suggestion.body;
    const resolutionId = this.reserveConversationIdentity(command.sessionId, "resolution", now);
    const directiveId = accepted
      ? this.reserveConversationIdentity(command.sessionId, "directive", now)
      : undefined;
    const resolutionEvent = this.appendEvent(
      command.sessionId,
      command,
      now,
      "suggestion.resolved",
      {
        suggestionId: command.suggestionId,
        suggestionSequence: suggestion.sequence,
        suggestionVersion: 2,
        resolutionId,
        resolution: command.resolution,
        ...(directiveId === undefined ? {} : { directiveId }),
      }
    );
    this.bindConversationIdentity(
      resolutionId,
      command.sessionId,
      "resolution",
      resolutionEvent.sequence
    );
    const events = [resolutionEvent];
    let directiveEvent: SessionEvent | undefined;
    if (directiveId !== undefined) {
      directiveEvent = this.appendQueuedDirective(
        command,
        now,
        directiveId,
        directiveBody,
        session,
        {
          kind: "suggestion",
          suggestionId: command.suggestionId,
          resolutionId,
        }
      );
      events.push(directiveEvent);
    }
    this.recordSuggestionResolution(
      command.sessionId,
      command.suggestionId,
      resolutionId,
      resolutionEvent.sequence,
      command.resolution,
      directiveId
    );
    return result(
      command,
      {
        sessionId: command.sessionId,
        suggestionId: command.suggestionId,
        suggestionVersion: 2,
        resolutionId,
        resolution: command.resolution,
        ...(directiveId === undefined
          ? {}
          : {
              directiveId,
              directiveStatus: "queued",
              directiveQueueSequence: directiveEvent?.sequence,
            }),
      },
      events
    );
  }

  private enqueueDirective(
    command: Extract<SessionCommand, { type: "directive.enqueue" }>,
    now: number
  ): CommandResult {
    const session = this.requireDirectiveAuthority(
      command.sessionId,
      command.actor.userId,
      command.expectedSteeringRevision
    );
    const body = requiredConversationBody(command.body, "Directive body");
    const directiveId = this.reserveConversationIdentity(command.sessionId, "directive", now);
    const event = this.appendQueuedDirective(command, now, directiveId, body, session, {
      kind: "direct",
    });
    return result(
      command,
      {
        sessionId: command.sessionId,
        directiveId,
        directiveStatus: "queued",
        queueSequence: event.sequence,
        steeringRevision: session.steering_revision,
      },
      [event]
    );
  }

  private startAgentRun(
    command: Extract<SessionCommand, { type: "run.start" }>,
    now: number
  ): CommandResult {
    const authorityIssuer = this.requireRuntimeCommandAuthorityIssuer();
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    if (session.status !== "active") {
      throw new TeamSessionError("conflict", "Only an active Session can start a Run");
    }
    if (session.runtime_authorization_state !== "enforced") {
      throw new TeamSessionError(
        "conflict",
        "Runtime authorization must be enforced before a Run can start"
      );
    }
    assertExpectedRevision(
      session.run_state_revision as number,
      command.expectedSessionRevision,
      "Run state"
    );
    if (this.mutableAgentRun(command.sessionId)) {
      throw new TeamSessionError("conflict", "This Session already has a mutable Run");
    }
    validateInitialGoalsOrThrow(command.initialGoals);
    const assignment = this.ensureCurrentRuntimeAssignment(session, now);
    this.assertRunPolicyCommit(command.commit, session, assignment);
    if (command.initialYoloActionGrantId !== undefined && command.commit.policy.mode !== "yolo") {
      throw new TeamSessionError(
        "invalid-command",
        "An initial YOLO Action Grant is valid only for YOLO mode"
      );
    }

    const agentRunId = this.nextId("run");
    const goalSetId = this.nextId("goal-set");
    const runtimeCommandId = this.nextId("runtime-command");
    const goals: GoalItem[] = command.initialGoals.map((goal) => ({
      ...goal,
      acceptanceCriteria: [...goal.acceptanceCriteria],
      dependencyGoalIds: [...goal.dependencyGoalIds],
      version: 1,
      status: "pending",
    }));
    this.db
      .prepare(
        `INSERT INTO agent_runs
           (id, session_id, team_id, project_id, runtime_assignment_id,
            start_command_id, lifecycle,
            state_version, current_policy_revision, current_goal_set_revision,
            runtime_authorization_generation, final_review_version,
            created_by_user_id, created_at_ms, updated_at_ms, terminal_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, 'starting', 1, 1, 1, ?, 1, ?, ?, ?, NULL)`
      )
      .run(
        agentRunId,
        command.sessionId,
        session.team_id,
        session.project_id,
        assignment.id,
        runtimeCommandId,
        assignment.runtime_authorization_generation,
        command.actor.userId,
        now,
        now
      );
    const goalSetDigest = this.insertGoalSetSnapshot({
      agentRunId,
      goalSetId,
      revision: 1,
      goals,
      now,
    });
    const policySnapshot = this.insertRunPolicyRevision({
      agentRunId,
      sessionId: command.sessionId,
      revision: 1,
      policy: command.commit.policy,
      policyDigest: command.commit.policyDigest,
      goalSetId,
      goalSetRevision: 1,
      goalSetDigest,
      goals,
      assignment,
      yoloConfirmationRef: command.commit.yoloConfirmation?.challengeId,
      now,
    });
    const requestEvent = this.appendEvent(
      command.sessionId,
      command,
      now,
      "run.runtime-command.requested",
      {
        commandId: runtimeCommandId,
        agentRunId,
        operation: "run.start",
        targetLifecycle: "active",
        fromRunStateVersion: 1,
        toRunStateVersion: 2,
        lifecycle: "starting",
        stateVersion: 1,
        runPolicyRevision: 1,
        goalSetRevision: 1,
      }
    );
    const claims: Omit<Extract<RuntimeLifecycleCommand, { kind: "run.start" }>, "authority"> = {
      kind: "run.start",
      commandId: runtimeCommandId,
      binding: policySnapshot.binding,
      projectCeilingRevision: policySnapshot.projectCeilingRevision,
      runtimeAuthorizationGeneration: policySnapshot.runtimeAuthorizationGeneration,
      requiredEffectEnforcerSetDigest: policySnapshot.requiredEffectEnforcerSetDigest,
      causationId: requestEvent.eventId,
      actor: { kind: command.actor.kind, actorRef: command.actor.userId },
      issuedAtMs: now,
      deadlineAtMs: this.runtimeLifecycleDeadline(now),
      agentRunId,
      runPolicyRevision: 1,
      fromRunStateVersion: 1,
      toRunStateVersion: 2,
      policy: policySnapshot,
    };
    const runtimeCommand: Extract<RuntimeLifecycleCommand, { kind: "run.start" }> = {
      ...claims,
      authority: authorityIssuer.issue(claims),
    };
    const intent = this.runtimeLifecycle.enqueue({
      command: runtimeCommand,
      sourceSessionSequence: requestEvent.sequence,
    });
    const runStateRevision = this.advanceRunStateRevision(command.sessionId);
    return result(
      command,
      {
        sessionId: command.sessionId,
        agentRunId,
        lifecycle: "starting",
        stateVersion: 1,
        runPolicyRevision: 1,
        goalSetRevision: 1,
        runStateRevision,
        runtimeCommandId: intent.commandId,
        runtimeCommandStatus: "pending",
      },
      [requestEvent]
    );
  }

  private reviseAgentRunPolicy(
    command: Extract<SessionCommand, { type: "run.policy.revise" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    if (run.lifecycle === "starting" || run.lifecycle === "pausing") {
      throw new TeamSessionError(
        "conflict",
        "Run policy cannot change while Runtime lifecycle enforcement is pending"
      );
    }
    if (this.hasUnresolvedRuntimeLifecycle(run.id as string)) {
      throw new TeamSessionError(
        "conflict",
        "Run policy cannot change while Runtime lifecycle truth is unresolved"
      );
    }
    assertExpectedRevision(
      run.current_policy_revision as number,
      command.expectedRunPolicyRevision,
      "Run policy"
    );
    const assignment = this.requireRuntimeAssignment(run.runtime_assignment_id as string);
    if (
      assignment.session_id !== command.sessionId ||
      assignment.status !== "ready" ||
      session.runtime_authorization_state !== "enforced" ||
      assignment.runtime_authorization_generation !== session.runtime_authorization_generation ||
      run.runtime_authorization_generation !== session.runtime_authorization_generation
    ) {
      throw new TeamSessionError(
        "conflict",
        "Run Runtime binding changed; recover or stop the Run before revising policy"
      );
    }
    this.assertRunPolicyCommit(command.commit, session, assignment);
    const current = this.readRunPolicyDraft(
      command.agentRunId,
      run.current_policy_revision as number
    );
    const currentSnapshot = this.db
      .prepare(
        `SELECT policy_body_digest, runtime_assignment_id, runtime_assignment_generation,
                sandbox_id, sandbox_generation, runtime_principal_id,
                runtime_authorization_generation, required_effect_enforcer_set_digest
         FROM run_policy_revisions WHERE agent_run_id = ? AND revision = ?`
      )
      .get(command.agentRunId, run.current_policy_revision) as SqlRow | undefined;
    if (!currentSnapshot) {
      throw new TeamSessionError("conflict", "Run policy revision is unavailable");
    }
    const bindingChanged = !this.policySnapshotMatchesAssignment(
      currentSnapshot,
      assignment,
      session.runtime_authorization_generation as number
    );
    const policyBodyChanged = currentSnapshot.policy_body_digest !== command.commit.policyDigest;
    if (!bindingChanged && !policyBodyChanged) {
      throw new TeamSessionError("conflict", "Run policy and Runtime binding are unchanged");
    }
    const widening = isRunPolicyWidening(current, command.commit.policy);
    if (widening) {
      throw new TeamSessionError(
        "conflict",
        "A wider Run policy requires a completed one-shot approval"
      );
    }
    if (command.commit.wideningActionGrantId !== undefined) {
      throw new TeamSessionError(
        "invalid-command",
        "A widening Action Grant is invalid for a tightening policy revision"
      );
    }
    const nextRevision = (run.current_policy_revision as number) + 1;
    const goalSet = this.currentGoalSetSnapshot(run);
    this.insertRunPolicyRevision({
      agentRunId: command.agentRunId,
      sessionId: command.sessionId,
      revision: nextRevision,
      previousRevision: run.current_policy_revision as number,
      policy: command.commit.policy,
      policyDigest: command.commit.policyDigest,
      goalSetId: goalSet.goalSetId,
      goalSetRevision: goalSet.revision,
      goalSetDigest: goalSet.digest,
      goals: goalSet.goals,
      assignment,
      yoloConfirmationRef: command.commit.yoloConfirmation?.challengeId,
      now,
    });
    const updated = this.db
      .prepare(
        `UPDATE agent_runs
         SET current_policy_revision = ?, state_version = state_version + 1, updated_at_ms = ?
         WHERE id = ? AND session_id = ? AND current_policy_revision = ?
         RETURNING state_version`
      )
      .get(
        nextRevision,
        now,
        command.agentRunId,
        command.sessionId,
        command.expectedRunPolicyRevision
      ) as SqlRow | undefined;
    if (!updated) throw new TeamSessionError("stale-revision", "Run policy changed concurrently");
    const invalidatedGrantCount = this.invalidateMutableRunGrants(
      command.agentRunId,
      now,
      "policy-revision"
    );
    const runStateRevision = this.advanceRunStateRevision(command.sessionId);
    const event = this.appendEvent(command.sessionId, command, now, "run.policy.revised", {
      agentRunId: command.agentRunId,
      previousRunPolicyRevision: command.expectedRunPolicyRevision,
      runPolicyRevision: nextRevision,
      policyDigest: command.commit.policyDigest,
      transition: bindingChanged
        ? policyBodyChanged
          ? "rebind-and-tighten"
          : "rebind"
        : "tighten",
      mode: command.commit.policy.mode,
      completionPolicy: command.commit.policy.completionPolicy.kind,
      stateVersion: updated.state_version,
      invalidatedGrantCount,
      runStateRevision,
    });
    return result(
      command,
      {
        sessionId: command.sessionId,
        agentRunId: command.agentRunId,
        runPolicyRevision: nextRevision,
        stateVersion: updated.state_version,
        invalidatedGrantCount,
        runStateRevision,
      },
      [event]
    );
  }

  private pauseAgentRun(
    command: Extract<SessionCommand, { type: "run.pause" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    const assignment = this.requireReadyRunRuntimeBinding(session, run);
    assertExpectedVersion(
      run.state_version as number,
      command.expectedRunStateVersion,
      "Run state"
    );
    if (run.lifecycle !== "active") {
      throw new TeamSessionError("conflict", "Only an active Run can be paused");
    }
    return this.requestRuntimeLifecycleTransition(command, run, assignment, now);
  }

  private resumeAgentRun(
    command: Extract<SessionCommand, { type: "run.resume" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    assertExpectedVersion(
      run.state_version as number,
      command.expectedRunStateVersion,
      "Run state"
    );
    assertExpectedRevision(
      run.current_policy_revision as number,
      command.expectedRunPolicyRevision,
      "Run policy"
    );
    assertExpectedRevision(
      run.runtime_authorization_generation as number,
      command.expectedRuntimeAuthorizationGeneration,
      "Run Runtime Authorization"
    );
    if (run.lifecycle !== "paused") {
      throw new TeamSessionError("conflict", "Only a paused Run can be resumed");
    }
    const assignment = this.requireRuntimeAssignment(run.runtime_assignment_id as string);
    const policySnapshot = this.db
      .prepare(
        `SELECT runtime_assignment_id, runtime_assignment_generation,
                sandbox_id, sandbox_generation, runtime_principal_id,
                runtime_authorization_generation, required_effect_enforcer_set_digest
         FROM run_policy_revisions WHERE agent_run_id = ? AND revision = ?`
      )
      .get(run.id, run.current_policy_revision) as SqlRow | undefined;
    if (
      !policySnapshot ||
      assignment.status !== "ready" ||
      !this.policySnapshotMatchesAssignment(
        policySnapshot,
        assignment,
        session.runtime_authorization_generation as number
      )
    ) {
      throw new TeamSessionError(
        "conflict",
        "Run policy must be rebound to the enforced Runtime before resuming"
      );
    }
    if (
      session.status !== "active" ||
      session.runtime_authorization_state !== "enforced" ||
      session.runtime_authorization_generation !== run.runtime_authorization_generation ||
      !this.activeResponsibilityHolder(command.sessionId, "assignee")
    ) {
      throw new TeamSessionError(
        "conflict",
        "A Run requires an active Session, enforced Runtime, and accountable Assignee"
      );
    }
    return this.requestRuntimeLifecycleTransition(command, run, assignment, now);
  }

  private stopAgentRun(
    command: Extract<SessionCommand, { type: "run.stop" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    const assignment = this.requireReadyRunRuntimeBinding(session, run);
    assertExpectedVersion(
      run.state_version as number,
      command.expectedRunStateVersion,
      "Run state"
    );
    if (run.lifecycle === "pausing") {
      throw new TeamSessionError("conflict", "Emergency-stop enforcement is already in progress");
    }
    return this.requestRuntimeLifecycleTransition(command, run, assignment, now);
  }

  private emergencyStopAgentRun(
    command: Extract<SessionCommand, { type: "run.emergency-stop" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireSessionManager(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    const assignment = this.requireRuntimeAssignment(run.runtime_assignment_id as string);
    const binding = command.runtimeBinding;
    if (
      binding.runtimeAssignmentId !== assignment.id ||
      binding.runtimeAssignmentGeneration !== assignment.generation ||
      binding.sandboxId !== assignment.sandbox_id ||
      binding.sandboxGeneration !== assignment.sandbox_generation
    ) {
      throw new TeamSessionError("stale-revision", "Emergency-stop Runtime binding changed");
    }
    const controlBefore = session.control_epoch as number;
    const steeringBefore = session.steering_revision as number;
    this.advanceControlFence(command.sessionId);
    const steeringRevision = this.advanceSteeringRevision(command.sessionId);
    const authorization = this.db
      .prepare(
        `UPDATE sessions
         SET runtime_authorization_generation = runtime_authorization_generation + 1,
             runtime_authorization_state = 'quarantined'
         WHERE id = ?
         RETURNING runtime_authorization_generation`
      )
      .get(command.sessionId) as SqlRow | undefined;
    if (!authorization) deny();
    this.db
      .prepare(
        `UPDATE runtime_assignments
         SET runtime_authorization_generation = ?, status = 'quarantined'
         WHERE id = ?`
      )
      .run(authorization.runtime_authorization_generation, assignment.id);
    this.recordRuntimeAuthorizationEpoch(
      command.sessionId,
      this.requireRuntimeAssignment(assignment.id as string),
      authorization.runtime_authorization_generation as number,
      now
    );
    const invalidatedGrantCount = this.invalidateMutableRunGrants(command.agentRunId, now);
    this.db
      .prepare(
        `UPDATE runtime_outbox
         SET status = 'superseded', lease_owner = NULL, lease_expires_at_ms = NULL,
             delivered_at_ms = ?
         WHERE session_id = ? AND status IN ('pending', 'processing', 'failed')`
      )
      .run(now, command.sessionId);
    this.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'superseded', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = 'emergency_fenced_before_dispatch',
             updated_at_ms = ?, terminal_at_ms = ?
         WHERE agent_run_id = ? AND status = 'pending'`
      )
      .run(now, now, command.agentRunId);
    this.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'awaiting-receipt', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = 'emergency_fenced_dispatch_uncertain',
             available_at_ms = MAX(available_at_ms, ?), updated_at_ms = ?
         WHERE agent_run_id = ? AND status = 'processing'`
      )
      .run(now, now, command.agentRunId);
    const transitioned = this.updateAgentRunLifecycle(
      run,
      "pausing",
      now,
      authorization.runtime_authorization_generation as number
    );
    const runStateRevision = this.advanceRunStateRevision(command.sessionId);
    const control = this.controlProjection(command.sessionId);
    const event = this.appendEvent(
      command.sessionId,
      command,
      now,
      "run.emergency-stop.requested",
      {
        agentRunId: command.agentRunId,
        lifecycle: "pausing",
        stateVersion: transitioned.stateVersion,
        reason: requiredConversationBody(command.reason, "Emergency-stop reason"),
        previousControlEpoch: controlBefore,
        controlEpoch: control.controlEpoch,
        previousSteeringRevision: steeringBefore,
        steeringRevision,
        runtimeAuthorizationGeneration: authorization.runtime_authorization_generation,
        invalidatedGrantCount,
        revokeAllRunGrants: true,
        runStateRevision,
      }
    );
    const retireOutboxId = this.nextId("outbox");
    const retirePayload: RuntimeOutboxPayload<"runtime.session.retire"> = {
      sessionId: command.sessionId,
      runtimeAuthorizationGeneration: authorization.runtime_authorization_generation as number,
      reason: "emergency-stop",
      agentRunId: command.agentRunId,
      runtimeAssignmentId: assignment.id as string,
      runtimeAssignmentGeneration: assignment.generation as number,
      sandboxId: assignment.sandbox_id as string,
      sandboxGeneration: assignment.sandbox_generation as number,
    };
    this.db
      .prepare(
        `INSERT INTO runtime_outbox
           (id, session_id, session_sequence, kind, payload_json, status, attempts, created_at_ms)
         VALUES (?, ?, ?, 'runtime.session.retire', ?, 'pending', 0, ?)`
      )
      .run(retireOutboxId, command.sessionId, event.sequence, JSON.stringify(retirePayload), now);
    return result(
      command,
      {
        sessionId: command.sessionId,
        agentRunId: command.agentRunId,
        lifecycle: "pausing",
        stateVersion: transitioned.stateVersion,
        controlEpoch: control.controlEpoch,
        steeringRevision,
        runtimeAuthorizationGeneration: authorization.runtime_authorization_generation,
        invalidatedGrantCount,
        runStateRevision,
        enforcementPending: true,
        retireOutboxId,
      },
      [event]
    );
  }

  private addRunGoal(
    command: Extract<SessionCommand, { type: "goal.add" }>,
    now: number
  ): CommandResult {
    const session = this.requireRunSteeringAuthority(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    this.requireReadyRunRuntimeBinding(session, run);
    const current = this.currentGoalSetSnapshot(run);
    assertExpectedRevision(current.revision, command.expectedGoalSetRevision, "Goal Set");
    if (current.goals.some((goal) => goal.goalId === command.goal.goalId)) {
      throw new TeamSessionError("conflict", "Goal id is already in this Run");
    }
    const position = command.goal.position;
    if (!Number.isSafeInteger(position) || position < 1 || position > current.goals.length + 1) {
      throw new TeamSessionError("invalid-command", "New Goal position is invalid");
    }
    const goals = current.goals.map(cloneGoalItem);
    goals.splice(position - 1, 0, {
      goalId: command.goal.goalId,
      position: command.goal.position,
      title: command.goal.title,
      acceptanceCriteria: [...command.goal.acceptanceCriteria],
      dependencyGoalIds: [...command.goal.dependencyGoalIds],
      version: 1,
      status: "pending",
    });
    renumberGoals(goals);
    validateGoalItemsOrThrow(goals);
    const directive = this.appendRunDirective(command, now, session, command.directive, {
      kind: "goal-add",
      agentRunId: command.agentRunId,
      goalId: command.goal.goalId,
    });
    return this.commitGoalSetMutation(command, run, current, goals, now, directive, {
      change: "goal-added",
      goalId: command.goal.goalId,
    });
  }

  private strengthenRunGoalCriteria(
    command: Extract<SessionCommand, { type: "goal.criteria.strengthen" }>,
    now: number
  ): CommandResult {
    const session = this.requireRunSteeringAuthority(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    this.requireReadyRunRuntimeBinding(session, run);
    const current = this.currentGoalSetSnapshot(run);
    assertExpectedRevision(current.revision, command.expectedGoalSetRevision, "Goal Set");
    if (!Array.isArray(command.addedCriteria) || command.addedCriteria.length < 1) {
      throw new TeamSessionError("invalid-command", "At least one stronger criterion is required");
    }
    const goals = current.goals.map(cloneGoalItem);
    const goal = goals.find((candidate) => candidate.goalId === command.goalId);
    if (!goal) deny();
    const added = command.addedCriteria.map((criterion) =>
      requiredText(criterion, "Goal acceptance criterion", 1_000)
    );
    if (added.some((criterion) => goal.acceptanceCriteria.includes(criterion))) {
      throw new TeamSessionError("conflict", "A Goal criterion is already present");
    }
    goal.acceptanceCriteria = [...goal.acceptanceCriteria, ...added];
    goal.version += 1;
    goal.status = "pending";
    validateGoalItemsOrThrow(goals);
    const directive = this.appendRunDirective(command, now, session, command.directive, {
      kind: "goal-criteria-strengthened",
      agentRunId: command.agentRunId,
      goalId: command.goalId,
    });
    return this.commitGoalSetMutation(command, run, current, goals, now, directive, {
      change: "goal-criteria-strengthened",
      goalId: command.goalId,
      addedCriteriaCount: added.length,
    });
  }

  private addRunGoalDependency(
    command: Extract<SessionCommand, { type: "goal.dependency.add" }>,
    now: number
  ): CommandResult {
    const session = this.requireRunSteeringAuthority(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    this.requireReadyRunRuntimeBinding(session, run);
    const current = this.currentGoalSetSnapshot(run);
    assertExpectedRevision(current.revision, command.expectedGoalSetRevision, "Goal Set");
    const goals = current.goals.map(cloneGoalItem);
    const goal = goals.find((candidate) => candidate.goalId === command.goalId);
    const dependency = goals.find((candidate) => candidate.goalId === command.dependencyGoalId);
    if (!goal || !dependency) deny();
    if (goal.dependencyGoalIds.includes(dependency.goalId)) {
      throw new TeamSessionError("conflict", "Goal dependency is already present");
    }
    goal.dependencyGoalIds = [...goal.dependencyGoalIds, dependency.goalId];
    goal.version += 1;
    goal.status = "pending";
    validateGoalItemsOrThrow(goals);
    const directive = this.appendRunDirective(command, now, session, command.directive, {
      kind: "goal-dependency-added",
      agentRunId: command.agentRunId,
      goalId: command.goalId,
      dependencyGoalId: command.dependencyGoalId,
    });
    return this.commitGoalSetMutation(command, run, current, goals, now, directive, {
      change: "goal-dependency-added",
      goalId: command.goalId,
      dependencyGoalId: command.dependencyGoalId,
    });
  }

  private reorderRunGoal(
    command: Extract<SessionCommand, { type: "goal.reorder" }>,
    now: number
  ): CommandResult {
    const session = this.requireRunSteeringAuthority(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    this.requireReadyRunRuntimeBinding(session, run);
    const current = this.currentGoalSetSnapshot(run);
    assertExpectedRevision(current.revision, command.expectedGoalSetRevision, "Goal Set");
    if (command.goalId === command.beforeGoalId) {
      throw new TeamSessionError("invalid-command", "A Goal cannot be ordered before itself");
    }
    const goals = current.goals.map(cloneGoalItem);
    const from = goals.findIndex((goal) => goal.goalId === command.goalId);
    if (from < 0) deny();
    const [moved] = goals.splice(from, 1);
    if (!moved) deny();
    const destination =
      command.beforeGoalId === undefined
        ? goals.length
        : goals.findIndex((goal) => goal.goalId === command.beforeGoalId);
    if (destination < 0) deny();
    goals.splice(destination, 0, moved);
    renumberGoals(goals);
    validateGoalItemsOrThrow(goals);
    const directive = this.appendRunDirective(command, now, session, command.directive, {
      kind: "goal-reordered",
      agentRunId: command.agentRunId,
      goalId: command.goalId,
      beforeGoalId: command.beforeGoalId ?? null,
    });
    return this.commitGoalSetMutation(command, run, current, goals, now, directive, {
      change: "goal-reordered",
      goalId: command.goalId,
      beforeGoalId: command.beforeGoalId ?? null,
    });
  }

  private reviewRunGoalEvidence(
    command: Extract<SessionCommand, { type: "goal.evidence.review" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireRunAssignee(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    this.requireReadyRunRuntimeBinding(session, run);
    const current = this.currentGoalSetSnapshot(run);
    const goals = current.goals.map(cloneGoalItem);
    const goal = goals.find((candidate) => candidate.goalId === command.goalId);
    if (!goal) deny();
    assertExpectedVersion(goal.version, command.expectedGoalVersion, "Goal");
    const evidence = this.db
      .prepare(
        `SELECT * FROM goal_evidence
         WHERE agent_run_id = ? AND goal_id = ? AND goal_version = ? AND status = 'proposed'
         ORDER BY created_at_ms ASC, id ASC`
      )
      .all(command.agentRunId, command.goalId, command.expectedGoalVersion) as SqlRow[];
    if (evidence.length === 0) {
      throw new TeamSessionError("conflict", "This Goal has no proposed evidence to review");
    }
    if (command.disposition === "request-more-work" && command.directive === undefined) {
      throw new TeamSessionError(
        "invalid-command",
        "Requesting more work requires an attributed Directive"
      );
    }
    const evidenceStatus = command.disposition === "validate" ? "validated" : "more-work-requested";
    this.db
      .prepare(
        `UPDATE goal_evidence SET status = ?, reviewed_at_ms = ?
         WHERE agent_run_id = ? AND goal_id = ? AND goal_version = ? AND status = 'proposed'`
      )
      .run(evidenceStatus, now, command.agentRunId, command.goalId, command.expectedGoalVersion);
    goal.version += 1;
    goal.status = command.disposition === "validate" ? "validated" : "in-progress";
    let directive: SessionEvent | undefined;
    if (command.directive) {
      directive = this.appendRunDirective(command, now, session, command.directive, {
        kind: "goal-evidence-review",
        agentRunId: command.agentRunId,
        goalId: command.goalId,
        disposition: command.disposition,
      });
    }
    return this.commitGoalSetMutation(command, run, current, goals, now, directive, {
      change: "goal-evidence-reviewed",
      goalId: command.goalId,
      goalVersion: goal.version,
      disposition: command.disposition,
      reviewedEvidenceCount: evidence.length,
    });
  }

  private resolveAgentRunFinalReview(
    command: Extract<SessionCommand, { type: "run.final-review.resolve" }>,
    now: number
  ): CommandResult {
    const session = this.requireSession(command.sessionId);
    this.requireRunAssignee(command.sessionId, command.actor.userId);
    const run = this.requireMutableAgentRun(command.sessionId, command.agentRunId);
    this.requireReadyRunRuntimeBinding(session, run);
    assertExpectedVersion(
      run.final_review_version as number,
      command.expectedFinalReviewVersion,
      "Final review"
    );
    if (run.lifecycle !== "agent-work-finished") {
      throw new TeamSessionError("conflict", "This Run is not ready for final review");
    }
    const goals = this.currentGoalSetSnapshot(run).goals;
    const events: SessionEvent[] = [];
    if (command.resolution.kind === "accept-outcome") {
      if (goals.some((goal) => goal.status !== "validated")) {
        throw new TeamSessionError("conflict", "Every Goal must be validated before acceptance");
      }
      const transitioned = this.updateAgentRunLifecycle(run, "completed", now);
      const invalidatedGrantCount = this.invalidateMutableRunGrants(command.agentRunId, now);
      const runStateRevision = this.advanceRunStateRevision(command.sessionId);
      events.push(
        this.appendEvent(command.sessionId, command, now, "run.completed", {
          agentRunId: command.agentRunId,
          lifecycle: "completed",
          stateVersion: transitioned.stateVersion,
          finalReviewVersion: (run.final_review_version as number) + 1,
          invalidatedGrantCount,
          runStateRevision,
        })
      );
      this.db
        .prepare(
          `UPDATE agent_runs SET final_review_version = final_review_version + 1 WHERE id = ?`
        )
        .run(command.agentRunId);
      return result(
        command,
        {
          sessionId: command.sessionId,
          agentRunId: command.agentRunId,
          lifecycle: "completed",
          stateVersion: transitioned.stateVersion,
          finalReviewVersion: (run.final_review_version as number) + 1,
          invalidatedGrantCount,
          runStateRevision,
        },
        events
      );
    }

    const directive = this.appendRunDirective(command, now, session, command.resolution.directive, {
      kind: "final-review-continue",
      agentRunId: command.agentRunId,
    });
    events.push(directive);
    const updated = this.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = 'active', state_version = state_version + 1,
             final_review_version = final_review_version + 1, updated_at_ms = ?
         WHERE id = ? AND session_id = ? AND lifecycle = 'agent-work-finished'
           AND final_review_version = ?
         RETURNING state_version, final_review_version`
      )
      .get(now, command.agentRunId, command.sessionId, command.expectedFinalReviewVersion) as
      | SqlRow
      | undefined;
    if (!updated) throw new TeamSessionError("stale-revision", "Final review changed concurrently");
    const runStateRevision = this.advanceRunStateRevision(command.sessionId);
    events.push(
      this.appendEvent(command.sessionId, command, now, "run.final-review.continued", {
        agentRunId: command.agentRunId,
        lifecycle: "active",
        stateVersion: updated.state_version,
        finalReviewVersion: updated.final_review_version,
        directiveId: directive.payload.directiveId,
        runStateRevision,
      })
    );
    return result(
      command,
      {
        sessionId: command.sessionId,
        agentRunId: command.agentRunId,
        lifecycle: "active",
        stateVersion: updated.state_version,
        finalReviewVersion: updated.final_review_version,
        directiveId: directive.payload.directiveId,
        runStateRevision,
      },
      events
    );
  }

  private appendQueuedDirective(
    command: SessionCommand & { sessionId: string },
    now: number,
    directiveId: string,
    body: string,
    session: SqlRow,
    origin: Record<string, unknown>
  ): SessionEvent {
    this.assertPendingDirectiveCapacity(command.sessionId, command.actor.userId);
    const event = this.appendEvent(command.sessionId, command, now, "directive.queued", {
      directiveId,
      status: "queued",
      body,
      steeringPolicy: session.steering_policy,
      steeringRevision: session.steering_revision,
      origin,
    });
    this.bindConversationIdentity(directiveId, command.sessionId, "directive", event.sequence);
    this.db
      .prepare(
        `INSERT INTO conversation_directives
           (directive_id, session_id, author_user_id, queue_sequence, status, terminal_sequence)
         VALUES (?, ?, ?, ?, 'queued', NULL)`
      )
      .run(directiveId, command.sessionId, command.actor.userId, event.sequence);
    return event;
  }

  private assertPendingDirectiveCapacity(sessionId: string, authorUserId: string): void {
    const authorPending = this.db
      .prepare(
        `SELECT COUNT(*) AS count FROM conversation_directives
         WHERE author_user_id = ? AND status = 'queued'`
      )
      .get(authorUserId) as SqlRow;
    if ((authorPending.count as number) >= MAX_PENDING_DIRECTIVES_PER_AUTHOR) {
      throw new TeamSessionError(
        "conflict",
        `A Steerer may have at most ${MAX_PENDING_DIRECTIVES_PER_AUTHOR} pending Directives`
      );
    }
    const sessionPending = this.db
      .prepare(
        `SELECT COUNT(*) AS count FROM conversation_directives
         WHERE session_id = ? AND status = 'queued'`
      )
      .get(sessionId) as SqlRow;
    if ((sessionPending.count as number) >= MAX_PENDING_DIRECTIVES_PER_SESSION) {
      throw new TeamSessionError(
        "conflict",
        `A Session may have at most ${MAX_PENDING_DIRECTIVES_PER_SESSION} pending Directives`
      );
    }
  }

  private requireConversationParticipant(sessionId: string, userId: string): SqlRow {
    const session = this.requireSession(sessionId);
    if (!this.hasSessionAccess(sessionId, userId)) deny();
    return session;
  }

  private requireDirectiveAuthority(
    sessionId: string,
    userId: string,
    expectedSteeringRevision: number
  ): SqlRow {
    const session = this.requireConversationParticipant(sessionId, userId);
    if (session.status !== "active") {
      throw new TeamSessionError("conflict", "An inactive Session cannot queue Directives");
    }
    const isSteerer = this.hasResponsibility(sessionId, userId, "steerer");
    const isSingleController =
      session.steering_policy === "single" &&
      this.hasResponsibility(sessionId, userId, "controller");
    if (!isSteerer || (session.steering_policy === "single" && !isSingleController)) deny();
    assertExpectedRevision(
      session.steering_revision as number,
      expectedSteeringRevision,
      "Steering"
    );
    return session;
  }

  private requireSuggestionEvent(
    sessionId: string,
    suggestionId: string
  ): { sequence: number; body: string } {
    const row = this.db
      .prepare(
        `SELECT identity.created_sequence AS sequence, event.payload_json
         FROM conversation_identities identity
         JOIN session_events event
           ON event.session_id = identity.session_id
          AND event.sequence = identity.created_sequence
         WHERE identity.id = ? AND identity.session_id = ? AND identity.kind = 'suggestion'`
      )
      .get(suggestionId, sessionId) as SqlRow | undefined;
    if (!row) deny();
    const payload = JSON.parse(row.payload_json as string) as Record<string, unknown>;
    if (payload.suggestionId !== suggestionId) {
      throw new TeamSessionError("conflict", "Suggestion identity ledger is invalid");
    }
    return {
      sequence: row.sequence as number,
      body: requiredConversationBody(payload.body, "Stored Suggestion body"),
    };
  }

  private suggestionResolutionEvent(
    sessionId: string,
    suggestionId: string
  ): { suggestionVersion: number } | undefined {
    const row = this.db
      .prepare(
        `SELECT suggestion_version FROM conversation_suggestion_resolutions
         WHERE suggestion_id = ? AND session_id = ?`
      )
      .get(suggestionId, sessionId) as SqlRow | undefined;
    return row ? { suggestionVersion: row.suggestion_version as number } : undefined;
  }

  private recordSuggestionResolution(
    sessionId: string,
    suggestionId: string,
    resolutionId: string,
    resolutionSequence: number,
    decision: "accept" | "accept-edited" | "reject",
    directiveId: string | undefined
  ): void {
    this.db
      .prepare(
        `INSERT INTO conversation_suggestion_resolutions
           (suggestion_id, session_id, resolution_id, resolution_sequence,
            suggestion_version, decision, directive_id)
         VALUES (?, ?, ?, ?, 2, ?, ?)`
      )
      .run(
        suggestionId,
        sessionId,
        resolutionId,
        resolutionSequence,
        decision,
        directiveId ?? null
      );
  }

  private acknowledgeRuntimeOutbox(
    command: Extract<SessionCommand, { type: "runtime.outbox.acknowledge" }>,
    now: number
  ): CommandResult {
    if (command.actor.userId !== command.workerId) deny();
    const outbox = this.requireRuntimeOutboxLease(
      command.outboxId,
      command.workerId,
      command.expectedAttempt,
      now
    );
    const sessionId = outbox.session_id as string;
    const kind = outbox.kind as RuntimeOutboxKind;
    const payload = JSON.parse(outbox.payload_json as string) as Record<string, unknown>;
    const session = this.requireSession(sessionId);
    const generation = runtimeGenerationFromPayload(payload);
    const currentGeneration = session.runtime_authorization_generation as number;
    if (generation > currentGeneration) {
      throw new TeamSessionError("conflict", "Runtime outbox generation is ahead of Session state");
    }
    const emergencyStopEnforcement = payload.reason === "emergency-stop";
    const superseded = !emergencyStopEnforcement && generation < currentGeneration;
    const delivered = this.db
      .prepare(
        `UPDATE runtime_outbox
         SET status = ?, lease_owner = NULL, lease_expires_at_ms = NULL,
             delivered_at_ms = ?, last_error = NULL
         WHERE id = ? AND status = 'processing' AND lease_owner = ?
           AND attempts = ? AND lease_expires_at_ms > ?`
      )
      .run(
        superseded ? "superseded" : "delivered",
        now,
        command.outboxId,
        command.workerId,
        command.expectedAttempt,
        now
      );
    if (delivered.changes !== 1) {
      throw new TeamSessionError("stale-revision", "Runtime outbox lease changed");
    }
    let enforced = false;
    if (
      !superseded &&
      (kind === "runtime.session.ensure" || kind === "runtime.authorization.fence") &&
      generation === session.runtime_authorization_generation
    ) {
      const updated = this.db
        .prepare(
          `UPDATE sessions SET runtime_authorization_state = 'enforced'
           WHERE id = ? AND runtime_authorization_generation = ?
             AND runtime_authorization_state = 'pending'`
        )
        .run(sessionId, generation);
      enforced = updated.changes === 1;
    }
    let emergencyStopStateVersion: number | undefined;
    let runStateRevision: number | undefined;
    let recoveredRun:
      | {
          agentRunId: string;
          lifecycle: "paused" | "agent-work-finished";
          stateVersion: number;
          sandboxState: "ready";
        }
      | undefined;
    if (
      !superseded &&
      kind === "runtime.authorization.fence" &&
      payload.reason === "assignee-loss" &&
      enforced
    ) {
      const recovery = this.db
        .prepare(
          `SELECT run.id, run.lifecycle, run.state_version, assignment.id AS assignment_id
           FROM agent_runs run
           JOIN runtime_assignments assignment ON assignment.id = run.runtime_assignment_id
           WHERE run.session_id = ?
             AND run.runtime_authorization_generation = ?
             AND run.lifecycle IN ('pausing', 'paused', 'agent-work-finished')
             AND assignment.session_id = run.session_id
             AND assignment.runtime_authorization_generation = ?
             AND assignment.status = 'recovering'
           ORDER BY run.created_at_ms DESC, run.id DESC LIMIT 1`
        )
        .get(sessionId, generation, generation) as SqlRow | undefined;
      if (recovery) {
        const assignmentReady = this.db
          .prepare(
            `UPDATE runtime_assignments SET status = 'ready'
             WHERE id = ? AND session_id = ?
               AND runtime_authorization_generation = ? AND status = 'recovering'`
          )
          .run(recovery.assignment_id, sessionId, generation);
        if (assignmentReady.changes !== 1) {
          throw new TeamSessionError(
            "stale-revision",
            "Run Runtime Assignment recovery changed concurrently"
          );
        }
        let lifecycle = recovery.lifecycle as "paused" | "agent-work-finished";
        let stateVersion = recovery.state_version as number;
        if (recovery.lifecycle === "pausing") {
          const paused = this.db
            .prepare(
              `UPDATE agent_runs
               SET lifecycle = 'paused', state_version = state_version + 1, updated_at_ms = ?
               WHERE id = ? AND session_id = ? AND state_version = ?
                 AND runtime_authorization_generation = ? AND lifecycle = 'pausing'
               RETURNING state_version`
            )
            .get(now, recovery.id, sessionId, recovery.state_version, generation) as
            | SqlRow
            | undefined;
          if (!paused) {
            throw new TeamSessionError("stale-revision", "Run pause changed concurrently");
          }
          lifecycle = "paused";
          stateVersion = paused.state_version as number;
        }
        runStateRevision = this.advanceRunStateRevision(sessionId);
        recoveredRun = {
          agentRunId: recovery.id as string,
          lifecycle,
          stateVersion,
          sandboxState: "ready",
        };
      }
    }
    if (!superseded && kind === "runtime.session.retire" && payload.reason === "emergency-stop") {
      const agentRunId = requiredIdentifier(payload.agentRunId, "Emergency-stop Agent Run id");
      const stopped = this.db
        .prepare(
          `UPDATE agent_runs
           SET lifecycle = 'emergency-stopped', state_version = state_version + 1,
               updated_at_ms = ?, terminal_at_ms = ?
           WHERE id = ? AND session_id = ? AND lifecycle = 'pausing'
             AND runtime_authorization_generation >= ?
           RETURNING state_version`
        )
        .get(now, now, agentRunId, sessionId, generation) as SqlRow | undefined;
      if (!stopped) {
        throw new TeamSessionError("conflict", "Emergency-stop Run state is unavailable");
      }
      this.db
        .prepare(
          `UPDATE runtime_assignments
           SET status = 'retired', retired_at_ms = ?
           WHERE id = ? AND session_id = ? AND status = 'quarantined'`
        )
        .run(now, payload.runtimeAssignmentId, sessionId);
      this.db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'superseded', lease_owner = NULL, lease_expires_at_ms = NULL,
               delivered_at_ms = ?
           WHERE session_id = ? AND session_sequence > ?
             AND status IN ('pending', 'processing')`
        )
        .run(now, sessionId, outbox.session_sequence);
      emergencyStopStateVersion = stopped.state_version as number;
      runStateRevision = this.advanceRunStateRevision(sessionId);
    }
    const eventType = superseded
      ? "runtime.outbox.superseded"
      : emergencyStopStateVersion !== undefined
        ? "run.emergency-stopped"
        : kind === "runtime.session.ensure" && enforced
          ? "runtime.session.ensured"
          : kind === "runtime.authorization.fence" && enforced
            ? "session.runtime-authorization.enforced"
            : kind === "runtime.session.retire"
              ? "runtime.session.retired"
              : "runtime.outbox.delivered";
    const event = this.appendEvent(sessionId, command, now, eventType, {
      outboxId: command.outboxId,
      kind,
      workerId: command.workerId,
      attempt: command.expectedAttempt,
      runtimeAuthorizationGeneration: generation,
      enforced,
      superseded,
      ...(emergencyStopStateVersion === undefined
        ? {}
        : {
            agentRunId: payload.agentRunId,
            lifecycle: "emergency-stopped",
            stateVersion: emergencyStopStateVersion,
            enforcementAcknowledged: true,
            runStateRevision,
          }),
    });
    const events = [event];
    if (recoveredRun) {
      events.push(
        this.appendEvent(
          sessionId,
          command,
          now,
          recoveredRun.lifecycle === "paused" ? "run.paused" : "run.runtime-authorization.enforced",
          {
            ...recoveredRun,
            reason: "assignee-loss",
            runtimeAuthorizationGeneration: generation,
            runStateRevision,
          }
        )
      );
    }
    return result(
      command,
      {
        outboxId: command.outboxId,
        sessionId,
        kind,
        attempt: command.expectedAttempt,
        runtimeAuthorizationGeneration: generation,
        enforced,
        superseded,
        ...(emergencyStopStateVersion === undefined
          ? {}
          : {
              agentRunId: payload.agentRunId,
              lifecycle: "emergency-stopped",
              stateVersion: emergencyStopStateVersion,
              runStateRevision,
            }),
      },
      events
    );
  }

  private failRuntimeOutbox(
    command: Extract<SessionCommand, { type: "runtime.outbox.fail" }>,
    now: number
  ): CommandResult {
    if (command.actor.userId !== command.workerId) deny();
    const outbox = this.requireRuntimeOutboxLease(
      command.outboxId,
      command.workerId,
      command.expectedAttempt,
      now
    );
    const sessionId = outbox.session_id as string;
    const kind = outbox.kind as RuntimeOutboxKind;
    const payload = JSON.parse(outbox.payload_json as string) as Record<string, unknown>;
    const session = this.requireSession(sessionId);
    const generation = runtimeGenerationFromPayload(payload);
    const currentGeneration = session.runtime_authorization_generation as number;
    if (generation > currentGeneration) {
      throw new TeamSessionError("conflict", "Runtime outbox generation is ahead of Session state");
    }
    const superseded = payload.reason !== "emergency-stop" && generation < currentGeneration;
    const status = superseded ? "superseded" : command.retryable ? "pending" : "failed";
    const failed = this.db
      .prepare(
        `UPDATE runtime_outbox
         SET status = ?, lease_owner = NULL, lease_expires_at_ms = NULL,
             last_error = ?, delivered_at_ms = ?
         WHERE id = ? AND status = 'processing' AND lease_owner = ?
           AND attempts = ? AND lease_expires_at_ms > ?`
      )
      .run(
        status,
        command.errorCode,
        superseded ? now : null,
        command.outboxId,
        command.workerId,
        command.expectedAttempt,
        now
      );
    if (failed.changes !== 1) {
      throw new TeamSessionError("stale-revision", "Runtime outbox lease changed");
    }
    let quarantined = false;
    if (!superseded && !command.retryable && kind !== "runtime.session.retire") {
      const updated = this.db
        .prepare(
          `UPDATE sessions SET runtime_authorization_state = 'quarantined'
           WHERE id = ? AND runtime_authorization_generation = ?`
        )
        .run(sessionId, generation);
      quarantined = updated.changes === 1;
    }
    const event = this.appendEvent(
      sessionId,
      command,
      now,
      quarantined
        ? "session.runtime-authorization.quarantined"
        : superseded
          ? "runtime.outbox.superseded"
          : command.retryable
            ? "runtime.outbox.retry-scheduled"
            : "runtime.outbox.failed",
      {
        outboxId: command.outboxId,
        kind,
        workerId: command.workerId,
        attempt: command.expectedAttempt,
        retryable: command.retryable,
        errorCode: command.errorCode,
        runtimeAuthorizationGeneration: generation,
        quarantined,
        superseded,
      }
    );
    return result(
      command,
      {
        outboxId: command.outboxId,
        sessionId,
        kind,
        attempt: command.expectedAttempt,
        retryable: command.retryable,
        runtimeAuthorizationGeneration: generation,
        quarantined,
        superseded,
      },
      [event]
    );
  }

  private requireRuntimeOutboxLease(
    outboxId: string,
    workerId: string,
    expectedAttempt: number,
    now: number
  ): SqlRow {
    const outbox = this.db
      .prepare(
        `SELECT * FROM runtime_outbox
         WHERE id = ? AND status = 'processing' AND lease_owner = ?
           AND attempts = ? AND lease_expires_at_ms > ?`
      )
      .get(outboxId, workerId, expectedAttempt, now) as SqlRow | undefined;
    if (!outbox) {
      throw new TeamSessionError("stale-revision", "Runtime outbox lease is unavailable");
    }
    return outbox;
  }

  private commandReplay(command: SessionCommand, payloadDigest: string): CommandResult | null {
    const existing = this.db
      .prepare(
        `SELECT payload_digest, result_json, secret_result FROM accepted_commands
         WHERE source_scope = ? AND source_key = ?`
      )
      .get(command.idempotency.scope, command.idempotency.key) as SqlRow | undefined;
    if (!existing) return null;
    if (existing.payload_digest !== payloadDigest) {
      throw new TeamSessionError(
        "idempotency-conflict",
        "Idempotency key was already used for a different command"
      );
    }
    const parsed = JSON.parse(existing.result_json as string) as CommandResult;
    const replay = {
      ...parsed,
      replayed: true,
      data:
        existing.secret_result === 1
          ? {
              ...parsed.data,
              invitationTokenUnavailable: true,
              recoveryAction: "revoke-and-reissue",
            }
          : parsed.data,
    };
    return this.projectReplayResultForActor(replay, command);
  }

  private projectReplayResultForActor(
    commandResult: CommandResult,
    command: SessionCommand
  ): CommandResult {
    if (command.actor.kind === "system") return commandResult;
    if (!this.hasCurrentReplayVisibility(command, commandResult, command.actor.userId)) {
      return {
        ...commandResult,
        data: { receiptUnavailable: true },
        events: [],
      };
    }
    return this.projectCommandResultForActor(commandResult, command.actor);
  }

  private hasCurrentReplayVisibility(
    command: SessionCommand,
    commandResult: CommandResult,
    actorUserId: string
  ): boolean {
    switch (command.type) {
      case "team.create": {
        const teamId = command.teamId ?? replayIdentifier(commandResult.data.teamId);
        return teamId !== undefined && this.hasTeamVisibility(teamId, actorUserId);
      }
      case "team.membership.grant":
      case "team.membership.revoke":
        return this.hasTeamVisibility(command.teamId, actorUserId);
      case "project.create": {
        const projectId = command.projectId ?? replayIdentifier(commandResult.data.projectId);
        return projectId !== undefined && this.hasProjectVisibility(projectId, actorUserId);
      }
      case "project.access.grant":
      case "project.access.revoke":
        return this.hasProjectVisibility(command.projectId, actorUserId);
      case "session.start": {
        const sessionId = command.sessionId ?? replayIdentifier(commandResult.data.sessionId);
        return sessionId !== undefined && this.hasSessionAccess(sessionId, actorUserId);
      }
      case "session.invitation.redeem": {
        const sessionId = replayIdentifier(commandResult.data.sessionId);
        const invitationId = replayIdentifier(commandResult.data.invitationId);
        return (
          sessionId !== undefined &&
          invitationId !== undefined &&
          this.hasRedeemedInvitationReceiptVisibility(sessionId, invitationId, actorUserId)
        );
      }
      case "session.invitation.create":
      case "session.invitation.revoke":
      case "session.join":
      case "session.share.create":
      case "session.share.revoke":
      case "session.participant.grant":
      case "session.participant.revoke":
      case "session.responsibility.grant":
      case "session.responsibility.revoke":
      case "session.control.transfer":
      case "session.control.release":
      case "session.assignee.claim":
      case "session.handoff.offer":
      case "session.handoff.accept":
      case "session.handoff.cancel":
      case "comment.add":
      case "suggestion.add":
      case "suggestion.resolve":
      case "directive.enqueue":
      case "run.start":
      case "run.policy.revise":
      case "run.pause":
      case "run.resume":
      case "run.stop":
      case "run.emergency-stop":
      case "goal.add":
      case "goal.criteria.strengthen":
      case "goal.dependency.add":
      case "goal.reorder":
      case "goal.evidence.review":
      case "run.final-review.resolve":
        return this.hasSessionAccess(command.sessionId, actorUserId);
      case "runtime.outbox.acknowledge":
      case "runtime.outbox.fail":
        // Runtime commands are system-only. Keep this branch fail-closed if
        // the command envelope rules ever change without updating replay.
        return false;
    }
  }

  private projectCommandResultForActor(
    commandResult: CommandResult,
    actor: ActorContext
  ): CommandResult {
    if (actor.kind === "system") return commandResult;
    return {
      ...commandResult,
      events: commandResult.events.filter((event) =>
        this.hasSessionAccess(event.sessionId, actor.userId)
      ),
    };
  }

  private appendEvent(
    sessionId: string,
    command: SessionCommand,
    occurredAtMs: number,
    type: string,
    payload: Record<string, unknown>
  ): SessionEvent {
    const session = this.requireSession(sessionId);
    const sequence = session.next_sequence as number;
    const updated = this.db
      .prepare(
        `UPDATE sessions SET next_sequence = next_sequence + 1
         WHERE id = ? AND next_sequence = ?`
      )
      .run(sessionId, sequence);
    if (updated.changes !== 1) {
      throw new TeamSessionError("conflict", "Could not allocate canonical Session sequence");
    }
    const event: SessionEvent = {
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      eventId: this.nextId("event"),
      sessionId,
      sequence,
      type,
      occurredAtMs,
      actor: { ...command.actor },
      source: { ...command.idempotency },
      payload,
    };
    this.db
      .prepare(
        `INSERT INTO session_events (
           session_id, sequence, event_id, type, occurred_at_ms,
           actor_kind, actor_user_id, actor_display_name,
           source_scope, source_key, payload_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        event.sessionId,
        event.sequence,
        event.eventId,
        event.type,
        event.occurredAtMs,
        event.actor.kind,
        event.actor.userId,
        event.actor.displayName,
        event.source.scope,
        event.source.key,
        JSON.stringify(event.payload)
      );
    return event;
  }

  private appendAccessRevisionEvents(
    sessions: SqlRow[],
    command: SessionCommand,
    now: number,
    reason: string,
    payload: Record<string, unknown>
  ): SessionEvent[] {
    return sessions.map((session) =>
      this.appendEvent(session.id as string, command, now, "session.access.revision.advanced", {
        ...payload,
        reason,
        accessRevision: session.access_revision as number,
      })
    );
  }

  private revokeAcrossSessions(
    sql: string,
    params: SqlValue[],
    userId: string,
    command: SessionCommand,
    now: number,
    eventType: string,
    payload: Record<string, unknown>
  ): SessionEvent[] {
    const rows = (this.db.prepare(sql).all(...params) as SqlRow[]).sort((left, right) =>
      String(left.id).localeCompare(String(right.id))
    );
    const events: SessionEvent[] = [];
    for (const row of rows) {
      events.push(
        ...this.revokeOneParticipant(row.id as string, userId, command, now, eventType, payload)
      );
    }
    return events;
  }

  private revokeOneParticipant(
    sessionId: string,
    userId: string,
    command: SessionCommand,
    now: number,
    eventType: string,
    payload: Record<string, unknown>
  ): SessionEvent[] {
    const participant = this.db
      .prepare(
        `SELECT id FROM session_participants
         WHERE session_id = ? AND user_id = ? AND status = 'active'`
      )
      .get(sessionId, userId) as SqlRow | undefined;
    if (!participant) return [];
    const assignee = this.hasResponsibility(sessionId, userId, "assignee");
    const controller = this.hasResponsibility(sessionId, userId, "controller");
    const steerer = this.hasResponsibility(sessionId, userId, "steerer");
    const supervisor = this.hasResponsibility(sessionId, userId, "supervisor");
    this.db
      .prepare(
        `UPDATE session_participants
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE session_id = ? AND user_id = ? AND status = 'active'`
      )
      .run(now, sessionId, userId);
    this.db
      .prepare(
        `UPDATE session_responsibilities
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE session_id = ? AND user_id = ? AND status = 'active'`
      )
      .run(now, sessionId, userId);
    const steeringRevision = steerer ? this.advanceSteeringRevision(sessionId) : undefined;
    const supervisionRevision = supervisor ? this.advanceSupervisionRevision(sessionId) : undefined;
    const assigneeRevision = assignee ? this.advanceAssigneeRevision(sessionId) : undefined;
    let runtimeAuthorizationGeneration: number | undefined;
    let runtimeAuthorizationState: "pending" | "quarantined" | undefined;
    let runTransition: AssigneeLossRunTransition | undefined;
    if (assignee) {
      const updated = this.db
        .prepare(
          `UPDATE sessions
           SET status = 'awaiting_assignee',
               runtime_authorization_generation = runtime_authorization_generation + 1,
               runtime_authorization_state = CASE
                 WHEN runtime_authorization_state = 'quarantined' THEN 'quarantined'
                 ELSE 'pending'
               END
           WHERE id = ?
           RETURNING runtime_authorization_generation, runtime_authorization_state`
        )
        .get(sessionId) as SqlRow | undefined;
      if (!updated) deny();
      runtimeAuthorizationGeneration = updated.runtime_authorization_generation as number;
      runtimeAuthorizationState = updated.runtime_authorization_state as "pending" | "quarantined";
      this.advanceControlFence(sessionId);
      runTransition = this.beginRunRecoveryAfterAssigneeLoss(
        sessionId,
        runtimeAuthorizationGeneration,
        runtimeAuthorizationState,
        now
      );
    } else if (controller) {
      this.advanceControlFence(sessionId);
    }
    const cancelledHandoffs = assignee
      ? this.cancelOfferedHandoffs(sessionId, now, command.actor.userId, "assignee-lost")
      : this.cancelOfferedHandoffs(
          sessionId,
          now,
          command.actor.userId,
          "participant-access-lost",
          undefined,
          userId
        );
    const control = this.controlProjection(sessionId);
    const events = [
      this.appendEvent(sessionId, command, now, eventType, {
        ...payload,
        accessRevision: this.requireSession(sessionId).access_revision,
        participantId: participant.id,
        assigneeRequired: assignee,
        controlReleased: controller,
        ...control,
        ...(steeringRevision === undefined ? {} : { steeringRevision }),
        ...(supervisionRevision === undefined ? {} : { supervisionRevision }),
        ...(assigneeRevision === undefined ? {} : { assigneeRevision }),
      }),
    ];
    if (steerer) {
      events.push(
        ...this.appendQueuedDirectiveCancellationEvents(sessionId, command, now, userId, eventType)
      );
    }
    if (controller) {
      events.push(
        this.appendEvent(sessionId, command, now, "session.control.released", {
          previousControllerUserId: userId,
          reason: eventType,
          ...control,
        })
      );
    } else if (assignee) {
      events.push(
        this.appendEvent(sessionId, command, now, "session.control.fenced", {
          reason: "awaiting-assignee",
          ...control,
        })
      );
    }
    events.push(
      ...this.appendHandoffCancellationEvents(sessionId, command, now, cancelledHandoffs)
    );
    if (assignee) {
      if (runtimeAuthorizationGeneration === undefined || runtimeAuthorizationState === undefined) {
        throw new TeamSessionError("conflict", "Runtime authorization fence was not advanced");
      }
      const runtimeEvent = this.appendEvent(
        sessionId,
        command,
        now,
        "session.runtime-authorization.advanced",
        {
          reason: "assignee-loss",
          runtimeAuthorizationGeneration,
          enforcementState: runtimeAuthorizationState,
        }
      );
      const runtimeFencePayload: RuntimeOutboxPayload<"runtime.authorization.fence"> = {
        sessionId,
        reason: "assignee-loss",
        runtimeAuthorizationGeneration,
      };
      this.db
        .prepare(
          `INSERT INTO runtime_outbox
             (id, session_id, session_sequence, kind, payload_json, status, attempts, created_at_ms)
           VALUES (?, ?, ?, 'runtime.authorization.fence', ?, 'pending', 0, ?)`
        )
        .run(
          this.nextId("outbox"),
          sessionId,
          runtimeEvent.sequence,
          JSON.stringify(runtimeFencePayload),
          now
        );
      events.push(runtimeEvent);
      if (runTransition) {
        events.push(
          this.appendEvent(sessionId, command, now, "run.runtime-authorization.rebinding", {
            agentRunId: runTransition.agentRunId,
            lifecycle: runTransition.lifecycle,
            stateVersion: runTransition.stateVersion,
            reason: "assignee-loss",
            runtimeAuthorizationGeneration,
            sandboxState: runTransition.sandboxState,
            invalidatedGrantCount: runTransition.invalidatedGrantCount,
            runStateRevision: runTransition.runStateRevision,
          })
        );
      }
      events.push(
        this.appendEvent(sessionId, command, now, "assignee.required", {
          previousAssigneeUserId: userId,
          reason: eventType,
          assigneeRevision,
          ...control,
        })
      );
    }
    return events;
  }

  private beginRunRecoveryAfterAssigneeLoss(
    sessionId: string,
    runtimeAuthorizationGeneration: number,
    runtimeAuthorizationState: "pending" | "quarantined",
    now: number
  ): AssigneeLossRunTransition | undefined {
    const run = this.mutableAgentRun(sessionId);
    if (!run) return undefined;
    const assignment = this.requireRuntimeAssignment(run.runtime_assignment_id as string);

    // Emergency Stop already owns this transition. Assignee loss may advance
    // the Session fence, but it must not replace quarantine/retirement with an
    // ordinary recoverable pause.
    if (run.lifecycle === "pausing" && assignment.status === "quarantined") {
      return undefined;
    }
    if (run.lifecycle === "pausing") {
      throw new TeamSessionError("conflict", "Run pause enforcement is already in progress");
    }
    if (assignment.status === "retired" || assignment.status === "failed") {
      throw new TeamSessionError("conflict", "Run Runtime Assignment cannot be recovered");
    }

    const assignmentState = this.db
      .prepare(
        `UPDATE runtime_assignments
         SET runtime_authorization_generation = ?,
             status = CASE
               WHEN status = 'quarantined' OR ? = 'quarantined' THEN 'quarantined'
               ELSE 'recovering'
             END
         WHERE id = ? AND session_id = ? AND generation = ?
           AND status IN ('provisioning', 'ready', 'checkpointing', 'recovering', 'quarantined')
         RETURNING status`
      )
      .get(
        runtimeAuthorizationGeneration,
        runtimeAuthorizationState,
        assignment.id,
        sessionId,
        assignment.generation
      ) as SqlRow | undefined;
    if (!assignmentState) {
      throw new TeamSessionError("stale-revision", "Run Runtime Assignment changed concurrently");
    }
    this.recordRuntimeAuthorizationEpoch(
      sessionId,
      this.requireRuntimeAssignment(assignment.id as string),
      runtimeAuthorizationGeneration,
      now
    );

    const nextLifecycle =
      run.lifecycle === "active" ? "pausing" : (run.lifecycle as "paused" | "agent-work-finished");
    const updated = this.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = ?, state_version = state_version + 1, updated_at_ms = ?,
             runtime_authorization_generation = ?
         WHERE id = ? AND session_id = ? AND state_version = ?
           AND lifecycle IN ('active', 'paused', 'agent-work-finished')
         RETURNING state_version`
      )
      .get(
        nextLifecycle,
        now,
        runtimeAuthorizationGeneration,
        run.id,
        sessionId,
        run.state_version
      ) as SqlRow | undefined;
    if (!updated) throw new TeamSessionError("stale-revision", "Run state changed concurrently");

    const invalidatedGrantCount = this.invalidateMutableRunGrants(
      run.id as string,
      now,
      "runtime-authorization"
    );
    return {
      agentRunId: run.id as string,
      lifecycle: nextLifecycle,
      stateVersion: updated.state_version as number,
      sandboxState: assignmentState.status as "recovering" | "quarantined",
      invalidatedGrantCount,
      runStateRevision: this.advanceRunStateRevision(sessionId),
    };
  }

  private terminalAuthorization(query: SessionTerminalAuthorizationQuery): TerminalAuthorization {
    const session = this.sessionRow(query.sessionId);
    if (!session || !this.hasSessionAccess(query.sessionId, query.actor.userId)) {
      return {
        sessionId: query.sessionId,
        action: query.action,
        allowed: false,
        reason: "not-authorized",
        controlEpoch: 0,
        runtimeAuthorizationGeneration: 0,
      };
    }
    const epoch = session.control_epoch as number;
    const runtimeAuthorizationGeneration = session.runtime_authorization_generation as number;
    const participant = this.activeParticipant(query.sessionId, query.actor.userId);
    if (session.status === "ended" || (session.status !== "active" && query.action !== "observe")) {
      return {
        sessionId: query.sessionId,
        action: query.action,
        allowed: false,
        reason: "session-not-active",
        participantId: participant?.id as string,
        controlEpoch: epoch,
        runtimeAuthorizationGeneration,
      };
    }
    if (query.action === "observe") {
      return {
        sessionId: query.sessionId,
        action: query.action,
        allowed: true,
        participantId: participant?.id as string,
        controlEpoch: epoch,
        runtimeAuthorizationGeneration,
      };
    }
    if (session.runtime_authorization_state !== "enforced") {
      return {
        sessionId: query.sessionId,
        action: query.action,
        allowed: false,
        reason:
          session.runtime_authorization_state === "quarantined"
            ? "runtime-authorization-quarantined"
            : "runtime-authorization-pending",
        participantId: participant?.id as string,
        controlEpoch: epoch,
        runtimeAuthorizationGeneration,
      };
    }
    if (query.expectedRuntimeAuthorizationGeneration !== runtimeAuthorizationGeneration) {
      return {
        sessionId: query.sessionId,
        action: query.action,
        allowed: false,
        reason: "stale-runtime-authorization-generation",
        participantId: participant?.id as string,
        controlEpoch: epoch,
        runtimeAuthorizationGeneration,
      };
    }
    if (query.expectedControlEpoch !== epoch) {
      return {
        sessionId: query.sessionId,
        action: query.action,
        allowed: false,
        reason: "stale-control-epoch",
        participantId: participant?.id as string,
        controlEpoch: epoch,
        runtimeAuthorizationGeneration,
      };
    }
    const allowed =
      this.hasResponsibility(query.sessionId, query.actor.userId, "controller") &&
      this.hasResponsibility(query.sessionId, query.actor.userId, "steerer");
    return {
      sessionId: query.sessionId,
      action: query.action,
      allowed,
      ...(allowed ? {} : { reason: "not-authorized" as const }),
      participantId: participant?.id as string,
      controlEpoch: epoch,
      runtimeAuthorizationGeneration,
    };
  }

  private projectWorkspaceDiscovery(actorUserId: string): WorkspaceDiscoveryView {
    const memberships = this.db
      .prepare(
        `SELECT t.id, t.name, t.created_at_ms, m.role, m.version
         FROM team_memberships m
         JOIN teams t ON t.id = m.team_id
         WHERE m.user_id = ? AND m.status = 'active'
         ORDER BY t.created_at_ms ASC, t.id ASC`
      )
      .all(actorUserId) as SqlRow[];
    const teams = memberships.map((membership) => {
      const teamId = membership.id as string;
      const role = membership.role as TeamRole;
      const administrator = role === "owner" || role === "admin";
      const projects = this.db
        .prepare(
          `SELECT p.id, p.name, p.created_at_ms,
                  pa.role AS access_role, pa.version AS access_version
           FROM projects p
           LEFT JOIN project_access pa
             ON pa.project_id = p.id AND pa.user_id = ? AND pa.status = 'active'
           WHERE p.team_id = ? AND (
             ? = 1 OR
             (? <> 'guest' AND pa.user_id IS NOT NULL) OR
             (? = 'guest' AND EXISTS (
               SELECT 1 FROM sessions s
               JOIN session_participants sp
                 ON sp.session_id = s.id AND sp.user_id = ? AND sp.status = 'active'
               JOIN session_shares ss
                 ON ss.session_id = s.id AND ss.user_id = ? AND ss.status = 'active'
               WHERE s.project_id = p.id
             ))
           )
           ORDER BY p.created_at_ms ASC, p.id ASC`
        )
        .all(
          actorUserId,
          teamId,
          administrator ? 1 : 0,
          role,
          role,
          actorUserId,
          actorUserId
        ) as SqlRow[];
      const projectViews: WorkspaceProjectView[] = projects.map((project) => {
        const hasContentAccess =
          role !== "guest" &&
          typeof project.access_role === "string" &&
          typeof project.access_version === "number";
        const accessRole = hasContentAccess ? (project.access_role as ProjectRole) : undefined;
        return {
          projectId: project.id as string,
          name: project.name as string,
          createdAtMs: project.created_at_ms as number,
          visibility: hasContentAccess
            ? "content"
            : administrator
              ? "administration"
              : "session-only",
          ...(accessRole === undefined
            ? {}
            : {
                viewerAccess: {
                  role: accessRole,
                  version: project.access_version as number,
                },
              }),
          capabilities: {
            viewContent: hasContentAccess,
            startSession: hasContentAccess,
            manageAccess: administrator || accessRole === "maintainer",
          },
        };
      });
      return {
        teamId,
        name: membership.name as string,
        createdAtMs: membership.created_at_ms as number,
        viewerMembership: {
          role,
          version: membership.version as number,
        },
        capabilities: {
          createProject: administrator,
          manageMemberships: administrator,
        },
        projects: projectViews,
      };
    });
    return { teams };
  }

  private listPublicSessions(
    userId: string,
    teamId: string | undefined,
    projectionNow: number
  ): SessionInboxItemView[] {
    const rows = this.db
      .prepare(
        `SELECT s.id FROM sessions s
         JOIN session_participants p
           ON p.session_id = s.id AND p.user_id = ? AND p.status = 'active'
         WHERE (? IS NULL OR s.team_id = ?)
         ORDER BY s.created_at_ms ASC, s.id ASC`
      )
      .all(userId, teamId ?? null, teamId ?? null) as SqlRow[];
    return rows
      .filter((row) => this.hasSessionAccess(row.id as string, userId))
      .map((row) => this.projectPublicSessionInboxItem(row.id as string, userId, projectionNow));
  }

  private projectPublicSessionInboxItem(
    sessionId: string,
    actorUserId: string,
    projectionNow: number,
    projectedHandoffs?: SqlRow[]
  ): SessionInboxItemView {
    const session = this.requireSession(sessionId);
    const participants = this.publicSessionParticipants(sessionId);
    const viewerParticipant = participants.find(
      (participant) => participant.userId === actorUserId
    );
    const membership = this.activeMembership(session.team_id as string, actorUserId);
    if (!viewerParticipant || !membership || !this.hasSessionAccess(sessionId, actorUserId)) deny();
    const projectAccess = this.activeProjectAccess(session.project_id as string, actorUserId);
    const latestSequence = (session.next_sequence as number) - 1;
    const responsibilities = this.publicSessionResponsibilities(participants);
    const viewerResponsibilities = viewerParticipant.responsibilities;
    const manager =
      viewerResponsibilities.includes("assignee") || viewerResponsibilities.includes("supervisor");
    const controller = viewerResponsibilities.includes("controller");
    const steerer = viewerResponsibilities.includes("steerer");
    const directSteering =
      session.status === "active" &&
      steerer &&
      (session.steering_policy === "shared" || controller);
    const activeHandoffs = projectedHandoffs ?? this.activeHandoffRows(sessionId, projectionNow);
    const viewer: SessionViewerView = {
      participantId: viewerParticipant.participantId,
      userId: actorUserId,
      displayName: viewerParticipant.displayName,
      membershipRole: viewerParticipant.membershipRole,
      responsibilities: viewerResponsibilities,
      basis: {
        participantVersion: viewerParticipant.version,
        teamMembershipVersion: membership.version as number,
        ...(projectAccess === undefined
          ? {}
          : { projectAccessVersion: projectAccess.version as number }),
        responsibilityVersions: viewerParticipant.responsibilityVersions,
        accessRevision: session.access_revision as number,
        assigneeRevision: session.assignee_revision as number,
        supervisionRevision: session.supervision_revision as number,
        steeringRevision: session.steering_revision as number,
        controlRevision: session.control_revision as number,
        controlEpoch: session.control_epoch as number,
        runtimeAuthorizationGeneration: session.runtime_authorization_generation as number,
        runStateRevision: session.run_state_revision as number,
        latestSequence,
      },
      capabilities: this.publicSessionCapabilities({
        session,
        actorUserId,
        membership,
        projectAccess,
        manager,
        controller,
        steerer,
        directSteering,
        activeHandoffs,
      }),
    };
    return {
      sessionId,
      teamId: session.team_id as string,
      projectId: session.project_id as string,
      name: session.name as string,
      status: session.status as SessionInboxItemView["status"],
      steeringPolicy: session.steering_policy as SessionInboxItemView["steeringPolicy"],
      runtime: {
        kind: "local-tmux",
        isolation: "trusted-shared-host",
        yoloEligible: false,
        authorizationGeneration: session.runtime_authorization_generation as number,
        authorizationState:
          session.runtime_authorization_state as SessionInboxItemView["runtime"]["authorizationState"],
      },
      responsibilities,
      viewer,
      latestSequence,
      createdAtMs: session.created_at_ms as number,
    };
  }

  private projectPublicSessionDetail(
    sessionId: string,
    actorUserId: string,
    projectionNow: number
  ): SessionDetailView {
    const activeHandoffs = this.activeHandoffRows(sessionId, projectionNow);
    const inbox = this.projectPublicSessionInboxItem(
      sessionId,
      actorUserId,
      projectionNow,
      activeHandoffs
    );
    const participants = this.publicSessionParticipants(sessionId);
    const manager =
      inbox.viewer.responsibilities.includes("assignee") ||
      inbox.viewer.responsibilities.includes("supervisor");
    const shares: PublicSessionShareView[] = manager
      ? (
          this.db
            .prepare(
              `SELECT user_id, version, created_at_ms FROM session_shares
             WHERE session_id = ? AND status = 'active'
             ORDER BY created_at_ms ASC, user_id ASC`
            )
            .all(sessionId) as SqlRow[]
        ).map((share) => ({
          userId: share.user_id as string,
          displayName: this.latestActorDisplayName(share.user_id as string),
          version: share.version as number,
          createdAtMs: share.created_at_ms as number,
        }))
      : [];
    const openHandoffs: PublicOpenHandoffView[] = activeHandoffs
      .filter(
        (handoff) =>
          manager ||
          handoff.offerer_user_id === actorUserId ||
          handoff.recipient_user_id === actorUserId
      )
      .map((handoff) => ({
        handoffId: handoff.id as string,
        offererUserId: handoff.offerer_user_id as string,
        recipientParticipantId: handoff.recipient_participant_id as string,
        recipientUserId: handoff.recipient_user_id as string,
        offeredUnder: handoff.offered_under_kind as "assignee" | "supervisor",
        version: handoff.version as number,
        contextSequence: handoff.context_sequence as number,
        expiresAtMs: handoff.expires_at_ms as number,
        createdAtMs: handoff.created_at_ms as number,
        briefing: JSON.parse(handoff.briefing_json as string) as PublicOpenHandoffView["briefing"],
      }));
    return { ...inbox, participants, shares, openHandoffs };
  }

  private publicSessionParticipants(sessionId: string): PublicSessionParticipantView[] {
    const rows = this.db
      .prepare(
        `SELECT p.id, p.user_id, p.version, p.joined_at_ms, m.role AS membership_role
         FROM session_participants p
         JOIN sessions s ON s.id = p.session_id
         JOIN team_memberships m
           ON m.team_id = s.team_id AND m.user_id = p.user_id AND m.status = 'active'
         WHERE p.session_id = ? AND p.status = 'active'
         ORDER BY p.joined_at_ms ASC, p.id ASC`
      )
      .all(sessionId) as SqlRow[];
    return rows.flatMap((row) => {
      const userId = row.user_id as string;
      if (!this.hasSessionAccess(sessionId, userId)) return [];
      const responsibilityRows = this.db
        .prepare(
          `SELECT kind, version FROM session_responsibilities
           WHERE session_id = ? AND user_id = ? AND status = 'active'`
        )
        .all(sessionId, userId) as SqlRow[];
      const responsibilities = RESPONSIBILITY_ORDER.filter((kind) =>
        responsibilityRows.some((responsibility) => responsibility.kind === kind)
      );
      return [
        {
          participantId: row.id as string,
          userId,
          displayName: this.latestActorDisplayName(userId),
          membershipRole: row.membership_role as TeamRole,
          observer: responsibilities.length === 0,
          responsibilities,
          responsibilityVersions: Object.fromEntries(
            responsibilityRows.map((responsibility) => [
              responsibility.kind as string,
              responsibility.version as number,
            ])
          ) as PublicSessionParticipantView["responsibilityVersions"],
          joinedAtMs: row.joined_at_ms as number,
          version: row.version as number,
        },
      ];
    });
  }

  private publicSessionResponsibilities(
    participants: PublicSessionParticipantView[]
  ): PublicSessionResponsibilityView {
    const holders = (kind: SessionResponsibility): PublicSessionIdentityView[] =>
      participants
        .filter((participant) => participant.responsibilities.includes(kind))
        .map(({ participantId, userId, displayName }) => ({ participantId, userId, displayName }));
    return {
      assignee: holders("assignee")[0],
      supervisors: holders("supervisor"),
      steerers: holders("steerer"),
      controller: holders("controller")[0],
    };
  }

  private publicSessionCapabilities(input: {
    session: SqlRow;
    actorUserId: string;
    membership: SqlRow;
    projectAccess?: SqlRow;
    manager: boolean;
    controller: boolean;
    steerer: boolean;
    directSteering: boolean;
    activeHandoffs: SqlRow[];
  }): SessionViewerCapabilities {
    const active = input.session.status === "active";
    const ended = input.session.status === "ended";
    const assignee = this.hasResponsibility(
      input.session.id as string,
      input.actorUserId,
      "assignee"
    );
    const supervisor = this.hasResponsibility(
      input.session.id as string,
      input.actorUserId,
      "supervisor"
    );
    const teamAdministrator =
      input.membership.role === "owner" || input.membership.role === "admin";
    const relevantOpenHandoff = input.activeHandoffs.some(
      (handoff) =>
        handoff.offerer_user_id === input.actorUserId ||
        handoff.recipient_user_id === input.actorUserId
    );
    return {
      addComment: true,
      addSuggestion: !ended,
      resolveSuggestion: input.directSteering,
      enqueueDirective: input.directSteering,
      observeTerminal: !ended,
      mutateTerminal:
        active &&
        input.session.runtime_authorization_state === "enforced" &&
        input.controller &&
        input.steerer,
      createInvitation: !ended && teamAdministrator,
      revokeInvitation: teamAdministrator,
      manageShares: input.manager,
      manageParticipants: input.manager,
      manageSupervisors: assignee,
      manageSteerers: input.manager,
      transferControl: active && (input.manager || input.controller),
      releaseControl: input.controller,
      offerHandoff: !ended && (assignee || supervisor),
      acceptHandoff:
        !ended &&
        input.activeHandoffs.some((handoff) => handoff.recipient_user_id === input.actorUserId),
      cancelHandoff: relevantOpenHandoff || input.manager,
      claimAssignee:
        input.session.status === "awaiting_assignee" &&
        input.membership.role !== "guest" &&
        input.projectAccess !== undefined,
    };
  }

  private publicProjectionTime(): number {
    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TeamSessionError("invalid-command", "Invalid projection time");
    }
    return now;
  }

  private activeHandoffRows(sessionId: string, now: number): SqlRow[] {
    return this.db
      .prepare(
        `SELECT * FROM session_handoffs
         WHERE session_id = ? AND status = 'offered' AND expires_at_ms > ?
         ORDER BY created_at_ms ASC, id ASC`
      )
      .all(sessionId, now) as SqlRow[];
  }

  private latestActorDisplayName(userId: string): string {
    const snapshot = this.db
      .prepare(
        `SELECT actor_display_name FROM accepted_commands
         WHERE actor_kind = 'human' AND actor_user_id = ?
         ORDER BY accepted_sequence DESC LIMIT 1`
      )
      .get(userId) as SqlRow | undefined;
    return (snapshot?.actor_display_name as string | undefined) ?? userId;
  }

  private listVisibleSessions(userId: string, teamId?: string): SessionView[] {
    const rows = this.db
      .prepare(
        `SELECT s.id FROM sessions s
         JOIN session_participants p
           ON p.session_id = s.id AND p.user_id = ? AND p.status = 'active'
         WHERE (? IS NULL OR s.team_id = ?)
         ORDER BY s.created_at_ms ASC, s.id ASC`
      )
      .all(userId, teamId ?? null, teamId ?? null) as SqlRow[];
    return rows
      .filter((row) => this.hasSessionAccess(row.id as string, userId))
      .map((row) => this.projectSession(row.id as string));
  }

  private projectTeamAccess(teamId: string, actorUserId: string): TeamAccessView {
    this.requireTeamAdministrator(teamId, actorUserId);
    const team = this.db.prepare("SELECT id, name FROM teams WHERE id = ?").get(teamId) as
      | SqlRow
      | undefined;
    if (!team) deny();
    const memberships = (
      this.db
        .prepare(
          `SELECT user_id, role, status, version, created_at_ms, revoked_at_ms
           FROM team_memberships WHERE team_id = ?
           ORDER BY created_at_ms ASC, user_id ASC`
        )
        .all(teamId) as SqlRow[]
    ).map((row) => ({
      userId: row.user_id as string,
      role: row.role as TeamRole,
      status: row.status as "active" | "revoked",
      version: row.version as number,
      createdAtMs: row.created_at_ms as number,
      ...(row.revoked_at_ms === null ? {} : { revokedAtMs: row.revoked_at_ms as number }),
    }));
    return { teamId, name: team.name as string, memberships };
  }

  private projectProjectAccess(projectId: string, actorUserId: string): ProjectAccessView {
    const project = this.requireProject(projectId);
    this.requireProjectAdministrator(project, actorUserId);
    const access = (
      this.db
        .prepare(
          `SELECT user_id, role, status, version, created_at_ms, revoked_at_ms
           FROM project_access WHERE project_id = ?
           ORDER BY created_at_ms ASC, user_id ASC`
        )
        .all(projectId) as SqlRow[]
    ).map((row) => ({
      userId: row.user_id as string,
      role: row.role as ProjectRole,
      status: row.status as "active" | "revoked",
      version: row.version as number,
      createdAtMs: row.created_at_ms as number,
      ...(row.revoked_at_ms === null ? {} : { revokedAtMs: row.revoked_at_ms as number }),
    }));
    return {
      projectId,
      teamId: project.team_id as string,
      name: project.name as string,
      access,
    };
  }

  private projectSessionAdmission(sessionId: string, actorUserId: string): SessionAdmissionView {
    const session = this.requireSession(sessionId);
    const teamId = session.team_id as string;
    const projectId = session.project_id as string;
    if (!this.hasSessionAccess(sessionId, actorUserId)) deny();
    const membership = this.activeMembership(teamId, actorUserId);
    if (!membership) deny();
    const sessionManager = this.isSessionManager(sessionId, actorUserId);
    const teamAdministrator = membership.role === "owner" || membership.role === "admin";
    if (!sessionManager && !teamAdministrator) deny();
    const actorProjectAccess = this.activeProjectAccess(projectId, actorUserId);
    const canGrantProjectAccess =
      sessionManager && (teamAdministrator || actorProjectAccess?.role === "maintainer");

    const activeInvitations = teamAdministrator
      ? (
          this.db
            .prepare(
              `SELECT id, membership_role, version, expires_at_ms
               FROM session_invitations
               WHERE session_id = ? AND status = 'active'
               ORDER BY created_at_ms ASC, id ASC`
            )
            .all(sessionId) as SqlRow[]
        ).map((row) => ({
          invitationId: row.id as string,
          membershipRole: row.membership_role as "member" | "guest",
          version: row.version as number,
          expiresAtMs: row.expires_at_ms as number,
        }))
      : [];

    const candidateUsers = new Set<string>();
    const accessCandidates: SessionAdmissionView["accessCandidates"] = [];
    const redeemedInvitations = sessionManager
      ? (this.db
          .prepare(
            `SELECT id, membership_role, redeemed_by_user_id
             FROM session_invitations
             WHERE session_id = ? AND status = 'redeemed'
             ORDER BY redeemed_at_ms DESC, id DESC`
          )
          .all(sessionId) as SqlRow[])
      : [];
    for (const invitation of redeemedInvitations) {
      const userId = invitation.redeemed_by_user_id as string | null;
      if (!userId || candidateUsers.has(userId)) continue;
      const targetMembership = this.activeMembership(teamId, userId);
      const membershipRole = invitation.membership_role as "member" | "guest";
      if (
        !targetMembership ||
        (targetMembership.role === "guest") !== (membershipRole === "guest")
      ) {
        continue;
      }
      // Once the underlying grant exists, the invitee can join without any
      // further private admission metadata being exposed to a manager.
      if (this.hasUnderlyingSessionAccess(sessionId, userId)) continue;
      candidateUsers.add(userId);
      const common = {
        invitationId: invitation.id as string,
        userId,
        displayName: this.latestActorDisplayName(userId),
      };
      if (membershipRole === "guest") {
        accessCandidates.push({
          ...common,
          membershipRole,
          requiredGrant: "session-share",
        });
      } else {
        accessCandidates.push({
          ...common,
          membershipRole,
          requiredGrant: "project-access",
          expectedProjectAccessVersion:
            (this.projectAccess(projectId, userId)?.version as number | undefined) ?? 0,
        });
      }
    }

    return {
      sessionId,
      accessRevision: session.access_revision as number,
      capabilities: {
        canRevokeInvitations: teamAdministrator,
        canGrantGuestShare: sessionManager && session.status !== "ended",
        canGrantProjectAccess,
      },
      activeInvitations,
      accessCandidates,
    };
  }

  private projectInvitations(sessionId: string): SessionView["invitations"] {
    return (
      this.db
        .prepare(
          `SELECT id, membership_role, status, version, expires_at_ms,
                  created_by_user_id, created_at_ms, redeemed_by_user_id,
                  redeemed_at_ms, revoked_at_ms
           FROM session_invitations WHERE session_id = ?
           ORDER BY created_at_ms ASC, id ASC`
        )
        .all(sessionId) as SqlRow[]
    ).map((row) => ({
      invitationId: row.id as string,
      membershipRole: row.membership_role as "member" | "guest",
      status: row.status as "active" | "redeemed" | "revoked",
      version: row.version as number,
      expiresAtMs: row.expires_at_ms as number,
      createdByUserId: row.created_by_user_id as string,
      createdAtMs: row.created_at_ms as number,
      ...(row.redeemed_by_user_id === null
        ? {}
        : { redeemedByUserId: row.redeemed_by_user_id as string }),
      ...(row.redeemed_at_ms === null ? {} : { redeemedAtMs: row.redeemed_at_ms as number }),
      ...(row.revoked_at_ms === null ? {} : { revokedAtMs: row.revoked_at_ms as number }),
    }));
  }

  private projectSessionRunState(sessionId: string): SessionRunStateView | null {
    const session = this.requireSession(sessionId);
    const run = this.db
      .prepare(
        `SELECT * FROM agent_runs
         WHERE session_id = ?
         ORDER BY CASE
           WHEN lifecycle IN ('starting', 'active', 'pausing', 'paused', 'agent-work-finished') THEN 0
           ELSE 1
         END ASC,
         created_at_ms DESC,
         id DESC
         LIMIT 1`
      )
      .get(sessionId) as SqlRow | undefined;
    if (!run) return null;
    const policy = this.readRunPolicyDraft(run.id as string, run.current_policy_revision as number);
    const goalSet = this.currentGoalSetSnapshot(run);
    const evidenceRows = this.db
      .prepare(
        `SELECT * FROM goal_evidence
         WHERE agent_run_id = ? AND goal_set_revision = ?
         ORDER BY created_at_ms ASC, id ASC`
      )
      .all(run.id, goalSet.revision) as SqlRow[];
    const currentGoalsById = new Map(goalSet.goals.map((goal) => [goal.goalId, goal]));
    const evidenceByGoal = new Map<string, GoalEvidence[]>();
    for (const row of evidenceRows) {
      const goalId = row.goal_id as string;
      const currentGoal = currentGoalsById.get(goalId);
      if (!currentGoal || row.goal_version !== currentGoal.version) continue;
      const evidence: GoalEvidence = {
        evidenceId: row.id as string,
        agentRunId: row.agent_run_id as string,
        goalSetRevision: row.goal_set_revision as number,
        goalId,
        goalVersion: row.goal_version as number,
        evidenceRef: row.evidence_ref as string,
        evidenceDigest: row.evidence_digest as string,
        status: row.status as GoalEvidence["status"],
        createdAtMs: row.created_at_ms as number,
        ...(row.reviewed_at_ms === null ? {} : { reviewedAtMs: row.reviewed_at_ms as number }),
      };
      const existing = evidenceByGoal.get(goalId) ?? [];
      existing.push(evidence);
      evidenceByGoal.set(goalId, existing);
    }
    const attentionRows = this.db
      .prepare(
        `SELECT request.* FROM attention_requests request
         WHERE request.agent_run_id = ?
           AND request.version = (
             SELECT MAX(candidate.version) FROM attention_requests candidate
             WHERE candidate.id = request.id
           )
           AND request.status = 'open'
         ORDER BY request.deadline_at_ms ASC, request.id ASC`
      )
      .all(run.id) as SqlRow[];
    const assignment = this.requireRuntimeAssignment(run.runtime_assignment_id as string);
    const policySnapshot = this.db
      .prepare(
        `SELECT runtime_assignment_id, runtime_assignment_generation,
                sandbox_id, sandbox_generation, runtime_principal_id,
                runtime_authorization_generation, required_effect_enforcer_set_digest
         FROM run_policy_revisions WHERE agent_run_id = ? AND revision = ?`
      )
      .get(run.id, run.current_policy_revision) as SqlRow | undefined;
    if (!policySnapshot) {
      throw new TeamSessionError("conflict", "Run policy revision is unavailable");
    }
    const lifecycle = run.lifecycle as AgentRunLifecycle;
    const pendingLifecycle = this.db
      .prepare(
        `SELECT command.operation, command.created_at_ms, dispatch.status
         FROM runtime_run_commands command
         JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
         WHERE command.agent_run_id = ?
           AND dispatch.status IN ('pending', 'processing', 'awaiting-receipt', 'compensating')
         ORDER BY command.command_sequence DESC LIMIT 1`
      )
      .get(run.id) as SqlRow | undefined;
    return {
      agentRunId: run.id as string,
      lifecycle,
      stateVersion: run.state_version as number,
      pendingLifecycleOperation: pendingLifecycle
        ? {
            kind: runtimeLifecycleOperationKind(pendingLifecycle.operation as string),
            status: runtimeLifecycleProjectionStatus(pendingLifecycle.status as string),
            requestedAtMs: pendingLifecycle.created_at_ms as number,
          }
        : null,
      attention: {
        openRequestIds: attentionRows.map((row) => row.id as string),
        blockingRequestIds: attentionRows
          .filter((row) => row.independent_work_may_continue === 0)
          .map((row) => row.id as string),
        independentAuthorizedWorkMayContinue: attentionRows.every(
          (row) => row.independent_work_may_continue === 1
        ),
      },
      // Phase 4 has immutable configured limits but no authoritative usage ledger yet.
      // Never claim compliance until Runtime receipts drive durable accounting.
      limitStatus: "accounting-unavailable",
      sandboxState: assignment.status as SessionRunStateView["sandboxState"],
      finalReviewState:
        lifecycle === "completed"
          ? "accepted"
          : lifecycle === "agent-work-finished"
            ? "open"
            : "not-ready",
      mode: policy.mode,
      runPolicyRevision: run.current_policy_revision as number,
      goalSetRevision: run.current_goal_set_revision as number,
      finalReviewVersion: run.final_review_version as number,
      limits: policy.limits,
      policyRuntimeBindingCurrent:
        run.runtime_authorization_generation === session.runtime_authorization_generation &&
        this.policySnapshotMatchesAssignment(
          policySnapshot,
          assignment,
          session.runtime_authorization_generation as number
        ),
      runtimeAssignmentGeneration: assignment.generation as number,
      sandboxGeneration: assignment.sandbox_generation as number,
      runtimeAuthorizationGeneration: run.runtime_authorization_generation as number,
      completionPolicy: policy.completionPolicy.kind,
      goals: goalSet.goals.map((goal) => ({
        ...goal,
        evidence: evidenceByGoal.get(goal.goalId) ?? [],
      })),
    };
  }

  private projectSession(sessionId: string): SessionView {
    const session = this.requireSession(sessionId);
    const projectionNow = this.clock();
    if (!Number.isSafeInteger(projectionNow) || projectionNow < 0) {
      throw new TeamSessionError("invalid-command", "Invalid projection time");
    }
    const participantRows = this.db
      .prepare(
        `SELECT p.*, m.role AS membership_role
         FROM session_participants p
         LEFT JOIN sessions s ON s.id = p.session_id
         LEFT JOIN team_memberships m ON m.team_id = s.team_id AND m.user_id = p.user_id
         WHERE p.session_id = ?
         ORDER BY p.joined_at_ms ASC, p.id ASC`
      )
      .all(sessionId) as SqlRow[];
    const participants: SessionParticipantView[] = participantRows.map((row) => {
      const responsibilities = this.db
        .prepare(
          `SELECT kind, version FROM session_responsibilities
           WHERE session_id = ? AND user_id = ? AND status = 'active'`
        )
        .all(sessionId, row.user_id) as SqlRow[];
      const ordered = RESPONSIBILITY_ORDER.filter((kind) =>
        responsibilities.some((responsibility) => responsibility.kind === kind)
      );
      const active = row.status === "active";
      const responsibilityVersions = Object.fromEntries(
        responsibilities.map((responsibility) => [
          responsibility.kind as string,
          responsibility.version as number,
        ])
      ) as SessionParticipantView["responsibilityVersions"];
      return {
        participantId: row.id as string,
        userId: row.user_id as string,
        membershipRole: (row.membership_role as TeamRole | null) ?? "guest",
        active,
        observer: active && ordered.length === 0,
        responsibilities: ordered,
        responsibilityVersions,
        joinedAtMs: row.joined_at_ms as number,
        version: row.version as number,
        ...(row.revoked_at_ms === null ? {} : { revokedAtMs: row.revoked_at_ms as number }),
      };
    });
    const shares = (
      this.db
        .prepare(
          `SELECT user_id, status, version, created_at_ms, revoked_at_ms
           FROM session_shares WHERE session_id = ?
           ORDER BY created_at_ms ASC, user_id ASC`
        )
        .all(sessionId) as SqlRow[]
    ).map((row) => ({
      userId: row.user_id as string,
      status: row.status as "active" | "revoked",
      version: row.version as number,
      createdAtMs: row.created_at_ms as number,
      ...(row.revoked_at_ms === null ? {} : { revokedAtMs: row.revoked_at_ms as number }),
    }));
    const invitations = this.projectInvitations(sessionId);
    const handoffs = (
      this.db
        .prepare(
          `SELECT * FROM session_handoffs WHERE session_id = ?
           ORDER BY created_at_ms ASC, id ASC`
        )
        .all(sessionId) as SqlRow[]
    ).map((row) => {
      const storedStatus = row.status as "offered" | "accepted" | "cancelled" | "expired";
      return {
        handoffId: row.id as string,
        offererUserId: row.offerer_user_id as string,
        recipientParticipantId: row.recipient_participant_id as string,
        recipientUserId: row.recipient_user_id as string,
        offeredUnder: row.offered_under_kind as "assignee" | "supervisor",
        status:
          storedStatus === "offered" && (row.expires_at_ms as number) <= projectionNow
            ? ("expired" as const)
            : storedStatus,
        version: row.version as number,
        baseAssigneeRevision: row.base_assignee_revision as number,
        contextSequence: row.context_sequence as number,
        expiresAtMs: row.expires_at_ms as number,
        createdAtMs: row.created_at_ms as number,
        briefing: JSON.parse(
          row.briefing_json as string
        ) as SessionView["handoffs"][number]["briefing"],
        ...(row.resolved_at_ms === null ? {} : { resolvedAtMs: row.resolved_at_ms as number }),
        ...(row.resolved_by_user_id === null
          ? {}
          : { resolvedByUserId: row.resolved_by_user_id as string }),
        ...(row.cancellation_reason === null
          ? {}
          : { cancellationReason: row.cancellation_reason as string }),
      };
    });
    return {
      sessionId,
      teamId: session.team_id as string,
      projectId: session.project_id as string,
      name: session.name as string,
      status: session.status as SessionView["status"],
      steeringPolicy: session.steering_policy as SessionView["steeringPolicy"],
      accessRevision: session.access_revision as number,
      assigneeRevision: session.assignee_revision as number,
      supervisionRevision: session.supervision_revision as number,
      steeringRevision: session.steering_revision as number,
      controlRevision: session.control_revision as number,
      controlEpoch: session.control_epoch as number,
      runStateRevision: session.run_state_revision as number,
      runtime: {
        kind: "local-tmux",
        isolation: "trusted-shared-host",
        tmuxName: session.tmux_name as string,
        yoloEligible: false,
        authorizationGeneration: session.runtime_authorization_generation as number,
        authorizationState:
          session.runtime_authorization_state as SessionView["runtime"]["authorizationState"],
      },
      participants,
      shares,
      invitations,
      handoffs,
      latestSequence: (session.next_sequence as number) - 1,
      createdAtMs: session.created_at_ms as number,
    };
  }

  private readEvents(sessionId: string, afterSequence: number, limit: number): SessionEvent[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM session_events
         WHERE session_id = ? AND sequence > ?
         ORDER BY sequence ASC LIMIT ?`
      )
      .all(sessionId, afterSequence, limit) as SqlRow[];
    return rows.map((row) => ({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      eventId: row.event_id as string,
      sessionId: row.session_id as string,
      sequence: row.sequence as number,
      type: row.type as string,
      occurredAtMs: row.occurred_at_ms as number,
      actor: {
        kind: row.actor_kind as ActorContext["kind"],
        userId: row.actor_user_id as string,
        displayName: row.actor_display_name as string,
      },
      source: { scope: row.source_scope as string, key: row.source_key as string },
      payload: JSON.parse(row.payload_json as string) as Record<string, unknown>,
    }));
  }

  private hasSessionAccess(sessionId: string, userId: string): boolean {
    return (
      Boolean(this.activeParticipant(sessionId, userId)) &&
      this.hasUnderlyingSessionAccess(sessionId, userId)
    );
  }

  private hasTeamVisibility(teamId: string, userId: string): boolean {
    return Boolean(this.activeMembership(teamId, userId));
  }

  private hasRedeemedInvitationReceiptVisibility(
    sessionId: string,
    invitationId: string,
    userId: string
  ): boolean {
    const invitation = this.db
      .prepare(
        `SELECT i.team_id FROM session_invitations i
         WHERE i.id = ? AND i.session_id = ? AND i.status = 'redeemed'
           AND i.redeemed_by_user_id = ?`
      )
      .get(invitationId, sessionId, userId) as SqlRow | undefined;
    return Boolean(invitation && this.activeMembership(invitation.team_id as string, userId));
  }

  private hasProjectVisibility(projectId: string, userId: string): boolean {
    const project = this.db.prepare("SELECT team_id FROM projects WHERE id = ?").get(projectId) as
      | SqlRow
      | undefined;
    if (!project) return false;
    const membership = this.activeMembership(project.team_id as string, userId);
    if (!membership || membership.role === "guest") return false;
    if (membership.role === "owner" || membership.role === "admin") return true;
    return Boolean(this.activeProjectAccess(projectId, userId));
  }

  private hasUnderlyingSessionAccess(sessionId: string, userId: string): boolean {
    const session = this.sessionRow(sessionId);
    if (!session) return false;
    const membership = this.activeMembership(session.team_id as string, userId);
    if (!membership) return false;
    if (membership.role === "guest") {
      return Boolean(
        this.db
          .prepare(
            `SELECT 1 FROM session_shares
             WHERE session_id = ? AND user_id = ? AND status = 'active'`
          )
          .get(sessionId, userId)
      );
    }
    return Boolean(this.activeProjectAccess(session.project_id as string, userId));
  }

  private isSessionManager(sessionId: string, userId: string): boolean {
    if (!this.hasSessionAccess(sessionId, userId)) return false;
    return (
      this.hasResponsibility(sessionId, userId, "assignee") ||
      this.hasResponsibility(sessionId, userId, "supervisor")
    );
  }

  private requireSessionManager(sessionId: string, userId: string): void {
    if (!this.isSessionManager(sessionId, userId)) deny();
  }

  private requireRunAssignee(sessionId: string, userId: string): void {
    if (
      !this.hasSessionAccess(sessionId, userId) ||
      !this.hasResponsibility(sessionId, userId, "assignee")
    ) {
      deny();
    }
  }

  private requireRunSteeringAuthority(sessionId: string, userId: string): SqlRow {
    const session = this.requireConversationParticipant(sessionId, userId);
    if (session.status !== "active") {
      throw new TeamSessionError("conflict", "An inactive Session cannot steer a Run");
    }
    const steerer = this.hasResponsibility(sessionId, userId, "steerer");
    const controller = this.hasResponsibility(sessionId, userId, "controller");
    if (!steerer || (session.steering_policy === "single" && !controller)) deny();
    return session;
  }

  private mutableAgentRun(sessionId: string): SqlRow | undefined {
    return this.db
      .prepare(
        `SELECT * FROM agent_runs
         WHERE session_id = ?
           AND lifecycle IN ('starting', 'active', 'pausing', 'paused', 'agent-work-finished')
         ORDER BY created_at_ms DESC, id DESC LIMIT 1`
      )
      .get(sessionId) as SqlRow | undefined;
  }

  private requireMutableAgentRun(sessionId: string, agentRunId: string): SqlRow {
    const run = this.db
      .prepare(
        `SELECT * FROM agent_runs
         WHERE id = ? AND session_id = ?
           AND lifecycle IN ('starting', 'active', 'pausing', 'paused', 'agent-work-finished')`
      )
      .get(agentRunId, sessionId) as SqlRow | undefined;
    if (!run) deny();
    return run;
  }

  private requireRuntimeAssignment(runtimeAssignmentId: string): SqlRow {
    const assignment = this.db
      .prepare(`SELECT * FROM runtime_assignments WHERE id = ?`)
      .get(runtimeAssignmentId) as SqlRow | undefined;
    if (!assignment) {
      throw new TeamSessionError("conflict", "Run Runtime Assignment is unavailable");
    }
    return assignment;
  }

  private requireRuntimeCommandAuthorityIssuer(): RuntimeCommandAuthorityIssuer {
    if (!this.runtimeCommandAuthorityIssuer) {
      throw new TeamSessionError("conflict", "Runtime lifecycle authority is not configured");
    }
    return this.runtimeCommandAuthorityIssuer;
  }

  private runtimeLifecycleDeadline(issuedAtMs: number): number {
    const deadlineAtMs = issuedAtMs + this.runtimeLifecycleCommandTtlMs;
    if (!Number.isSafeInteger(deadlineAtMs) || deadlineAtMs <= issuedAtMs) {
      throw new TeamSessionError("invalid-command", "Runtime lifecycle deadline is invalid");
    }
    return deadlineAtMs;
  }

  private ensureCurrentRuntimeAssignment(session: SqlRow, now: number): SqlRow {
    const current = this.db
      .prepare(
        `SELECT * FROM runtime_assignments
         WHERE session_id = ? AND status IN (
           'provisioning', 'ready', 'checkpointing', 'recovering', 'quarantined'
         )
         ORDER BY generation DESC LIMIT 1`
      )
      .get(session.id) as SqlRow | undefined;
    if (current) {
      if (
        current.team_id !== session.team_id ||
        current.project_id !== session.project_id ||
        current.runtime_authorization_generation !== session.runtime_authorization_generation
      ) {
        throw new TeamSessionError("conflict", "Runtime Assignment binding is stale");
      }
      if (current.status !== "ready") {
        throw new TeamSessionError("conflict", "Runtime Assignment is not ready");
      }
      this.recordRuntimeAuthorizationEpoch(
        session.id as string,
        current,
        session.runtime_authorization_generation as number,
        now
      );
      return current;
    }
    const assignmentId = this.nextId("runtime-assignment");
    const sandboxId = this.nextId("sandbox");
    const runtimePrincipalId = this.nextId("runtime-principal");
    this.db
      .prepare(
        `INSERT INTO runtime_assignments
           (id, session_id, team_id, project_id, generation, runtime_kind,
            sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, status, created_at_ms, retired_at_ms)
         VALUES (?, ?, ?, ?, 1, ?, ?, 1, ?, ?, 'ready', ?, NULL)`
      )
      .run(
        assignmentId,
        session.id,
        session.team_id,
        session.project_id,
        session.runtime_kind,
        sandboxId,
        runtimePrincipalId,
        session.runtime_authorization_generation,
        now
      );
    const assignment = this.requireRuntimeAssignment(assignmentId);
    this.recordRuntimeAuthorizationEpoch(
      session.id as string,
      assignment,
      session.runtime_authorization_generation as number,
      now
    );
    return assignment;
  }

  private recordRuntimeAuthorizationEpoch(
    sessionId: string,
    assignment: SqlRow,
    generation: number,
    now: number
  ): void {
    const authorization = this.resolveRuntimeAuthorizationSnapshot(
      sessionId,
      assignment,
      generation
    );
    this.db
      .prepare(
        `INSERT INTO runtime_authorization_epochs
           (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id,
            effect_enforcer_set_digest, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(session_id, generation) DO NOTHING`
      )
      .run(
        sessionId,
        generation,
        assignment.id,
        assignment.generation,
        assignment.sandbox_id,
        assignment.sandbox_generation,
        assignment.runtime_principal_id,
        authorization?.effectEnforcerSetDigest ?? null,
        now
      );
    const exact = this.db
      .prepare(
        `SELECT 1 FROM runtime_authorization_epochs
         WHERE session_id = ? AND generation = ? AND runtime_assignment_id = ?
           AND runtime_assignment_generation = ? AND sandbox_id = ?
           AND sandbox_generation = ? AND runtime_principal_id = ?
           AND effect_enforcer_set_digest IS ?`
      )
      .get(
        sessionId,
        generation,
        assignment.id,
        assignment.generation,
        assignment.sandbox_id,
        assignment.sandbox_generation,
        assignment.runtime_principal_id,
        authorization?.effectEnforcerSetDigest ?? null
      );
    if (!exact) {
      throw new TeamSessionError("conflict", "Runtime Authorization epoch binding is immutable");
    }
  }

  private resolveRuntimeAuthorizationSnapshot(
    sessionId: string,
    assignment: SqlRow,
    generation: number
  ): RuntimeAuthorizationSnapshot | undefined {
    if (!this.runtimeAuthorizationSnapshotSource) return undefined;
    if (
      assignment.session_id !== sessionId ||
      assignment.runtime_authorization_generation !== generation ||
      !Number.isSafeInteger(generation) ||
      generation < 1
    ) {
      throw new TeamSessionError("conflict", "Runtime Authorization binding is invalid");
    }
    const binding: RuntimeBinding = Object.freeze({
      teamId: assignment.team_id as string,
      projectId: assignment.project_id as string,
      sessionId,
      runtimeAssignmentId: assignment.id as string,
      runtimeAssignmentGeneration: assignment.generation as number,
      sandboxId: assignment.sandbox_id as string,
      sandboxGeneration: assignment.sandbox_generation as number,
      runtimePrincipalId: assignment.runtime_principal_id as string,
    });
    try {
      return snapshotTrustedRuntimeAuthorization(
        this.runtimeAuthorizationSnapshotSource.resolve(
          Object.freeze({ binding, runtimeAuthorizationGeneration: generation })
        ),
        generation
      );
    } catch {
      throw new TeamSessionError(
        "conflict",
        "Trusted Runtime Authorization snapshot is unavailable"
      );
    }
  }

  private requireRuntimeAuthorizationEpochDigest(
    sessionId: string,
    assignment: SqlRow,
    generation: number
  ): string {
    const digest = this.runtimeAuthorizationEpochDigest(sessionId, assignment, generation);
    if (!digest) {
      throw new TeamSessionError(
        "conflict",
        "Trusted Runtime Authorization snapshot is unavailable"
      );
    }
    return digest;
  }

  private runtimeAuthorizationEpochDigest(
    sessionId: string,
    assignment: SqlRow,
    generation: number
  ): string | undefined {
    const epoch = this.db
      .prepare(
        `SELECT effect_enforcer_set_digest FROM runtime_authorization_epochs
         WHERE session_id = ? AND generation = ? AND runtime_assignment_id = ?
           AND runtime_assignment_generation = ? AND sandbox_id = ?
           AND sandbox_generation = ? AND runtime_principal_id = ?`
      )
      .get(
        sessionId,
        generation,
        assignment.id,
        assignment.generation,
        assignment.sandbox_id,
        assignment.sandbox_generation,
        assignment.runtime_principal_id
      ) as SqlRow | undefined;
    if (!epoch || !isSha256Digest(epoch.effect_enforcer_set_digest)) {
      return undefined;
    }
    return epoch.effect_enforcer_set_digest;
  }

  private assertRunPolicyCommit(
    commit: Extract<SessionCommand, { type: "run.start" }>["commit"],
    session: SqlRow,
    assignment: SqlRow
  ): void {
    try {
      assertValidRunPolicyCommit(commit, {
        sessionName: session.name as string,
        yoloEligible: session.yolo_eligible === 1,
        projectCeilingRevision: LOCAL_TMUX_PROJECT_CEILING_REVISION,
        runtimeAssignmentGeneration: assignment.generation as number,
        sandboxId: assignment.sandbox_id as string,
        sandboxGeneration: assignment.sandbox_generation as number,
        runtimeAuthorizationGeneration: assignment.runtime_authorization_generation as number,
      });
    } catch (error) {
      throw new TeamSessionError(
        "invalid-command",
        error instanceof Error ? error.message : "Run policy is invalid"
      );
    }
  }

  private insertRunPolicyRevision(input: {
    agentRunId: string;
    sessionId: string;
    revision: number;
    previousRevision?: number;
    policy: RunPolicyDraft;
    policyDigest: string;
    goalSetId: string;
    goalSetRevision: number;
    goalSetDigest: string;
    goals: ReadonlyArray<GoalItem | MutableGoalItem>;
    assignment: SqlRow;
    yoloConfirmationRef?: string;
    now: number;
  }): AgentRunPolicySnapshot {
    const requiredEffectEnforcerSetDigest = this.requireRuntimeAuthorizationEpochDigest(
      input.sessionId,
      input.assignment,
      input.assignment.runtime_authorization_generation as number
    );
    const initialGoalSet: GoalSet = {
      goalSetId: input.goalSetId,
      agentRunId: input.agentRunId,
      revision: input.goalSetRevision,
      ...(input.goalSetRevision === 1 ? {} : { previousRevision: input.goalSetRevision - 1 }),
      digest: input.goalSetDigest,
      goals: input.goals.map((goal) => ({
        ...goal,
        acceptanceCriteria: [...goal.acceptanceCriteria],
        dependencyGoalIds: [...goal.dependencyGoalIds],
      })),
    };
    const snapshotWithoutDigest = {
      agentRunId: input.agentRunId,
      revision: input.revision,
      ...(input.previousRevision === undefined ? {} : { previousRevision: input.previousRevision }),
      ...input.policy,
      policyBodyDigest: input.policyDigest,
      initialGoalSet,
      scopedExternalRules: [],
      projectCeilingRevision: LOCAL_TMUX_PROJECT_CEILING_REVISION,
      projectCeilingDigest: LOCAL_TMUX_PROJECT_CEILING_DIGEST,
      binding: {
        teamId: input.assignment.team_id as string,
        projectId: input.assignment.project_id as string,
        sessionId: input.sessionId,
        runtimeAssignmentId: input.assignment.id as string,
        runtimeAssignmentGeneration: input.assignment.generation as number,
        sandboxId: input.assignment.sandbox_id as string,
        sandboxGeneration: input.assignment.sandbox_generation as number,
        runtimePrincipalId: input.assignment.runtime_principal_id as string,
      },
      runtimeAuthorizationGeneration: input.assignment.runtime_authorization_generation as number,
      requiredEffectEnforcerSetDigest,
      ...(input.yoloConfirmationRef === undefined
        ? {}
        : { yoloConfirmationRef: input.yoloConfirmationRef }),
      createdAtMs: input.now,
    } satisfies Omit<AgentRunPolicySnapshot, "digest">;
    const snapshot: AgentRunPolicySnapshot = {
      ...snapshotWithoutDigest,
      digest: sha256(canonicalJson(snapshotWithoutDigest)),
    };
    this.db
      .prepare(
        `INSERT INTO run_policy_revisions
           (agent_run_id, session_id, revision, previous_revision, digest, policy_body_digest,
            mode, completion_policy,
            scoped_external_policy_ref, scoped_external_rules_json, limits_json,
            initial_goal_set_id, initial_goal_set_revision,
            project_ceiling_revision, project_ceiling_digest,
            runtime_assignment_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, required_effect_enforcer_set_digest,
            yolo_confirmation_ref, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        input.agentRunId,
        input.sessionId,
        input.revision,
        input.previousRevision ?? null,
        snapshot.digest,
        input.policyDigest,
        input.policy.mode,
        input.policy.completionPolicy.kind,
        input.policy.scopedExternalPolicyRef,
        JSON.stringify(input.policy.limits),
        input.goalSetId,
        input.goalSetRevision,
        LOCAL_TMUX_PROJECT_CEILING_REVISION,
        LOCAL_TMUX_PROJECT_CEILING_DIGEST,
        input.assignment.id,
        input.assignment.generation,
        input.assignment.sandbox_id,
        input.assignment.sandbox_generation,
        input.assignment.runtime_principal_id,
        input.assignment.runtime_authorization_generation,
        requiredEffectEnforcerSetDigest,
        input.yoloConfirmationRef ?? null,
        input.now
      );
    return snapshot;
  }

  private readRunPolicyDraft(agentRunId: string, revision: number): RunPolicyDraft {
    const row = this.db
      .prepare(
        `SELECT mode, completion_policy, scoped_external_policy_ref, limits_json
         FROM run_policy_revisions WHERE agent_run_id = ? AND revision = ?`
      )
      .get(agentRunId, revision) as SqlRow | undefined;
    if (!row) throw new TeamSessionError("conflict", "Run policy revision is unavailable");
    return {
      mode: row.mode as RunPolicyDraft["mode"],
      completionPolicy: {
        kind: row.completion_policy as RunPolicyDraft["completionPolicy"]["kind"],
      },
      scopedExternalPolicyRef: row.scoped_external_policy_ref as string,
      limits: JSON.parse(row.limits_json as string) as RunPolicyDraft["limits"],
    };
  }

  private policySnapshotMatchesAssignment(
    snapshot: SqlRow,
    assignment: SqlRow,
    runtimeAuthorizationGeneration: number
  ): boolean {
    const epochDigest = this.runtimeAuthorizationEpochDigest(
      assignment.session_id as string,
      assignment,
      runtimeAuthorizationGeneration
    );
    return (
      snapshot.runtime_assignment_id === assignment.id &&
      snapshot.runtime_assignment_generation === assignment.generation &&
      snapshot.sandbox_id === assignment.sandbox_id &&
      snapshot.sandbox_generation === assignment.sandbox_generation &&
      snapshot.runtime_principal_id === assignment.runtime_principal_id &&
      snapshot.runtime_authorization_generation === runtimeAuthorizationGeneration &&
      assignment.runtime_authorization_generation === runtimeAuthorizationGeneration &&
      epochDigest !== undefined &&
      snapshot.required_effect_enforcer_set_digest === epochDigest
    );
  }

  private requireReadyRunRuntimeBinding(session: SqlRow, run: SqlRow): SqlRow {
    if (run.lifecycle === "starting" || run.lifecycle === "pausing") {
      throw new TeamSessionError(
        "conflict",
        "Run mutation is unavailable while Runtime lifecycle enforcement is pending"
      );
    }
    if (this.hasUnresolvedRuntimeLifecycle(run.id as string)) {
      throw new TeamSessionError(
        "conflict",
        "Run mutation is unavailable while Runtime lifecycle truth is unresolved"
      );
    }
    const assignment = this.requireRuntimeAssignment(run.runtime_assignment_id as string);
    const policySnapshot = this.db
      .prepare(
        `SELECT runtime_assignment_id, runtime_assignment_generation,
                sandbox_id, sandbox_generation, runtime_principal_id,
                runtime_authorization_generation, required_effect_enforcer_set_digest
         FROM run_policy_revisions WHERE agent_run_id = ? AND revision = ?`
      )
      .get(run.id, run.current_policy_revision) as SqlRow | undefined;
    if (
      session.status !== "active" ||
      session.runtime_authorization_state !== "enforced" ||
      run.runtime_authorization_generation !== session.runtime_authorization_generation ||
      assignment.status !== "ready" ||
      !policySnapshot ||
      !this.policySnapshotMatchesAssignment(
        policySnapshot,
        assignment,
        session.runtime_authorization_generation as number
      )
    ) {
      throw new TeamSessionError(
        "conflict",
        "Run Runtime enforcement is not ready; use Emergency Stop if safety requires termination"
      );
    }
    return assignment;
  }

  private hasUnresolvedRuntimeLifecycle(agentRunId: string): boolean {
    return Boolean(
      this.db
        .prepare(
          `SELECT 1 FROM runtime_run_command_dispatch
           WHERE agent_run_id = ?
             AND status IN ('pending', 'processing', 'awaiting-receipt', 'compensating')`
        )
        .get(agentRunId)
    );
  }

  private insertGoalSetSnapshot(input: {
    agentRunId: string;
    goalSetId: string;
    revision: number;
    previousRevision?: number;
    goals: ReadonlyArray<GoalItem | MutableGoalItem>;
    now: number;
  }): string {
    const digest = sha256(
      canonicalJson({
        goalSetId: input.goalSetId,
        agentRunId: input.agentRunId,
        revision: input.revision,
        previousRevision: input.previousRevision,
        goals: input.goals,
      })
    );
    this.db
      .prepare(
        `INSERT INTO goal_sets
           (goal_set_id, agent_run_id, revision, previous_revision, digest, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        input.goalSetId,
        input.agentRunId,
        input.revision,
        input.previousRevision ?? null,
        digest,
        input.now
      );
    const insertGoal = this.db.prepare(
      `INSERT INTO goals
         (agent_run_id, goal_set_id, goal_set_revision, goal_id, position, version, title,
          acceptance_criteria_json, dependency_goal_ids_json, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const goal of input.goals) {
      insertGoal.run(
        input.agentRunId,
        input.goalSetId,
        input.revision,
        goal.goalId,
        goal.position,
        goal.version,
        goal.title,
        JSON.stringify(goal.acceptanceCriteria),
        JSON.stringify(goal.dependencyGoalIds),
        goal.status
      );
    }
    return digest;
  }

  private currentGoalSetSnapshot(run: SqlRow): {
    goalSetId: string;
    revision: number;
    digest: string;
    goals: MutableGoalItem[];
  } {
    const revision = run.current_goal_set_revision as number;
    const set = this.db
      .prepare(
        `SELECT goal_set_id, digest FROM goal_sets
         WHERE agent_run_id = ? AND revision = ?`
      )
      .get(run.id, revision) as SqlRow | undefined;
    if (!set) throw new TeamSessionError("conflict", "Current Goal Set is unavailable");
    const rows = this.db
      .prepare(
        `SELECT * FROM goals
         WHERE goal_set_id = ? AND goal_set_revision = ?
         ORDER BY position ASC, goal_id ASC`
      )
      .all(set.goal_set_id, revision) as SqlRow[];
    return {
      goalSetId: set.goal_set_id as string,
      revision,
      digest: set.digest as string,
      goals: rows.map((row) => ({
        goalId: row.goal_id as string,
        position: row.position as number,
        title: row.title as string,
        acceptanceCriteria: JSON.parse(row.acceptance_criteria_json as string) as string[],
        dependencyGoalIds: JSON.parse(row.dependency_goal_ids_json as string) as string[],
        version: row.version as number,
        status: row.status as GoalItem["status"],
      })),
    };
  }

  private appendRunDirective(
    command: SessionCommand & { sessionId: string },
    now: number,
    session: SqlRow,
    directive: { format: "plain-text"; body: string },
    origin: Record<string, unknown>
  ): SessionEvent {
    if (!directive || directive.format !== "plain-text") {
      throw new TeamSessionError("invalid-command", "Run Directive format is invalid");
    }
    const body = requiredConversationBody(directive.body, "Run Directive body");
    const directiveId = this.reserveConversationIdentity(command.sessionId, "directive", now);
    return this.appendQueuedDirective(command, now, directiveId, body, session, origin);
  }

  private commitGoalSetMutation(
    command: SessionCommand & { sessionId: string; agentRunId: string },
    run: SqlRow,
    current: { goalSetId: string; revision: number },
    goals: MutableGoalItem[],
    now: number,
    directive: SessionEvent | undefined,
    change: Record<string, unknown>
  ): CommandResult {
    const revision = current.revision + 1;
    const digest = this.insertGoalSetSnapshot({
      agentRunId: command.agentRunId,
      goalSetId: current.goalSetId,
      revision,
      previousRevision: current.revision,
      goals,
      now,
    });
    const updated = this.db
      .prepare(
        `UPDATE agent_runs
         SET current_goal_set_revision = ?, state_version = state_version + 1, updated_at_ms = ?
         WHERE id = ? AND session_id = ? AND current_goal_set_revision = ?
         RETURNING state_version`
      )
      .get(revision, now, command.agentRunId, command.sessionId, current.revision) as
      | SqlRow
      | undefined;
    if (!updated) throw new TeamSessionError("stale-revision", "Goal Set changed concurrently");
    const runStateRevision = this.advanceRunStateRevision(command.sessionId);
    const event = this.appendEvent(command.sessionId, command, now, "goal-set.revised", {
      agentRunId: command.agentRunId,
      previousGoalSetRevision: current.revision,
      goalSetRevision: revision,
      goalSetDigest: digest,
      goalCount: goals.length,
      stateVersion: updated.state_version,
      directiveId: directive?.payload.directiveId ?? null,
      ...change,
      runStateRevision,
    });
    const events = directive ? [directive, event] : [event];
    return result(
      command,
      {
        sessionId: command.sessionId,
        agentRunId: command.agentRunId,
        goalSetRevision: revision,
        goalSetDigest: digest,
        stateVersion: updated.state_version,
        directiveId: directive?.payload.directiveId,
        runStateRevision,
      },
      events
    );
  }

  private requestRuntimeLifecycleTransition(
    command: Extract<SessionCommand, { type: "run.pause" | "run.resume" | "run.stop" }>,
    run: SqlRow,
    assignment: SqlRow,
    now: number
  ): CommandResult {
    const authorityIssuer = this.requireRuntimeCommandAuthorityIssuer();
    const unresolved = this.db
      .prepare(
        `SELECT 1 FROM runtime_run_command_dispatch
         WHERE agent_run_id = ?
           AND status IN ('pending', 'processing', 'awaiting-receipt', 'compensating')`
      )
      .get(run.id);
    if (unresolved) {
      throw new TeamSessionError(
        "conflict",
        "This Run already has a lifecycle operation awaiting Runtime truth"
      );
    }
    const policy = this.db
      .prepare(
        `SELECT project_ceiling_revision, required_effect_enforcer_set_digest
         FROM run_policy_revisions
         WHERE agent_run_id = ? AND revision = ?`
      )
      .get(run.id, run.current_policy_revision) as SqlRow | undefined;
    if (!policy) {
      throw new TeamSessionError("conflict", "Run policy revision is unavailable");
    }
    const requiredEffectEnforcerSetDigest = this.requireRuntimeAuthorizationEpochDigest(
      command.sessionId,
      assignment,
      run.runtime_authorization_generation as number
    );
    if (policy.required_effect_enforcer_set_digest !== requiredEffectEnforcerSetDigest) {
      throw new TeamSessionError(
        "conflict",
        "Run policy Runtime Authorization snapshot is unavailable"
      );
    }
    const runtimeCommandId = this.nextId("runtime-command");
    const targetLifecycle =
      command.type === "run.pause"
        ? "paused"
        : command.type === "run.resume"
          ? "active"
          : "stopped";
    const fromRunStateVersion = run.state_version as number;
    const toRunStateVersion = fromRunStateVersion + 1;
    const requestEvent = this.appendEvent(
      command.sessionId,
      command,
      now,
      "run.runtime-command.requested",
      {
        commandId: runtimeCommandId,
        agentRunId: run.id,
        operation: command.type,
        targetLifecycle,
        fromRunStateVersion,
        toRunStateVersion,
        lifecycle: run.lifecycle,
        stateVersion: fromRunStateVersion,
        runPolicyRevision: run.current_policy_revision,
        goalSetRevision: run.current_goal_set_revision,
        reason: "reason" in command ? (command.reason ?? null) : null,
      }
    );
    const common = {
      commandId: runtimeCommandId,
      binding: {
        teamId: assignment.team_id as string,
        projectId: assignment.project_id as string,
        sessionId: command.sessionId,
        runtimeAssignmentId: assignment.id as string,
        runtimeAssignmentGeneration: assignment.generation as number,
        sandboxId: assignment.sandbox_id as string,
        sandboxGeneration: assignment.sandbox_generation as number,
        runtimePrincipalId: assignment.runtime_principal_id as string,
      },
      projectCeilingRevision: policy.project_ceiling_revision as string,
      runtimeAuthorizationGeneration: run.runtime_authorization_generation as number,
      requiredEffectEnforcerSetDigest,
      causationId: requestEvent.eventId,
      actor: { kind: command.actor.kind, actorRef: command.actor.userId },
      issuedAtMs: now,
      deadlineAtMs: this.runtimeLifecycleDeadline(now),
      agentRunId: run.id as string,
      runPolicyRevision: run.current_policy_revision as number,
      fromRunStateVersion,
      toRunStateVersion,
    } as const;
    let runtimeCommand: RuntimeLifecycleCommand;
    if (command.type === "run.pause") {
      const claims: Omit<Extract<RuntimeLifecycleCommand, { kind: "run.pause" }>, "authority"> = {
        ...common,
        kind: "run.pause",
        reason: "human",
      };
      runtimeCommand = { ...claims, authority: authorityIssuer.issue(claims) };
    } else if (command.type === "run.resume") {
      const claims: Omit<Extract<RuntimeLifecycleCommand, { kind: "run.resume" }>, "authority"> = {
        ...common,
        kind: "run.resume",
        accountableAssigneePresent: true,
      };
      runtimeCommand = { ...claims, authority: authorityIssuer.issue(claims) };
    } else {
      const claims: Omit<Extract<RuntimeLifecycleCommand, { kind: "run.stop" }>, "authority"> = {
        ...common,
        kind: "run.stop",
        reason: "human",
      };
      runtimeCommand = { ...claims, authority: authorityIssuer.issue(claims) };
    }
    const intent = this.runtimeLifecycle.enqueue({
      command: runtimeCommand,
      sourceSessionSequence: requestEvent.sequence,
    });
    const runStateRevision = this.advanceRunStateRevision(command.sessionId);
    return result(
      command,
      {
        sessionId: command.sessionId,
        agentRunId: run.id,
        lifecycle: run.lifecycle,
        stateVersion: fromRunStateVersion,
        requestedLifecycle: targetLifecycle,
        runtimeCommandId: intent.commandId,
        runtimeCommandStatus: "pending",
        runStateRevision,
      },
      [requestEvent]
    );
  }

  private updateAgentRunLifecycle(
    run: SqlRow,
    lifecycle: AgentRunLifecycle,
    now: number,
    runtimeAuthorizationGeneration?: number
  ): { stateVersion: number } {
    const terminal = isTerminalRunLifecycle(lifecycle);
    const updated = this.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = ?, state_version = state_version + 1, updated_at_ms = ?,
             terminal_at_ms = ?, runtime_authorization_generation = COALESCE(?, runtime_authorization_generation)
         WHERE id = ? AND session_id = ? AND state_version = ?
         RETURNING state_version`
      )
      .get(
        lifecycle,
        now,
        terminal ? now : null,
        runtimeAuthorizationGeneration ?? null,
        run.id,
        run.session_id,
        run.state_version
      ) as SqlRow | undefined;
    if (!updated) throw new TeamSessionError("stale-revision", "Run state changed concurrently");
    return { stateVersion: updated.state_version as number };
  }

  private invalidateMutableRunGrants(
    agentRunId: string,
    now: number,
    reason:
      | "policy-revision"
      | "runtime-assignment"
      | "sandbox-generation"
      | "runtime-authorization"
      | "run-terminal" = "run-terminal"
  ): number {
    const grants = this.db
      .prepare(
        `SELECT grant.id, state.version
         FROM action_grants grant
         JOIN action_grant_states state ON state.grant_id = grant.id
         WHERE grant.agent_run_id = ?
           AND state.version = (
             SELECT MAX(candidate.version) FROM action_grant_states candidate
             WHERE candidate.grant_id = grant.id
           )
           AND state.status IN ('issued', 'enforcement-pending', 'active')
         ORDER BY grant.id ASC`
      )
      .all(agentRunId) as SqlRow[];
    const insert = this.db.prepare(
      `INSERT INTO action_grant_states
         (grant_id, version, previous_version, status, reason, actor_ref, created_at_ms)
       VALUES (?, ?, ?, 'invalidated', ?, 'team-session-kernel', ?)`
    );
    for (const grant of grants) {
      const version = grant.version as number;
      insert.run(grant.id, version + 1, version, reason, now);
    }
    return grants.length;
  }

  private advanceRunStateRevision(sessionId: string): number {
    const updated = this.db
      .prepare(
        `UPDATE sessions SET run_state_revision = run_state_revision + 1
         WHERE id = ? RETURNING run_state_revision`
      )
      .get(sessionId) as SqlRow | undefined;
    if (!updated) deny();
    return updated.run_state_revision as number;
  }

  private requireProjectAdministrator(project: SqlRow, userId: string): void {
    const membership = this.activeMembership(project.team_id as string, userId);
    if (!membership) deny();
    if (membership.role === "owner" || membership.role === "admin") return;
    const access = this.activeProjectAccess(project.id as string, userId);
    if (access?.role === "maintainer") return;
    deny();
  }

  private requireTeamAdministrator(teamId: string, userId: string): void {
    const membership = this.activeMembership(teamId, userId);
    if (!membership || (membership.role !== "owner" && membership.role !== "admin")) deny();
  }

  private activeMembership(teamId: string, userId: string): SqlRow | undefined {
    return this.db
      .prepare(
        `SELECT * FROM team_memberships
         WHERE team_id = ? AND user_id = ? AND status = 'active'`
      )
      .get(teamId, userId) as SqlRow | undefined;
  }

  private membership(teamId: string, userId: string): SqlRow | undefined {
    return this.db
      .prepare("SELECT * FROM team_memberships WHERE team_id = ? AND user_id = ?")
      .get(teamId, userId) as SqlRow | undefined;
  }

  private activeMembershipCount(teamId: string, role: TeamRole): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS count FROM team_memberships
         WHERE team_id = ? AND role = ? AND status = 'active'`
      )
      .get(teamId, role) as SqlRow;
    return row.count as number;
  }

  private activeProjectAccess(projectId: string, userId: string): SqlRow | undefined {
    return this.db
      .prepare(
        `SELECT * FROM project_access
         WHERE project_id = ? AND user_id = ? AND status = 'active'`
      )
      .get(projectId, userId) as SqlRow | undefined;
  }

  private projectAccess(projectId: string, userId: string): SqlRow | undefined {
    return this.db
      .prepare("SELECT * FROM project_access WHERE project_id = ? AND user_id = ?")
      .get(projectId, userId) as SqlRow | undefined;
  }

  private share(sessionId: string, userId: string): SqlRow | undefined {
    return this.db
      .prepare("SELECT * FROM session_shares WHERE session_id = ? AND user_id = ?")
      .get(sessionId, userId) as SqlRow | undefined;
  }

  private activeParticipant(sessionId: string, userId: string): SqlRow | undefined {
    return this.db
      .prepare(
        `SELECT * FROM session_participants
         WHERE session_id = ? AND user_id = ? AND status = 'active'`
      )
      .get(sessionId, userId) as SqlRow | undefined;
  }

  private participant(sessionId: string, userId: string): SqlRow | undefined {
    return this.db
      .prepare("SELECT * FROM session_participants WHERE session_id = ? AND user_id = ?")
      .get(sessionId, userId) as SqlRow | undefined;
  }

  private hasResponsibility(
    sessionId: string,
    userId: string,
    kind: SessionResponsibility
  ): boolean {
    return Boolean(
      this.db
        .prepare(
          `SELECT 1 FROM session_responsibilities
           WHERE session_id = ? AND user_id = ? AND kind = ? AND status = 'active'`
        )
        .get(sessionId, userId, kind)
    );
  }

  private activeResponsibilityCount(sessionId: string, kind: SessionResponsibility): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS count FROM session_responsibilities
         WHERE session_id = ? AND kind = ? AND status = 'active'`
      )
      .get(sessionId, kind) as SqlRow;
    return row.count as number;
  }

  private activeResponsibilityHolder(
    sessionId: string,
    kind: SessionResponsibility
  ): SqlRow | undefined {
    return this.db
      .prepare(
        `SELECT user_id FROM session_responsibilities
         WHERE session_id = ? AND kind = ? AND status = 'active'
         ORDER BY user_id ASC LIMIT 1`
      )
      .get(sessionId, kind) as SqlRow | undefined;
  }

  private advanceSteeringRevision(sessionId: string): number {
    const updated = this.db
      .prepare(
        `UPDATE sessions SET steering_revision = steering_revision + 1
         WHERE id = ? RETURNING steering_revision`
      )
      .get(sessionId) as SqlRow | undefined;
    if (!updated) deny();
    return updated.steering_revision as number;
  }

  private allocateAcceptedSequence(): number {
    const updated = this.db
      .prepare(
        `UPDATE kernel_state
         SET next_accepted_sequence = next_accepted_sequence + 1
         WHERE singleton = 1
         RETURNING next_accepted_sequence - 1 AS accepted_sequence`
      )
      .get() as SqlRow | undefined;
    if (!updated) {
      throw new TeamSessionError("conflict", "Could not allocate canonical command sequence");
    }
    return updated.accepted_sequence as number;
  }

  private advanceSupervisionRevision(sessionId: string): number {
    const updated = this.db
      .prepare(
        `UPDATE sessions SET supervision_revision = supervision_revision + 1
         WHERE id = ? RETURNING supervision_revision`
      )
      .get(sessionId) as SqlRow | undefined;
    if (!updated) deny();
    return updated.supervision_revision as number;
  }

  private advanceAssigneeRevision(sessionId: string): number {
    const updated = this.db
      .prepare(
        `UPDATE sessions SET assignee_revision = assignee_revision + 1
         WHERE id = ? RETURNING assignee_revision`
      )
      .get(sessionId) as SqlRow | undefined;
    if (!updated) deny();
    return updated.assignee_revision as number;
  }

  private advanceAccessRevision(sessionId: string): number {
    const updated = this.db
      .prepare(
        `UPDATE sessions SET access_revision = access_revision + 1
         WHERE id = ? RETURNING access_revision`
      )
      .get(sessionId) as SqlRow | undefined;
    if (!updated) deny();
    return updated.access_revision as number;
  }

  private advanceTeamAccessRevisions(teamId: string): SqlRow[] {
    const rows = this.db
      .prepare(
        `UPDATE sessions SET access_revision = access_revision + 1
         WHERE team_id = ? RETURNING id, access_revision`
      )
      .all(teamId) as SqlRow[];
    return rows.sort((left, right) => String(left.id).localeCompare(String(right.id)));
  }

  private advanceProjectAccessRevisions(projectId: string): SqlRow[] {
    const rows = this.db
      .prepare(
        `UPDATE sessions SET access_revision = access_revision + 1
         WHERE project_id = ? RETURNING id, access_revision`
      )
      .all(projectId) as SqlRow[];
    return rows.sort((left, right) => String(left.id).localeCompare(String(right.id)));
  }

  private recordUserRevocations(
    sessions: SqlRow[],
    userId: string,
    reason: string,
    now: number
  ): void {
    const statement = this.db.prepare(
      `INSERT INTO session_user_revocations
         (session_id, user_id, last_access_revision, reason, revoked_at_ms)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(session_id, user_id) DO UPDATE SET
         last_access_revision = excluded.last_access_revision,
         reason = excluded.reason,
         revoked_at_ms = excluded.revoked_at_ms
       WHERE excluded.last_access_revision > session_user_revocations.last_access_revision`
    );
    for (const session of sessions) {
      statement.run(session.id, userId, session.access_revision, reason, now);
    }
  }

  private advanceControlFence(
    sessionId: string,
    expectedRevision?: number,
    expectedEpoch?: number
  ): void {
    const session = this.requireSession(sessionId);
    const revision = session.control_revision as number;
    const epoch = session.control_epoch as number;
    if (expectedRevision !== undefined) {
      assertExpectedRevision(revision, expectedRevision, "Control");
    }
    if (expectedEpoch !== undefined) {
      assertExpectedRevision(epoch, expectedEpoch, "Control fencing epoch");
    }
    const updated = this.db
      .prepare(
        `UPDATE sessions
         SET control_revision = control_revision + 1, control_epoch = control_epoch + 1
         WHERE id = ? AND control_revision = ? AND control_epoch = ?`
      )
      .run(sessionId, revision, epoch);
    if (updated.changes !== 1) {
      throw new TeamSessionError("stale-revision", "Control state changed concurrently");
    }
  }

  private controlProjection(sessionId: string): {
    controlRevision: number;
    controlEpoch: number;
  } {
    const session = this.requireSession(sessionId);
    return {
      controlRevision: session.control_revision as number,
      controlEpoch: session.control_epoch as number,
    };
  }

  private setMembership(teamId: string, userId: string, role: TeamRole, now: number): void {
    this.db
      .prepare(
        `INSERT INTO team_memberships
           (team_id, user_id, role, status, version, created_at_ms, revoked_at_ms)
         VALUES (?, ?, ?, 'active', 1, ?, NULL)
         ON CONFLICT(team_id, user_id) DO UPDATE SET
           role = excluded.role,
           status = 'active',
           version = team_memberships.version + 1,
           revoked_at_ms = NULL`
      )
      .run(teamId, userId, role, now);
  }

  private upsertMembership(teamId: string, userId: string, role: TeamRole, now: number): TeamRole {
    const existing = this.db
      .prepare("SELECT role, status FROM team_memberships WHERE team_id = ? AND user_id = ?")
      .get(teamId, userId) as SqlRow | undefined;
    const effectiveRole =
      existing?.status === "active" && ROLE_RANK[existing.role as TeamRole] > ROLE_RANK[role]
        ? (existing.role as TeamRole)
        : role;
    if (existing?.status === "active" && existing.role === effectiveRole) return effectiveRole;
    this.setMembership(teamId, userId, effectiveRole, now);
    return effectiveRole;
  }

  private upsertProjectAccess(
    projectId: string,
    userId: string,
    role: ProjectRole,
    now: number,
    preserveMaintainer = false
  ): ProjectRole {
    const existing = this.db
      .prepare("SELECT role, status FROM project_access WHERE project_id = ? AND user_id = ?")
      .get(projectId, userId) as SqlRow | undefined;
    const effectiveRole =
      preserveMaintainer && existing?.status === "active" && existing.role === "maintainer"
        ? "maintainer"
        : role;
    if (existing?.status === "active" && existing.role === effectiveRole) return effectiveRole;
    this.db
      .prepare(
        `INSERT INTO project_access
           (project_id, user_id, role, status, version, created_at_ms, revoked_at_ms)
         VALUES (?, ?, ?, 'active', 1, ?, NULL)
         ON CONFLICT(project_id, user_id) DO UPDATE SET
           role = excluded.role,
           status = 'active',
           version = project_access.version + 1,
           revoked_at_ms = NULL`
      )
      .run(projectId, userId, effectiveRole, now);
    return effectiveRole;
  }

  private upsertShare(sessionId: string, userId: string, now: number): void {
    if (this.share(sessionId, userId)?.status === "active") return;
    this.db
      .prepare(
        `INSERT INTO session_shares
           (session_id, user_id, status, version, created_at_ms, revoked_at_ms)
         VALUES (?, ?, 'active', 1, ?, NULL)
         ON CONFLICT(session_id, user_id) DO UPDATE SET
           status = 'active', version = session_shares.version + 1, revoked_at_ms = NULL`
      )
      .run(sessionId, userId, now);
  }

  private upsertParticipant(sessionId: string, userId: string, now: number): string {
    const existing = this.db
      .prepare("SELECT id FROM session_participants WHERE session_id = ? AND user_id = ?")
      .get(sessionId, userId) as SqlRow | undefined;
    const participantId = (existing?.id as string | undefined) ?? this.nextId("participant");
    this.db
      .prepare(
        `INSERT INTO session_participants
           (id, session_id, user_id, status, version, joined_at_ms, revoked_at_ms)
         VALUES (?, ?, ?, 'active', 1, ?, NULL)
         ON CONFLICT(session_id, user_id) DO UPDATE SET
           status = 'active', version = session_participants.version + 1,
           joined_at_ms = excluded.joined_at_ms, revoked_at_ms = NULL`
      )
      .run(participantId, sessionId, userId, now);
    return participantId;
  }

  private upsertResponsibility(
    sessionId: string,
    userId: string,
    kind: SessionResponsibility,
    now: number
  ): void {
    this.db
      .prepare(
        `INSERT INTO session_responsibilities
           (session_id, user_id, kind, status, version, granted_at_ms, revoked_at_ms)
         VALUES (?, ?, ?, 'active', 1, ?, NULL)
         ON CONFLICT(session_id, user_id, kind) DO UPDATE SET
           status = 'active', version = session_responsibilities.version + 1,
           granted_at_ms = excluded.granted_at_ms, revoked_at_ms = NULL`
      )
      .run(sessionId, userId, kind, now);
  }

  private responsibility(
    sessionId: string,
    userId: string,
    kind: SessionResponsibility
  ): SqlRow | undefined {
    return this.db
      .prepare(
        `SELECT * FROM session_responsibilities
         WHERE session_id = ? AND user_id = ? AND kind = ?`
      )
      .get(sessionId, userId, kind) as SqlRow | undefined;
  }

  private revokeResponsibilityRow(
    sessionId: string,
    userId: string,
    kind: SessionResponsibility,
    now: number
  ): void {
    this.db
      .prepare(
        `UPDATE session_responsibilities
         SET status = 'revoked', version = version + 1, revoked_at_ms = ?
         WHERE session_id = ? AND user_id = ? AND kind = ? AND status = 'active'`
      )
      .run(now, sessionId, userId, kind);
  }

  private activeParticipantById(sessionId: string, participantId: string): SqlRow | undefined {
    return this.db
      .prepare(
        `SELECT * FROM session_participants
         WHERE session_id = ? AND id = ? AND status = 'active'`
      )
      .get(sessionId, participantId) as SqlRow | undefined;
  }

  private handoff(sessionId: string, handoffId: string): SqlRow | undefined {
    return this.db
      .prepare("SELECT * FROM session_handoffs WHERE session_id = ? AND id = ?")
      .get(sessionId, handoffId) as SqlRow | undefined;
  }

  private cancelOfferedHandoffs(
    sessionId: string,
    now: number,
    resolvedByUserId: string,
    reason: string,
    exceptHandoffId?: string,
    relatedUserId?: string
  ): SqlRow[] {
    const cancelled = this.db
      .prepare(
        `UPDATE session_handoffs
         SET status = CASE WHEN expires_at_ms <= ? THEN 'expired' ELSE 'cancelled' END,
             version = version + 1,
             resolved_at_ms = ?, resolved_by_user_id = ?,
             cancellation_reason = CASE WHEN expires_at_ms <= ? THEN 'expired' ELSE ? END
         WHERE session_id = ? AND status = 'offered'
           AND (? IS NULL OR id <> ?)
           AND (? IS NULL OR offerer_user_id = ? OR recipient_user_id = ?)
         RETURNING id, version, status, cancellation_reason, resolved_by_user_id`
      )
      .all(
        now,
        now,
        resolvedByUserId,
        now,
        reason,
        sessionId,
        exceptHandoffId ?? null,
        exceptHandoffId ?? null,
        relatedUserId ?? null,
        relatedUserId ?? null,
        relatedUserId ?? null
      ) as SqlRow[];
    return cancelled.sort((left, right) => String(left.id).localeCompare(String(right.id)));
  }

  private cancelHandoffsOfferedBy(
    sessionId: string,
    offererUserId: string,
    now: number,
    resolvedByUserId: string,
    reason: string
  ): SqlRow[] {
    const cancelled = this.db
      .prepare(
        `UPDATE session_handoffs
         SET status = CASE WHEN expires_at_ms <= ? THEN 'expired' ELSE 'cancelled' END,
             version = version + 1,
             resolved_at_ms = ?, resolved_by_user_id = ?,
             cancellation_reason = CASE WHEN expires_at_ms <= ? THEN 'expired' ELSE ? END
         WHERE session_id = ? AND offerer_user_id = ? AND status = 'offered'
         RETURNING id, version, status, cancellation_reason, resolved_by_user_id`
      )
      .all(now, now, resolvedByUserId, now, reason, sessionId, offererUserId) as SqlRow[];
    return cancelled.sort((left, right) => String(left.id).localeCompare(String(right.id)));
  }

  private appendHandoffCancellationEvents(
    sessionId: string,
    command: SessionCommand,
    now: number,
    cancelled: SqlRow[]
  ): SessionEvent[] {
    return cancelled.map((handoff) =>
      this.appendEvent(
        sessionId,
        command,
        now,
        handoff.status === "expired" ? "session.handoff.expired" : "session.handoff.cancelled",
        {
          handoffId: handoff.id,
          handoffVersion: handoff.version,
          reason: handoff.cancellation_reason,
          resolvedByUserId: handoff.resolved_by_user_id,
        }
      )
    );
  }

  private appendQueuedDirectiveCancellationEvents(
    sessionId: string,
    command: SessionCommand,
    now: number,
    originalAuthorUserId: string,
    reason: string
  ): SessionEvent[] {
    const queuedRows = this.db
      .prepare(
        `SELECT directive_id, queue_sequence FROM conversation_directives
         WHERE session_id = ? AND author_user_id = ? AND status = 'queued'
         ORDER BY queue_sequence ASC
         LIMIT ?`
      )
      .all(sessionId, originalAuthorUserId, MAX_PENDING_DIRECTIVES_PER_AUTHOR + 1) as SqlRow[];
    if (queuedRows.length > MAX_PENDING_DIRECTIVES_PER_AUTHOR) {
      throw new TeamSessionError("conflict", "Pending Directive author ceiling is violated");
    }
    return queuedRows.map((row) => {
      const directiveId = row.directive_id as string;
      const queueSequence = row.queue_sequence as number;
      const event = this.appendEvent(sessionId, command, now, "directive.cancelled", {
        directiveId,
        status: "cancelled",
        queueSequence,
        originalAuthorUserId,
        reason,
      });
      const updated = this.db
        .prepare(
          `UPDATE conversation_directives
           SET status = 'cancelled', terminal_sequence = ?
           WHERE directive_id = ? AND session_id = ? AND status = 'queued'`
        )
        .run(event.sequence, directiveId, sessionId);
      if (updated.changes !== 1) {
        throw new TeamSessionError("conflict", "Queued Directive state changed concurrently");
      }
      return event;
    });
  }

  private sessionRow(sessionId: string): SqlRow | undefined {
    return this.db.prepare("SELECT * FROM sessions WHERE id = ?").get(sessionId) as
      | SqlRow
      | undefined;
  }

  private requireSession(sessionId: string): SqlRow {
    const session = this.sessionRow(sessionId);
    if (!session) deny();
    return session;
  }

  private requireProject(projectId: string): SqlRow {
    const project = this.db.prepare("SELECT * FROM projects WHERE id = ?").get(projectId) as
      | SqlRow
      | undefined;
    if (!project) deny();
    return project;
  }

  private sessionControlEpoch(sessionId: string): number {
    return this.requireSession(sessionId).control_epoch as number;
  }

  private nextId(label: string): string {
    const value = requiredText(this.idGenerator(), `${label} id`, 300);
    return value;
  }

  private reserveConversationIdentity(
    sessionId: string,
    kind: ConversationIdentityKind,
    now: number
  ): string {
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const candidate = this.nextId(kind);
      const inserted = this.db
        .prepare(
          `INSERT INTO conversation_identities
             (id, session_id, kind, created_sequence, created_at_ms)
           VALUES (?, ?, ?, NULL, ?)
           ON CONFLICT(id) DO NOTHING`
        )
        .run(candidate, sessionId, kind, now);
      if (inserted.changes === 1) return candidate;
    }
    throw new TeamSessionError(
      "conflict",
      `Could not allocate a unique ${kind} id for Session ${sessionId}`
    );
  }

  private bindConversationIdentity(
    id: string,
    sessionId: string,
    kind: ConversationIdentityKind,
    createdSequence: number
  ): void {
    const updated = this.db
      .prepare(
        `UPDATE conversation_identities SET created_sequence = ?
         WHERE id = ? AND session_id = ? AND kind = ? AND created_sequence IS NULL`
      )
      .run(createdSequence, id, sessionId, kind);
    if (updated.changes !== 1) {
      throw new TeamSessionError("conflict", "Conversation identity reservation is invalid");
    }
  }

  private assertOpen(): void {
    if (this.closed) throw new Error("Team Session module is closed");
  }
}

function result(
  command: SessionCommand,
  data: Record<string, unknown>,
  events: SessionEvent[] = []
): CommandResult {
  return {
    accepted: true,
    // Replaced by dispatch after the command's global order is allocated in
    // the same transaction. Keeping construction local makes handlers simple.
    acceptedSequence: 0,
    commandType: command.type,
    replayed: false,
    data,
    events: [...events].sort(
      (left, right) =>
        left.sessionId.localeCompare(right.sessionId) || left.sequence - right.sequence
    ),
  };
}

function sanitizeResultForPersistence(value: CommandResult): CommandResult {
  if (!("invitationToken" in value.data)) return value;
  const { invitationToken: _secret, ...safeData } = value.data;
  return { ...value, data: safeData };
}

function replayIdentifier(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function commandAuditPayload(command: SessionCommand): Record<string, unknown> {
  if (command.type === "session.invitation.redeem") {
    const { actor: _actor, idempotency: _idempotency, token, ...safePayload } = command;
    return { ...safePayload, tokenDigest: sha256(token) };
  }
  const { actor: _actor, idempotency: _idempotency, ...payload } = command;
  return payload;
}

function validateCommandEnvelope(command: SessionCommand): void {
  if (!command || command.schemaVersion !== TEAM_SESSION_SCHEMA_VERSION) {
    throw new TeamSessionError("invalid-command", "Unsupported command schema version");
  }
  validateQueryActor(command.actor);
  const runtimeWorkerCommand =
    command.type === "runtime.outbox.acknowledge" || command.type === "runtime.outbox.fail";
  if (runtimeWorkerCommand ? command.actor.kind !== "system" : command.actor.kind !== "human") {
    deny();
  }
  requiredText(command.idempotency?.scope, "Idempotency scope", 300);
  requiredText(command.idempotency?.key, "Idempotency key", 500);
  if (
    command.occurredAtMs !== undefined &&
    (!Number.isSafeInteger(command.occurredAtMs) || command.occurredAtMs < 0)
  ) {
    throw new TeamSessionError("invalid-command", "Invalid command time");
  }
  validateCommandPayload(command);
}

function validateCommandPayload(command: SessionCommand): void {
  switch (command.type) {
    case "team.create":
      if (command.teamId !== undefined) requiredIdentifier(command.teamId, "Team id");
      requiredText(command.name, "Team name", 120);
      return;
    case "project.create":
      requiredIdentifier(command.teamId, "Team id");
      if (command.projectId !== undefined) requiredIdentifier(command.projectId, "Project id");
      requiredText(command.name, "Project name", 120);
      optionalText(command.sourceRef, 500);
      return;
    case "team.membership.grant":
      requiredIdentifier(command.teamId, "Team id");
      requiredIdentifier(command.userId, "User id");
      assertEnum(command.role, ["owner", "admin", "member", "guest"], "Team role");
      requiredVersion(command.expectedMembershipVersion, "Team Membership");
      return;
    case "project.access.grant":
      requiredIdentifier(command.projectId, "Project id");
      requiredIdentifier(command.userId, "User id");
      assertEnum(command.role, ["maintainer", "contributor"], "Project role");
      requiredVersion(command.expectedAccessVersion, "Project Access");
      return;
    case "project.access.revoke":
      requiredIdentifier(command.projectId, "Project id");
      requiredIdentifier(command.userId, "User id");
      requiredVersion(command.expectedAccessVersion, "Project Access");
      return;
    case "team.membership.revoke":
      requiredIdentifier(command.teamId, "Team id");
      requiredIdentifier(command.userId, "User id");
      requiredVersion(command.expectedMembershipVersion, "Team Membership");
      return;
    case "session.start":
      requiredIdentifier(command.teamId, "Team id");
      requiredIdentifier(command.projectId, "Project id");
      if (command.sessionId !== undefined) {
        requiredCanonicalSessionId(command.sessionId, "Session id");
      }
      requiredText(command.name, "Session name", 160);
      if (!isValidTmuxSessionName(command.tmuxName)) {
        throw new TeamSessionError("invalid-command", "tmux name is invalid");
      }
      if (command.steeringPolicy !== undefined) {
        assertEnum(command.steeringPolicy, ["single", "shared"], "Steering policy");
      }
      return;
    case "session.invitation.create":
      requiredIdentifier(command.sessionId, "Session id");
      assertEnum(command.membershipRole, ["member", "guest"], "Invitation role");
      if (!Number.isSafeInteger(command.expiresAtMs) || command.expiresAtMs < 0) {
        throw new TeamSessionError("invalid-command", "Invalid invitation expiry");
      }
      requiredRevision(command.expectedAccessRevision, "Session Access");
      return;
    case "session.invitation.revoke":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.invitationId, "Invitation id");
      requiredVersion(command.expectedInvitationVersion, "Invitation");
      return;
    case "session.invitation.redeem":
      requiredText(command.token, "Invitation token", 1_000);
      return;
    case "session.join":
      requiredIdentifier(command.sessionId, "Session id");
      if (command.invitationId !== undefined) {
        requiredIdentifier(command.invitationId, "Invitation id");
      }
      return;
    case "session.share.create":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.userId, "User id");
      requiredRevision(command.expectedAccessRevision, "Session Access");
      return;
    case "session.share.revoke":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.userId, "User id");
      requiredVersion(command.expectedShareVersion, "Session Share");
      return;
    case "session.participant.grant":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.userId, "User id");
      requiredVersion(command.expectedParticipantVersion, "Session Participant");
      requiredRevision(command.expectedAccessRevision, "Session Access");
      return;
    case "session.participant.revoke":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.userId, "User id");
      requiredVersion(command.expectedParticipantVersion, "Session Participant");
      return;
    case "session.responsibility.grant":
    case "session.responsibility.revoke":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.userId, "User id");
      assertEnum(command.responsibility, ["supervisor", "steerer"], "Session responsibility");
      if (command.responsibility === "supervisor") {
        requiredRevision(command.expectedSupervisionRevision, "Supervision");
      } else {
        requiredRevision(command.expectedSteeringRevision, "Steering");
        if (command.type === "session.responsibility.revoke") {
          requiredRevision(command.expectedControlRevision, "Control");
          requiredRevision(command.expectedControlEpoch, "Control fencing epoch");
        }
      }
      if (command.type === "session.responsibility.grant") {
        requiredVersion(command.expectedParticipantVersion, "Session Participant");
      }
      return;
    case "session.control.transfer":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.userId, "User id");
      requiredRevision(command.expectedControlRevision, "Control");
      requiredRevision(command.expectedControlEpoch, "Control fencing epoch");
      requiredVersion(command.expectedParticipantVersion, "Session Participant");
      return;
    case "session.control.release":
      requiredIdentifier(command.sessionId, "Session id");
      requiredRevision(command.expectedControlRevision, "Control");
      requiredRevision(command.expectedControlEpoch, "Control fencing epoch");
      return;
    case "session.assignee.claim":
      requiredIdentifier(command.sessionId, "Session id");
      requiredRevision(command.expectedAssigneeRevision, "Assignee");
      requiredRevision(command.expectedAccessRevision, "Session Access");
      return;
    case "session.handoff.offer":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.recipientParticipantId, "Recipient Participant id");
      requiredRevision(command.expectedAssigneeRevision, "Assignee");
      requiredVersion(command.expectedRecipientParticipantVersion, "Recipient Participant");
      requiredVersion(command.expectedOffererResponsibilityVersion, "Handoff authority");
      if (
        command.expiresAtMs !== undefined &&
        (!Number.isSafeInteger(command.expiresAtMs) || command.expiresAtMs < 0)
      ) {
        throw new TeamSessionError("invalid-command", "Invalid Handoff expiry");
      }
      normalizeHandoffBriefing(command.briefing, 1);
      return;
    case "session.handoff.accept":
    case "session.handoff.cancel":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.handoffId, "Handoff id");
      requiredVersion(command.expectedHandoffVersion, "Handoff");
      return;
    case "comment.add":
      requiredIdentifier(command.sessionId, "Session id");
      requiredConversationBody(command.body, "Comment body");
      rejectClientOwnedField(command, "commentId", "Comment id");
      return;
    case "suggestion.add":
      requiredIdentifier(command.sessionId, "Session id");
      requiredConversationBody(command.body, "Suggestion body");
      rejectClientOwnedField(command, "suggestionId", "Suggestion id");
      return;
    case "suggestion.resolve":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.suggestionId, "Suggestion id");
      assertEnum(
        command.resolution,
        ["accept", "accept-edited", "reject"],
        "Suggestion resolution"
      );
      requiredRevision(command.expectedSuggestionVersion, "Suggestion");
      requiredRevision(command.expectedSteeringRevision, "Steering");
      rejectClientOwnedField(command, "resolutionId", "Suggestion resolution id");
      rejectClientOwnedField(command, "directiveId", "Directive id");
      if (command.resolution === "accept-edited") {
        requiredConversationBody(command.editedBody, "Edited Directive body");
      } else if (Object.prototype.hasOwnProperty.call(command, "editedBody")) {
        throw new TeamSessionError(
          "invalid-command",
          "Edited Directive body is only valid for accept-edited"
        );
      }
      return;
    case "directive.enqueue":
      requiredIdentifier(command.sessionId, "Session id");
      requiredConversationBody(command.body, "Directive body");
      requiredRevision(command.expectedSteeringRevision, "Steering");
      rejectClientOwnedField(command, "directiveId", "Directive id");
      return;
    case "run.start":
      requiredIdentifier(command.sessionId, "Session id");
      requiredRevision(command.expectedSessionRevision, "Run state");
      validateInitialGoalsOrThrow(command.initialGoals);
      if (command.initialYoloActionGrantId !== undefined) {
        requiredIdentifier(command.initialYoloActionGrantId, "Initial YOLO Action Grant id");
      }
      return;
    case "run.policy.revise":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredRevision(command.expectedRunPolicyRevision, "Run policy");
      return;
    case "run.pause":
    case "run.stop":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredRevision(command.expectedRunStateVersion, "Run state");
      optionalText(command.reason, 1_000);
      return;
    case "run.resume":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredRevision(command.expectedRunStateVersion, "Run state");
      requiredRevision(command.expectedRunPolicyRevision, "Run policy");
      requiredRevision(command.expectedRuntimeAuthorizationGeneration, "Run Runtime Authorization");
      return;
    case "run.emergency-stop":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredIdentifier(command.runtimeBinding?.runtimeAssignmentId, "Runtime Assignment id");
      requiredRevision(command.runtimeBinding?.runtimeAssignmentGeneration, "Runtime Assignment");
      requiredIdentifier(command.runtimeBinding?.sandboxId, "Sandbox id");
      requiredRevision(command.runtimeBinding?.sandboxGeneration, "Sandbox generation");
      if (command.revokeAllRunGrants !== true) {
        throw new TeamSessionError("invalid-command", "Emergency stop must revoke every Run grant");
      }
      requiredConversationBody(command.reason, "Emergency-stop reason");
      return;
    case "goal.add":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredRevision(command.expectedGoalSetRevision, "Goal Set");
      requiredGoalDefinition(command.goal);
      requiredRunDirective(command.directive);
      return;
    case "goal.criteria.strengthen":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredIdentifier(command.goalId, "Goal id");
      requiredRevision(command.expectedGoalSetRevision, "Goal Set");
      if (
        !Array.isArray(command.addedCriteria) ||
        command.addedCriteria.length < 1 ||
        command.addedCriteria.length > 32
      ) {
        throw new TeamSessionError("invalid-command", "Added Goal criteria are invalid");
      }
      command.addedCriteria.forEach((criterion) =>
        requiredText(criterion, "Goal acceptance criterion", 1_000)
      );
      requiredRunDirective(command.directive);
      return;
    case "goal.dependency.add":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredIdentifier(command.goalId, "Goal id");
      requiredIdentifier(command.dependencyGoalId, "Dependency Goal id");
      requiredRevision(command.expectedGoalSetRevision, "Goal Set");
      requiredRunDirective(command.directive);
      return;
    case "goal.reorder":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredIdentifier(command.goalId, "Goal id");
      if (command.beforeGoalId !== undefined) {
        requiredIdentifier(command.beforeGoalId, "Before Goal id");
      }
      requiredRevision(command.expectedGoalSetRevision, "Goal Set");
      requiredRunDirective(command.directive);
      return;
    case "goal.evidence.review":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredIdentifier(command.goalId, "Goal id");
      requiredRevision(command.expectedGoalVersion, "Goal");
      assertEnum(command.disposition, ["validate", "request-more-work"], "Evidence review");
      if (command.directive !== undefined) requiredRunDirective(command.directive);
      return;
    case "run.final-review.resolve":
      requiredIdentifier(command.sessionId, "Session id");
      requiredIdentifier(command.agentRunId, "Agent Run id");
      requiredRevision(command.expectedFinalReviewVersion, "Final review");
      if (command.resolution?.kind === "continue-work") {
        requiredRunDirective(command.resolution.directive);
      } else if (command.resolution?.kind !== "accept-outcome") {
        throw new TeamSessionError("invalid-command", "Final review resolution is invalid");
      }
      return;
    case "runtime.outbox.acknowledge":
      requiredIdentifier(command.outboxId, "Runtime outbox id");
      requiredIdentifier(command.workerId, "Runtime worker id");
      requiredRevision(command.expectedAttempt, "Runtime outbox attempt");
      return;
    case "runtime.outbox.fail":
      requiredIdentifier(command.outboxId, "Runtime outbox id");
      requiredIdentifier(command.workerId, "Runtime worker id");
      requiredRevision(command.expectedAttempt, "Runtime outbox attempt");
      if (typeof command.retryable !== "boolean") {
        throw new TeamSessionError("invalid-command", "Runtime retry flag is invalid");
      }
      assertEnum(command.errorCode, RUNTIME_OUTBOX_ERROR_CODES, "Runtime error code");
      return;
    default:
      throw new TeamSessionError("invalid-command", "Unsupported command type");
  }
}

function validateQuery(
  query:
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
    | SessionRunStateQuery
): void {
  switch (query.type) {
    case "session.get":
      requiredIdentifier(query.sessionId, "Session id");
      return;
    case "session.list":
      if (query.teamId !== undefined) requiredIdentifier(query.teamId, "Team id");
      return;
    case "workspace.discovery":
      return;
    case "session.inbox":
      if (query.teamId !== undefined) requiredIdentifier(query.teamId, "Team id");
      return;
    case "session.detail":
      requiredIdentifier(query.sessionId, "Session id");
      return;
    case "session.public-run-state":
      requiredIdentifier(query.sessionId, "Session id");
      return;
    case "session.events":
      requiredIdentifier(query.sessionId, "Session id");
      if (
        query.afterSequence !== undefined &&
        (!Number.isSafeInteger(query.afterSequence) || query.afterSequence < 0)
      ) {
        throw new TeamSessionError("invalid-command", "Invalid event sequence");
      }
      if (
        query.limit !== undefined &&
        (!Number.isSafeInteger(query.limit) || query.limit < 1 || query.limit > 1_000)
      ) {
        throw new TeamSessionError("invalid-command", "Invalid event limit");
      }
      return;
    case "session.terminal-authorization":
      requiredIdentifier(query.sessionId, "Session id");
      assertEnum(query.action, ["observe", "input", "resize", "interrupt"], "Terminal action");
      if (
        query.expectedControlEpoch !== undefined &&
        (!Number.isSafeInteger(query.expectedControlEpoch) || query.expectedControlEpoch < 1)
      ) {
        throw new TeamSessionError("invalid-command", "Invalid control epoch");
      }
      if (
        query.expectedRuntimeAuthorizationGeneration !== undefined &&
        (!Number.isSafeInteger(query.expectedRuntimeAuthorizationGeneration) ||
          query.expectedRuntimeAuthorizationGeneration < 1)
      ) {
        throw new TeamSessionError("invalid-command", "Invalid Runtime Authorization Generation");
      }
      return;
    case "session.admission":
      requiredIdentifier(query.sessionId, "Session id");
      return;
    case "team.access":
      requiredIdentifier(query.teamId, "Team id");
      return;
    case "project.access":
      requiredIdentifier(query.projectId, "Project id");
      return;
    case "session.run-state":
      requiredIdentifier(query.sessionId, "Session id");
      return;
    default:
      throw new TeamSessionError("invalid-command", "Unsupported query type");
  }
}

function validateQueryActor(actor: ActorContext): void {
  if (!actor || (actor.kind !== "human" && actor.kind !== "system")) {
    throw new TeamSessionError("invalid-command", "Invalid actor");
  }
  requiredText(actor.userId, "Actor user id", 300);
  requiredText(actor.displayName, "Actor display name", 300);
}

function requiredText(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") {
    throw new TeamSessionError("invalid-command", `${label} is required`);
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength || /[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new TeamSessionError("invalid-command", `${label} is invalid`);
  }
  return trimmed;
}

function requiredConversationBody(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new TeamSessionError("invalid-command", `${label} is required`);
  }
  if (
    value.trim().length === 0 ||
    Buffer.byteLength(value, "utf8") > MAX_CONVERSATION_BODY_BYTES ||
    /[\u0000-\u0008\u000b-\u001f\u007f]/.test(value)
  ) {
    throw new TeamSessionError("invalid-command", `${label} is invalid`);
  }
  return value;
}

function requiredRunDirective(
  value: unknown
): asserts value is { format: "plain-text"; body: string } {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TeamSessionError("invalid-command", "Run Directive is invalid");
  }
  const directive = value as Record<string, unknown>;
  const keys = Object.keys(directive).sort();
  if (keys.length !== 2 || keys[0] !== "body" || keys[1] !== "format") {
    throw new TeamSessionError("invalid-command", "Run Directive contains an unknown field");
  }
  if (directive.format !== "plain-text") {
    throw new TeamSessionError("invalid-command", "Run Directive format is invalid");
  }
  requiredConversationBody(directive.body, "Run Directive body");
}

function requiredGoalDefinition(value: unknown): asserts value is GoalDefinition {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TeamSessionError("invalid-command", "Goal is invalid");
  }
  const goal = value as Record<string, unknown>;
  const expected = ["acceptanceCriteria", "dependencyGoalIds", "goalId", "position", "title"];
  const keys = Object.keys(goal).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TeamSessionError("invalid-command", "Goal contains an unknown or missing field");
  }
  requiredIdentifier(goal.goalId, "Goal id");
  requiredRevision(goal.position, "Goal position");
  requiredText(goal.title, "Goal title", 1_000);
  if (
    !Array.isArray(goal.acceptanceCriteria) ||
    goal.acceptanceCriteria.length < 1 ||
    goal.acceptanceCriteria.length > 32
  ) {
    throw new TeamSessionError("invalid-command", "Goal acceptance criteria are invalid");
  }
  goal.acceptanceCriteria.forEach((criterion) =>
    requiredText(criterion, "Goal acceptance criterion", 1_000)
  );
  if (
    !Array.isArray(goal.dependencyGoalIds) ||
    goal.dependencyGoalIds.length > 99 ||
    goal.dependencyGoalIds.some((dependency) => typeof dependency !== "string")
  ) {
    throw new TeamSessionError("invalid-command", "Goal dependencies are invalid");
  }
  goal.dependencyGoalIds.forEach((dependency) =>
    requiredIdentifier(dependency, "Dependency Goal id")
  );
}

function rejectClientOwnedField(command: SessionCommand, field: string, label: string): void {
  if (Object.prototype.hasOwnProperty.call(command, field)) {
    throw new TeamSessionError("invalid-command", `${label} is server-generated`);
  }
}

function requiredIdentifier(value: unknown, label: string): string {
  const identifier = requiredText(value, label, 300);
  if (identifier !== value) {
    throw new TeamSessionError("invalid-command", `${label} is invalid`);
  }
  return identifier;
}

function requiredCanonicalSessionId(value: unknown, label: string): string {
  const identifier = requiredIdentifier(value, label);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(identifier)) {
    throw new TeamSessionError("invalid-command", `${label} is invalid`);
  }
  return identifier;
}

function assertEnum<T extends string>(value: unknown, allowed: readonly T[], label: string): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new TeamSessionError("invalid-command", `${label} is invalid`);
  }
  return value as T;
}

function assertExpectedRevision(actual: number, expected: number, label: string): void {
  requiredRevision(expected, label);
  if (actual !== expected) {
    throw new TeamSessionError("stale-revision", `${label} changed; refresh and retry`);
  }
}

function assertExpectedVersion(actual: number, expected: number, label: string): void {
  if (!Number.isSafeInteger(expected) || expected < 0) {
    throw new TeamSessionError("invalid-command", `${label} version is invalid`);
  }
  if (actual !== expected) {
    throw new TeamSessionError("stale-revision", `${label} changed; refresh and retry`);
  }
}

function requiredRevision(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new TeamSessionError("invalid-command", `${label} revision is invalid`);
  }
  return value as number;
}

function requiredVersion(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TeamSessionError("invalid-command", `${label} version is invalid`);
  }
  return value as number;
}

function projectRuntimeOutboxDelivery(
  row: SqlRow,
  attempts: number,
  leaseOwner: string,
  leaseExpiresAtMs: number
): RuntimeOutboxDelivery {
  const outboxId = row.id as string;
  const sessionId = row.session_id as string;
  const sessionSequence = row.session_sequence as number;
  const payload = JSON.parse(row.payload_json as string) as Record<string, unknown>;
  if (payload.sessionId !== sessionId) {
    throw new TeamSessionError("conflict", "Runtime outbox Session binding is invalid");
  }
  const runtimeAuthorizationGeneration = runtimeGenerationFromPayload(payload);
  const base = {
    outboxId,
    sessionId,
    sessionSequence,
    attempts,
    leaseOwner,
    leaseExpiresAtMs,
  };
  switch (row.kind as RuntimeOutboxKind) {
    case "runtime.session.ensure": {
      if (payload.runtimeKind !== "local-tmux" || !isValidTmuxSessionName(payload.tmuxName)) {
        throw new TeamSessionError("conflict", "Runtime ensure payload is invalid");
      }
      return {
        ...base,
        kind: "runtime.session.ensure",
        payload: {
          sessionId,
          runtimeKind: "local-tmux",
          tmuxName: payload.tmuxName as string,
          runtimeAuthorizationGeneration,
        },
      };
    }
    case "runtime.authorization.fence":
      if (payload.reason !== "assignee-loss" && payload.reason !== "emergency-stop") {
        throw new TeamSessionError("conflict", "Runtime fence payload is invalid");
      }
      return {
        ...base,
        kind: "runtime.authorization.fence",
        payload: {
          sessionId,
          reason: payload.reason,
          runtimeAuthorizationGeneration,
        },
      };
    case "runtime.session.retire": {
      const emergency = payload.reason === "emergency-stop";
      if (
        (payload.reason !== undefined && !emergency) ||
        (emergency &&
          (typeof payload.agentRunId !== "string" ||
            typeof payload.runtimeAssignmentId !== "string" ||
            !Number.isSafeInteger(payload.runtimeAssignmentGeneration) ||
            typeof payload.sandboxId !== "string" ||
            !Number.isSafeInteger(payload.sandboxGeneration))) ||
        (!emergency &&
          (payload.agentRunId !== undefined ||
            payload.runtimeAssignmentId !== undefined ||
            payload.runtimeAssignmentGeneration !== undefined ||
            payload.sandboxId !== undefined ||
            payload.sandboxGeneration !== undefined))
      ) {
        throw new TeamSessionError("conflict", "Runtime retire payload is invalid");
      }
      if (emergency) {
        return {
          ...base,
          kind: "runtime.session.retire",
          payload: {
            sessionId,
            runtimeAuthorizationGeneration,
            reason: "emergency-stop",
            agentRunId: payload.agentRunId as string,
            runtimeAssignmentId: payload.runtimeAssignmentId as string,
            runtimeAssignmentGeneration: payload.runtimeAssignmentGeneration as number,
            sandboxId: payload.sandboxId as string,
            sandboxGeneration: payload.sandboxGeneration as number,
          },
        };
      }
      return {
        ...base,
        kind: "runtime.session.retire",
        payload: { sessionId, runtimeAuthorizationGeneration },
      };
    }
    default:
      throw new TeamSessionError("conflict", "Runtime outbox kind is invalid");
  }
}

function runtimeGenerationFromPayload(payload: Record<string, unknown>): number {
  const generation = payload.runtimeAuthorizationGeneration;
  if (!Number.isSafeInteger(generation) || (generation as number) < 1) {
    throw new TeamSessionError("conflict", "Runtime outbox payload has no valid generation");
  }
  return generation as number;
}

function normalizeHandoffBriefing(
  briefing:
    | {
        summary: string;
        blockers?: string[];
        artifactRefs?: string[];
      }
    | undefined,
  contextSequence: number
): { summary: string; blockers: string[]; artifactRefs: string[] } {
  if (!briefing) {
    return {
      summary: `Review the Session through canonical event ${contextSequence} before accepting responsibility.`,
      blockers: [],
      artifactRefs: [],
    };
  }
  return {
    summary: requiredText(briefing.summary, "Handoff summary", 1_000),
    blockers: normalizedTextList(briefing.blockers, "Handoff blocker", 20, 500),
    artifactRefs: normalizedTextList(
      briefing.artifactRefs,
      "Handoff artifact reference",
      50,
      1_000
    ),
  };
}

function normalizedTextList(
  value: unknown,
  label: string,
  maximumItems: number,
  maximumLength: number
): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new TeamSessionError("invalid-command", `${label} list is invalid`);
  }
  return value.map((item) => requiredText(item, label, maximumLength));
}

function optionalText(value: unknown, maxLength: number): string | null {
  if (value === undefined || value === null || value === "") return null;
  return requiredText(value, "Optional text", maxLength);
}

function validateInitialGoalsOrThrow(goals: ReadonlyArray<GoalDefinition>): void {
  try {
    validateInitialGoals(goals);
  } catch (error) {
    throw new TeamSessionError(
      "invalid-command",
      error instanceof Error ? error.message : "Initial Goals are invalid"
    );
  }
}

function validateGoalItemsOrThrow(goals: ReadonlyArray<MutableGoalItem>): void {
  validateInitialGoalsOrThrow(
    goals.map((goal) => ({
      goalId: goal.goalId,
      position: goal.position,
      title: goal.title,
      acceptanceCriteria: goal.acceptanceCriteria,
      dependencyGoalIds: goal.dependencyGoalIds,
    }))
  );
}

function cloneGoalItem(goal: GoalItem | MutableGoalItem): MutableGoalItem {
  return {
    goalId: goal.goalId,
    position: goal.position,
    title: goal.title,
    acceptanceCriteria: [...goal.acceptanceCriteria],
    dependencyGoalIds: [...goal.dependencyGoalIds],
    version: goal.version,
    status: goal.status,
  };
}

function renumberGoals(goals: MutableGoalItem[]): void {
  goals.forEach((goal, index) => {
    goal.position = index + 1;
  });
}

function isTerminalRunLifecycle(lifecycle: AgentRunLifecycle): boolean {
  return (
    lifecycle === "completed" ||
    lifecycle === "failed" ||
    lifecycle === "stopped" ||
    lifecycle === "emergency-stopped"
  );
}

function runtimeLifecycleOperationKind(value: string): "start" | "pause" | "resume" | "stop" {
  switch (value) {
    case "run.start":
      return "start";
    case "run.pause":
      return "pause";
    case "run.resume":
      return "resume";
    case "run.stop":
      return "stop";
    default:
      throw new TeamSessionError("conflict", "Runtime lifecycle operation is invalid");
  }
}

function runtimeLifecycleProjectionStatus(
  value: string
): "queued" | "awaiting-runtime" | "compensating" {
  switch (value) {
    case "pending":
      return "queued";
    case "processing":
      return "queued";
    case "awaiting-receipt":
      return "awaiting-runtime";
    case "compensating":
      return "compensating";
    default:
      throw new TeamSessionError("conflict", "Runtime lifecycle dispatch state is invalid");
  }
}

function snapshotTrustedRuntimeAuthorization(
  value: RuntimeAuthorizationSnapshot | undefined,
  expectedGeneration: number
): RuntimeAuthorizationSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Runtime Authorization snapshot is invalid");
  }
  const prototype = Object.getPrototypeOf(value);
  const ownNames = Object.getOwnPropertyNames(value).sort();
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    Object.getOwnPropertySymbols(value).length !== 0 ||
    ownNames.length !== RUNTIME_AUTHORIZATION_SNAPSHOT_FIELDS.length ||
    ownNames.some((field, index) => field !== RUNTIME_AUTHORIZATION_SNAPSHOT_FIELDS[index])
  ) {
    throw new TypeError("Runtime Authorization snapshot is invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    RUNTIME_AUTHORIZATION_SNAPSHOT_FIELDS.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor || !("value" in descriptor) || descriptor.enumerable !== true;
    })
  ) {
    throw new TypeError("Runtime Authorization snapshot is invalid");
  }
  const snapshot = Object.fromEntries(
    RUNTIME_AUTHORIZATION_SNAPSHOT_FIELDS.map((field) => [field, descriptors[field]!.value])
  ) as unknown as RuntimeAuthorizationSnapshot;
  if (
    !Number.isSafeInteger(snapshot.generation) ||
    snapshot.generation < 1 ||
    snapshot.generation !== expectedGeneration ||
    !isSafeRuntimeAuthorizationRef(snapshot.networkPolicyRef) ||
    !isSha256Digest(snapshot.networkPolicyDigest) ||
    !isSafeRuntimeAuthorizationRef(snapshot.credentialPolicyRef) ||
    !isSha256Digest(snapshot.credentialPolicyDigest) ||
    !isSha256Digest(snapshot.effectEnforcerSetDigest)
  ) {
    throw new TypeError("Runtime Authorization snapshot is invalid");
  }
  return Object.freeze({ ...snapshot });
}

function isSafeRuntimeAuthorizationRef(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 300 &&
    value === value.trim() &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function isSha256Digest(value: unknown): value is string {
  return typeof value === "string" && SHA256_DIGEST.test(value);
}

function commandDigest(command: SessionCommand): string {
  const { actor, idempotency: _idempotency, occurredAtMs: _occurredAtMs, ...payload } = command;
  return sha256(
    canonicalJson({
      actor: { kind: actor.kind, userId: actor.userId },
      payload,
    })
  );
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  const pairs = Object.keys(object)
    .filter((key) => object[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`);
  return `{${pairs.join(",")}}`;
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function deny(): never {
  throw new TeamSessionError("not-authorized", "Resource is unavailable");
}

function clamp(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return minimum;
  return Math.min(maximum, Math.max(minimum, Math.floor(value)));
}

function boundedIntegerOption(
  value: number,
  minimum: number,
  maximum: number,
  label: string
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function isConstraintError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message.includes("SQLITE_CONSTRAINT") || error.message.includes("constraint failed"))
  );
}

async function abortableDelay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return;
  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", finish);
      resolve();
    };
    const timer = setTimeout(finish, milliseconds);
    signal?.addEventListener("abort", finish, { once: true });
  });
}
