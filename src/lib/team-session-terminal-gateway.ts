import { isValidTmuxSessionName } from "./tmux";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type ActorContext,
  type FollowSessionOptions,
  type SessionEvent,
  type SessionGetQuery,
  type SessionTerminalAuthorizationQuery,
  type SessionView,
  type TerminalAuthorization,
} from "./team-sessions";

export type TerminalMutationAction = "input" | "resize" | "interrupt";
export type HumanActorContext = ActorContext & { kind: "human" };

/**
 * The narrow part of the Team Session kernel used at the terminal gateway
 * seam. Production supplies TeamSessions; tests can supply an in-memory
 * adapter without starting tmux or a PTY.
 */
export interface TeamSessionTerminalKernel {
  inspect(query: SessionGetQuery): Promise<SessionView | null>;
  inspect(query: SessionTerminalAuthorizationQuery): Promise<TerminalAuthorization>;
  performTerminalMutation(query: SessionTerminalAuthorizationQuery, mutation: () => void): void;
  follow(options: FollowSessionOptions): AsyncIterable<SessionEvent>;
}

export interface OpenTeamSessionTerminalOptions {
  /** Canonical Team Session id, never a tmux session name. */
  sessionId: string;
  actor: HumanActorContext;
}

export interface MonitorTeamSessionTerminalOptions {
  signal?: AbortSignal;
}

/** Safe to send to a client; it deliberately carries no private state. */
export interface TerminalConnectionInvalidation {
  kind: "terminal-authorization-changed";
  publicReason: "Terminal authorization changed";
}

export interface TeamSessionTerminalConnection {
  readonly sessionId: string;
  readonly tmuxName: string;
  readonly controlEpoch: number;
  readonly runtimeAuthorizationGeneration: number;

  /** A projection only; it never permits a later terminal mutation. */
  canPerform(action: TerminalMutationAction): Promise<boolean>;

  /**
   * Runs exactly one synchronous effect while the kernel's final
   * authorization transaction is held. No reusable permit is returned.
   */
  perform(action: TerminalMutationAction, mutation: () => void): void;

  /**
   * Resolves when this connection must be closed. An intentional abort
   * resolves to null; dependency errors and unexpected stream completion
   * fail closed with a client-safe invalidation.
   */
  monitor(
    options?: MonitorTeamSessionTerminalOptions
  ): Promise<TerminalConnectionInvalidation | null>;
}

export interface TeamSessionTerminalGateway {
  open(options: OpenTeamSessionTerminalOptions): Promise<TeamSessionTerminalConnection>;
}

export interface CreateTeamSessionTerminalGatewayOptions {
  teamSessions: TeamSessionTerminalKernel;
  monitorPollIntervalMs?: number;
  isRuntimeWriteAllowed?: (input: {
    sessionId: string;
    runtimeAuthorizationGeneration: number;
  }) => boolean;
}

/**
 * A deliberately opaque failure. Callers must not distinguish a missing
 * Session from revoked access, stale control, or quarantined Runtime state.
 */
export class TeamSessionTerminalGatewayError extends Error {
  readonly code = "terminal-unavailable" as const;

  constructor() {
    super("Terminal session unavailable");
    this.name = "TeamSessionTerminalGatewayError";
  }
}

interface AuthorizedSnapshot {
  sessionId: string;
  tmuxName: string;
  controlEpoch: number;
  runtimeAuthorizationGeneration: number;
  latestSequence: number;
  participantId: string;
  participantVersion: number;
}

const INVALIDATION: TerminalConnectionInvalidation = Object.freeze({
  kind: "terminal-authorization-changed",
  publicReason: "Terminal authorization changed",
});

class CanonicalTeamSessionTerminalGateway implements TeamSessionTerminalGateway {
  private readonly teamSessions: TeamSessionTerminalKernel;
  private readonly monitorPollIntervalMs: number;
  private readonly isRuntimeWriteAllowed: NonNullable<
    CreateTeamSessionTerminalGatewayOptions["isRuntimeWriteAllowed"]
  >;

  constructor(options: CreateTeamSessionTerminalGatewayOptions) {
    this.teamSessions = options.teamSessions;
    this.monitorPollIntervalMs = options.monitorPollIntervalMs ?? 100;
    this.isRuntimeWriteAllowed = options.isRuntimeWriteAllowed ?? (() => true);
  }

  async open(options: OpenTeamSessionTerminalOptions): Promise<TeamSessionTerminalConnection> {
    if (!isCanonicalSessionId(options.sessionId) || options.actor.kind !== "human") {
      throw unavailable();
    }

    const actor = freezeActor(options.actor);
    let snapshot: AuthorizedSnapshot;
    try {
      snapshot = await this.readAuthorizedSnapshot(options.sessionId, actor);
    } catch {
      throw unavailable();
    }

    return new CanonicalTeamSessionTerminalConnection(
      this.teamSessions,
      actor,
      snapshot,
      this.monitorPollIntervalMs,
      this.isRuntimeWriteAllowed,
      (sessionId, currentActor) => this.readAuthorizedSnapshot(sessionId, currentActor)
    );
  }

  private async readAuthorizedSnapshot(
    sessionId: string,
    actor: HumanActorContext
  ): Promise<AuthorizedSnapshot> {
    const authorization = await this.teamSessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.terminal-authorization",
      sessionId,
      action: "observe",
      actor,
    });
    // Read the Session projection last. This makes current access and Runtime
    // enforcement the final admission check and narrows the attach race after
    // the observe decision as far as the kernel's read interface permits.
    const view = await this.teamSessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.get",
      sessionId,
      actor,
    });
    if (!view) throw unavailable();

    const participant = view.participants.find(
      (candidate) => candidate.userId === actor.userId && candidate.active
    );

    if (
      !authorization.allowed ||
      authorization.action !== "observe" ||
      authorization.sessionId !== sessionId ||
      view.sessionId !== sessionId ||
      view.status !== "active" ||
      view.runtime.kind !== "local-tmux" ||
      view.runtime.isolation !== "trusted-shared-host" ||
      view.runtime.yoloEligible !== false ||
      view.runtime.authorizationState !== "enforced" ||
      !isValidTmuxSessionName(view.runtime.tmuxName) ||
      !isSafeCounter(view.controlEpoch) ||
      !isSafeCounter(view.runtime.authorizationGeneration) ||
      !isSafeCounter(view.latestSequence) ||
      authorization.controlEpoch !== view.controlEpoch ||
      authorization.runtimeAuthorizationGeneration !== view.runtime.authorizationGeneration ||
      !participant ||
      authorization.participantId !== participant.participantId ||
      !isSafeCounter(participant.version)
    ) {
      throw unavailable();
    }

    return Object.freeze({
      sessionId,
      tmuxName: view.runtime.tmuxName,
      controlEpoch: view.controlEpoch,
      runtimeAuthorizationGeneration: view.runtime.authorizationGeneration,
      latestSequence: view.latestSequence,
      participantId: participant.participantId,
      participantVersion: participant.version,
    });
  }
}

class CanonicalTeamSessionTerminalConnection implements TeamSessionTerminalConnection {
  readonly sessionId: string;
  readonly tmuxName: string;
  readonly controlEpoch: number;
  readonly runtimeAuthorizationGeneration: number;

  constructor(
    private readonly teamSessions: TeamSessionTerminalKernel,
    private readonly actor: HumanActorContext,
    private readonly snapshot: AuthorizedSnapshot,
    private readonly monitorPollIntervalMs: number,
    private readonly isRuntimeWriteAllowed: NonNullable<
      CreateTeamSessionTerminalGatewayOptions["isRuntimeWriteAllowed"]
    >,
    private readonly readAuthorizedSnapshot: (
      sessionId: string,
      actor: HumanActorContext
    ) => Promise<AuthorizedSnapshot>
  ) {
    this.sessionId = snapshot.sessionId;
    this.tmuxName = snapshot.tmuxName;
    this.controlEpoch = snapshot.controlEpoch;
    this.runtimeAuthorizationGeneration = snapshot.runtimeAuthorizationGeneration;
  }

  async canPerform(action: TerminalMutationAction): Promise<boolean> {
    if (!isTerminalMutationAction(action)) return false;
    try {
      const authorization = await this.teamSessions.inspect(this.mutationQuery(action));
      return this.matchesAuthorization(authorization, action) && this.runtimeAllowsWrite();
    } catch {
      return false;
    }
  }

  perform(action: TerminalMutationAction, mutation: () => void): void {
    if (!isTerminalMutationAction(action) || typeof mutation !== "function") throw unavailable();
    try {
      this.teamSessions.performTerminalMutation(this.mutationQuery(action), () => {
        if (!this.runtimeAllowsWrite()) throw unavailable();
        const result = mutation();
        if (result !== undefined) throw unavailable();
      });
    } catch {
      throw unavailable();
    }
  }

  private mutationQuery(action: TerminalMutationAction): SessionTerminalAuthorizationQuery {
    return {
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.terminal-authorization",
      sessionId: this.snapshot.sessionId,
      action,
      expectedControlEpoch: this.snapshot.controlEpoch,
      expectedRuntimeAuthorizationGeneration: this.snapshot.runtimeAuthorizationGeneration,
      actor: this.actor,
    };
  }

  private matchesAuthorization(
    authorization: TerminalAuthorization,
    action: TerminalMutationAction
  ): boolean {
    return (
      authorization.allowed &&
      authorization.action === action &&
      authorization.sessionId === this.snapshot.sessionId &&
      authorization.controlEpoch === this.snapshot.controlEpoch &&
      authorization.runtimeAuthorizationGeneration ===
        this.snapshot.runtimeAuthorizationGeneration &&
      authorization.participantId === this.snapshot.participantId
    );
  }

  private runtimeAllowsWrite(): boolean {
    return this.isRuntimeWriteAllowed({
      sessionId: this.snapshot.sessionId,
      runtimeAuthorizationGeneration: this.snapshot.runtimeAuthorizationGeneration,
    });
  }

  async monitor(
    options: MonitorTeamSessionTerminalOptions = {}
  ): Promise<TerminalConnectionInvalidation | null> {
    if (options.signal?.aborted) return null;

    try {
      if (!(await this.isCurrent())) return INVALIDATION;

      for await (const _event of this.teamSessions.follow({
        sessionId: this.snapshot.sessionId,
        afterSequence: this.snapshot.latestSequence,
        actor: this.actor,
        signal: options.signal,
        pollIntervalMs: this.monitorPollIntervalMs,
      })) {
        if (options.signal?.aborted) return null;
        if (!(await this.isCurrent())) return INVALIDATION;
      }

      // The canonical follower only completes without an abort when access is
      // lost or the kernel closes. Both require this connection to close.
      return options.signal?.aborted ? null : INVALIDATION;
    } catch {
      return options.signal?.aborted ? null : INVALIDATION;
    }
  }

  private async isCurrent(): Promise<boolean> {
    const current = await this.readAuthorizedSnapshot(this.snapshot.sessionId, this.actor);
    return (
      current.sessionId === this.snapshot.sessionId &&
      current.tmuxName === this.snapshot.tmuxName &&
      current.controlEpoch === this.snapshot.controlEpoch &&
      current.runtimeAuthorizationGeneration === this.snapshot.runtimeAuthorizationGeneration &&
      current.participantId === this.snapshot.participantId &&
      current.participantVersion === this.snapshot.participantVersion
    );
  }
}

export function createTeamSessionTerminalGateway(
  options: CreateTeamSessionTerminalGatewayOptions
): TeamSessionTerminalGateway {
  if (
    !Number.isSafeInteger(options.monitorPollIntervalMs ?? 100) ||
    (options.monitorPollIntervalMs ?? 100) < 10 ||
    (options.monitorPollIntervalMs ?? 100) > 5_000
  ) {
    throw new TypeError("Invalid Team Session terminal monitor poll interval");
  }
  return new CanonicalTeamSessionTerminalGateway(options);
}

function freezeActor(actor: HumanActorContext): HumanActorContext {
  return Object.freeze({
    kind: "human",
    userId: actor.userId,
    displayName: actor.displayName,
  });
}

function isCanonicalSessionId(value: unknown): value is string {
  return (
    typeof value === "string" && value.length > 0 && value.length <= 256 && value.trim() === value
  );
}

function isSafeCounter(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isTerminalMutationAction(value: unknown): value is TerminalMutationAction {
  return value === "input" || value === "resize" || value === "interrupt";
}

function unavailable(): TeamSessionTerminalGatewayError {
  return new TeamSessionTerminalGatewayError();
}
