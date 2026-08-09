import { types as nodeTypes } from "node:util";
import { digestHostedRuntimeAssignmentPlan } from "./runtime/hosted-runtime-adapter";
import type {
  HostedAssignmentLookup,
  HostedAssignmentPlanSource,
  HostedRuntimeAssignmentPlan,
} from "./runtime/hosted-runtime-control-plane";
import { snapshotRuntimeSupervisorPortableData } from "./runtime/runtime-supervisor-snapshot";
import { isValidTmuxSessionName } from "./tmux";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type ActorContext,
  type FollowSessionOptions,
  type RuntimeBinding,
  type SessionEvent,
  type SessionGetQuery,
  type SessionTerminalAuthorizationQuery,
  type SessionView,
  type TerminalAuthorization,
} from "./team-sessions";

export type TerminalMutationAction = "input" | "resize" | "interrupt";
export type HumanActorContext = ActorContext & { kind: "human" };
type AnyFunction = (...args: unknown[]) => unknown;

interface CapturedHostedAssignmentPlanSource {
  readonly receiver: object;
  readonly resolve: AnyFunction;
  readonly isCurrent: AnyFunction;
}

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

export interface LocalTeamSessionTerminalBinding {
  readonly kind: "local-tmux";
  readonly tmuxName: string;
}

/**
 * Provider-neutral identity for a hosted terminal. Provider-native sandbox
 * ids and errors stay behind the hosted transport adapter.
 */
export interface HostedTeamSessionTerminalBinding {
  readonly kind: "hosted";
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly assignmentPlanDigest: string;
  readonly incarnation: string;
  readonly specificationDigest: string;
}

export type TeamSessionTerminalBinding =
  | LocalTeamSessionTerminalBinding
  | HostedTeamSessionTerminalBinding;

export interface TeamSessionTerminalConnection {
  readonly sessionId: string;
  readonly binding: TeamSessionTerminalBinding;
  /** Compatibility projection for the local PTY path only. */
  readonly tmuxName?: string;
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
  /** Private durable source; required before a hosted terminal can attach. */
  hostedAssignmentPlans?: HostedAssignmentPlanSource;
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
  binding: TeamSessionTerminalBinding;
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
  private readonly hostedAssignmentPlans: CapturedHostedAssignmentPlanSource | undefined;

  constructor(options: CreateTeamSessionTerminalGatewayOptions) {
    this.teamSessions = options.teamSessions;
    this.monitorPollIntervalMs = options.monitorPollIntervalMs ?? 100;
    this.isRuntimeWriteAllowed = options.isRuntimeWriteAllowed ?? (() => true);
    this.hostedAssignmentPlans = options.hostedAssignmentPlans
      ? captureHostedAssignmentPlanSource(options.hostedAssignmentPlans)
      : undefined;
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
      this.hostedAssignmentPlans,
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
      view.runtime.yoloEligible !== false ||
      view.runtime.authorizationState !== "enforced" ||
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

    let binding: TeamSessionTerminalBinding;
    if (view.runtime.kind === "local-tmux") {
      if (
        view.runtime.isolation !== "trusted-shared-host" ||
        !isValidTmuxSessionName(view.runtime.tmuxName)
      ) {
        throw unavailable();
      }
      binding = Object.freeze({ kind: "local-tmux", tmuxName: view.runtime.tmuxName });
    } else {
      if (view.runtime.isolation !== "isolated-hosted") throw unavailable();
      binding = this.resolveHostedBinding(
        view,
        view.runtime.authorizationGeneration,
        this.hostedAssignmentPlans
      );
    }

    return Object.freeze({
      sessionId,
      binding,
      controlEpoch: view.controlEpoch,
      runtimeAuthorizationGeneration: view.runtime.authorizationGeneration,
      latestSequence: view.latestSequence,
      participantId: participant.participantId,
      participantVersion: participant.version,
    });
  }

  private resolveHostedBinding(
    view: SessionView,
    runtimeAuthorizationGeneration: number,
    source: CapturedHostedAssignmentPlanSource | undefined
  ): HostedTeamSessionTerminalBinding {
    if (!source) throw unavailable();
    const lookup: HostedAssignmentLookup = Object.freeze({
      kind: "session",
      sessionId: view.sessionId,
      runtimeAuthorizationGeneration,
    });
    if (Reflect.apply(source.isCurrent, source.receiver, [lookup]) !== true) throw unavailable();
    const unsafePlan = Reflect.apply(source.resolve, source.receiver, [lookup]);
    if (unsafePlan === null) throw unavailable();
    const plan = snapshotRuntimeSupervisorPortableData(unsafePlan) as HostedRuntimeAssignmentPlan;
    const assignmentPlanDigest = digestHostedRuntimeAssignmentPlan(plan);
    if (
      plan.binding.sessionId !== view.sessionId ||
      plan.binding.teamId !== view.teamId ||
      plan.binding.projectId !== view.projectId ||
      plan.runtimeAuthorizationGeneration !== runtimeAuthorizationGeneration
    ) {
      throw unavailable();
    }
    return Object.freeze({
      kind: "hosted",
      binding: plan.binding,
      runtimeAuthorizationGeneration,
      assignmentPlanDigest,
      incarnation: plan.incarnation,
      specificationDigest: plan.specificationDigest,
    });
  }
}

class CanonicalTeamSessionTerminalConnection implements TeamSessionTerminalConnection {
  readonly sessionId: string;
  readonly binding: TeamSessionTerminalBinding;
  readonly tmuxName: string | undefined;
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
    private readonly hostedAssignmentPlans: CapturedHostedAssignmentPlanSource | undefined,
    private readonly readAuthorizedSnapshot: (
      sessionId: string,
      actor: HumanActorContext
    ) => Promise<AuthorizedSnapshot>
  ) {
    this.sessionId = snapshot.sessionId;
    this.binding = snapshot.binding;
    this.tmuxName = snapshot.binding.kind === "local-tmux" ? snapshot.binding.tmuxName : undefined;
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
    if (
      !this.isRuntimeWriteAllowed({
        sessionId: this.snapshot.sessionId,
        runtimeAuthorizationGeneration: this.snapshot.runtimeAuthorizationGeneration,
      })
    ) {
      return false;
    }
    if (this.snapshot.binding.kind !== "hosted") return true;
    try {
      const current = this.readHostedBinding();
      return current !== null && sameTerminalBinding(current, this.snapshot.binding);
    } catch {
      return false;
    }
  }

  private readHostedBinding(): HostedTeamSessionTerminalBinding | null {
    // `readAuthorizedSnapshot` is asynchronous because it also reads the
    // kernel. Hosted mutation fencing may not await inside the transaction, so
    // capture just the synchronous durable-plan check here.
    const source = this.hostedAssignmentPlans;
    if (!source || this.snapshot.binding.kind !== "hosted") return null;
    const lookup: HostedAssignmentLookup = Object.freeze({
      kind: "session",
      sessionId: this.snapshot.sessionId,
      runtimeAuthorizationGeneration: this.snapshot.runtimeAuthorizationGeneration,
    });
    if (Reflect.apply(source.isCurrent, source.receiver, [lookup]) !== true) return null;
    const unsafePlan = Reflect.apply(source.resolve, source.receiver, [lookup]);
    if (unsafePlan === null) return null;
    const plan = snapshotRuntimeSupervisorPortableData(unsafePlan) as HostedRuntimeAssignmentPlan;
    const assignmentPlanDigest = digestHostedRuntimeAssignmentPlan(plan);
    return Object.freeze({
      kind: "hosted",
      binding: plan.binding,
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      assignmentPlanDigest,
      incarnation: plan.incarnation,
      specificationDigest: plan.specificationDigest,
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
      sameTerminalBinding(current.binding, this.snapshot.binding) &&
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

function sameTerminalBinding(
  left: TeamSessionTerminalBinding,
  right: TeamSessionTerminalBinding
): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === "local-tmux") {
    return right.kind === "local-tmux" && left.tmuxName === right.tmuxName;
  }
  return (
    right.kind === "hosted" &&
    left.runtimeAuthorizationGeneration === right.runtimeAuthorizationGeneration &&
    left.assignmentPlanDigest === right.assignmentPlanDigest &&
    left.incarnation === right.incarnation &&
    left.specificationDigest === right.specificationDigest &&
    sameRuntimeBinding(left.binding, right.binding)
  );
}

function sameRuntimeBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
  return (
    left.teamId === right.teamId &&
    left.projectId === right.projectId &&
    left.sessionId === right.sessionId &&
    left.runtimeAssignmentId === right.runtimeAssignmentId &&
    left.runtimeAssignmentGeneration === right.runtimeAssignmentGeneration &&
    left.sandboxId === right.sandboxId &&
    left.sandboxGeneration === right.sandboxGeneration &&
    left.runtimePrincipalId === right.runtimePrincipalId
  );
}

function captureHostedAssignmentPlanSource(
  value: HostedAssignmentPlanSource
): CapturedHostedAssignmentPlanSource {
  const receiver = safeObject(value);
  return Object.freeze({
    receiver,
    resolve: captureDataMethod(receiver, "resolve"),
    isCurrent: captureDataMethod(receiver, "isCurrent"),
  });
}

function captureDataMethod(receiver: object, name: string): AnyFunction {
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) throw new TypeError();
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError();
      }
      return descriptor.value as AnyFunction;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw new TypeError();
}

function safeObject(value: unknown): object {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) {
    throw new TypeError();
  }
  if (nodeTypes.isProxy(value)) throw new TypeError();
  return value;
}

function unavailable(): TeamSessionTerminalGatewayError {
  return new TeamSessionTerminalGatewayError();
}
