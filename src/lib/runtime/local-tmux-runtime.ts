import { execFile, type ExecFileException } from "child_process";
import { createHash, randomBytes } from "crypto";
import { isValidTmuxSessionName } from "../tmux";
import type { RuntimeOutboxDelivery, RuntimeOutboxErrorCode } from "../team-sessions";

const SERVER_MARKER_OPTION = "@terminalx_runtime_server";
const MANAGED_OPTION = "@terminalx_managed";
const SESSION_ID_OPTION = "@terminalx_session_id";
const SESSION_INCARNATION_OPTION = "@terminalx_session_incarnation";
const AUTHORIZATION_GENERATION_OPTION = "@terminalx_runtime_authorization_generation";
const SESSION_LIST_FORMAT = `#{session_name}\t#{${MANAGED_OPTION}}\t#{${SESSION_ID_OPTION}}\t#{${AUTHORIZATION_GENERATION_OPTION}}\t#{session_id}\t#{${SESSION_INCARNATION_OPTION}}\t#{${SERVER_MARKER_OPTION}}`;
const SESSION_INCARNATION_PATTERN = /^[0-9a-f]{64}$/;
const NEVER_ABORT_SIGNAL = new AbortController().signal;

export const CANONICAL_TMUX_SOCKET_NAME_ENV = "TERMINALX_TMUX_SOCKET_NAME";
export const DEFAULT_CANONICAL_TMUX_SOCKET_NAME = "terminalx-multiplayer";
export const CANONICAL_TMUX_CONFIG_FILE = "/dev/null";

const SAFE_ENVIRONMENT_KEYS = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "LANG",
  "LANGUAGE",
  "LC_ALL",
  "LC_CTYPE",
  "LC_MESSAGES",
  "LC_COLLATE",
  "LC_NUMERIC",
  "LC_TIME",
  "LC_MONETARY",
  "TZ",
] as const;

export type ExactCommandFailure =
  | "exit"
  | "timeout"
  | "not-found"
  | "permission-denied"
  | "aborted"
  | "spawn-failed";

export type ExactCommandResult =
  | { ok: true; stdout: string; stderr: string }
  | {
      ok: false;
      failure: ExactCommandFailure;
      exitCode?: number;
      stdout: string;
      stderr: string;
    };

export interface ExactCommandRequest {
  file: string;
  args: readonly string[];
  env: Readonly<Record<string, string>>;
  timeoutMs: number;
  signal: AbortSignal;
}

export interface ExactCommandExecutor {
  execute(request: ExactCommandRequest): Promise<ExactCommandResult>;
}

export interface RuntimeWriteStateUpdate {
  sessionId: string;
  runtimeAuthorizationGeneration: number;
  state: "active" | "fenced" | "retired";
}

export interface CanonicalPtyTermination {
  sessionId: string;
  tmuxName: string;
  /** Immutable tmux built-in `#{session_id}`; never resolve destructive work by name alone. */
  tmuxSessionRef: string;
  /** Unguessable identity stored on the exact tmux Session that owns `$id`. */
  tmuxSessionIncarnation: string;
  runtimeAuthorizationGeneration: number;
  reason: "authorization-fence" | "retire";
}

/**
 * The synchronous write-state callback is the immediate enforcement point.
 * Terminal transports must consult the same state before every mutation.
 */
export interface LocalTmuxFenceCallbacks {
  updateWriteState(update: RuntimeWriteStateUpdate, signal: AbortSignal): void;
  terminateCanonicalPtys(input: CanonicalPtyTermination, signal: AbortSignal): Promise<void>;
  /** Checked before and after ensure so a superseded worker cannot resurrect a Session. */
  runtimeEnsureState(
    input: {
      sessionId: string;
      tmuxName: string;
      runtimeAuthorizationGeneration: number;
    },
    signal: AbortSignal
  ): Promise<"pending" | "enforced" | "stale">;
  /** Required before a destructive retire; false fails closed without touching tmux. */
  isCurrentRuntimeBinding(
    input: {
      sessionId: string;
      runtimeAuthorizationGeneration: number;
      emergencyStop?: {
        agentRunId: string;
        runtimeAssignmentId: string;
        runtimeAssignmentGeneration: number;
        sandboxId: string;
        sandboxGeneration: number;
      };
    },
    signal: AbortSignal
  ): Promise<boolean>;
}

export interface CreateLocalTmuxRuntimeOptions {
  executor?: ExactCommandExecutor;
  fenceCallbacks: LocalTmuxFenceCallbacks;
  sourceEnvironment?: Readonly<Record<string, string | undefined>>;
  tmuxBinary?: string;
  commandTimeoutMs?: number;
  /** Test seam for the cryptographically random per-session incarnation. */
  sessionIncarnationSource?: () => string;
}

interface CanonicalSessionMetadata {
  tmuxName: string;
  managed: boolean;
  sessionId: string;
  runtimeAuthorizationGeneration: number;
  tmuxSessionRef: string;
  tmuxSessionIncarnation: string;
}

type CanonicalServerState =
  | { kind: "absent" }
  | { kind: "canonical"; tmuxSessionIncarnation: string };

export class RuntimeEffectError extends Error {
  constructor(
    readonly code: RuntimeOutboxErrorCode,
    readonly retryable: boolean
  ) {
    super(code);
    this.name = "RuntimeEffectError";
  }
}

export function createNodeExactCommandExecutor(): ExactCommandExecutor {
  return {
    execute(request) {
      return new Promise((resolve) => {
        execFile(
          request.file,
          [...request.args],
          {
            encoding: "utf8" as BufferEncoding,
            env: { ...request.env } as NodeJS.ProcessEnv,
            maxBuffer: 1024 * 1024,
            timeout: request.timeoutMs,
            signal: request.signal,
            windowsHide: true,
          },
          (error: ExecFileException | null, stdout: string, stderr: string) => {
            if (!error) {
              resolve({ ok: true, stdout, stderr });
              return;
            }
            const failure = classifyNodeExecutionError(error);
            const code = (error as NodeJS.ErrnoException).code;
            resolve({
              ok: false,
              failure,
              ...(typeof code === "number" ? { exitCode: code } : {}),
              stdout,
              stderr,
            });
          }
        );
      });
    },
  };
}

export function buildCanonicalTmuxEnvironment(
  source: Readonly<Record<string, string | undefined>> = process.env
): Readonly<Record<string, string>> {
  const environment: Record<string, string> = {};
  for (const key of SAFE_ENVIRONMENT_KEYS) {
    const value = source[key];
    if (typeof value === "string" && value.length > 0 && !/[\0\r\n]/.test(value)) {
      environment[key] = value;
    }
  }
  environment.PATH ??= "/usr/local/bin:/usr/bin:/bin";
  environment.TERM = "xterm-256color";
  return Object.freeze(environment);
}

export class LocalTmuxRuntime {
  private readonly executor: ExactCommandExecutor;
  private readonly callbacks: LocalTmuxFenceCallbacks;
  private readonly environment: Readonly<Record<string, string>>;
  private readonly tmuxBinary: string;
  private readonly socketNameSource: Readonly<Record<string, string | undefined>>;
  private readonly commandTimeoutMs: number;
  private readonly sessionIncarnationSource: () => string;
  private readonly writeStates = new Map<string, RuntimeWriteStateUpdate>();

  constructor(options: CreateLocalTmuxRuntimeOptions) {
    if (
      !Number.isSafeInteger(options.commandTimeoutMs ?? 5_000) ||
      (options.commandTimeoutMs ?? 5_000) < 250 ||
      (options.commandTimeoutMs ?? 5_000) > 30_000
    ) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    this.executor = options.executor ?? createNodeExactCommandExecutor();
    this.callbacks = options.fenceCallbacks;
    this.environment = buildCanonicalTmuxEnvironment(options.sourceEnvironment);
    this.tmuxBinary = options.tmuxBinary ?? "tmux";
    this.socketNameSource = options.sourceEnvironment ?? process.env;
    this.commandTimeoutMs = options.commandTimeoutMs ?? 5_000;
    this.sessionIncarnationSource =
      options.sessionIncarnationSource ?? (() => randomBytes(32).toString("hex"));
  }

  async apply(delivery: RuntimeOutboxDelivery, unsafeSignal?: AbortSignal): Promise<void> {
    const signal = unsafeSignal ?? NEVER_ABORT_SIGNAL;
    throwIfRuntimeAborted(signal);
    if (delivery.dispatchMode !== "apply") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    switch (delivery.kind) {
      case "runtime.session.ensure":
        await this.ensure(delivery, signal);
        return;
      case "runtime.authorization.fence":
        await this.fence(delivery, signal);
        return;
      case "runtime.session.retire":
        await this.retire(delivery, signal);
        return;
    }
  }

  /**
   * Resolve an attempt that may already have changed tmux. Reconciliation is
   * deliberately separate from apply: it first observes the exact canonical
   * binding and may finish only that binding's idempotent target state.
   */
  async reconcile(delivery: RuntimeOutboxDelivery, unsafeSignal?: AbortSignal): Promise<void> {
    const signal = unsafeSignal ?? NEVER_ABORT_SIGNAL;
    throwIfRuntimeAborted(signal);
    if (delivery.dispatchMode !== "reconcile") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    switch (delivery.kind) {
      case "runtime.session.ensure":
        await this.reconcileEnsure(delivery, signal);
        return;
      case "runtime.authorization.fence":
        await this.reconcileFence(delivery, signal);
        return;
      case "runtime.session.retire":
        await this.retire(delivery, signal);
        return;
    }
  }

  private async reconcileEnsure(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.session.ensure" }>,
    signal: AbortSignal
  ): Promise<void> {
    if (delivery.payload.runtimeKind !== "local-tmux") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const { sessionId, tmuxName, runtimeAuthorizationGeneration } = delivery.payload;
    validateBinding(sessionId, tmuxName, runtimeAuthorizationGeneration);
    const desiredState = await this.runtimeEnsureState(
      {
        sessionId,
        tmuxName,
        runtimeAuthorizationGeneration,
      },
      signal
    );
    const server = await this.serverState(sessionId, signal);
    if (server.kind === "absent") {
      if (desiredState === "stale") return;
      if (desiredState === "enforced") {
        throw new RuntimeEffectError("runtime_invalid_state", false);
      }
      await this.ensure(delivery, signal);
      return;
    }

    const existing = await this.sessionById(sessionId, signal);
    if (!existing) {
      if (desiredState === "stale") return;
      if (desiredState === "enforced") {
        throw new RuntimeEffectError("runtime_invalid_state", false);
      }
      await this.ensure(delivery, signal);
      return;
    }

    const exactBinding =
      existing.tmuxName === tmuxName &&
      existing.runtimeAuthorizationGeneration === runtimeAuthorizationGeneration;
    if (desiredState === "stale") {
      if (exactBinding) {
        await this.cleanupSupersededEnsure(existing, signal);
        return;
      }
      // Only a strictly newer generation proves this is a replacement. A
      // different name at the same generation is conflicting state and must
      // never be acknowledged as the requested ensure.
      if (existing.runtimeAuthorizationGeneration > runtimeAuthorizationGeneration) return;
      throw new RuntimeEffectError(
        existing.runtimeAuthorizationGeneration === runtimeAuthorizationGeneration
          ? "runtime_conflict"
          : "runtime_invalid_state",
        false
      );
    }
    if (!exactBinding) {
      throw new RuntimeEffectError(
        existing.runtimeAuthorizationGeneration > runtimeAuthorizationGeneration
          ? "runtime_conflict"
          : "runtime_invalid_state",
        false
      );
    }
    const finalState = await this.runtimeEnsureState(
      {
        sessionId,
        tmuxName,
        runtimeAuthorizationGeneration,
      },
      signal
    );
    if (finalState === "stale") {
      await this.cleanupSupersededEnsure(existing, signal);
      return;
    }
    await this.requireExactSessionStillPresent(existing, signal);
    this.updateWriteState(
      {
        sessionId,
        runtimeAuthorizationGeneration,
        state: "active",
      },
      signal
    );
  }

  private async reconcileFence(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.authorization.fence" }>,
    signal: AbortSignal
  ): Promise<void> {
    await this.enforceFence(delivery, signal, true);
  }

  private async enforceFence(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.authorization.fence" }>,
    signal: AbortSignal,
    allowAbsent: boolean
  ): Promise<void> {
    if ("runtimeKind" in delivery.payload) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const { sessionId, runtimeAuthorizationGeneration } = delivery.payload;
    validateGeneration(runtimeAuthorizationGeneration);
    validateCanonicalSessionId(sessionId);
    throwIfRuntimeAborted(signal);
    if (!allowAbsent) {
      // A fresh fence is the synchronous write-denial boundary. Local input
      // must stop before any asynchronous tmux observation or mutation.
      this.updateWriteState(
        {
          sessionId,
          runtimeAuthorizationGeneration,
          state: "fenced",
        },
        signal
      );
    }
    const server = await this.serverState(sessionId, signal);
    if (server.kind === "absent") {
      if (!allowAbsent) throw new RuntimeEffectError("runtime_invalid_state", false);
      this.updateWriteState(
        {
          sessionId,
          runtimeAuthorizationGeneration,
          state: "fenced",
        },
        signal
      );
      return;
    }
    const session = await this.sessionById(sessionId, signal);
    if (!session) {
      if (!allowAbsent) throw new RuntimeEffectError("runtime_invalid_state", false);
      this.updateWriteState(
        {
          sessionId,
          runtimeAuthorizationGeneration,
          state: "fenced",
        },
        signal
      );
      return;
    }
    if (session.runtimeAuthorizationGeneration > runtimeAuthorizationGeneration) {
      return;
    }

    if (allowAbsent) {
      this.updateWriteState(
        {
          sessionId,
          runtimeAuthorizationGeneration,
          state: "fenced",
        },
        signal
      );
    }
    const beforeUpdate = await this.reobserveExactSession(session, signal);
    if (!beforeUpdate) return;
    await this.requireGuardedSuccess(
      sessionId,
      beforeUpdate,
      `set-option -t ${exactTmuxSessionTarget(beforeUpdate.tmuxSessionRef)} ${AUTHORIZATION_GENERATION_OPTION} ${runtimeAuthorizationGeneration}`,
      signal
    );
    const verified = await this.sessionById(sessionId, signal);
    if (!verified) return;
    if (
      verified.tmuxSessionRef !== session.tmuxSessionRef ||
      verified.tmuxSessionIncarnation !== session.tmuxSessionIncarnation ||
      verified.tmuxName !== session.tmuxName ||
      verified.runtimeAuthorizationGeneration !== runtimeAuthorizationGeneration
    ) {
      throw new RuntimeEffectError("runtime_conflict", false);
    }
    const beforeDetach = await this.reobserveExactSession(verified, signal);
    if (!beforeDetach) return;
    await this.detachClients(sessionId, beforeDetach, signal);
    const beforeTermination = await this.reobserveExactSession(verified, signal);
    if (!beforeTermination) return;
    await this.terminateCanonicalPtys(
      {
        sessionId,
        tmuxName: beforeTermination.tmuxName,
        tmuxSessionRef: beforeTermination.tmuxSessionRef,
        tmuxSessionIncarnation: beforeTermination.tmuxSessionIncarnation,
        runtimeAuthorizationGeneration,
        reason: "authorization-fence",
      },
      signal
    );
    await this.observeAfterDestructiveEffect(verified, signal);
  }

  private async ensure(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.session.ensure" }>,
    signal: AbortSignal
  ): Promise<void> {
    if (delivery.payload.runtimeKind !== "local-tmux") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const { sessionId, tmuxName, runtimeAuthorizationGeneration } = delivery.payload;
    validateBinding(sessionId, tmuxName, runtimeAuthorizationGeneration);
    const initialState = await this.runtimeEnsureState(
      {
        sessionId,
        tmuxName,
        runtimeAuthorizationGeneration,
      },
      signal
    );
    if (initialState === "stale") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const server = await this.serverState(sessionId, signal);
    if (server.kind === "canonical") {
      const existing = await this.sessionById(sessionId, signal);
      if (existing) {
        this.assertOwnedBinding(existing, sessionId, tmuxName, runtimeAuthorizationGeneration);
        if (existing.runtimeAuthorizationGeneration === runtimeAuthorizationGeneration) {
          await this.requireEnsureStillCurrentOrCleanup(existing, signal);
          await this.requireExactSessionStillPresent(existing, signal);
          this.updateWriteState(
            {
              sessionId,
              runtimeAuthorizationGeneration,
              state: "active",
            },
            signal
          );
        }
        return;
      }
    }

    if (initialState === "enforced") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }

    const proposedSessionIncarnation = this.nextSessionIncarnation();
    const created = await this.run(
      sessionId,
      this.createSessionArgs(
        sessionId,
        tmuxName,
        runtimeAuthorizationGeneration,
        proposedSessionIncarnation
      ),
      signal
    );
    if (!created.ok) {
      const raced = await this.exactBindingOrNull(
        tmuxName,
        sessionId,
        runtimeAuthorizationGeneration,
        signal
      );
      if (!raced) throw executionFailure(created);
    }
    const serverAfterCreate = await this.requireCanonicalServer(sessionId, signal);
    if (created.ok && serverAfterCreate.tmuxSessionIncarnation !== proposedSessionIncarnation) {
      throw new RuntimeEffectError("runtime_conflict", false);
    }
    const verified = await this.sessionById(sessionId, signal);
    if (!verified) throw new RuntimeEffectError("runtime_invalid_state", false);
    this.assertOwnedBinding(verified, sessionId, tmuxName, runtimeAuthorizationGeneration);
    if (verified.runtimeAuthorizationGeneration === runtimeAuthorizationGeneration) {
      await this.requireEnsureStillCurrentOrCleanup(verified, signal);
      await this.requireExactSessionStillPresent(verified, signal);
      this.updateWriteState(
        {
          sessionId,
          runtimeAuthorizationGeneration,
          state: "active",
        },
        signal
      );
    }
  }

  private async requireEnsureStillCurrentOrCleanup(
    expected: CanonicalSessionMetadata,
    signal: AbortSignal
  ): Promise<void> {
    const { sessionId, tmuxName, runtimeAuthorizationGeneration } = expected;
    const state = await this.runtimeEnsureState(
      {
        sessionId,
        tmuxName,
        runtimeAuthorizationGeneration,
      },
      signal
    );
    if (state === "pending" || state === "enforced") {
      return;
    }

    await this.cleanupSupersededEnsure(expected, signal);
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }

  private async cleanupSupersededEnsure(
    expected: CanonicalSessionMetadata,
    signal: AbortSignal
  ): Promise<void> {
    const { sessionId, tmuxName, runtimeAuthorizationGeneration } = expected;
    if (!(await this.ensureIsStale(sessionId, tmuxName, runtimeAuthorizationGeneration, signal))) {
      return;
    }
    const session = await this.reobserveExactSession(expected, signal);
    if (!session) return;

    this.updateWriteState(
      {
        sessionId,
        runtimeAuthorizationGeneration,
        state: "retired",
      },
      signal
    );
    if (!(await this.ensureIsStale(sessionId, tmuxName, runtimeAuthorizationGeneration, signal))) {
      return;
    }
    const beforeDetach = await this.reobserveExactSession(session, signal);
    if (!beforeDetach) return;
    await this.detachClients(sessionId, beforeDetach, signal);
    if (!(await this.ensureIsStale(sessionId, tmuxName, runtimeAuthorizationGeneration, signal))) {
      return;
    }
    const beforeTermination = await this.reobserveExactSession(session, signal);
    if (!beforeTermination) return;
    await this.terminateCanonicalPtys(
      {
        sessionId,
        tmuxName,
        tmuxSessionRef: beforeTermination.tmuxSessionRef,
        tmuxSessionIncarnation: beforeTermination.tmuxSessionIncarnation,
        runtimeAuthorizationGeneration,
        reason: "retire",
      },
      signal
    );
    if (!(await this.ensureIsStale(sessionId, tmuxName, runtimeAuthorizationGeneration, signal))) {
      return;
    }
    const beforeKill = await this.reobserveExactSession(session, signal);
    if (!beforeKill) return;
    const kill = await this.runGuardedEffect(
      sessionId,
      beforeKill,
      `kill-session -t ${exactTmuxSessionTarget(beforeKill.tmuxSessionRef)}`,
      signal
    );
    if (!kill.ok && !isNoServer(kill)) throw executionFailure(kill);
    await this.observeAfterDestructiveEffect(session, signal, true);
  }

  private async fence(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.authorization.fence" }>,
    signal: AbortSignal
  ): Promise<void> {
    await this.enforceFence(delivery, signal, false);
  }

  private async retire(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.session.retire" }>,
    signal: AbortSignal
  ): Promise<void> {
    if ("runtimeKind" in delivery.payload) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const { sessionId, runtimeAuthorizationGeneration } = delivery.payload;
    validateGeneration(runtimeAuthorizationGeneration);
    validateCanonicalSessionId(sessionId);
    if (delivery.payload.reason !== "emergency-stop") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const binding = {
      sessionId,
      runtimeAuthorizationGeneration,
      emergencyStop: {
        agentRunId: delivery.payload.agentRunId,
        runtimeAssignmentId: delivery.payload.runtimeAssignmentId,
        runtimeAssignmentGeneration: delivery.payload.runtimeAssignmentGeneration,
        sandboxId: delivery.payload.sandboxId,
        sandboxGeneration: delivery.payload.sandboxGeneration,
      },
    };
    if (!(await this.currentRuntimeBinding(binding, signal))) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const state = await this.serverState(sessionId, signal);
    if (state.kind === "absent") {
      this.updateWriteState(
        {
          sessionId,
          runtimeAuthorizationGeneration,
          state: "retired",
        },
        signal
      );
      return;
    }
    const session = await this.sessionById(sessionId, signal);
    if (!session) {
      this.updateWriteState(
        {
          sessionId,
          runtimeAuthorizationGeneration,
          state: "retired",
        },
        signal
      );
      return;
    }
    if (session.runtimeAuthorizationGeneration > runtimeAuthorizationGeneration) {
      throw new RuntimeEffectError("runtime_conflict", false);
    }
    this.updateWriteState(
      {
        sessionId,
        runtimeAuthorizationGeneration,
        state: "retired",
      },
      signal
    );
    if (!(await this.currentRuntimeBinding(binding, signal))) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const beforeDetach = await this.reobserveExactSession(session, signal);
    if (!beforeDetach) throw new RuntimeEffectError("runtime_conflict", false);
    await this.detachClients(sessionId, beforeDetach, signal);
    if (!(await this.currentRuntimeBinding(binding, signal))) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const beforeTermination = await this.reobserveExactSession(session, signal);
    if (!beforeTermination) throw new RuntimeEffectError("runtime_conflict", false);
    await this.terminateCanonicalPtys(
      {
        sessionId,
        tmuxName: beforeTermination.tmuxName,
        tmuxSessionRef: beforeTermination.tmuxSessionRef,
        tmuxSessionIncarnation: beforeTermination.tmuxSessionIncarnation,
        runtimeAuthorizationGeneration,
        reason: "retire",
      },
      signal
    );
    if (!(await this.currentRuntimeBinding(binding, signal))) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const beforeKill = await this.reobserveExactSession(session, signal);
    if (!beforeKill) throw new RuntimeEffectError("runtime_conflict", false);
    await this.requireGuardedSuccess(
      sessionId,
      beforeKill,
      `kill-session -t ${exactTmuxSessionTarget(beforeKill.tmuxSessionRef)}`,
      signal
    );
    await this.observeAfterDestructiveEffect(session, signal, true);
  }

  private async serverState(sessionId: string, signal: AbortSignal): Promise<CanonicalServerState> {
    const marker = await this.run(
      sessionId,
      ["show-options", "-gqv", SERVER_MARKER_OPTION],
      signal
    );
    if (marker.ok) {
      const tmuxSessionIncarnation = parseCanonicalTmuxServerMarker(
        marker.stdout.trim(),
        sessionId
      );
      if (tmuxSessionIncarnation) return { kind: "canonical", tmuxSessionIncarnation };
      throw new RuntimeEffectError("runtime_conflict", false);
    }
    if (isNoServer(marker)) return { kind: "absent" };
    throw executionFailure(marker);
  }

  private async requireCanonicalServer(
    sessionId: string,
    signal: AbortSignal
  ): Promise<Extract<CanonicalServerState, { kind: "canonical" }>> {
    const state = await this.serverState(sessionId, signal);
    if (state.kind !== "canonical") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    return state;
  }

  private async sessionById(
    sessionId: string,
    signal: AbortSignal
  ): Promise<CanonicalSessionMetadata | null> {
    const result = await this.run(sessionId, ["list-sessions", "-F", SESSION_LIST_FORMAT], signal);
    if (!result.ok) {
      if (isNoServer(result)) return null;
      throw executionFailure(result);
    }
    const sessions = result.stdout.split("\n").filter(Boolean).map(parseSessionListLine);
    if (sessions.length === 0) return null;
    if (sessions.length !== 1) throw new RuntimeEffectError("runtime_conflict", false);
    const [session] = sessions;
    if (!session?.managed || session.sessionId !== sessionId) {
      throw new RuntimeEffectError("runtime_conflict", false);
    }
    return session;
  }

  private async exactBindingOrNull(
    tmuxName: string,
    sessionId: string,
    generation: number,
    signal: AbortSignal
  ): Promise<CanonicalSessionMetadata | null> {
    const server = await this.serverState(sessionId, signal);
    if (server.kind !== "canonical") return null;
    const metadata = await this.sessionById(sessionId, signal);
    if (!metadata) return null;
    this.assertOwnedBinding(metadata, sessionId, tmuxName, generation);
    return metadata;
  }

  private assertOwnedBinding(
    metadata: CanonicalSessionMetadata,
    sessionId: string,
    tmuxName: string,
    requestedGeneration: number
  ): void {
    if (!metadata.managed || metadata.sessionId !== sessionId || metadata.tmuxName !== tmuxName) {
      throw new RuntimeEffectError("runtime_conflict", false);
    }
    if (metadata.runtimeAuthorizationGeneration < requestedGeneration) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
  }

  private async runtimeEnsureState(
    input: {
      sessionId: string;
      tmuxName: string;
      runtimeAuthorizationGeneration: number;
    },
    signal: AbortSignal
  ): Promise<"pending" | "enforced" | "stale"> {
    throwIfRuntimeAborted(signal);
    const state = await this.callbacks.runtimeEnsureState(input, signal);
    throwIfRuntimeAborted(signal);
    return state;
  }

  private async ensureIsStale(
    sessionId: string,
    tmuxName: string,
    runtimeAuthorizationGeneration: number,
    signal: AbortSignal
  ): Promise<boolean> {
    return (
      (await this.runtimeEnsureState(
        { sessionId, tmuxName, runtimeAuthorizationGeneration },
        signal
      )) === "stale"
    );
  }

  private async currentRuntimeBinding(
    input: Parameters<LocalTmuxFenceCallbacks["isCurrentRuntimeBinding"]>[0],
    signal: AbortSignal
  ): Promise<boolean> {
    throwIfRuntimeAborted(signal);
    const current = await this.callbacks.isCurrentRuntimeBinding(input, signal);
    throwIfRuntimeAborted(signal);
    return current;
  }

  private async terminateCanonicalPtys(
    input: CanonicalPtyTermination,
    signal: AbortSignal
  ): Promise<void> {
    throwIfRuntimeAborted(signal);
    await this.callbacks.terminateCanonicalPtys(input, signal);
    throwIfRuntimeAborted(signal);
  }

  private async reobserveExactSession(
    expected: CanonicalSessionMetadata,
    signal: AbortSignal
  ): Promise<CanonicalSessionMetadata | null> {
    const observed = await this.sessionById(expected.sessionId, signal);
    if (!observed) return null;
    if (
      observed.tmuxSessionRef === expected.tmuxSessionRef &&
      observed.tmuxSessionIncarnation === expected.tmuxSessionIncarnation &&
      observed.tmuxName === expected.tmuxName &&
      observed.sessionId === expected.sessionId &&
      observed.runtimeAuthorizationGeneration === expected.runtimeAuthorizationGeneration
    ) {
      return observed;
    }
    // Once an effect has observed its exact target, every live replacement is
    // conflicting state. Initial reconciliation may recognize a newer durable
    // generation before selecting a target, but a mid-effect replacement must
    // never be collapsed into successful absence.
    throw new RuntimeEffectError("runtime_conflict", false);
  }

  private async requireExactSessionStillPresent(
    expected: CanonicalSessionMetadata,
    signal: AbortSignal
  ): Promise<CanonicalSessionMetadata> {
    const observed = await this.reobserveExactSession(expected, signal);
    if (!observed) throw new RuntimeEffectError("runtime_conflict", false);
    return observed;
  }

  private async observeAfterDestructiveEffect(
    expected: CanonicalSessionMetadata,
    signal: AbortSignal,
    expectRemoved = false
  ): Promise<void> {
    const observed = await this.sessionById(expected.sessionId, signal);
    if (!observed) return;
    if (
      observed.tmuxSessionRef !== expected.tmuxSessionRef ||
      observed.tmuxSessionIncarnation !== expected.tmuxSessionIncarnation ||
      observed.tmuxName !== expected.tmuxName ||
      observed.runtimeAuthorizationGeneration !== expected.runtimeAuthorizationGeneration
    ) {
      throw new RuntimeEffectError("runtime_conflict", false);
    }
    if (expectRemoved) throw new RuntimeEffectError("runtime_conflict", false);
  }

  private createSessionArgs(
    sessionId: string,
    tmuxName: string,
    generation: number,
    tmuxSessionIncarnation: string
  ): string[] {
    const args = [
      "start-server",
      ";",
      "set-option",
      "-g",
      SERVER_MARKER_OPTION,
      canonicalServerMarker(sessionId, tmuxSessionIncarnation),
      ";",
      "set-option",
      "-g",
      "update-environment",
      "",
      ";",
      "set-option",
      "-g",
      "prefix",
      "None",
      ";",
      "set-option",
      "-g",
      "prefix2",
      "None",
      ";",
      "new-session",
      "-d",
      "-E",
      "-s",
      tmuxName,
    ];
    for (const [key, value] of Object.entries(this.environment).sort(([a], [b]) =>
      a.localeCompare(b)
    )) {
      args.push("-e", `${key}=${value}`);
    }
    args.push(
      ";",
      "set-option",
      "-t",
      canonicalTmuxTarget(tmuxName),
      MANAGED_OPTION,
      "1",
      ";",
      "set-option",
      "-t",
      canonicalTmuxTarget(tmuxName),
      SESSION_ID_OPTION,
      sessionId,
      ";",
      "set-option",
      "-t",
      canonicalTmuxTarget(tmuxName),
      SESSION_INCARNATION_OPTION,
      tmuxSessionIncarnation,
      ";",
      "set-option",
      "-t",
      canonicalTmuxTarget(tmuxName),
      AUTHORIZATION_GENERATION_OPTION,
      String(generation)
    );
    return args;
  }

  private nextSessionIncarnation(): string {
    let tmuxSessionIncarnation: string;
    try {
      tmuxSessionIncarnation = this.sessionIncarnationSource();
    } catch {
      throw new RuntimeEffectError("runtime_internal", true);
    }
    if (!isCanonicalTmuxSessionIncarnation(tmuxSessionIncarnation)) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    return tmuxSessionIncarnation;
  }

  private async detachClients(
    sessionId: string,
    session: CanonicalSessionMetadata,
    signal: AbortSignal
  ): Promise<void> {
    const result = await this.runGuardedEffect(
      sessionId,
      session,
      `detach-client -s ${exactTmuxSessionTarget(session.tmuxSessionRef)}`,
      signal
    );
    if (!result.ok && !/no clients?/i.test(result.stderr)) throw executionFailure(result);
  }

  private async requireGuardedSuccess(
    sessionId: string,
    expected: CanonicalSessionMetadata,
    exactCommand: string,
    signal: AbortSignal
  ): Promise<void> {
    const result = await this.runGuardedEffect(sessionId, expected, exactCommand, signal);
    if (!result.ok) throw executionFailure(result);
  }

  /**
   * The predicate and effect execute through one tmux client connection. If
   * the server exits, that connection cannot silently migrate to a restarted
   * server that has reused the same `$id`.
   */
  private async runGuardedEffect(
    sessionId: string,
    expected: CanonicalSessionMetadata,
    exactCommand: string,
    signal: AbortSignal
  ): Promise<ExactCommandResult> {
    return this.run(
      sessionId,
      [
        "if-shell",
        "-F",
        "-t",
        exactTmuxSessionTarget(expected.tmuxSessionRef),
        exactCanonicalBindingPredicate(expected),
        exactCommand,
        "display-message -p terminalx-runtime-binding-unavailable",
      ],
      signal
    );
  }

  private async run(
    sessionId: string,
    args: readonly string[],
    signal: AbortSignal
  ): Promise<ExactCommandResult> {
    throwIfRuntimeAborted(signal);
    const result = await this.executor.execute({
      file: this.tmuxBinary,
      args: [
        "-L",
        getCanonicalTmuxSocketName(sessionId, this.socketNameSource),
        "-f",
        CANONICAL_TMUX_CONFIG_FILE,
        ...args,
      ],
      env: this.environment,
      timeoutMs: this.commandTimeoutMs,
      signal,
    });
    throwIfRuntimeAborted(signal);
    return result;
  }

  private updateWriteState(update: RuntimeWriteStateUpdate, signal: AbortSignal): void {
    throwIfRuntimeAborted(signal);
    const current = this.writeStates.get(update.sessionId);
    if (current) {
      if (update.runtimeAuthorizationGeneration < current.runtimeAuthorizationGeneration) return;
      if (
        update.runtimeAuthorizationGeneration === current.runtimeAuthorizationGeneration &&
        writeStateRank(update.state) < writeStateRank(current.state)
      ) {
        return;
      }
    }
    this.writeStates.set(update.sessionId, update);
    this.callbacks.updateWriteState(update, signal);
    throwIfRuntimeAborted(signal);
  }
}

export function canonicalTmuxTarget(name: string): string {
  if (!isValidTmuxSessionName(name)) {
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }
  return `=${name}:`;
}

function exactTmuxSessionTarget(tmuxSessionRef: string): string {
  if (!/^\$[0-9]{1,20}$/.test(tmuxSessionRef)) {
    throw new RuntimeEffectError("runtime_conflict", false);
  }
  return tmuxSessionRef;
}

function exactCanonicalBindingPredicate(expected: CanonicalSessionMetadata): string {
  const conditions = [
    tmuxFormatEquals(
      `#{${SERVER_MARKER_OPTION}}`,
      canonicalServerMarker(expected.sessionId, expected.tmuxSessionIncarnation)
    ),
    tmuxFormatEquals("#{session_id}", exactTmuxSessionTarget(expected.tmuxSessionRef)),
    tmuxFormatEquals(`#{${MANAGED_OPTION}}`, "1"),
    tmuxFormatEquals(`#{${SESSION_ID_OPTION}}`, expected.sessionId),
    tmuxFormatEquals(`#{${SESSION_INCARNATION_OPTION}}`, expected.tmuxSessionIncarnation),
    tmuxFormatEquals(
      `#{${AUTHORIZATION_GENERATION_OPTION}}`,
      String(expected.runtimeAuthorizationGeneration)
    ),
  ];
  return conditions.reduceRight((right, condition) =>
    right ? `#{&&:${condition},${right}}` : condition
  );
}

function tmuxFormatEquals(format: string, exactLiteral: string): string {
  return `#{==:${format},${exactLiteral}}`;
}

export function getCanonicalTmuxSocketName(
  sessionId: string,
  source: Readonly<Record<string, string | undefined>> = process.env
): string {
  validateCanonicalSessionId(sessionId);
  const configured = source[CANONICAL_TMUX_SOCKET_NAME_ENV];
  const namespace = configured || DEFAULT_CANONICAL_TMUX_SOCKET_NAME;
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(namespace)) {
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }
  const digest = createHash("sha256")
    .update("terminalx/canonical-tmux-session-socket/v1\0", "utf8")
    .update(namespace, "utf8")
    .update("\0", "utf8")
    .update(sessionId, "utf8")
    .digest("hex")
    .slice(0, 48);
  const socketName = `${namespace.slice(0, 15)}-${digest}`;
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(socketName)) {
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }
  return socketName;
}

function canonicalServerMarker(sessionId: string, tmuxSessionIncarnation: string): string {
  validateCanonicalSessionId(sessionId);
  if (!isCanonicalTmuxSessionIncarnation(tmuxSessionIncarnation)) {
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }
  return `v2:${sessionId}:${tmuxSessionIncarnation}`;
}

export function isCanonicalTmuxSessionIncarnation(value: unknown): value is string {
  return typeof value === "string" && SESSION_INCARNATION_PATTERN.test(value);
}

export function parseCanonicalTmuxServerMarker(
  marker: string,
  expectedSessionId: string
): string | null {
  const prefix = `v2:${expectedSessionId}:`;
  if (!marker.startsWith(prefix)) return null;
  const tmuxSessionIncarnation = marker.slice(prefix.length);
  return isCanonicalTmuxSessionIncarnation(tmuxSessionIncarnation) ? tmuxSessionIncarnation : null;
}

function validateBinding(sessionId: string, tmuxName: string, generation: number): void {
  validateCanonicalSessionId(sessionId);
  canonicalTmuxTarget(tmuxName);
  validateGeneration(generation);
}

function validateCanonicalSessionId(sessionId: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(sessionId)) {
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }
}

function validateGeneration(generation: number): void {
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }
}

function parseSessionMetadata(
  tmuxName: string,
  managed: string,
  sessionId: string,
  generation: string,
  tmuxSessionRef: string,
  tmuxSessionIncarnation: string,
  serverMarker: string
): CanonicalSessionMetadata {
  const parsedGeneration = Number(generation);
  exactTmuxSessionTarget(tmuxSessionRef);
  const markerIncarnation = parseCanonicalTmuxServerMarker(serverMarker, sessionId);
  if (
    !isCanonicalTmuxSessionIncarnation(tmuxSessionIncarnation) ||
    markerIncarnation !== tmuxSessionIncarnation
  ) {
    throw new RuntimeEffectError("runtime_conflict", false);
  }
  return {
    tmuxName,
    managed: managed === "1",
    sessionId,
    runtimeAuthorizationGeneration:
      Number.isSafeInteger(parsedGeneration) && parsedGeneration >= 1 ? parsedGeneration : 0,
    tmuxSessionRef,
    tmuxSessionIncarnation,
  };
}

function parseSessionListLine(line: string): CanonicalSessionMetadata {
  const fields = line.split("\t");
  if (fields.length !== 7) throw new RuntimeEffectError("runtime_conflict", false);
  const [
    tmuxName = "",
    managed = "",
    sessionId = "",
    generation = "",
    tmuxSessionRef = "",
    tmuxSessionIncarnation = "",
    serverMarker = "",
  ] = fields;
  const metadata = parseSessionMetadata(
    tmuxName,
    managed,
    sessionId,
    generation,
    tmuxSessionRef,
    tmuxSessionIncarnation,
    serverMarker
  );
  if (!isValidTmuxSessionName(metadata.tmuxName)) {
    throw new RuntimeEffectError("runtime_conflict", false);
  }
  return metadata;
}

function isNoServer(result: Exclude<ExactCommandResult, { ok: true }>): boolean {
  const stderr = result.stderr.trim();
  return (
    /^no server running on [^\r\n]+$/i.test(stderr) ||
    /^no sessions$/i.test(stderr) ||
    /^error connecting to [^\r\n]+ \(No such file or directory\)$/i.test(stderr)
  );
}

function executionFailure(result: Exclude<ExactCommandResult, { ok: true }>): RuntimeEffectError {
  switch (result.failure) {
    case "aborted":
    case "timeout":
      return new RuntimeEffectError("runtime_timeout", true);
    case "not-found":
      return new RuntimeEffectError("runtime_unavailable", true);
    case "permission-denied":
      return new RuntimeEffectError("runtime_permission_denied", false);
    case "spawn-failed":
      return new RuntimeEffectError("runtime_unavailable", true);
    case "exit":
      if (/permission denied/i.test(result.stderr)) {
        return new RuntimeEffectError("runtime_permission_denied", false);
      }
      return new RuntimeEffectError("runtime_internal", true);
  }
}

function classifyNodeExecutionError(error: Error): ExactCommandFailure {
  const nodeError = error as NodeJS.ErrnoException & { killed?: boolean };
  if (nodeError.name === "AbortError" || nodeError.code === "ABORT_ERR") return "aborted";
  if (nodeError.killed || nodeError.code === "ETIMEDOUT") return "timeout";
  if (nodeError.code === "ENOENT") return "not-found";
  if (nodeError.code === "EACCES" || nodeError.code === "EPERM") return "permission-denied";
  if (typeof nodeError.code === "number") return "exit";
  return "spawn-failed";
}

function throwIfRuntimeAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new RuntimeEffectError("runtime_timeout", true);
}

function writeStateRank(state: RuntimeWriteStateUpdate["state"]): number {
  switch (state) {
    case "active":
      return 0;
    case "fenced":
      return 1;
    case "retired":
      return 2;
  }
}
