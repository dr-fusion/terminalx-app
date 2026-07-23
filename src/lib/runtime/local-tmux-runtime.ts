import { execFile, type ExecFileException } from "child_process";
import { createHash } from "crypto";
import { isValidTmuxSessionName } from "../tmux";
import type { RuntimeOutboxDelivery, RuntimeOutboxErrorCode } from "../team-sessions";

const SERVER_MARKER_OPTION = "@terminalx_runtime_server";
const MANAGED_OPTION = "@terminalx_managed";
const SESSION_ID_OPTION = "@terminalx_session_id";
const AUTHORIZATION_GENERATION_OPTION = "@terminalx_runtime_authorization_generation";
const SESSION_LIST_FORMAT = `#{session_name}\t#{${MANAGED_OPTION}}\t#{${SESSION_ID_OPTION}}\t#{${AUTHORIZATION_GENERATION_OPTION}}`;

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
  runtimeAuthorizationGeneration: number;
  reason: "authorization-fence" | "retire";
}

/**
 * The synchronous write-state callback is the immediate enforcement point.
 * Terminal transports must consult the same state before every mutation.
 */
export interface LocalTmuxFenceCallbacks {
  updateWriteState(update: RuntimeWriteStateUpdate): void;
  terminateCanonicalPtys(input: CanonicalPtyTermination): Promise<void>;
  /** Required before a destructive retire; false fails closed without touching tmux. */
  isCurrentRuntimeBinding(input: {
    sessionId: string;
    runtimeAuthorizationGeneration: number;
  }): Promise<boolean>;
}

export interface CreateLocalTmuxRuntimeOptions {
  executor?: ExactCommandExecutor;
  fenceCallbacks: LocalTmuxFenceCallbacks;
  sourceEnvironment?: Readonly<Record<string, string | undefined>>;
  tmuxBinary?: string;
  commandTimeoutMs?: number;
}

interface CanonicalSessionMetadata {
  tmuxName: string;
  managed: boolean;
  sessionId: string;
  runtimeAuthorizationGeneration: number;
}

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
  }

  async apply(delivery: RuntimeOutboxDelivery): Promise<void> {
    switch (delivery.kind) {
      case "runtime.session.ensure":
        await this.ensure(delivery);
        return;
      case "runtime.authorization.fence":
        await this.fence(delivery);
        return;
      case "runtime.session.retire":
        await this.retire(delivery);
        return;
    }
  }

  private async ensure(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.session.ensure" }>
  ): Promise<void> {
    const { sessionId, tmuxName, runtimeAuthorizationGeneration } = delivery.payload;
    validateBinding(sessionId, tmuxName, runtimeAuthorizationGeneration);
    const server = await this.serverState(sessionId);
    if (server === "canonical") {
      const existing = await this.sessionById(sessionId);
      if (existing) {
        this.assertOwnedBinding(existing, sessionId, tmuxName, runtimeAuthorizationGeneration);
        if (existing.runtimeAuthorizationGeneration === runtimeAuthorizationGeneration) {
          this.updateWriteState({
            sessionId,
            runtimeAuthorizationGeneration,
            state: "active",
          });
        }
        return;
      }
    }

    const created = await this.run(
      sessionId,
      this.createSessionArgs(sessionId, tmuxName, runtimeAuthorizationGeneration)
    );
    if (!created.ok) {
      const raced = await this.exactBindingOrNull(
        tmuxName,
        sessionId,
        runtimeAuthorizationGeneration
      );
      if (!raced) throw executionFailure(created);
    }
    await this.requireCanonicalServer(sessionId);
    const verified = await this.sessionById(sessionId);
    if (!verified) throw new RuntimeEffectError("runtime_invalid_state", false);
    this.assertOwnedBinding(verified, sessionId, tmuxName, runtimeAuthorizationGeneration);
    if (verified.runtimeAuthorizationGeneration === runtimeAuthorizationGeneration) {
      this.updateWriteState({
        sessionId,
        runtimeAuthorizationGeneration,
        state: "active",
      });
    }
  }

  private async fence(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.authorization.fence" }>
  ): Promise<void> {
    const { sessionId, runtimeAuthorizationGeneration } = delivery.payload;
    validateGeneration(runtimeAuthorizationGeneration);
    validateCanonicalSessionId(sessionId);
    this.updateWriteState({
      sessionId,
      runtimeAuthorizationGeneration,
      state: "fenced",
    });

    await this.requireCanonicalServer(sessionId);
    const session = await this.sessionById(sessionId);
    if (!session) throw new RuntimeEffectError("runtime_invalid_state", false);
    if (session.runtimeAuthorizationGeneration > runtimeAuthorizationGeneration) return;
    await this.requireSuccess(sessionId, [
      "set-option",
      "-t",
      canonicalTmuxTarget(session.tmuxName),
      AUTHORIZATION_GENERATION_OPTION,
      String(runtimeAuthorizationGeneration),
    ]);
    await this.detachClients(sessionId, session.tmuxName);
    await this.callbacks.terminateCanonicalPtys({
      sessionId,
      tmuxName: session.tmuxName,
      runtimeAuthorizationGeneration,
      reason: "authorization-fence",
    });
  }

  private async retire(
    delivery: Extract<RuntimeOutboxDelivery, { kind: "runtime.session.retire" }>
  ): Promise<void> {
    const { sessionId, runtimeAuthorizationGeneration } = delivery.payload;
    validateGeneration(runtimeAuthorizationGeneration);
    validateCanonicalSessionId(sessionId);
    if (
      !(await this.callbacks.isCurrentRuntimeBinding({
        sessionId,
        runtimeAuthorizationGeneration,
      }))
    ) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    const state = await this.serverState(sessionId);
    if (state === "absent") {
      this.updateWriteState({
        sessionId,
        runtimeAuthorizationGeneration,
        state: "retired",
      });
      return;
    }
    const session = await this.sessionById(sessionId);
    if (!session) {
      this.updateWriteState({
        sessionId,
        runtimeAuthorizationGeneration,
        state: "retired",
      });
      return;
    }
    if (session.runtimeAuthorizationGeneration !== runtimeAuthorizationGeneration) {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
    this.updateWriteState({
      sessionId,
      runtimeAuthorizationGeneration,
      state: "retired",
    });
    await this.detachClients(sessionId, session.tmuxName);
    await this.callbacks.terminateCanonicalPtys({
      sessionId,
      tmuxName: session.tmuxName,
      runtimeAuthorizationGeneration,
      reason: "retire",
    });
    await this.requireSuccess(sessionId, [
      "kill-session",
      "-t",
      canonicalTmuxTarget(session.tmuxName),
    ]);
  }

  private async serverState(sessionId: string): Promise<"absent" | "canonical"> {
    const marker = await this.run(sessionId, ["show-options", "-gqv", SERVER_MARKER_OPTION]);
    if (marker.ok) {
      if (marker.stdout.trim() === canonicalServerMarker(sessionId)) return "canonical";
      throw new RuntimeEffectError("runtime_conflict", false);
    }
    if (isNoServer(marker)) return "absent";
    throw executionFailure(marker);
  }

  private async requireCanonicalServer(sessionId: string): Promise<void> {
    if ((await this.serverState(sessionId)) !== "canonical") {
      throw new RuntimeEffectError("runtime_invalid_state", false);
    }
  }

  private async sessionById(sessionId: string): Promise<CanonicalSessionMetadata | null> {
    const result = await this.run(sessionId, ["list-sessions", "-F", SESSION_LIST_FORMAT]);
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
    generation: number
  ): Promise<CanonicalSessionMetadata | null> {
    const server = await this.serverState(sessionId);
    if (server !== "canonical") return null;
    const metadata = await this.sessionById(sessionId);
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

  private createSessionArgs(sessionId: string, tmuxName: string, generation: number): string[] {
    const args = [
      "start-server",
      ";",
      "set-option",
      "-g",
      SERVER_MARKER_OPTION,
      canonicalServerMarker(sessionId),
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
      AUTHORIZATION_GENERATION_OPTION,
      String(generation)
    );
    return args;
  }

  private async detachClients(sessionId: string, tmuxName: string): Promise<void> {
    const result = await this.run(sessionId, [
      "detach-client",
      "-s",
      canonicalTmuxTarget(tmuxName),
    ]);
    if (!result.ok && !/no clients?/i.test(result.stderr)) throw executionFailure(result);
  }

  private async requireSuccess(sessionId: string, args: readonly string[]): Promise<void> {
    const result = await this.run(sessionId, args);
    if (!result.ok) throw executionFailure(result);
  }

  private run(sessionId: string, args: readonly string[]): Promise<ExactCommandResult> {
    return this.executor.execute({
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
    });
  }

  private updateWriteState(update: RuntimeWriteStateUpdate): void {
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
    this.callbacks.updateWriteState(update);
  }
}

export function canonicalTmuxTarget(name: string): string {
  if (!isValidTmuxSessionName(name)) {
    throw new RuntimeEffectError("runtime_invalid_state", false);
  }
  return `=${name}:`;
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

function canonicalServerMarker(sessionId: string): string {
  validateCanonicalSessionId(sessionId);
  return `v1:${sessionId}`;
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

function parseSessionMetadata(tmuxName: string, output: string): CanonicalSessionMetadata {
  const [managed = "", sessionId = "", generation = ""] = output.trim().split("\t");
  const parsedGeneration = Number(generation);
  return {
    tmuxName,
    managed: managed === "1",
    sessionId,
    runtimeAuthorizationGeneration:
      Number.isSafeInteger(parsedGeneration) && parsedGeneration >= 1 ? parsedGeneration : 0,
  };
}

function parseSessionListLine(line: string): CanonicalSessionMetadata {
  const [tmuxName = "", managed = "", sessionId = "", generation = ""] = line.split("\t");
  const metadata = parseSessionMetadata(tmuxName, `${managed}\t${sessionId}\t${generation}`);
  if (!isValidTmuxSessionName(metadata.tmuxName)) {
    throw new RuntimeEffectError("runtime_conflict", false);
  }
  return metadata;
}

function isNoServer(result: Exclude<ExactCommandResult, { ok: true }>): boolean {
  return /no server running|no sessions|error connecting/i.test(result.stderr);
}

function executionFailure(result: Exclude<ExactCommandResult, { ok: true }>): RuntimeEffectError {
  switch (result.failure) {
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
  if (nodeError.killed || nodeError.code === "ETIMEDOUT") return "timeout";
  if (nodeError.code === "ENOENT") return "not-found";
  if (nodeError.code === "EACCES" || nodeError.code === "EPERM") return "permission-denied";
  if (typeof nodeError.code === "number") return "exit";
  return "spawn-failed";
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
