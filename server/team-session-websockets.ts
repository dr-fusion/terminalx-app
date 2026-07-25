import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { TextDecoder, types as nodeTypes } from "node:util";
import { WebSocket, WebSocketServer, type RawData } from "ws";
import {
  resolveRequestActor,
  type RequestActor,
  type RequestHeaders,
} from "../src/lib/request-actor";
import { getPublicUrl, trustProxyHeaders } from "../src/lib/security-config";
import { snapshotRuntimeSupervisorPortableData } from "../src/lib/runtime/runtime-supervisor-snapshot";
import type {
  HostedTerminalAdapter,
  HostedTerminalConnection,
} from "../src/lib/runtime/hosted-terminal";
import type {
  HostedTeamSessionTerminalBinding,
  TeamSessionTerminalBinding,
} from "../src/lib/team-session-terminal-gateway";
import { projectPublicSessionEvent } from "../src/lib/team-sessions/public-event";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type ActorContext,
  type FollowSessionOptions,
  type SessionEvent,
  type SessionGetQuery,
  type SessionView,
} from "../src/lib/team-sessions";

const MAX_WEBSOCKET_PAYLOAD_BYTES = 64 * 1024;
const MAX_TERMINAL_INPUT_BYTES = 16 * 1024;
const MAX_BUFFERED_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_QUEUED_TERMINAL_MESSAGES = 16;
const MAX_QUEUED_HOSTED_MUTATIONS = 8;
const MAX_QUEUED_HOSTED_MUTATION_BYTES = 128 * 1024;
const DEFAULT_CREDENTIAL_CHECK_INTERVAL_MS = 1_000;
const DEFAULT_EVENT_POLL_INTERVAL_MS = 100;
const SHUTDOWN_SETTLEMENT_TIMEOUT_MS = 250;
const CONNECTION_LIMITS = Object.freeze({
  terminal: { perUser: 2, perSession: 8, global: 16 },
  events: { perUser: 4, perSession: 32, global: 256 },
});
const CANONICAL_SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$/;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

type TerminalMutationAction = "input" | "resize" | "interrupt";
type HumanActorContext = ActorContext & { kind: "human" };
type AnyFunction = (...args: unknown[]) => unknown;

interface CapturedHostedTerminalAdapter {
  readonly receiver: object;
  readonly connect: AnyFunction;
}

interface CapturedHostedTerminalConnection {
  readonly receiver: object;
  readonly binding: HostedTeamSessionTerminalBinding;
  readonly onData: AnyFunction;
  readonly onExit: AnyFunction;
  readonly input: AnyFunction;
  readonly resize: AnyFunction;
  readonly interrupt: AnyFunction;
  readonly destroy: AnyFunction;
}

export interface CanonicalTerminalConnection {
  readonly sessionId: string;
  readonly binding: TeamSessionTerminalBinding;
  readonly tmuxName?: string;
  readonly controlEpoch: number;
  readonly runtimeAuthorizationGeneration: number;

  /** A projection only; it never grants a reusable write permit. */
  canPerform(action: TerminalMutationAction): Promise<boolean>;
  /**
   * The implementation must authorize the captured fences and invoke `effect`
   * synchronously, without an await or queue boundary between those two steps.
   */
  perform(action: TerminalMutationAction, effect: () => void): void;
  monitor(options?: { signal?: AbortSignal }): Promise<unknown>;
}

export interface CanonicalTerminalGateway {
  open(options: {
    sessionId: string;
    actor: HumanActorContext;
  }): Promise<CanonicalTerminalConnection>;
}

export interface CanonicalTerminalPty {
  onData(listener: (data: string) => void): { dispose(): void };
  onExit(listener: () => void): { dispose(): void };
}

export interface CanonicalTerminalPtyAdapter {
  create(options: {
    tmuxName: string;
    shell: string;
    cols: number;
    rows: number;
    binding: {
      teamSessionId: string;
      runtimeAuthorizationGeneration: number;
      tmuxSocketName: string;
      tmuxSessionRef: string;
      tmuxSessionIncarnation: string;
      readOnly: boolean;
    };
  }): CanonicalTerminalPty;
  write(pty: CanonicalTerminalPty, data: string): void;
  resize(pty: CanonicalTerminalPty, cols: number, rows: number): void;
  interrupt(pty: CanonicalTerminalPty): void;
  destroy(pty: CanonicalTerminalPty): void;
}

export type CanonicalHostedTerminalConnection = HostedTerminalConnection;

/** Compatibility name for the provider-neutral asynchronous terminal port. */
export type CanonicalHostedTerminalAdapter = HostedTerminalAdapter;

export interface TeamSessionEventKernel {
  inspect(query: SessionGetQuery): Promise<SessionView | null>;
  follow(options: FollowSessionOptions): AsyncIterable<SessionEvent>;
}

export interface CreateTeamSessionWebSocketsOptions {
  teamSessions: TeamSessionEventKernel;
  terminalGateway: CanonicalTerminalGateway;
  pty: CanonicalTerminalPtyAdapter;
  hostedTerminal?: CanonicalHostedTerminalAdapter;
  /** Resolve the isolated tmux server for one canonical Team Session. */
  resolveTmuxSocketName: (sessionId: string) => string;
  /** Resolve the admitted generation to an immutable session-incarnation/`$id` pair. */
  resolveTmuxSessionRef: (input: {
    sessionId: string;
    tmuxName: string;
    runtimeAuthorizationGeneration: number;
    tmuxSocketName: string;
  }) => { tmuxSessionRef: string; tmuxSessionIncarnation: string };
  shell: string;
  resolveActor?: (headers: RequestHeaders) => Promise<RequestActor | null>;
  credentialCheckIntervalMs?: number;
  eventPollIntervalMs?: number;
  reportInternalError?: (errorName: string) => void;
}

export interface TeamSessionWebSockets {
  readonly terminalWebSocketServer: WebSocketServer;
  readonly eventWebSocketServer: WebSocketServer;

  /** Returns false without touching the socket when the path is not canonical. */
  handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer): Promise<boolean>;
  close(): Promise<void>;
}

/** Stable shutdown failure; dependency details are never interpolated. */
export class TeamSessionWebSocketShutdownError extends Error {
  constructor() {
    super("Team Session WebSocket shutdown did not settle");
    this.name = "TeamSessionWebSocketShutdownError";
  }
}

interface CredentialSnapshot extends RequestHeaders {
  readonly hasSessionCookie: boolean;
}

interface CanonicalRouteBase {
  sessionId: string;
  cols: number;
  rows: number;
  hasQueryCredential: boolean;
}

type CanonicalRoute = CanonicalRouteBase & ({ kind: "terminal" } | { kind: "events" });
type CanonicalRouteKind = CanonicalRoute["kind"];

interface Admission {
  actor: HumanActorContext;
  credentials: CredentialSnapshot;
  route: CanonicalRoute;
}

interface TerminalAdmission extends Admission {
  route: CanonicalRoute & { kind: "terminal" };
  connection: CanonicalTerminalConnection;
}

interface EventAdmission extends Admission {
  route: CanonicalRoute & { kind: "events" };
  session: SessionView;
}

export function createTeamSessionWebSockets(
  options: CreateTeamSessionWebSocketsOptions
): TeamSessionWebSockets {
  assertFactoryOptions(options);

  const hostedTerminalAdapter = options.hostedTerminal
    ? captureHostedTerminalAdapter(options.hostedTerminal)
    : undefined;
  const resolveActor = options.resolveActor ?? resolveRequestActor;
  const credentialCheckIntervalMs =
    options.credentialCheckIntervalMs ?? DEFAULT_CREDENTIAL_CHECK_INTERVAL_MS;
  const eventPollIntervalMs = options.eventPollIntervalMs ?? DEFAULT_EVENT_POLL_INTERVAL_MS;
  const terminalWebSocketServer = new WebSocketServer({
    noServer: true,
    maxPayload: MAX_WEBSOCKET_PAYLOAD_BYTES,
  });
  const eventWebSocketServer = new WebSocketServer({
    noServer: true,
    maxPayload: MAX_WEBSOCKET_PAYLOAD_BYTES,
  });
  const mutationQueues = new Map<string, Promise<void>>();
  const hostedDestroySettlements = new Set<Promise<void>>();
  const terminalServeSettlements = new Set<Promise<void>>();
  const eventServeSettlements = new Set<Promise<void>>();
  const connectionQuota = createConnectionQuota();
  let closed = false;
  let closePromise: Promise<void> | null = null;
  let hostedDestroyFailed = false;

  const destroyHostedTerminal = (terminal: CapturedHostedTerminalConnection): Promise<void> => {
    const settlement = invokeCapturedPromise(terminal.receiver, terminal.destroy, []).then(
      (result) => {
        if (result !== undefined) throw new TypeError();
      }
    );
    hostedDestroySettlements.add(settlement);
    void settlement.then(
      () => hostedDestroySettlements.delete(settlement),
      (error) => {
        hostedDestroySettlements.delete(settlement);
        hostedDestroyFailed = true;
        reportError(error, options.reportInternalError);
      }
    );
    return settlement;
  };

  const trackServe = (settlements: Set<Promise<void>>, settlement: Promise<void>): void => {
    settlements.add(settlement);
    void settlement.then(
      () => settlements.delete(settlement),
      (error) => {
        settlements.delete(settlement);
        reportError(error, options.reportInternalError);
      }
    );
  };

  const enqueueMutation = (sessionId: string, mutation: () => Promise<void>): Promise<void> => {
    const previous = mutationQueues.get(sessionId) ?? Promise.resolve();
    const next = previous.catch(() => undefined).then(mutation);
    mutationQueues.set(sessionId, next);
    const release = (): void => {
      if (mutationQueues.get(sessionId) === next) mutationQueues.delete(sessionId);
    };
    void next.then(release, release);
    return next;
  };

  return {
    terminalWebSocketServer,
    eventWebSocketServer,

    async handleUpgrade(request, socket, head): Promise<boolean> {
      const route = parseCanonicalRoute(request);
      if (!route) return false;

      if (closed) {
        rejectUpgrade(socket, 503, "Service Unavailable");
        return true;
      }
      if (route.hasQueryCredential) {
        rejectUpgrade(socket, 400, "Bad Request");
        return true;
      }

      const credentials = captureCredentials(request);
      if (!isSameOriginRequest(request, credentials)) {
        rejectUpgrade(socket, 403, "Forbidden");
        return true;
      }

      let requestActor: RequestActor | null;
      try {
        requestActor = await resolveActor(credentials);
      } catch (error) {
        reportError(error, options.reportInternalError);
        requestActor = null;
      }
      if (!requestActor || requestActor.kind !== "human") {
        rejectUpgrade(socket, 401, "Unauthorized");
        return true;
      }

      const actor: HumanActorContext = Object.freeze({
        kind: "human",
        userId: requestActor.userId,
        displayName: requestActor.displayName,
      });

      if (route.kind === "terminal") {
        let connection: CanonicalTerminalConnection;
        try {
          connection = await options.terminalGateway.open({ sessionId: route.sessionId, actor });
        } catch {
          rejectUpgrade(socket, 403, "Forbidden");
          return true;
        }

        const releaseQuota = connectionQuota.reserve(route.kind, actor.userId, route.sessionId);
        if (!releaseQuota) {
          rejectUpgrade(socket, 429, "Too Many Requests");
          return true;
        }

        try {
          terminalWebSocketServer.handleUpgrade(request, socket, head, (webSocket) => {
            trackServe(
              terminalServeSettlements,
              serveTerminal(
                webSocket,
                {
                  actor,
                  credentials,
                  route,
                  connection,
                },
                options,
                hostedTerminalAdapter,
                destroyHostedTerminal,
                resolveActor,
                credentialCheckIntervalMs,
                enqueueMutation,
                releaseQuota
              )
            );
          });
        } catch (error) {
          releaseQuota();
          reportError(error, options.reportInternalError);
          rejectUpgrade(socket, 503, "Service Unavailable");
        }
        return true;
      }

      let session: SessionView | null;
      try {
        session = await options.teamSessions.inspect({
          schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
          type: "session.get",
          sessionId: route.sessionId,
          actor,
        });
      } catch {
        session = null;
      }
      if (!session || session.sessionId !== route.sessionId) {
        rejectUpgrade(socket, 403, "Forbidden");
        return true;
      }

      const releaseQuota = connectionQuota.reserve(route.kind, actor.userId, route.sessionId);
      if (!releaseQuota) {
        rejectUpgrade(socket, 429, "Too Many Requests");
        return true;
      }

      try {
        eventWebSocketServer.handleUpgrade(request, socket, head, (webSocket) => {
          trackServe(
            eventServeSettlements,
            serveEvents(
              webSocket,
              { actor, credentials, route, session },
              options,
              resolveActor,
              credentialCheckIntervalMs,
              eventPollIntervalMs,
              releaseQuota
            )
          );
        });
      } catch (error) {
        releaseQuota();
        reportError(error, options.reportInternalError);
        rejectUpgrade(socket, 503, "Service Unavailable");
      }
      return true;
    },

    close(): Promise<void> {
      if (closePromise) return closePromise;
      closed = true;
      const close = (async () => {
        for (const webSocket of terminalWebSocketServer.clients) webSocket.terminate();
        for (const webSocket of eventWebSocketServer.clients) webSocket.terminate();
        await Promise.all([
          closeWebSocketServer(terminalWebSocketServer),
          closeWebSocketServer(eventWebSocketServer),
        ]);
        const serveSettled = await settleWithin(
          [...terminalServeSettlements, ...eventServeSettlements],
          SHUTDOWN_SETTLEMENT_TIMEOUT_MS
        );
        if (!serveSettled) {
          reportError(new Error("WebSocket serve shutdown timed out"), options.reportInternalError);
        }
        const destroySettlementsSettled = await settleWithin(
          [...hostedDestroySettlements],
          SHUTDOWN_SETTLEMENT_TIMEOUT_MS
        );
        const destroySettled = destroySettlementsSettled && !hostedDestroyFailed;
        if (!destroySettled) {
          reportError(new Error("Hosted terminal destroy timed out"), options.reportInternalError);
        }
        if (!serveSettled || !destroySettled) throw new TeamSessionWebSocketShutdownError();
      })();
      closePromise = close;
      return close;
    },
  };
}

async function serveTerminal(
  webSocket: WebSocket,
  admission: TerminalAdmission,
  options: CreateTeamSessionWebSocketsOptions,
  hostedTerminalAdapter: CapturedHostedTerminalAdapter | undefined,
  destroyHostedTerminal: (terminal: CapturedHostedTerminalConnection) => Promise<void>,
  resolveActor: (headers: RequestHeaders) => Promise<RequestActor | null>,
  credentialCheckIntervalMs: number,
  enqueueMutation: (sessionId: string, mutation: () => Promise<void>) => Promise<void>,
  releaseQuota: () => void
): Promise<void> {
  const abortController = new AbortController();
  let pty: CanonicalTerminalPty | undefined;
  let hostedTerminal: CapturedHostedTerminalConnection | undefined;
  let hostedMutationQueue: HostedTerminalMutationQueue | undefined;
  let dataSubscription: { dispose(): void } | undefined;
  let exitSubscription: { dispose(): void } | undefined;
  const pendingTerminalOutput: string[] = [];
  let pendingTerminalOutputBytes = 0;
  let terminalReady = false;
  let terminalExitPending = false;
  let cleanedUp = false;
  let credentialCheckActive = false;

  const cleanup = (): void => {
    if (cleanedUp) return;
    cleanedUp = true;
    abortController.abort();
    clearInterval(credentialTimer);
    releaseQuota();
    try {
      dataSubscription?.dispose();
    } catch (error) {
      reportError(error, options.reportInternalError);
    }
    try {
      exitSubscription?.dispose();
    } catch (error) {
      reportError(error, options.reportInternalError);
    }
    if (pty) options.pty.destroy(pty);
    hostedMutationQueue?.close();
    pendingTerminalOutput.length = 0;
    pendingTerminalOutputBytes = 0;
    if (hostedTerminal) {
      const terminal = hostedTerminal;
      hostedTerminal = undefined;
      void destroyHostedTerminal(terminal).catch(() => undefined);
    }
  };
  const closeUnavailable = (): void => {
    cleanup();
    closeWebSocket(webSocket, 1008, "Terminal unavailable");
  };
  const closeInvalidMessage = (): void => {
    cleanup();
    closeWebSocket(webSocket, 1008, "Invalid terminal message");
  };
  const credentialsAreCurrent = async (): Promise<boolean> => {
    try {
      const current = await resolveActor(admission.credentials);
      return current?.kind === "human" && current.userId === admission.actor.userId;
    } catch (error) {
      reportError(error, options.reportInternalError);
      return false;
    }
  };

  const credentialTimer = setInterval(() => {
    if (credentialCheckActive || abortController.signal.aborted) return;
    credentialCheckActive = true;
    void credentialsAreCurrent()
      .then((current) => {
        if (!current) closeUnavailable();
      })
      .finally(() => {
        credentialCheckActive = false;
      });
  }, credentialCheckIntervalMs);
  credentialTimer.unref();

  webSocket.once("close", cleanup);
  webSocket.once("error", () => {
    cleanup();
    webSocket.terminate();
  });

  try {
    if (!(await credentialsAreCurrent())) {
      closeUnavailable();
      return;
    }

    // Admission happened before the HTTP upgrade. Re-open at the last moment
    // so a revocation during the handshake cannot briefly receive PTY output.
    let connection = await options.terminalGateway.open({
      sessionId: admission.route.sessionId,
      actor: admission.actor,
    });
    if (
      connection.sessionId !== admission.route.sessionId ||
      connection.sessionId !== admission.connection.sessionId ||
      !sameTerminalBinding(connection.binding, admission.connection.binding) ||
      connection.controlEpoch !== admission.connection.controlEpoch ||
      connection.runtimeAuthorizationGeneration !==
        admission.connection.runtimeAuthorizationGeneration
    ) {
      closeUnavailable();
      return;
    }

    // This is a display-mode projection only. Every later PTY mutation still
    // passes through the connection's synchronous, transaction-held `perform`.
    let readOnly = !(await connection.canPerform("input"));

    if (!(await credentialsAreCurrent())) {
      closeUnavailable();
      return;
    }

    if (connection.binding.kind === "local-tmux") {
      const tmuxName = connection.binding.tmuxName;
      if (connection.tmuxName !== undefined && connection.tmuxName !== tmuxName) {
        closeUnavailable();
        return;
      }
      const tmuxSocketName = options.resolveTmuxSocketName(connection.sessionId);
      if (!isValidTmuxSocketName(tmuxSocketName)) {
        closeUnavailable();
        return;
      }
      let tmuxSessionRef: string;
      let tmuxSessionIncarnation: string;
      try {
        const resolvedBinding = options.resolveTmuxSessionRef({
          sessionId: connection.sessionId,
          tmuxName,
          runtimeAuthorizationGeneration: connection.runtimeAuthorizationGeneration,
          tmuxSocketName,
        });
        tmuxSessionRef = resolvedBinding.tmuxSessionRef;
        tmuxSessionIncarnation = resolvedBinding.tmuxSessionIncarnation;
      } catch {
        closeUnavailable();
        return;
      }
      if (
        !isImmutableTmuxSessionRef(tmuxSessionRef) ||
        !isTmuxSessionIncarnation(tmuxSessionIncarnation)
      ) {
        closeUnavailable();
        return;
      }

      pty = options.pty.create({
        tmuxName,
        shell: options.shell,
        cols: admission.route.cols,
        rows: admission.route.rows,
        binding: {
          teamSessionId: admission.route.sessionId,
          runtimeAuthorizationGeneration: connection.runtimeAuthorizationGeneration,
          tmuxSocketName,
          tmuxSessionRef,
          tmuxSessionIncarnation,
          readOnly,
        },
      });
    } else {
      if (!hostedTerminalAdapter) {
        closeUnavailable();
        return;
      }
      const attached = captureHostedTerminalConnection(
        await invokeCapturedPromise(hostedTerminalAdapter.receiver, hostedTerminalAdapter.connect, [
          Object.freeze({
            binding: connection.binding,
            cols: admission.route.cols,
            rows: admission.route.rows,
            signal: abortController.signal,
          }),
        ])
      );
      if (
        abortController.signal.aborted ||
        !sameTerminalBinding(attached.binding, connection.binding)
      ) {
        void destroyHostedTerminal(attached);
        closeUnavailable();
        return;
      }
      // From this point cleanup owns exactly-once destruction, including when
      // any post-connect authorization read throws.
      hostedTerminal = attached;

      // A hosted connect can take materially longer than the local PTY attach.
      // Re-read both credential and exact Session/plan authorization after it
      // completes, before registering output or announcing readiness.
      if (!(await credentialsAreCurrent())) {
        closeUnavailable();
        return;
      }
      const refreshed = await options.terminalGateway.open({
        sessionId: admission.route.sessionId,
        actor: admission.actor,
      });
      if (!sameTerminalConnection(refreshed, connection)) {
        closeUnavailable();
        return;
      }
      connection = refreshed;
      readOnly = !(await connection.canPerform("input"));
      hostedMutationQueue = new HostedTerminalMutationQueue(
        attached,
        abortController.signal,
        (error) => {
          reportError(error, options.reportInternalError);
          closeUnavailable();
        }
      );
    }

    // Start the durable authorization monitor before registering any PTY
    // output forwarding callback.
    void connection
      .monitor({ signal: abortController.signal })
      .then(() => {
        if (!abortController.signal.aborted) closeUnavailable();
      })
      .catch(() => {
        if (!abortController.signal.aborted) closeUnavailable();
      });

    const onTerminalData = (data: unknown): void => {
      if (typeof data !== "string") {
        closeUnavailable();
        return;
      }
      const bytes = Buffer.byteLength(data, "utf8");
      if (bytes > MAX_WEBSOCKET_PAYLOAD_BYTES) {
        closeUnavailable();
        return;
      }
      if (!terminalReady) {
        if (bytes > MAX_BUFFERED_OUTPUT_BYTES - pendingTerminalOutputBytes) {
          closeUnavailable();
          return;
        }
        pendingTerminalOutput.push(data);
        pendingTerminalOutputBytes += bytes;
        return;
      }
      sendJson(webSocket, { type: "terminal.output", data }, closeUnavailable);
    };
    const endTerminal = (): void => {
      sendJson(
        webSocket,
        { type: "terminal.ended", sessionId: admission.route.sessionId },
        closeUnavailable
      );
      cleanup();
      closeWebSocket(webSocket, 4000, "Terminal ended");
    };
    const onTerminalExit = (): void => {
      if (!terminalReady) {
        terminalExitPending = true;
        return;
      }
      endTerminal();
    };
    if (pty) {
      dataSubscription = pty.onData(onTerminalData);
      exitSubscription = pty.onExit(onTerminalExit);
    } else if (hostedTerminal) {
      dataSubscription = captureSubscription(
        Reflect.apply(hostedTerminal.onData, hostedTerminal.receiver, [onTerminalData])
      );
      exitSubscription = captureSubscription(
        Reflect.apply(hostedTerminal.onExit, hostedTerminal.receiver, [onTerminalExit])
      );
    } else {
      closeUnavailable();
      return;
    }
    if (abortController.signal.aborted) {
      dataSubscription?.dispose();
      exitSubscription?.dispose();
      return;
    }

    if (
      !sendJson(
        webSocket,
        {
          type: "terminal.ready",
          sessionId: admission.route.sessionId,
          canInput: !readOnly,
          controlEpoch: connection.controlEpoch,
          runtimeAuthorizationGeneration: connection.runtimeAuthorizationGeneration,
        },
        closeUnavailable
      )
    ) {
      return;
    }
    terminalReady = true;
    for (const data of pendingTerminalOutput.splice(0)) {
      if (abortController.signal.aborted) return;
      pendingTerminalOutputBytes -= Buffer.byteLength(data, "utf8");
      if (!sendJson(webSocket, { type: "terminal.output", data }, closeUnavailable)) return;
    }
    if (terminalExitPending) {
      endTerminal();
      return;
    }

    let messageQueue = Promise.resolve();
    let queuedMessages = 0;
    webSocket.on("message", (rawData, isBinary) => {
      if (queuedMessages >= MAX_QUEUED_TERMINAL_MESSAGES) {
        closeInvalidMessage();
        return;
      }
      queuedMessages += 1;
      messageQueue = messageQueue
        .then(() =>
          enqueueMutation(admission.route.sessionId, async () => {
            if ((!pty && !hostedTerminal) || abortController.signal.aborted) return;
            const message = parseTerminalMessage(rawData, isBinary);
            if (!message) {
              closeInvalidMessage();
              return;
            }
            if (
              message.controlEpoch !== connection.controlEpoch ||
              message.runtimeAuthorizationGeneration !==
                connection.runtimeAuthorizationGeneration ||
              readOnly
            ) {
              closeUnavailable();
              return;
            }
            if (!(await credentialsAreCurrent())) {
              closeUnavailable();
              return;
            }

            const currentPty = pty;
            if (currentPty) {
              switch (message.type) {
                case "input":
                  connection.perform("input", () => {
                    options.pty.write(currentPty, message.data);
                  });
                  break;
                case "resize":
                  connection.perform("resize", () => {
                    options.pty.resize(currentPty, message.cols, message.rows);
                  });
                  break;
                case "interrupt":
                  connection.perform("interrupt", () => {
                    options.pty.interrupt(currentPty);
                  });
                  break;
              }
              return;
            }

            const currentHostedQueue = hostedMutationQueue;
            if (!currentHostedQueue) return;
            switch (message.type) {
              case "input":
                connection.perform("input", () => {
                  currentHostedQueue.enqueue({ type: "input", data: message.data });
                });
                break;
              case "resize":
                connection.perform("resize", () => {
                  currentHostedQueue.enqueue({
                    type: "resize",
                    cols: message.cols,
                    rows: message.rows,
                  });
                });
                break;
              case "interrupt":
                connection.perform("interrupt", () => {
                  currentHostedQueue.enqueue({ type: "interrupt" });
                });
                break;
            }
          })
        )
        .catch(closeUnavailable)
        .finally(() => {
          queuedMessages -= 1;
        });
    });
  } catch (error) {
    reportError(error, options.reportInternalError);
    closeUnavailable();
  }
}

async function serveEvents(
  webSocket: WebSocket,
  admission: EventAdmission,
  options: CreateTeamSessionWebSocketsOptions,
  resolveActor: (headers: RequestHeaders) => Promise<RequestActor | null>,
  credentialCheckIntervalMs: number,
  eventPollIntervalMs: number,
  releaseQuota: () => void
): Promise<void> {
  const abortController = new AbortController();
  let credentialCheckActive = false;
  let cleanedUp = false;

  const cleanup = (): void => {
    if (cleanedUp) return;
    cleanedUp = true;
    abortController.abort();
    clearInterval(credentialTimer);
    releaseQuota();
  };
  const closeUnavailable = (): void => {
    cleanup();
    closeWebSocket(webSocket, 1008, "Session unavailable");
  };
  const credentialsAreCurrent = async (): Promise<boolean> => {
    try {
      const current = await resolveActor(admission.credentials);
      return current?.kind === "human" && current.userId === admission.actor.userId;
    } catch (error) {
      reportError(error, options.reportInternalError);
      return false;
    }
  };

  const credentialTimer = setInterval(() => {
    if (credentialCheckActive || abortController.signal.aborted) return;
    credentialCheckActive = true;
    void credentialsAreCurrent()
      .then((current) => {
        if (!current) closeUnavailable();
      })
      .finally(() => {
        credentialCheckActive = false;
      });
  }, credentialCheckIntervalMs);
  credentialTimer.unref();

  webSocket.once("close", cleanup);
  webSocket.once("error", () => {
    cleanup();
    webSocket.terminate();
  });
  webSocket.once("message", () => {
    cleanup();
    closeWebSocket(webSocket, 1008, "Read-only event stream");
  });

  try {
    if (!(await credentialsAreCurrent())) {
      closeUnavailable();
      return;
    }

    // The pre-upgrade read avoids accepting an unauthorized WebSocket. This
    // second read closes the small upgrade race before private projection data
    // is emitted.
    const currentSession = await options.teamSessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.get",
      sessionId: admission.route.sessionId,
      actor: admission.actor,
    });
    if (!currentSession || currentSession.sessionId !== admission.route.sessionId) {
      closeUnavailable();
      return;
    }
    if (
      !sendJson(
        webSocket,
        {
          type: "session.snapshot",
          session: publicSessionSnapshot(currentSession),
        },
        closeUnavailable
      )
    ) {
      return;
    }
    let latestSequence = currentSession.latestSequence;
    const events = options.teamSessions.follow({
      sessionId: admission.route.sessionId,
      afterSequence: latestSequence,
      actor: admission.actor,
      signal: abortController.signal,
      pollIntervalMs: eventPollIntervalMs,
    });
    const iterator = events[Symbol.asyncIterator]();
    let returnRequested = false;
    const requestFollowerReturn = (): void => {
      if (returnRequested || typeof iterator.return !== "function") return;
      returnRequested = true;
      try {
        void Promise.resolve(iterator.return()).catch((error) =>
          reportError(error, options.reportInternalError)
        );
      } catch (error) {
        reportError(error, options.reportInternalError);
      }
    };
    abortController.signal.addEventListener("abort", requestFollowerReturn, { once: true });
    try {
      while (true) {
        const result = await iterator.next();
        if (result.done) break;
        const event = result.value;
        if (abortController.signal.aborted) return;
        if (
          event.sessionId !== admission.route.sessionId ||
          !Number.isSafeInteger(event.sequence) ||
          event.sequence <= latestSequence
        ) {
          closeUnavailable();
          return;
        }
        latestSequence = event.sequence;
        if (
          !sendJson(
            webSocket,
            { type: "session.event", event: projectPublicSessionEvent(event) },
            closeUnavailable
          )
        ) {
          return;
        }
      }
    } finally {
      abortController.signal.removeEventListener("abort", requestFollowerReturn);
      if (abortController.signal.aborted) requestFollowerReturn();
    }

    if (!abortController.signal.aborted) closeUnavailable();
  } catch (error) {
    if (!abortController.signal.aborted) {
      reportError(error, options.reportInternalError);
      closeUnavailable();
    }
  }
}

type TerminalMessage =
  | {
      type: "input";
      data: string;
      controlEpoch: number;
      runtimeAuthorizationGeneration: number;
    }
  | {
      type: "resize";
      cols: number;
      rows: number;
      controlEpoch: number;
      runtimeAuthorizationGeneration: number;
    }
  | {
      type: "interrupt";
      controlEpoch: number;
      runtimeAuthorizationGeneration: number;
    };

type HostedTerminalMutation =
  | { readonly type: "input"; readonly data: string }
  | { readonly type: "resize"; readonly cols: number; readonly rows: number }
  | { readonly type: "interrupt" };

/**
 * The authorization callback may only synchronously enqueue. Adapter I/O is
 * deferred to a microtask and serialized outside the kernel transaction.
 */
class HostedTerminalMutationQueue {
  private readonly queued: Array<{
    readonly mutation: HostedTerminalMutation;
    readonly bytes: number;
  }> = [];
  private queuedBytes = 0;
  private draining = false;
  private closed = false;

  constructor(
    private readonly terminal: CapturedHostedTerminalConnection,
    private readonly signal: AbortSignal,
    private readonly onFailure: (error: unknown) => void
  ) {}

  enqueue(mutation: HostedTerminalMutation): void {
    const bytes = hostedMutationBytes(mutation);
    if (
      this.closed ||
      this.signal.aborted ||
      this.queued.length >= MAX_QUEUED_HOSTED_MUTATIONS ||
      bytes > MAX_QUEUED_HOSTED_MUTATION_BYTES - this.queuedBytes
    ) {
      throw new Error("Hosted terminal mutation queue unavailable");
    }
    this.queued.push({ mutation: Object.freeze({ ...mutation }), bytes });
    this.queuedBytes += bytes;
    if (this.draining) return;
    this.draining = true;
    queueMicrotask(() => void this.drain());
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.queued.length = 0;
    this.queuedBytes = 0;
  }

  private async drain(): Promise<void> {
    try {
      while (!this.closed && !this.signal.aborted) {
        const entry = this.queued.shift();
        if (!entry) break;
        this.queuedBytes -= entry.bytes;
        await this.dispatch(entry.mutation);
      }
    } catch (error) {
      this.close();
      this.onFailure(error);
    } finally {
      this.draining = false;
    }
  }

  private dispatch(mutation: HostedTerminalMutation): Promise<void> {
    switch (mutation.type) {
      case "input":
        return invokeCapturedVoidPromise(this.terminal.receiver, this.terminal.input, [
          mutation.data,
          this.signal,
        ]);
      case "resize":
        return invokeCapturedVoidPromise(this.terminal.receiver, this.terminal.resize, [
          mutation.cols,
          mutation.rows,
          this.signal,
        ]);
      case "interrupt":
        return invokeCapturedVoidPromise(this.terminal.receiver, this.terminal.interrupt, [
          this.signal,
        ]);
    }
  }
}

function hostedMutationBytes(mutation: HostedTerminalMutation): number {
  switch (mutation.type) {
    case "input":
      return Buffer.byteLength(mutation.data, "utf8");
    case "resize":
      return 16;
    case "interrupt":
      return 1;
  }
}

function parseTerminalMessage(rawData: RawData, isBinary: boolean): TerminalMessage | null {
  if (isBinary) return null;
  let text: string;
  try {
    text = UTF8_DECODER.decode(rawDataToBuffer(rawData));
  } catch {
    return null;
  }

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(value) || typeof value.type !== "string") return null;
  if (!isFence(value.controlEpoch) || !isFence(value.runtimeAuthorizationGeneration)) return null;

  switch (value.type) {
    case "input":
      if (
        !hasExactKeys(value, ["type", "data", "controlEpoch", "runtimeAuthorizationGeneration"])
      ) {
        return null;
      }
      if (
        typeof value.data !== "string" ||
        value.data.length === 0 ||
        Buffer.byteLength(value.data, "utf8") > MAX_TERMINAL_INPUT_BYTES
      ) {
        return null;
      }
      return {
        type: "input",
        data: value.data,
        controlEpoch: value.controlEpoch,
        runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
      };
    case "resize":
      if (
        !hasExactKeys(value, [
          "type",
          "cols",
          "rows",
          "controlEpoch",
          "runtimeAuthorizationGeneration",
        ]) ||
        !Number.isSafeInteger(value.cols) ||
        !Number.isSafeInteger(value.rows) ||
        (value.cols as number) < 1 ||
        (value.cols as number) > 500 ||
        (value.rows as number) < 1 ||
        (value.rows as number) > 200
      ) {
        return null;
      }
      return {
        type: "resize",
        cols: value.cols as number,
        rows: value.rows as number,
        controlEpoch: value.controlEpoch,
        runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
      };
    case "interrupt":
      if (!hasExactKeys(value, ["type", "controlEpoch", "runtimeAuthorizationGeneration"])) {
        return null;
      }
      return {
        type: "interrupt",
        controlEpoch: value.controlEpoch,
        runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
      };
    default:
      return null;
  }
}

function createConnectionQuota(): {
  reserve(kind: CanonicalRouteKind, userId: string, sessionId: string): (() => void) | null;
} {
  const totals: Record<CanonicalRouteKind, number> = { terminal: 0, events: 0 };
  const perUser: Record<CanonicalRouteKind, Map<string, number>> = {
    terminal: new Map(),
    events: new Map(),
  };
  const perSession: Record<CanonicalRouteKind, Map<string, number>> = {
    terminal: new Map(),
    events: new Map(),
  };

  return {
    reserve(kind, userId, sessionId) {
      const limits = CONNECTION_LIMITS[kind];
      const userCount = perUser[kind].get(userId) ?? 0;
      const sessionCount = perSession[kind].get(sessionId) ?? 0;
      if (
        totals[kind] >= limits.global ||
        userCount >= limits.perUser ||
        sessionCount >= limits.perSession
      ) {
        return null;
      }

      totals[kind] += 1;
      perUser[kind].set(userId, userCount + 1);
      perSession[kind].set(sessionId, sessionCount + 1);
      let released = false;
      return () => {
        if (released) return;
        released = true;
        totals[kind] = Math.max(0, totals[kind] - 1);
        decrementConnectionCount(perUser[kind], userId);
        decrementConnectionCount(perSession[kind], sessionId);
      };
    },
  };
}

function decrementConnectionCount(counts: Map<string, number>, key: string): void {
  const next = (counts.get(key) ?? 1) - 1;
  if (next <= 0) counts.delete(key);
  else counts.set(key, next);
}

function parseCanonicalRoute(request: IncomingMessage): CanonicalRoute | null {
  let url: URL;
  try {
    url = new URL(request.url ?? "", "http://terminalx.invalid");
  } catch {
    return null;
  }
  const match = /^\/ws\/team-sessions\/([^/]+)\/(terminal|events)$/.exec(url.pathname);
  if (!match) return null;

  let sessionId: string;
  try {
    sessionId = decodeURIComponent(match[1] ?? "");
  } catch {
    sessionId = "";
  }
  const kind = match[2];
  if (!CANONICAL_SESSION_ID_PATTERN.test(sessionId) || (kind !== "terminal" && kind !== "events")) {
    return {
      kind: kind === "events" ? "events" : "terminal",
      sessionId: "",
      cols: 80,
      rows: 24,
      hasQueryCredential: true,
    };
  }

  let hasQueryCredential = false;
  for (const key of url.searchParams.keys()) {
    if (key.toLowerCase() === "token") hasQueryCredential = true;
  }
  return {
    kind,
    sessionId,
    cols: boundedDimension(url.searchParams.get("cols"), 80, 500),
    rows: boundedDimension(url.searchParams.get("rows"), 24, 200),
    hasQueryCredential,
  };
}

function captureCredentials(request: IncomingMessage): CredentialSnapshot {
  const authorization = headerValue(request, "authorization");
  const cookie = headerValue(request, "cookie");
  const values = Object.freeze({ authorization, cookie });
  const hasSessionCookie = /(?:^|;)\s*terminalx-session=/.test(cookie ?? "");
  return Object.freeze({
    hasSessionCookie,
    get(name: string): string | null {
      switch (name.toLowerCase()) {
        case "authorization":
          return values.authorization;
        case "cookie":
          return values.cookie;
        default:
          return null;
      }
    },
  });
}

function isSameOriginRequest(request: IncomingMessage, credentials: CredentialSnapshot): boolean {
  const originValue = headerValue(request, "origin");
  if (!originValue) return !credentials.hasSessionCookie;
  if (originValue === "null") return false;

  let origin: URL;
  try {
    origin = new URL(originValue);
  } catch {
    return false;
  }
  if (
    (origin.protocol !== "http:" && origin.protocol !== "https:") ||
    originValue !== origin.origin
  ) {
    return false;
  }

  const publicUrl = getPublicUrl();
  if (publicUrl) return origin.origin === new URL(publicUrl).origin;

  let host = headerValue(request, "host");
  let protocol = isEncryptedRequest(request) ? "https" : "http";
  if (trustProxyHeaders()) {
    host = firstForwardedValue(headerValue(request, "x-forwarded-host")) || host;
    const forwardedProtocol = firstForwardedValue(headerValue(request, "x-forwarded-proto"));
    if (forwardedProtocol === "http" || forwardedProtocol === "https") {
      protocol = forwardedProtocol;
    }
  }
  if (!host) return false;
  try {
    return origin.origin === new URL(`${protocol}://${host}`).origin;
  } catch {
    return false;
  }
}

function publicSessionSnapshot(session: SessionView): Record<string, unknown> {
  return {
    sessionId: session.sessionId,
    name: session.name,
    status: session.status,
    steeringPolicy: session.steeringPolicy,
    runtime: {
      kind: session.runtime.kind,
      isolation: session.runtime.isolation,
      yoloEligible: session.runtime.yoloEligible,
      authorizationGeneration: session.runtime.authorizationGeneration,
      authorizationState: session.runtime.authorizationState,
    },
    latestSequence: session.latestSequence,
    createdAtMs: session.createdAtMs,
  };
}

function sendJson(webSocket: WebSocket, value: unknown, onBackpressure: () => void): boolean {
  if (webSocket.readyState !== WebSocket.OPEN) {
    onBackpressure();
    return false;
  }
  let payload: string;
  try {
    payload = JSON.stringify(value);
  } catch {
    onBackpressure();
    return false;
  }
  if (
    webSocket.bufferedAmount > MAX_BUFFERED_OUTPUT_BYTES ||
    Buffer.byteLength(payload, "utf8") > MAX_BUFFERED_OUTPUT_BYTES - webSocket.bufferedAmount
  ) {
    onBackpressure();
    return false;
  }
  try {
    webSocket.send(payload);
    return true;
  } catch {
    onBackpressure();
    return false;
  }
}

function rejectUpgrade(socket: Duplex, status: number, reason: string): void {
  if (socket.destroyed) return;
  socket.write(
    `HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n`
  );
  socket.destroy();
}

function closeWebSocket(webSocket: WebSocket, code: number, reason: string): void {
  if (webSocket.readyState !== WebSocket.OPEN) return;
  try {
    webSocket.close(code, reason);
  } catch {
    webSocket.terminate();
  }
}

function closeWebSocketServer(server: WebSocketServer): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

function settleWithin(
  settlements: readonly Promise<unknown>[],
  timeoutMs: number
): Promise<boolean> {
  if (settlements.length === 0) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    timer.unref();
    void Promise.allSettled(settlements).then((results) => {
      clearTimeout(timer);
      resolve(results.every((result) => result.status === "fulfilled"));
    });
  });
}

function captureHostedTerminalAdapter(
  value: CanonicalHostedTerminalAdapter
): CapturedHostedTerminalAdapter {
  const receiver = safeObject(value);
  return Object.freeze({ receiver, connect: captureDataMethod(receiver, "connect") });
}

function captureHostedTerminalConnection(value: unknown): CapturedHostedTerminalConnection {
  const receiver = safeObject(value);
  return Object.freeze({
    receiver,
    binding: snapshotHostedTerminalBinding(captureDataProperty(receiver, "binding")),
    onData: captureDataMethod(receiver, "onData"),
    onExit: captureDataMethod(receiver, "onExit"),
    input: captureDataMethod(receiver, "input"),
    resize: captureDataMethod(receiver, "resize"),
    interrupt: captureDataMethod(receiver, "interrupt"),
    destroy: captureDataMethod(receiver, "destroy"),
  });
}

function captureSubscription(value: unknown): { dispose(): void } {
  const receiver = safeObject(value);
  const dispose = captureDataMethod(receiver, "dispose");
  return Object.freeze({
    dispose(): void {
      const result = Reflect.apply(dispose, receiver, []);
      if (result !== undefined) throw new TypeError();
    },
  });
}

function captureDataMethod(receiver: object, name: string): AnyFunction {
  const value = captureDataProperty(receiver, name);
  if (typeof value !== "function") throw new TypeError();
  return value as AnyFunction;
}

function captureDataProperty(receiver: object, name: string): unknown {
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) throw new TypeError();
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor)) throw new TypeError();
      return descriptor.value;
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

function snapshotHostedTerminalBinding(value: unknown): HostedTeamSessionTerminalBinding {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  if (
    !isRecord(snapshot) ||
    !hasExactKeys(snapshot, [
      "kind",
      "binding",
      "runtimeAuthorizationGeneration",
      "assignmentPlanDigest",
      "incarnation",
      "specificationDigest",
    ]) ||
    snapshot.kind !== "hosted" ||
    !isRecord(snapshot.binding) ||
    !hasExactKeys(snapshot.binding, [
      "teamId",
      "projectId",
      "sessionId",
      "runtimeAssignmentId",
      "runtimeAssignmentGeneration",
      "sandboxId",
      "sandboxGeneration",
      "runtimePrincipalId",
    ]) ||
    !isSafeReference(snapshot.binding.teamId) ||
    !isSafeReference(snapshot.binding.projectId) ||
    !isSafeReference(snapshot.binding.sessionId) ||
    !isSafeReference(snapshot.binding.runtimeAssignmentId) ||
    !isPositiveFence(snapshot.binding.runtimeAssignmentGeneration) ||
    !isSafeReference(snapshot.binding.sandboxId) ||
    !isPositiveFence(snapshot.binding.sandboxGeneration) ||
    !isSafeReference(snapshot.binding.runtimePrincipalId) ||
    !isPositiveFence(snapshot.runtimeAuthorizationGeneration) ||
    !isSha256(snapshot.assignmentPlanDigest) ||
    !isSha256(snapshot.incarnation) ||
    !isSha256(snapshot.specificationDigest)
  ) {
    throw new TypeError();
  }
  return snapshot as unknown as HostedTeamSessionTerminalBinding;
}

function invokeCapturedPromise(
  receiver: object,
  method: AnyFunction,
  args: readonly unknown[]
): Promise<unknown> {
  try {
    return Promise.resolve(Reflect.apply(method, receiver, [...args]));
  } catch (error) {
    return Promise.reject(error);
  }
}

function invokeCapturedVoidPromise(
  receiver: object,
  method: AnyFunction,
  args: readonly unknown[]
): Promise<void> {
  return invokeCapturedPromise(receiver, method, args).then((result) => {
    if (result !== undefined) throw new TypeError();
  });
}

function reportError(_error: unknown, reporter: ((errorName: string) => void) | undefined): void {
  if (!reporter) return;
  reporter("InternalError");
}

function headerValue(request: IncomingMessage, name: string): string | null {
  const value = request.headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(",");
  return value ?? null;
}

function firstForwardedValue(value: string | null): string | null {
  return value?.split(",", 1)[0]?.trim().toLowerCase() || null;
}

function isEncryptedRequest(request: IncomingMessage): boolean {
  return Boolean((request.socket as typeof request.socket & { encrypted?: boolean }).encrypted);
}

function rawDataToBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  return Buffer.concat(data);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isFence(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
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
    left.binding.teamId === right.binding.teamId &&
    left.binding.projectId === right.binding.projectId &&
    left.binding.sessionId === right.binding.sessionId &&
    left.binding.runtimeAssignmentId === right.binding.runtimeAssignmentId &&
    left.binding.runtimeAssignmentGeneration === right.binding.runtimeAssignmentGeneration &&
    left.binding.sandboxId === right.binding.sandboxId &&
    left.binding.sandboxGeneration === right.binding.sandboxGeneration &&
    left.binding.runtimePrincipalId === right.binding.runtimePrincipalId
  );
}

function sameTerminalConnection(
  left: CanonicalTerminalConnection,
  right: CanonicalTerminalConnection
): boolean {
  return (
    left.sessionId === right.sessionId &&
    left.controlEpoch === right.controlEpoch &&
    left.runtimeAuthorizationGeneration === right.runtimeAuthorizationGeneration &&
    sameTerminalBinding(left.binding, right.binding)
  );
}

function isSafeReference(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 300 &&
    value.trim() === value &&
    !/[\0\r\n\t]/.test(value)
  );
}

function isPositiveFence(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function boundedDimension(value: string | null, fallback: number, maximum: number): number {
  if (!value || !/^[1-9][0-9]*$/.test(value)) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? Math.min(parsed, maximum) : fallback;
}

function assertFactoryOptions(options: CreateTeamSessionWebSocketsOptions): void {
  const credentialInterval =
    options.credentialCheckIntervalMs ?? DEFAULT_CREDENTIAL_CHECK_INTERVAL_MS;
  const eventInterval = options.eventPollIntervalMs ?? DEFAULT_EVENT_POLL_INTERVAL_MS;
  if (
    typeof options.resolveTmuxSocketName !== "function" ||
    typeof options.resolveTmuxSessionRef !== "function" ||
    !options.shell ||
    options.shell.length > 4_096 ||
    /[\0\r\n]/.test(options.shell) ||
    !Number.isSafeInteger(credentialInterval) ||
    credentialInterval < 10 ||
    credentialInterval > 2_000 ||
    !Number.isSafeInteger(eventInterval) ||
    eventInterval < 10 ||
    eventInterval > 5_000
  ) {
    throw new TypeError("Invalid canonical Team Session WebSocket configuration");
  }
}

function isValidTmuxSocketName(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value);
}

function isImmutableTmuxSessionRef(value: unknown): value is string {
  return typeof value === "string" && /^\$[0-9]{1,20}$/.test(value);
}

function isTmuxSessionIncarnation(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
