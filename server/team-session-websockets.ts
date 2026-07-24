import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { TextDecoder } from "node:util";
import { WebSocket, WebSocketServer, type RawData } from "ws";
import {
  resolveRequestActor,
  type RequestActor,
  type RequestHeaders,
} from "../src/lib/request-actor";
import { getPublicUrl, trustProxyHeaders } from "../src/lib/security-config";
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
const DEFAULT_CREDENTIAL_CHECK_INTERVAL_MS = 1_000;
const DEFAULT_EVENT_POLL_INTERVAL_MS = 100;
const CONNECTION_LIMITS = Object.freeze({
  terminal: { perUser: 2, perSession: 8, global: 16 },
  events: { perUser: 4, perSession: 32, global: 256 },
});
const CANONICAL_SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$/;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

type TerminalMutationAction = "input" | "resize" | "interrupt";
type HumanActorContext = ActorContext & { kind: "human" };

export interface CanonicalTerminalConnection {
  readonly sessionId: string;
  readonly tmuxName: string;
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
      readOnly: boolean;
    };
  }): CanonicalTerminalPty;
  write(pty: CanonicalTerminalPty, data: string): void;
  resize(pty: CanonicalTerminalPty, cols: number, rows: number): void;
  interrupt(pty: CanonicalTerminalPty): void;
  destroy(pty: CanonicalTerminalPty): void;
}

export interface TeamSessionEventKernel {
  inspect(query: SessionGetQuery): Promise<SessionView | null>;
  follow(options: FollowSessionOptions): AsyncIterable<SessionEvent>;
}

export interface CreateTeamSessionWebSocketsOptions {
  teamSessions: TeamSessionEventKernel;
  terminalGateway: CanonicalTerminalGateway;
  pty: CanonicalTerminalPtyAdapter;
  /** Resolve the isolated tmux server for one canonical Team Session. */
  resolveTmuxSocketName: (sessionId: string) => string;
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
  const connectionQuota = createConnectionQuota();
  let closed = false;

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
            void serveTerminal(
              webSocket,
              {
                actor,
                credentials,
                route,
                connection,
              },
              options,
              resolveActor,
              credentialCheckIntervalMs,
              enqueueMutation,
              releaseQuota
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
          void serveEvents(
            webSocket,
            { actor, credentials, route, session },
            options,
            resolveActor,
            credentialCheckIntervalMs,
            eventPollIntervalMs,
            releaseQuota
          );
        });
      } catch (error) {
        releaseQuota();
        reportError(error, options.reportInternalError);
        rejectUpgrade(socket, 503, "Service Unavailable");
      }
      return true;
    },

    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      for (const webSocket of terminalWebSocketServer.clients) webSocket.terminate();
      for (const webSocket of eventWebSocketServer.clients) webSocket.terminate();
      await Promise.all([
        closeWebSocketServer(terminalWebSocketServer),
        closeWebSocketServer(eventWebSocketServer),
      ]);
    },
  };
}

async function serveTerminal(
  webSocket: WebSocket,
  admission: TerminalAdmission,
  options: CreateTeamSessionWebSocketsOptions,
  resolveActor: (headers: RequestHeaders) => Promise<RequestActor | null>,
  credentialCheckIntervalMs: number,
  enqueueMutation: (sessionId: string, mutation: () => Promise<void>) => Promise<void>,
  releaseQuota: () => void
): Promise<void> {
  const abortController = new AbortController();
  let pty: CanonicalTerminalPty | undefined;
  let dataSubscription: { dispose(): void } | undefined;
  let exitSubscription: { dispose(): void } | undefined;
  let cleanedUp = false;
  let credentialCheckActive = false;

  const cleanup = (): void => {
    if (cleanedUp) return;
    cleanedUp = true;
    abortController.abort();
    clearInterval(credentialTimer);
    releaseQuota();
    dataSubscription?.dispose();
    exitSubscription?.dispose();
    if (pty) options.pty.destroy(pty);
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
    const connection = await options.terminalGateway.open({
      sessionId: admission.route.sessionId,
      actor: admission.actor,
    });
    if (
      connection.sessionId !== admission.route.sessionId ||
      connection.sessionId !== admission.connection.sessionId ||
      connection.tmuxName !== admission.connection.tmuxName ||
      connection.controlEpoch !== admission.connection.controlEpoch ||
      connection.runtimeAuthorizationGeneration !==
        admission.connection.runtimeAuthorizationGeneration
    ) {
      closeUnavailable();
      return;
    }

    // This is a display-mode projection only. Every later PTY mutation still
    // passes through the connection's synchronous, transaction-held `perform`.
    const readOnly = !(await connection.canPerform("input"));

    if (!(await credentialsAreCurrent())) {
      closeUnavailable();
      return;
    }

    const tmuxSocketName = options.resolveTmuxSocketName(connection.sessionId);
    if (!isValidTmuxSocketName(tmuxSocketName)) {
      closeUnavailable();
      return;
    }

    pty = options.pty.create({
      tmuxName: connection.tmuxName,
      shell: options.shell,
      cols: admission.route.cols,
      rows: admission.route.rows,
      binding: {
        teamSessionId: admission.route.sessionId,
        runtimeAuthorizationGeneration: connection.runtimeAuthorizationGeneration,
        tmuxSocketName,
        readOnly,
      },
    });

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

    dataSubscription = pty.onData((data) => {
      sendJson(webSocket, { type: "terminal.output", data }, closeUnavailable);
    });
    exitSubscription = pty.onExit(() => {
      sendJson(
        webSocket,
        { type: "terminal.ended", sessionId: admission.route.sessionId },
        closeUnavailable
      );
      cleanup();
      closeWebSocket(webSocket, 4000, "Terminal ended");
    });

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
            if (!pty || abortController.signal.aborted) return;
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
            if (!currentPty) return;
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
    for await (const event of options.teamSessions.follow({
      sessionId: admission.route.sessionId,
      afterSequence: latestSequence,
      actor: admission.actor,
      signal: abortController.signal,
      pollIntervalMs: eventPollIntervalMs,
    })) {
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
