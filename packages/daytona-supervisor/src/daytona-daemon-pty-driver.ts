import { request as httpRequest, type IncomingMessage, type RequestOptions } from "node:http";
import { types as nodeTypes } from "node:util";
import WebSocket, { type RawData } from "ws";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import {
  type DaytonaSupervisorPtyDriver,
  type DaytonaSupervisorPtyDriverConnection,
  type DaytonaSupervisorPtyDriverOpenRequest,
} from "./pty-registry";
import { DaytonaSupervisorProtocolError } from "./supervisor";

const FIXED_DAEMON_SOCKET = "/run/terminalx-private/daytona-daemon.sock" as const;
const FIXED_WORKING_DIRECTORY = "/home/terminalx" as const;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_PENDING_WEBSOCKET_BYTES = 1024 * 1024;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 60_000;

export interface CreateDaytonaDaemonPtyDriverOptions {
  readonly requestTimeoutMs: number;
  readonly maximumPendingWebSocketBytes: number;
}

/**
 * Fixed root-only Unix-socket adapter to the pinned Daytona daemon's native
 * creack/pty implementation. Root init owns the pathname and passes the
 * listening descriptor to the non-dumpable daemon; the terminalx uid cannot
 * traverse the socket directory or recover the daemon descriptor. No caller
 * can select a command, cwd, environment, URL, or credential.
 */
export function createDaytonaDaemonPtyDriver(
  unsafeOptions: CreateDaytonaDaemonPtyDriverOptions
): DaytonaSupervisorPtyDriver {
  const options = captureOptions(unsafeOptions);
  const connections = new Set<DaemonPtyConnection>();
  let closed = false;
  return Object.freeze({
    async open(
      request: DaytonaSupervisorPtyDriverOpenRequest,
      signal: AbortSignal
    ): Promise<DaytonaSupervisorPtyDriverConnection> {
      if (closed) unavailable();
      assertSignal(signal);
      const snapshot = snapshotOpenRequest(request);
      const body = Buffer.from(
        canonicalRuntimeJson({
          cols: snapshot.cols,
          cwd: FIXED_WORKING_DIRECTORY,
          envs: { TERM: "xterm-256color" },
          id: snapshot.terminalId,
          lazyStart: true,
          rows: snapshot.rows,
          sanitizeEnv: true,
        }),
        "utf8"
      );
      try {
        await createDaemonTerminal(snapshot.terminalId, body, options.requestTimeoutMs, signal);
      } finally {
        body.fill(0);
      }
      let connection: DaemonPtyConnection | null = null;
      try {
        connection = await DaemonPtyConnection.connect(snapshot.terminalId, options, signal);
        connections.add(connection);
        connection.onDriverExit(() => connections.delete(connection as DaemonPtyConnection));
        return connection.facade();
      } catch {
        await connection?.destroy().catch(() => undefined);
        await deleteDaemonTerminal(snapshot.terminalId, options.requestTimeoutMs).catch(
          () => undefined
        );
        unavailable();
      }
    },
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      await Promise.allSettled([...connections].map((connection) => connection.destroy()));
      connections.clear();
    },
  });
}

interface CapturedOptions {
  readonly requestTimeoutMs: number;
  readonly maximumPendingWebSocketBytes: number;
}

class DaemonPtyConnection {
  private readonly dataListeners = new Set<(bytes: Uint8Array) => void>();
  private readonly exitListeners = new Set<() => void>();
  private readonly driverExitListeners = new Set<() => void>();
  private readonly pending: Buffer[] = [];
  private pendingBytes = 0;
  private connected = false;
  private exited = false;
  private destroying: Promise<void> | null = null;

  private constructor(
    private readonly terminalId: string,
    private readonly socket: WebSocket,
    private readonly options: CapturedOptions
  ) {
    socket.binaryType = "nodebuffer";
    socket.on("message", (data, isBinary) => this.receive(data, isBinary));
    socket.once("close", () => this.exit());
    socket.once("error", () => this.exit());
  }

  static async connect(
    terminalId: string,
    options: CapturedOptions,
    signal: AbortSignal
  ): Promise<DaemonPtyConnection> {
    assertSignal(signal);
    const socket = new WebSocket(
      `ws+unix://${FIXED_DAEMON_SOCKET}:/process/pty/${encodeURIComponent(terminalId)}/connect`,
      {
        followRedirects: false,
        handshakeTimeout: options.requestTimeoutMs,
        maxPayload: 64 * 1024,
        perMessageDeflate: false,
      }
    );
    const connection = new DaemonPtyConnection(terminalId, socket, options);
    try {
      await connection.waitUntilConnected(signal);
      return connection;
    } catch {
      socket.terminate();
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
  }

  facade(): DaytonaSupervisorPtyDriverConnection {
    return Object.freeze({
      onData: (listener: (bytes: Uint8Array) => void) => this.onData(listener),
      onExit: (listener: () => void) => this.onExit(listener),
      input: (bytes: Uint8Array, signal: AbortSignal) => this.input(bytes, signal),
      resize: (cols: number, rows: number, signal: AbortSignal) => this.resize(cols, rows, signal),
      interrupt: (signal: AbortSignal) => this.interrupt(signal),
      destroy: () => this.destroy(),
      pause: () => this.socket.pause(),
      resume: () => this.socket.resume(),
    });
  }

  onDriverExit(listener: () => void): void {
    this.driverExitListeners.add(listener);
  }

  onData(listener: (bytes: Uint8Array) => void): { dispose(): void } {
    if (typeof listener !== "function" || nodeTypes.isProxy(listener) || this.exited) unavailable();
    this.dataListeners.add(listener);
    const pending = this.pending.splice(0);
    this.pendingBytes = 0;
    try {
      for (const bytes of pending) listener(bytes);
    } catch {
      void this.destroy().catch(() => undefined);
      unavailable();
    } finally {
      for (const bytes of pending) bytes.fill(0);
    }
    return Object.freeze({ dispose: () => this.dataListeners.delete(listener) });
  }

  onExit(listener: () => void): { dispose(): void } {
    if (typeof listener !== "function" || nodeTypes.isProxy(listener)) unavailable();
    this.exitListeners.add(listener);
    if (this.exited) listener();
    return Object.freeze({ dispose: () => this.exitListeners.delete(listener) });
  }

  async input(unsafeBytes: Uint8Array, signal: AbortSignal): Promise<void> {
    assertSignal(signal);
    if (
      this.exited ||
      !(unsafeBytes instanceof Uint8Array) ||
      nodeTypes.isProxy(unsafeBytes) ||
      unsafeBytes.byteLength < 1 ||
      this.socket.readyState !== WebSocket.OPEN ||
      this.socket.bufferedAmount + unsafeBytes.byteLength >
        this.options.maximumPendingWebSocketBytes
    ) {
      unavailable();
    }
    const bytes = Buffer.from(unsafeBytes);
    try {
      await new Promise<void>((resolve, reject) => {
        const abort = (): void => reject(new DaytonaSupervisorProtocolError("unavailable"));
        signal.addEventListener("abort", abort, { once: true });
        this.socket.send(bytes, { binary: true, compress: false }, (error) => {
          signal.removeEventListener("abort", abort);
          if (error || signal.aborted) reject(new DaytonaSupervisorProtocolError("unavailable"));
          else resolve();
        });
      });
    } finally {
      bytes.fill(0);
    }
  }

  async resize(cols: number, rows: number, signal: AbortSignal): Promise<void> {
    assertSignal(signal);
    if (this.exited) unavailable();
    const body = Buffer.from(canonicalRuntimeJson({ cols, rows }), "utf8");
    try {
      const response = await daemonRequest(
        "POST",
        `/process/pty/${encodeURIComponent(this.terminalId)}/resize`,
        body,
        200,
        this.options.requestTimeoutMs,
        signal
      );
      response.body.fill(0);
    } finally {
      body.fill(0);
    }
  }

  interrupt(signal: AbortSignal): Promise<void> {
    return this.input(Uint8Array.of(3), signal);
  }

  destroy(): Promise<void> {
    if (this.destroying) return this.destroying;
    this.destroying = (async () => {
      if (this.socket.readyState === WebSocket.OPEN) {
        this.socket.close(1000);
      } else if (this.socket.readyState !== WebSocket.CLOSED) {
        this.socket.terminate();
      }
      await deleteDaemonTerminal(this.terminalId, this.options.requestTimeoutMs).catch(
        () => undefined
      );
      this.exit();
    })();
    return this.destroying;
  }

  private waitUntilConnected(signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const abort = (): void => fail();
      const onControl = (data: RawData, isBinary: boolean): void => {
        if (isBinary) return;
        try {
          const text = rawDataBuffer(data).toString("utf8");
          const parsed = JSON.parse(text) as unknown;
          if (
            typeof parsed !== "object" ||
            parsed === null ||
            Array.isArray(parsed) ||
            Reflect.ownKeys(parsed).length !== 2 ||
            (parsed as { status?: unknown }).status !== "connected" ||
            (parsed as { type?: unknown }).type !== "control"
          ) {
            fail();
            return;
          }
          cleanup();
          this.connected = true;
          resolve();
        } catch {
          fail();
        }
      };
      const fail = (): void => {
        cleanup();
        reject(new DaytonaSupervisorProtocolError("unavailable"));
      };
      const cleanup = (): void => {
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        this.socket.removeListener("message", onControl);
        this.socket.removeListener("close", fail);
        this.socket.removeListener("error", fail);
      };
      const timer = setTimeout(fail, this.options.requestTimeoutMs);
      timer.unref();
      signal.addEventListener("abort", abort, { once: true });
      this.socket.on("message", onControl);
      this.socket.once("close", fail);
      this.socket.once("error", fail);
    });
  }

  private receive(data: RawData, isBinary: boolean): void {
    if (this.exited || !this.connected) return;
    if (!isBinary) {
      void this.destroy().catch(() => undefined);
      return;
    }
    const bytes = rawDataBuffer(data);
    if (bytes.byteLength < 1) return;
    if (this.dataListeners.size === 0) {
      this.pendingBytes += bytes.byteLength;
      if (this.pendingBytes > this.options.maximumPendingWebSocketBytes) {
        bytes.fill(0);
        void this.destroy().catch(() => undefined);
        return;
      }
      this.pending.push(bytes);
      return;
    }
    try {
      for (const listener of this.dataListeners) listener(bytes);
    } catch {
      void this.destroy().catch(() => undefined);
    } finally {
      bytes.fill(0);
    }
  }

  private exit(): void {
    if (this.exited) return;
    this.exited = true;
    for (const bytes of this.pending.splice(0)) bytes.fill(0);
    this.pendingBytes = 0;
    for (const listener of this.exitListeners) {
      try {
        listener();
      } catch {
        // A listener cannot keep a dead PTY alive.
      }
    }
    for (const listener of this.driverExitListeners) listener();
    this.dataListeners.clear();
    this.exitListeners.clear();
    this.driverExitListeners.clear();
  }
}

function captureOptions(value: CreateDaytonaDaemonPtyDriverOptions): CapturedOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Reflect.ownKeys(value).length !== 2 ||
    !Object.prototype.hasOwnProperty.call(value, "requestTimeoutMs") ||
    !Object.prototype.hasOwnProperty.call(value, "maximumPendingWebSocketBytes")
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    requestTimeoutMs: boundedInteger(value.requestTimeoutMs, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS),
    maximumPendingWebSocketBytes: boundedInteger(
      value.maximumPendingWebSocketBytes,
      64 * 1024,
      MAX_PENDING_WEBSOCKET_BYTES
    ),
  });
}

function snapshotOpenRequest(value: DaytonaSupervisorPtyDriverOpenRequest) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Reflect.ownKeys(value).length !== 3
  ) {
    throw new TypeError();
  }
  if (
    typeof value.terminalId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value.terminalId
    ) ||
    !Number.isSafeInteger(value.cols) ||
    value.cols < 2 ||
    value.cols > 500 ||
    !Number.isSafeInteger(value.rows) ||
    value.rows < 2 ||
    value.rows > 300
  ) {
    throw new TypeError();
  }
  return Object.freeze({ terminalId: value.terminalId, cols: value.cols, rows: value.rows });
}

function requireCreatedResponse(bytes: Buffer, terminalId: string): void {
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    unavailable();
  }
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== 1 ||
    (value as { sessionId?: unknown }).sessionId !== terminalId
  ) {
    unavailable();
  }
  if (canonicalRuntimeJson(value) !== bytes.toString("utf8")) unavailable();
}

async function deleteDaemonTerminal(terminalId: string, timeoutMs: number): Promise<void> {
  const signal = AbortSignal.timeout(timeoutMs);
  const response = await daemonRequest(
    "DELETE",
    `/process/pty/${encodeURIComponent(terminalId)}`,
    null,
    [200, 404],
    timeoutMs,
    signal
  );
  response.body.fill(0);
}

/**
 * Creation is not idempotent at the daemon boundary even though TerminalX
 * supplies a deterministic UUID. A transport failure may therefore mean the
 * daemon committed the PTY but its 201 response was lost. Always reconcile an
 * unsuccessful create with an independently-timed DELETE. A 409 is the one
 * unambiguous stale-identity case: after deleting it, retry exactly once while
 * the caller's operation is still live.
 */
async function createDaemonTerminal(
  terminalId: string,
  body: Buffer,
  timeoutMs: number,
  signal: AbortSignal
): Promise<void> {
  try {
    const first = await daemonRequest("POST", "/process/pty", body, [201, 409], timeoutMs, signal);
    try {
      if (first.statusCode === 201) {
        requireCreatedResponse(first.body, terminalId);
        return;
      }
    } finally {
      first.body.fill(0);
    }

    await deleteDaemonTerminal(terminalId, timeoutMs);
    assertSignal(signal);
    const retry = await daemonRequest("POST", "/process/pty", body, 201, timeoutMs, signal);
    try {
      requireCreatedResponse(retry.body, terminalId);
    } finally {
      retry.body.fill(0);
    }
  } catch {
    // Never reuse the caller's possibly-aborted signal for reconciliation. A
    // successful remote create must not survive merely because its response
    // crossed the operation timeout.
    await deleteDaemonTerminal(terminalId, timeoutMs).catch(() => undefined);
    unavailable();
  }
}

interface DaemonResponse {
  readonly statusCode: number;
  readonly body: Buffer;
}

async function daemonRequest(
  method: "POST" | "DELETE",
  path: string,
  body: Buffer | null,
  expectedStatus: number | readonly number[],
  timeoutMs: number,
  signal: AbortSignal
): Promise<DaemonResponse> {
  assertSignal(signal);
  const expected = Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus];
  const options: RequestOptions = {
    socketPath: FIXED_DAEMON_SOCKET,
    method,
    path,
    agent: false,
    headers: {
      accept: "application/json",
      ...(body
        ? {
            "content-length": String(body.byteLength),
            "content-type": "application/json",
          }
        : { "content-length": "0" }),
    },
    signal,
  };
  const response = await new Promise<IncomingMessage>((resolve, reject) => {
    const request = httpRequest(options, resolve);
    const timer = setTimeout(() => request.destroy(), timeoutMs);
    timer.unref();
    request.once("close", () => clearTimeout(timer));
    request.once("error", reject);
    if (body) request.end(body);
    else request.end();
  }).catch(() => unavailable());
  if (
    !expected.includes(response.statusCode ?? 0) ||
    response.headers["content-type"] !== "application/json; charset=utf-8" ||
    response.headers.location !== undefined ||
    response.headers["content-encoding"] !== undefined
  ) {
    response.destroy();
    unavailable();
  }
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const rawChunk of response) {
      const chunk = Buffer.isBuffer(rawChunk) ? Buffer.from(rawChunk) : Buffer.from(rawChunk);
      size += chunk.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        chunk.fill(0);
        unavailable();
      }
      chunks.push(chunk);
    }
    return Object.freeze({
      statusCode: response.statusCode as number,
      body: Buffer.concat(chunks, size),
    });
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function rawDataBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return Buffer.from(data);
  if (Array.isArray(data)) return Buffer.concat(data.map((item) => Buffer.from(item)));
  return Buffer.from(data as ArrayBuffer);
}

function assertSignal(signal: unknown): asserts signal is AbortSignal {
  if (!(signal instanceof AbortSignal) || nodeTypes.isProxy(signal) || signal.aborted)
    unavailable();
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError();
  }
  return value as number;
}

function unavailable(): never {
  throw new DaytonaSupervisorProtocolError("unavailable");
}
