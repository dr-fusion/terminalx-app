import { randomBytes } from "node:crypto";
import { chmodSync, lstatSync, realpathSync, type Stats } from "node:fs";
import { dirname, isAbsolute, normalize, relative, sep } from "node:path";
import { createConnection, createServer, type Server as NetServer, type Socket } from "node:net";
import { types as nodeTypes } from "node:util";
import type { DaytonaSupervisorPtyService, DaytonaSupervisorPtyStreamItem } from "./pty-registry";
import type {
  DaytonaSupervisorCommandOutcome,
  DaytonaSupervisorCommandRequest,
  DaytonaSupervisorFollowRequest,
  DaytonaSupervisorIsolationRequest,
  PinnedDaytonaSupervisorTransport,
} from "../../../src/lib/runtime/daytona-hosted-control-plane";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import {
  DAYTONA_SUPERVISOR_SOCKET_MAX_FRAME_BYTES,
  DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
  DaytonaSupervisorSocketFrameDecoder,
  encodeDaytonaSupervisorSocketFrame,
  snapshotDaytonaSupervisorSocketInboundFrame,
  snapshotDaytonaSupervisorSocketOutboundFrame,
  type DaytonaSupervisorSocketInboundFrame,
  type DaytonaSupervisorSocketMethod,
  type DaytonaSupervisorSocketOutboundFrame,
} from "./socket-framing";
import {
  DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
  DaytonaSupervisorProtocolError,
  type DaytonaSupervisorProtocolErrorCode,
} from "./supervisor";

const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 10 * 60_000;
const MAX_TERMINAL_TIMEOUT_MS = 7 * 24 * 60 * 60_000;
const MAX_INFLIGHT_REQUESTS = 128;
const MAX_CONNECT_ATTEMPTS = 4;
const MAX_PENDING_STREAM_ITEMS = 64;

export interface DaytonaSupervisorUnixPeerCredentials {
  readonly pid: number;
  readonly uid: number;
  readonly gid: number;
}

/**
 * Production implementations must obtain SO_PEERCRED from the accepted
 * descriptor. Filesystem ownership alone does not authenticate a connected
 * process after accept(2).
 */
export type DaytonaSupervisorUnixPeerCredentialVerifier = (
  socket: Socket,
  signal: AbortSignal
) => Promise<DaytonaSupervisorUnixPeerCredentials>;

export interface CreateDaytonaSupervisorUnixSocketServerOptions {
  readonly supervisor: PinnedDaytonaSupervisorTransport;
  readonly terminal: DaytonaSupervisorPtyService;
  readonly socketDirectory: string;
  readonly socketPath: string;
  readonly expectedOwnerUid: number;
  readonly expectedPeerUid: number;
  readonly expectedPeerGid?: number;
  readonly verifyPeerCredentials: DaytonaSupervisorUnixPeerCredentialVerifier;
  readonly authenticationTimeoutMs?: number;
  readonly requestTimeoutMs?: number;
  readonly terminalRequestTimeoutMs?: number;
  readonly maximumFrameBytes?: number;
  readonly maximumInflightRequests?: number;
}

export interface DaytonaSupervisorUnixSocketServer {
  readonly socketPath: string;
  listen(): Promise<void>;
  wait(): Promise<void>;
  close(): Promise<void>;
}

export interface CreateUnixSocketDaytonaSupervisorTransportOptions {
  readonly socketDirectory: string;
  readonly socketPath: string;
  readonly expectedOwnerUid: number;
  readonly connectTimeoutMs?: number;
  readonly requestTimeoutMs?: number;
  readonly maximumFrameBytes?: number;
  readonly connectAttempts?: number;
  readonly reconnectDelayMs?: number;
}

export interface DaytonaSupervisorPtySocketTransport {
  openTerminal(
    request: unknown,
    signal: AbortSignal
  ): AsyncIterable<DaytonaSupervisorPtyStreamItem>;
  terminalInput(request: unknown, signal: AbortSignal): Promise<void>;
  terminalResize(request: unknown, signal: AbortSignal): Promise<void>;
  terminalInterrupt(request: unknown, signal: AbortSignal): Promise<void>;
  terminalDestroy(request: unknown, signal: AbortSignal): Promise<void>;
}

/** Root-side listener. No TCP listener, bearer credential, or agent-readable socket is created. */
export function createDaytonaSupervisorUnixSocketServer(
  unsafeOptions: CreateDaytonaSupervisorUnixSocketServerOptions
): DaytonaSupervisorUnixSocketServer {
  return new RootOwnedUnixSocketServer(unsafeOptions);
}

/**
 * Root relay/client transport. A disconnected request fails closed; a later
 * request reconnects after revalidating the exact socket inode boundary.
 * Command retry remains the caller's explicit idempotent operation retry.
 */
export function createUnixSocketDaytonaSupervisorTransport(
  unsafeOptions: CreateUnixSocketDaytonaSupervisorTransportOptions
): PinnedDaytonaSupervisorTransport & DaytonaSupervisorPtySocketTransport {
  return new UnixSocketSupervisorClient(unsafeOptions);
}

class RootOwnedUnixSocketServer implements DaytonaSupervisorUnixSocketServer {
  readonly socketPath: string;
  private readonly options: CapturedServerOptions;
  private readonly server: NetServer;
  private readonly connections = new Set<Socket>();
  private listening = false;
  private closing: Promise<void> | null = null;
  private readonly done: Promise<void>;
  private readonly resolveDone: () => void;

  constructor(unsafeOptions: CreateDaytonaSupervisorUnixSocketServerOptions) {
    let resolveDone!: () => void;
    this.done = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });
    this.resolveDone = resolveDone;
    this.options = captureServerOptions(unsafeOptions);
    this.socketPath = this.options.boundary.socketPath;
    this.server = createServer({ pauseOnConnect: true }, (socket) => {
      this.connections.add(socket);
      socket.once("close", () => this.connections.delete(socket));
      socket.once("error", () => socket.destroy());
      void this.admit(socket);
    });
    this.server.on("error", () => {
      if (this.listening) void this.close();
    });
  }

  async listen(): Promise<void> {
    if (this.listening || this.closing) throw new DaytonaSupervisorProtocolError("conflict");
    assertEffectiveUid(this.options.boundary.expectedOwnerUid);
    assertProtectedDirectory(this.options.boundary);
    assertPathAbsent(this.socketPath);

    await new Promise<void>((resolve, reject) => {
      const onError = (): void => {
        this.server.removeListener("listening", onListening);
        reject(new DaytonaSupervisorProtocolError("not-ready"));
      };
      const onListening = (): void => {
        this.server.removeListener("error", onError);
        resolve();
      };
      this.server.once("error", onError);
      this.server.once("listening", onListening);
      this.server.listen(this.socketPath);
    });
    try {
      chmodSync(this.socketPath, 0o600);
      assertProtectedSocket(this.options.boundary);
      this.listening = true;
    } catch {
      await closeNetServer(this.server);
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closing = (async () => {
      this.listening = false;
      for (const socket of this.connections) socket.destroy();
      this.connections.clear();
      await closeNetServer(this.server);
      await Promise.allSettled([
        invokeClose(this.options.terminal),
        invokeClose(this.options.supervisor),
      ]);
      this.resolveDone();
    })();
    return this.closing;
  }

  wait(): Promise<void> {
    return this.done;
  }

  private async admit(socket: Socket): Promise<void> {
    const authentication = new AbortController();
    const timer = setTimeout(() => authentication.abort(), this.options.authenticationTimeoutMs);
    timer.unref();
    try {
      assertProtectedDirectory(this.options.boundary);
      assertProtectedSocket(this.options.boundary);
      const credentials = await this.options.verifyPeerCredentials(socket, authentication.signal);
      if (
        authentication.signal.aborted ||
        !validCredentials(credentials) ||
        credentials.uid !== this.options.expectedPeerUid ||
        (this.options.expectedPeerGid !== undefined &&
          credentials.gid !== this.options.expectedPeerGid)
      ) {
        throw new DaytonaSupervisorProtocolError("permission-denied");
      }
      assertProtectedSocket(this.options.boundary);
      this.serve(socket);
      socket.resume();
    } catch {
      socket.destroy();
    } finally {
      clearTimeout(timer);
      authentication.abort();
    }
  }

  private serve(socket: Socket): void {
    const decoder = new DaytonaSupervisorSocketFrameDecoder(this.options.maximumFrameBytes);
    const requests = new Map<string, AbortController>();
    const abortRequests = (): void => {
      decoder.destroy();
      for (const controller of requests.values()) controller.abort();
      requests.clear();
    };
    socket.once("close", abortRequests);
    socket.on("data", (chunk: Buffer) => {
      try {
        for (const unsafeFrame of decoder.push(chunk)) {
          const frame = snapshotDaytonaSupervisorSocketInboundFrame(unsafeFrame);
          if (frame.type === "cancel") {
            requests.get(frame.requestId)?.abort();
            continue;
          }
          if (
            requests.has(frame.requestId) ||
            requests.size >= this.options.maximumInflightRequests
          ) {
            throw new DaytonaSupervisorProtocolError("conflict");
          }
          const controller = new AbortController();
          requests.set(frame.requestId, controller);
          void this.dispatch(socket, frame, controller, requests);
        }
      } catch {
        socket.destroy();
      }
    });
  }

  private async dispatch(
    socket: Socket,
    frame: Extract<DaytonaSupervisorSocketInboundFrame, { readonly type: "request" }>,
    controller: AbortController,
    requests: Map<string, AbortController>
  ): Promise<void> {
    const timer = setTimeout(
      () => controller.abort(),
      frame.method === "terminal.open"
        ? this.options.terminalRequestTimeoutMs
        : this.options.requestTimeoutMs
    );
    timer.unref();
    try {
      if (frame.method === "isolation.attest") {
        const result = await this.options.supervisor.attestIsolation(
          frame.params as DaytonaSupervisorIsolationRequest,
          controller.signal
        );
        assertDispatchStillActive(controller.signal);
        await writeSocketFrame(
          socket,
          successFrame(frame.requestId, result),
          this.options.maximumFrameBytes
        );
        return;
      }
      if (frame.method === "command.execute") {
        const result = await this.options.supervisor.executeAuthenticated(
          frame.params as DaytonaSupervisorCommandRequest,
          controller.signal
        );
        assertDispatchStillActive(controller.signal);
        await writeSocketFrame(
          socket,
          successFrame(frame.requestId, result),
          this.options.maximumFrameBytes
        );
        return;
      }
      if (frame.method === "terminal.input") {
        await this.options.terminal.input(frame.params, controller.signal);
        assertDispatchStillActive(controller.signal);
        await writeSocketFrame(
          socket,
          successFrame(frame.requestId, null),
          this.options.maximumFrameBytes
        );
        return;
      }
      if (frame.method === "terminal.resize") {
        await this.options.terminal.resize(frame.params, controller.signal);
        assertDispatchStillActive(controller.signal);
        await writeSocketFrame(
          socket,
          successFrame(frame.requestId, null),
          this.options.maximumFrameBytes
        );
        return;
      }
      if (frame.method === "terminal.interrupt") {
        await this.options.terminal.interrupt(frame.params, controller.signal);
        assertDispatchStillActive(controller.signal);
        await writeSocketFrame(
          socket,
          successFrame(frame.requestId, null),
          this.options.maximumFrameBytes
        );
        return;
      }
      if (frame.method === "terminal.destroy") {
        await this.options.terminal.destroy(frame.params, controller.signal);
        assertDispatchStillActive(controller.signal);
        await writeSocketFrame(
          socket,
          successFrame(frame.requestId, null),
          this.options.maximumFrameBytes
        );
        return;
      }
      const stream =
        frame.method === "terminal.open"
          ? this.options.terminal.open(frame.params, controller.signal)
          : this.options.supervisor.followSigned(
              frame.params as DaytonaSupervisorFollowRequest,
              controller.signal
            );
      for await (const item of stream) {
        assertDispatchStillActive(controller.signal);
        await writeSocketFrame(
          socket,
          Object.freeze({
            protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
            version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
            type: "stream" as const,
            requestId: frame.requestId,
            item: snapshotRuntimeSupervisorPortableData(item),
          }),
          this.options.maximumFrameBytes
        );
      }
      assertDispatchStillActive(controller.signal);
      await writeSocketFrame(
        socket,
        Object.freeze({
          protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
          version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
          type: "end" as const,
          requestId: frame.requestId,
        }),
        this.options.maximumFrameBytes
      );
    } catch (error) {
      if (!socket.destroyed) {
        const safe = controller.signal.aborted
          ? new DaytonaSupervisorProtocolError("unavailable")
          : error instanceof DaytonaSupervisorProtocolError
            ? error
            : new DaytonaSupervisorProtocolError("internal");
        await writeSocketFrame(
          socket,
          failureFrame(frame.requestId, safe.code),
          this.options.maximumFrameBytes
        ).catch(() => socket.destroy());
      }
    } finally {
      clearTimeout(timer);
      controller.abort();
      if (requests.get(frame.requestId) === controller) requests.delete(frame.requestId);
    }
  }
}

class UnixSocketSupervisorClient implements PinnedDaytonaSupervisorTransport {
  private readonly options: CapturedClientOptions;
  private readonly requestPrefix: string;
  private nextRequest = 1;
  private socket: Socket | null = null;
  private connecting: Promise<Socket> | null = null;
  private decoder: DaytonaSupervisorSocketFrameDecoder | null = null;
  private readonly pending = new Map<string, PendingRequest>();
  private closed = false;

  constructor(unsafeOptions: CreateUnixSocketDaytonaSupervisorTransportOptions) {
    this.options = captureClientOptions(unsafeOptions);
    this.requestPrefix = randomBytes(12).toString("hex");
  }

  async attestIsolation(
    request: DaytonaSupervisorIsolationRequest,
    signal: AbortSignal
  ): Promise<unknown> {
    return this.unary("isolation.attest", request, signal);
  }

  async executeAuthenticated(
    request: DaytonaSupervisorCommandRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorCommandOutcome> {
    return (await this.unary(
      "command.execute",
      request,
      signal
    )) as DaytonaSupervisorCommandOutcome;
  }

  async *followSigned(
    request: DaytonaSupervisorFollowRequest,
    signal: AbortSignal
  ): AsyncIterable<unknown> {
    assertAbortSignal(signal);
    assertNotAborted(signal);
    const socket = await this.connectedSocket();
    const requestId = this.allocateRequestId();
    const queue = new SocketStreamQueue();
    const pending = createStreamPending(queue, signal, () => {
      void this.cancel(requestId);
    });
    this.pending.set(requestId, pending);
    try {
      await writeSocketFrame(
        socket,
        requestFrame(requestId, "observations.follow", request),
        this.options.maximumFrameBytes
      );
    } catch {
      this.finishPending(requestId, new DaytonaSupervisorProtocolError("unavailable"));
    }
    try {
      for await (const item of queue) yield item;
    } finally {
      if (this.pending.has(requestId)) {
        this.finishPending(requestId, new DaytonaSupervisorProtocolError("unavailable"));
        await this.cancel(requestId).catch(() => undefined);
      }
    }
  }

  openTerminal(
    request: unknown,
    signal: AbortSignal
  ): AsyncIterable<DaytonaSupervisorPtyStreamItem> {
    return this.stream(
      "terminal.open",
      request,
      signal
    ) as AsyncIterable<DaytonaSupervisorPtyStreamItem>;
  }

  terminalInput(request: unknown, signal: AbortSignal): Promise<void> {
    return this.voidUnary("terminal.input", request, signal);
  }

  terminalResize(request: unknown, signal: AbortSignal): Promise<void> {
    return this.voidUnary("terminal.resize", request, signal);
  }

  terminalInterrupt(request: unknown, signal: AbortSignal): Promise<void> {
    return this.voidUnary("terminal.interrupt", request, signal);
  }

  terminalDestroy(request: unknown, signal: AbortSignal): Promise<void> {
    return this.voidUnary("terminal.destroy", request, signal);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.failAll(new DaytonaSupervisorProtocolError("unavailable"));
    const socket = this.socket;
    this.socket = null;
    this.decoder?.destroy();
    this.decoder = null;
    socket?.destroy();
    const connecting = this.connecting;
    this.connecting = null;
    if (connecting) {
      const pendingSocket = await connecting.catch(() => null);
      pendingSocket?.destroy();
    }
  }

  private async unary(
    method: Exclude<DaytonaSupervisorSocketMethod, "observations.follow" | "terminal.open">,
    params: unknown,
    signal: AbortSignal
  ): Promise<unknown> {
    assertAbortSignal(signal);
    assertNotAborted(signal);
    const socket = await this.connectedSocket();
    const requestId = this.allocateRequestId();
    return new Promise<unknown>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.finishPending(requestId, new DaytonaSupervisorProtocolError("unavailable"));
        void this.cancel(requestId);
      }, this.options.requestTimeoutMs);
      timeout.unref();
      const abort = (): void => {
        this.finishPending(requestId, new DaytonaSupervisorProtocolError("unavailable"));
        void this.cancel(requestId);
      };
      signal.addEventListener("abort", abort, { once: true });
      this.pending.set(
        requestId,
        Object.freeze({
          kind: "unary" as const,
          resolve,
          reject,
          cleanup() {
            clearTimeout(timeout);
            signal.removeEventListener("abort", abort);
          },
        })
      );
      writeSocketFrame(
        socket,
        requestFrame(requestId, method, params),
        this.options.maximumFrameBytes
      ).catch(() => {
        this.finishPending(requestId, new DaytonaSupervisorProtocolError("unavailable"));
        socket.destroy();
      });
    });
  }

  private async voidUnary(
    method: "terminal.input" | "terminal.resize" | "terminal.interrupt" | "terminal.destroy",
    request: unknown,
    signal: AbortSignal
  ): Promise<void> {
    const result = await this.unary(method, request, signal);
    if (result !== null) throw new DaytonaSupervisorProtocolError("invalid-request");
  }

  private stream(
    method: "terminal.open",
    request: unknown,
    signal: AbortSignal
  ): AsyncIterable<unknown> {
    return Object.freeze({
      [Symbol.asyncIterator]: () => this.streamIterator(method, request, signal),
    });
  }

  private async *streamIterator(
    method: "terminal.open",
    request: unknown,
    signal: AbortSignal
  ): AsyncGenerator<unknown> {
    assertAbortSignal(signal);
    assertNotAborted(signal);
    const socket = await this.connectedSocket();
    const requestId = this.allocateRequestId();
    const queue = new SocketStreamQueue();
    const pending = createStreamPending(queue, signal, () => {
      void this.cancel(requestId);
    });
    this.pending.set(requestId, pending);
    try {
      await writeSocketFrame(
        socket,
        requestFrame(requestId, method, request),
        this.options.maximumFrameBytes
      );
    } catch {
      this.finishPending(requestId, new DaytonaSupervisorProtocolError("unavailable"));
    }
    try {
      for await (const item of queue) yield item;
    } finally {
      if (this.pending.has(requestId)) {
        this.finishPending(requestId, new DaytonaSupervisorProtocolError("unavailable"));
        await this.cancel(requestId).catch(() => undefined);
      }
    }
  }

  private connectedSocket(): Promise<Socket> {
    if (this.closed) return Promise.reject(new DaytonaSupervisorProtocolError("unavailable"));
    if (this.socket && !this.socket.destroyed) return Promise.resolve(this.socket);
    if (this.connecting) return this.connecting;
    this.connecting = this.connectWithRetry().finally(() => {
      this.connecting = null;
    });
    return this.connecting;
  }

  private async connectWithRetry(): Promise<Socket> {
    let attempt = 0;
    while (attempt < this.options.connectAttempts && !this.closed) {
      attempt += 1;
      try {
        return await this.connectOnce();
      } catch {
        if (attempt >= this.options.connectAttempts) break;
        await delay(this.options.reconnectDelayMs);
      }
    }
    throw new DaytonaSupervisorProtocolError("unavailable");
  }

  private async connectOnce(): Promise<Socket> {
    assertProtectedDirectory(this.options.boundary);
    assertProtectedSocket(this.options.boundary);
    const socket = createConnection({ path: this.options.boundary.socketPath });
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => fail(), this.options.connectTimeoutMs);
      timeout.unref();
      const cleanup = (): void => {
        clearTimeout(timeout);
        socket.removeListener("connect", connected);
        socket.removeListener("error", fail);
      };
      const connected = (): void => {
        cleanup();
        resolve();
      };
      const fail = (): void => {
        cleanup();
        socket.destroy();
        reject(new DaytonaSupervisorProtocolError("unavailable"));
      };
      socket.once("connect", connected);
      socket.once("error", fail);
    });
    try {
      assertProtectedDirectory(this.options.boundary);
      assertProtectedSocket(this.options.boundary);
    } catch {
      socket.destroy();
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    if (this.closed) {
      socket.destroy();
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    this.installSocket(socket);
    return socket;
  }

  private installSocket(socket: Socket): void {
    const decoder = new DaytonaSupervisorSocketFrameDecoder(this.options.maximumFrameBytes);
    this.socket = socket;
    this.decoder = decoder;
    socket.on("data", (chunk: Buffer) => {
      try {
        for (const rawFrame of decoder.push(chunk)) {
          this.receive(snapshotDaytonaSupervisorSocketOutboundFrame(rawFrame));
        }
      } catch {
        socket.destroy();
      }
    });
    socket.once("error", () => socket.destroy());
    socket.once("close", () => {
      decoder.destroy();
      if (this.socket === socket) {
        this.socket = null;
        this.decoder = null;
        this.failAll(new DaytonaSupervisorProtocolError("unavailable"));
      }
    });
  }

  private receive(frame: DaytonaSupervisorSocketOutboundFrame): void {
    const pending = this.pending.get(frame.requestId);
    if (!pending) {
      this.socket?.destroy();
      return;
    }
    if (frame.type === "response") {
      if (!frame.ok) {
        this.finishPending(frame.requestId, new DaytonaSupervisorProtocolError(frame.error.code));
        return;
      }
      if (pending.kind !== "unary") {
        this.socket?.destroy();
        return;
      }
      this.pending.delete(frame.requestId);
      pending.cleanup();
      pending.resolve(frame.result);
      return;
    }
    if (pending.kind !== "stream") {
      this.socket?.destroy();
      return;
    }
    if (frame.type === "stream") {
      pending.queue.push(frame.item);
      return;
    }
    this.pending.delete(frame.requestId);
    pending.cleanup();
    pending.queue.end();
  }

  private finishPending(requestId: string, error: DaytonaSupervisorProtocolError): void {
    const pending = this.pending.get(requestId);
    if (!pending) return;
    this.pending.delete(requestId);
    pending.cleanup();
    if (pending.kind === "unary") pending.reject(error);
    else pending.queue.fail(error);
  }

  private failAll(error: DaytonaSupervisorProtocolError): void {
    for (const requestId of [...this.pending.keys()]) this.finishPending(requestId, error);
  }

  private async cancel(requestId: string): Promise<void> {
    const socket = this.socket;
    if (!socket || socket.destroyed) return;
    await writeSocketFrame(
      socket,
      Object.freeze({
        protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
        version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
        type: "cancel" as const,
        requestId,
      }),
      this.options.maximumFrameBytes
    );
  }

  private allocateRequestId(): string {
    if (!Number.isSafeInteger(this.nextRequest) || this.nextRequest > Number.MAX_SAFE_INTEGER) {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    return `${this.requestPrefix}:${this.nextRequest++}`;
  }
}

type PendingRequest = PendingUnary | PendingStream;

interface PendingUnary {
  readonly kind: "unary";
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: DaytonaSupervisorProtocolError) => void;
  readonly cleanup: () => void;
}

interface PendingStream {
  readonly kind: "stream";
  readonly queue: SocketStreamQueue;
  readonly cleanup: () => void;
}

class SocketStreamQueue implements AsyncIterable<unknown> {
  private readonly values: unknown[] = [];
  private readonly readers: Array<{
    resolve: (value: IteratorResult<unknown>) => void;
    reject: (error: DaytonaSupervisorProtocolError) => void;
  }> = [];
  private ended = false;
  private error: DaytonaSupervisorProtocolError | null = null;

  push(value: unknown): void {
    if (this.ended || this.error) return;
    const reader = this.readers.shift();
    if (reader) reader.resolve({ done: false, value });
    else {
      if (this.values.length >= MAX_PENDING_STREAM_ITEMS) {
        this.fail(new DaytonaSupervisorProtocolError("unavailable"));
        throw new DaytonaSupervisorProtocolError("unavailable");
      }
      this.values.push(value);
    }
  }

  end(): void {
    if (this.ended || this.error) return;
    this.ended = true;
    for (const reader of this.readers.splice(0)) reader.resolve({ done: true, value: undefined });
  }

  fail(error: DaytonaSupervisorProtocolError): void {
    if (this.ended || this.error) return;
    this.error = error;
    this.values.length = 0;
    for (const reader of this.readers.splice(0)) reader.reject(error);
  }

  [Symbol.asyncIterator](): AsyncIterator<unknown> {
    return {
      next: (): Promise<IteratorResult<unknown>> => {
        if (this.values.length > 0) {
          return Promise.resolve({ done: false, value: this.values.shift() });
        }
        if (this.error) return Promise.reject(this.error);
        if (this.ended) return Promise.resolve({ done: true, value: undefined });
        return new Promise((resolve, reject) => this.readers.push({ resolve, reject }));
      },
    };
  }
}

interface SocketBoundary {
  readonly socketDirectory: string;
  readonly socketPath: string;
  readonly expectedOwnerUid: number;
}

interface CapturedServerOptions {
  readonly supervisor: PinnedDaytonaSupervisorTransport;
  readonly terminal: DaytonaSupervisorPtyService;
  readonly boundary: SocketBoundary;
  readonly expectedPeerUid: number;
  readonly expectedPeerGid?: number;
  readonly verifyPeerCredentials: DaytonaSupervisorUnixPeerCredentialVerifier;
  readonly authenticationTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly terminalRequestTimeoutMs: number;
  readonly maximumFrameBytes: number;
  readonly maximumInflightRequests: number;
}

interface CapturedClientOptions {
  readonly boundary: SocketBoundary;
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly maximumFrameBytes: number;
  readonly connectAttempts: number;
  readonly reconnectDelayMs: number;
}

function captureServerOptions(
  value: CreateDaytonaSupervisorUnixSocketServerOptions
): CapturedServerOptions {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value))
    throw new TypeError();
  const supervisor = captureSupervisor(value.supervisor);
  const terminal = captureTerminal(value.terminal);
  const expectedPeerUid = nonNegativeInteger(value.expectedPeerUid);
  const expectedPeerGid =
    value.expectedPeerGid === undefined ? undefined : nonNegativeInteger(value.expectedPeerGid);
  if (typeof value.verifyPeerCredentials !== "function") throw new TypeError();
  return Object.freeze({
    supervisor,
    terminal,
    boundary: captureBoundary(value),
    expectedPeerUid,
    ...(expectedPeerGid === undefined ? {} : { expectedPeerGid }),
    verifyPeerCredentials: value.verifyPeerCredentials,
    authenticationTimeoutMs: timeout(value.authenticationTimeoutMs ?? 2_000),
    requestTimeoutMs: timeout(value.requestTimeoutMs ?? 30_000),
    terminalRequestTimeoutMs: terminalTimeout(value.terminalRequestTimeoutMs ?? 24 * 60 * 60_000),
    maximumFrameBytes: maximumFrameBytes(value.maximumFrameBytes),
    maximumInflightRequests: boundedPositiveInteger(
      value.maximumInflightRequests ?? 32,
      MAX_INFLIGHT_REQUESTS
    ),
  });
}

function captureClientOptions(
  value: CreateUnixSocketDaytonaSupervisorTransportOptions
): CapturedClientOptions {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value))
    throw new TypeError();
  const connectAttempts = boundedPositiveInteger(value.connectAttempts ?? 2, MAX_CONNECT_ATTEMPTS);
  const reconnectDelayMs = value.reconnectDelayMs ?? 25;
  if (!Number.isSafeInteger(reconnectDelayMs) || reconnectDelayMs < 0 || reconnectDelayMs > 5_000) {
    throw new TypeError();
  }
  return Object.freeze({
    boundary: captureBoundary(value),
    connectTimeoutMs: timeout(value.connectTimeoutMs ?? 2_000),
    requestTimeoutMs: timeout(value.requestTimeoutMs ?? 30_000),
    maximumFrameBytes: maximumFrameBytes(value.maximumFrameBytes),
    connectAttempts,
    reconnectDelayMs,
  });
}

function captureBoundary(value: {
  readonly socketDirectory: string;
  readonly socketPath: string;
  readonly expectedOwnerUid: number;
}): SocketBoundary {
  if (
    typeof value.socketDirectory !== "string" ||
    !isAbsolute(value.socketDirectory) ||
    normalize(value.socketDirectory) !== value.socketDirectory ||
    typeof value.socketPath !== "string" ||
    !isAbsolute(value.socketPath) ||
    normalize(value.socketPath) !== value.socketPath ||
    dirname(value.socketPath) !== value.socketDirectory ||
    relative(value.socketDirectory, value.socketPath).includes(sep)
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    socketDirectory: value.socketDirectory,
    socketPath: value.socketPath,
    expectedOwnerUid: nonNegativeInteger(value.expectedOwnerUid),
  });
}

function captureSupervisor(
  value: PinnedDaytonaSupervisorTransport
): PinnedDaytonaSupervisorTransport {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof value.attestIsolation !== "function" ||
    typeof value.executeAuthenticated !== "function" ||
    typeof value.followSigned !== "function" ||
    typeof value.close !== "function"
  ) {
    throw new TypeError();
  }
  const attestIsolation = value.attestIsolation.bind(value);
  const executeAuthenticated = value.executeAuthenticated.bind(value);
  const followSigned = value.followSigned.bind(value);
  const close = value.close.bind(value);
  return Object.freeze({ attestIsolation, executeAuthenticated, followSigned, close });
}

function captureTerminal(value: DaytonaSupervisorPtyService): DaytonaSupervisorPtyService {
  if (
    typeof value !== "object" ||
    value === null ||
    nodeTypes.isProxy(value) ||
    typeof value.open !== "function" ||
    typeof value.input !== "function" ||
    typeof value.resize !== "function" ||
    typeof value.interrupt !== "function" ||
    typeof value.destroy !== "function" ||
    typeof value.close !== "function"
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    open: value.open.bind(value),
    input: value.input.bind(value),
    resize: value.resize.bind(value),
    interrupt: value.interrupt.bind(value),
    destroy: value.destroy.bind(value),
    close: value.close.bind(value),
  });
}

function requestFrame(
  requestId: string,
  method: DaytonaSupervisorSocketMethod,
  params: unknown
): DaytonaSupervisorSocketInboundFrame {
  return Object.freeze({
    protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    type: "request",
    requestId,
    method,
    params: snapshotRuntimeSupervisorPortableData(params),
  });
}

function successFrame(requestId: string, result: unknown): DaytonaSupervisorSocketOutboundFrame {
  return Object.freeze({
    protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    type: "response",
    requestId,
    ok: true,
    result: snapshotRuntimeSupervisorPortableData(result),
  });
}

function failureFrame(
  requestId: string,
  code: DaytonaSupervisorProtocolErrorCode
): DaytonaSupervisorSocketOutboundFrame {
  return Object.freeze({
    protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    type: "response",
    requestId,
    ok: false,
    error: Object.freeze({ code, message: new DaytonaSupervisorProtocolError(code).message }),
  });
}

async function writeSocketFrame(
  socket: Socket,
  frame: DaytonaSupervisorSocketInboundFrame | DaytonaSupervisorSocketOutboundFrame,
  maximumFrameBytes: number
): Promise<void> {
  if (socket.destroyed || !socket.writable) {
    throw new DaytonaSupervisorProtocolError("unavailable");
  }
  const bytes = encodeDaytonaSupervisorSocketFrame(frame, maximumFrameBytes);
  try {
    await new Promise<void>((resolve, reject) => {
      socket.write(bytes, (error?: Error | null) => {
        if (error) reject(new DaytonaSupervisorProtocolError("unavailable"));
        else resolve();
      });
    });
  } finally {
    bytes.fill(0);
  }
}

function createStreamPending(
  queue: SocketStreamQueue,
  signal: AbortSignal,
  cancel: () => void
): PendingStream {
  const abort = (): void => {
    queue.fail(new DaytonaSupervisorProtocolError("unavailable"));
    cancel();
  };
  signal.addEventListener("abort", abort, { once: true });
  return Object.freeze({
    kind: "stream",
    queue,
    cleanup() {
      signal.removeEventListener("abort", abort);
    },
  });
}

function assertProtectedDirectory(boundary: SocketBoundary): void {
  let stat: Stats;
  try {
    if (realpathSync.native(boundary.socketDirectory) !== boundary.socketDirectory)
      throw new Error();
    stat = lstatSync(boundary.socketDirectory);
  } catch {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
  if (
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    stat.uid !== boundary.expectedOwnerUid ||
    (stat.mode & 0o777) !== 0o700
  ) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function assertProtectedSocket(boundary: SocketBoundary): void {
  let stat: Stats;
  try {
    stat = lstatSync(boundary.socketPath);
  } catch {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
  if (
    stat.isSymbolicLink() ||
    !stat.isSocket() ||
    stat.nlink !== 1 ||
    stat.uid !== boundary.expectedOwnerUid ||
    (stat.mode & 0o777) !== 0o600
  ) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function assertPathAbsent(path: string): void {
  try {
    lstatSync(path);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return;
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
  throw new DaytonaSupervisorProtocolError("conflict");
}

function assertEffectiveUid(expectedUid: number): void {
  if (typeof process.geteuid !== "function" || process.geteuid() !== expectedUid) {
    throw new DaytonaSupervisorProtocolError("permission-denied");
  }
}

function validCredentials(value: unknown): value is DaytonaSupervisorUnixPeerCredentials {
  return (
    typeof value === "object" &&
    value !== null &&
    Number.isSafeInteger((value as DaytonaSupervisorUnixPeerCredentials).pid) &&
    (value as DaytonaSupervisorUnixPeerCredentials).pid > 0 &&
    Number.isSafeInteger((value as DaytonaSupervisorUnixPeerCredentials).uid) &&
    (value as DaytonaSupervisorUnixPeerCredentials).uid >= 0 &&
    Number.isSafeInteger((value as DaytonaSupervisorUnixPeerCredentials).gid) &&
    (value as DaytonaSupervisorUnixPeerCredentials).gid >= 0
  );
}

function assertDispatchStillActive(signal: AbortSignal): void {
  if (signal.aborted) throw new DaytonaSupervisorProtocolError("unavailable");
}

function assertAbortSignal(value: unknown): asserts value is AbortSignal {
  if (!(value instanceof AbortSignal)) throw new DaytonaSupervisorProtocolError("invalid-request");
}

function assertNotAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new DaytonaSupervisorProtocolError("unavailable");
}

function timeout(value: number): number {
  if (!Number.isSafeInteger(value) || value < MIN_TIMEOUT_MS || value > MAX_TIMEOUT_MS) {
    throw new TypeError();
  }
  return value;
}

function terminalTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value < MIN_TIMEOUT_MS || value > MAX_TERMINAL_TIMEOUT_MS) {
    throw new TypeError();
  }
  return value;
}

function maximumFrameBytes(value: number | undefined): number {
  const result = value ?? DAYTONA_SUPERVISOR_SOCKET_MAX_FRAME_BYTES;
  if (!Number.isSafeInteger(result) || result < 1024 || result > 16 * 1024 * 1024) {
    throw new TypeError();
  }
  return result;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError();
  return value as number;
}

function boundedPositiveInteger(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) {
    throw new TypeError();
  }
  return value as number;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function delay(milliseconds: number): Promise<void> {
  if (milliseconds === 0) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    timer.unref();
  });
}

async function closeNetServer(server: NetServer): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function invokeClose(service: { close(): Promise<void> }): Promise<void> {
  await service.close();
}
