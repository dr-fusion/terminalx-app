import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { Agent, request as httpsRequest, type RequestOptions } from "node:https";
import { isIP } from "node:net";
import { checkServerIdentity, type DetailedPeerCertificate } from "node:tls";
import { TextDecoder, types as nodeTypes } from "node:util";
import type {
  DaytonaSupervisorPtyConnection,
  DaytonaSupervisorPtyDestroyRequest,
  DaytonaSupervisorPtyExitFrame,
  DaytonaSupervisorPtyInputRequest,
  DaytonaSupervisorPtyInterruptRequest,
  DaytonaSupervisorPtyOpenRequest,
  DaytonaSupervisorPtyOutputFrame,
  DaytonaSupervisorPtyResizeRequest,
  DaytonaSupervisorPtyTransport,
} from "./daytona-hosted-terminal-adapter";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type {
  DaytonaSupervisorCommandOutcome,
  DaytonaSupervisorCommandRequest,
  DaytonaSupervisorFollowRequest,
  DaytonaSupervisorIsolationRequest,
  PinnedDaytonaSupervisorTransport,
} from "./daytona-hosted-control-plane";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";
import {
  DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
  DaytonaSupervisorSocketFrameDecoder,
  encodeDaytonaSupervisorSocketFrame,
  snapshotDaytonaSupervisorSocketOutboundFrame,
  type DaytonaSupervisorSocketMethod,
  type DaytonaSupervisorSocketOutboundFrame,
} from "../../../packages/daytona-supervisor/src/socket-framing";
import {
  DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
  DaytonaSupervisorProtocolError,
} from "../../../packages/daytona-supervisor/src/supervisor";
import type {
  DaytonaSupervisorPtyInputWireRequest,
  DaytonaSupervisorPtyStreamItem,
} from "../../../packages/daytona-supervisor/src/pty-registry";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_CREDENTIAL_BYTES = 4096;
const MAX_CA_BYTES = 1024 * 1024;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 10 * 60_000;
const MAX_TERMINAL_LIFETIME_MS = 7 * 24 * 60 * 60_000;
const MAX_PENDING_TERMINAL_OUTPUT_BYTES = 16 * 1024 * 1024;
export const DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE =
  "application/vnd.terminalx.supervisor-framed" as const;

export interface CreateDaytonaSupervisorRelayTransportOptions {
  /** Exact dedicated hardened runner origin. Paths, queries and credentials are rejected. */
  readonly runnerOrigin: string;
  /** Explicit trusted CA bundle; ambient Node/system CA selection is not used. */
  readonly runnerCaPem: string;
  /** SHA-256 of the live TLS SubjectPublicKeyInfo DER. */
  readonly runnerTlsSpkiSha256: string;
  /** Ownership transfers to this transport and is zeroed on close. */
  readonly runnerCredential: Uint8Array;
  readonly connectTimeoutMs?: number;
  readonly requestTimeoutMs?: number;
  readonly terminalLifetimeMs?: number;
  readonly maximumPendingTerminalOutputBytes?: number;
  readonly maximumFrameBytes?: number;
}

/**
 * External-app transport to the hardened runner's one fixed root relay route.
 * Every logical call gets an independent streaming POST, so a follow request
 * cannot head-of-line block lifecycle commands. The runner credential and TLS
 * keys terminate outside the Sandbox; only framed bytes reach the fixed relay.
 */
export function createDaytonaSupervisorRelayTransport(
  unsafeOptions: CreateDaytonaSupervisorRelayTransportOptions
): PinnedDaytonaSupervisorTransport & DaytonaSupervisorPtyTransport {
  return new DaytonaSupervisorRelayTransport(unsafeOptions);
}

class DaytonaSupervisorRelayTransport
  implements PinnedDaytonaSupervisorTransport, DaytonaSupervisorPtyTransport
{
  private readonly options: CapturedOptions;
  private readonly agent: Agent;
  private readonly terminals = new Set<RelayPtyConnection>();
  private closed = false;
  private closing: Promise<void> | null = null;

  constructor(unsafeOptions: CreateDaytonaSupervisorRelayTransportOptions) {
    this.options = captureOptions(unsafeOptions);
    try {
      this.agent = new Agent({
        keepAlive: false,
        maxSockets: 64,
        maxFreeSockets: 0,
        timeout: this.options.connectTimeoutMs,
      });
    } catch (error) {
      this.options.credential.fill(0);
      throw error;
    }
  }

  async attestIsolation(
    request: DaytonaSupervisorIsolationRequest,
    signal: AbortSignal
  ): Promise<unknown> {
    const response = await this.unary(
      request.providerSandboxId,
      "isolation.attest",
      request,
      signal
    );
    return response;
  }

  async executeAuthenticated(
    request: DaytonaSupervisorCommandRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorCommandOutcome> {
    return (await this.unary(
      request.providerSandboxId,
      "command.execute",
      request,
      signal
    )) as DaytonaSupervisorCommandOutcome;
  }

  async *followSigned(
    request: DaytonaSupervisorFollowRequest,
    signal: AbortSignal
  ): AsyncIterable<unknown> {
    const exchange = await this.openExchange(
      request.providerSandboxId,
      "observations.follow",
      request,
      signal
    );
    let ended = false;
    try {
      for await (const frame of exchange.frames) {
        if (frame.requestId !== exchange.requestId) throw protocolFailure();
        if (frame.type === "stream") {
          yield frame.item;
          continue;
        }
        if (frame.type === "response" && !frame.ok) {
          throw new DaytonaSupervisorProtocolError(frame.error.code);
        }
        if (frame.type !== "end") throw protocolFailure();
        ended = true;
      }
      if (!ended) throw new DaytonaSupervisorProtocolError("unavailable");
    } finally {
      exchange.abort();
    }
  }

  async open(
    request: DaytonaSupervisorPtyOpenRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorPtyConnection> {
    if (this.closed || this.closing) throw new DaytonaSupervisorProtocolError("unavailable");
    const snapshot = snapshotPtyOpenRequest(request);
    const exchange = await this.openExchange(
      snapshot.providerSandboxId,
      "terminal.open",
      snapshot,
      signal
    );
    const iterator = exchange.frames[Symbol.asyncIterator]();
    try {
      const first = await iterator.next();
      if (first.done) throw new DaytonaSupervisorProtocolError("unavailable");
      const frame = first.value;
      if (frame.requestId !== exchange.requestId) throw protocolFailure();
      if (frame.type === "response" && !frame.ok) {
        throw new DaytonaSupervisorProtocolError(frame.error.code);
      }
      if (frame.type !== "stream") throw protocolFailure();
      const ready = snapshotPtyReady(frame.item);
      assertReadyMatches(ready, snapshot);
      const connection = new RelayPtyConnection({
        owner: this,
        request: snapshot,
        exchange,
        iterator,
        maximumPendingOutputBytes: this.options.maximumPendingTerminalOutputBytes,
      });
      this.terminals.add(connection);
      connection.start();
      return connection.facade();
    } catch (error) {
      exchange.abort();
      await iterator.return?.().catch(() => undefined);
      if (error instanceof DaytonaSupervisorProtocolError) throw error;
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
  }

  async close(): Promise<void> {
    if (this.closing) return this.closing;
    if (this.closed) return;
    this.closing = (async () => {
      await Promise.allSettled(
        [...this.terminals].map((terminal) => terminal.closeFromTransport())
      );
      this.terminals.clear();
      this.closed = true;
      this.options.credential.fill(0);
      this.agent.destroy();
    })();
    return this.closing;
  }

  removeTerminal(connection: RelayPtyConnection): void {
    this.terminals.delete(connection);
  }

  terminalUnary(
    providerSandboxId: string,
    method: "terminal.input" | "terminal.resize" | "terminal.interrupt" | "terminal.destroy",
    params: unknown,
    signal: AbortSignal
  ): Promise<unknown> {
    return this.unary(providerSandboxId, method, params, signal);
  }

  private async unary(
    providerSandboxId: string,
    method: Exclude<DaytonaSupervisorSocketMethod, "observations.follow" | "terminal.open">,
    params: unknown,
    signal: AbortSignal
  ): Promise<unknown> {
    const exchange = await this.openExchange(providerSandboxId, method, params, signal);
    let result: unknown;
    let received = false;
    try {
      for await (const frame of exchange.frames) {
        if (received || frame.requestId !== exchange.requestId || frame.type !== "response") {
          throw protocolFailure();
        }
        received = true;
        if (!frame.ok) throw new DaytonaSupervisorProtocolError(frame.error.code);
        result = frame.result;
      }
      if (!received) throw new DaytonaSupervisorProtocolError("unavailable");
      return result;
    } finally {
      exchange.abort();
    }
  }

  private async openExchange(
    unsafeProviderSandboxId: string,
    method: DaytonaSupervisorSocketMethod,
    params: unknown,
    signal: AbortSignal
  ): Promise<RelayExchange> {
    if (this.closed || (this.closing && method !== "terminal.destroy")) {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    if (!(signal instanceof AbortSignal) || nodeTypes.isProxy(signal) || signal.aborted) {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    const providerSandboxId = sandboxId(unsafeProviderSandboxId);
    const requestId = randomBytes(16).toString("hex");
    const body = encodeDaytonaSupervisorSocketFrame(
      Object.freeze({
        protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
        version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
        type: "request" as const,
        requestId,
        method,
        params: snapshotRuntimeSupervisorPortableData(params),
      }),
      this.options.maximumFrameBytes
    );
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    signal.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(
      abort,
      method === "terminal.open" ? this.options.terminalLifetimeMs : this.options.requestTimeoutMs
    );
    timer.unref();
    const cleanup = (): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      controller.abort();
    };
    try {
      const credential = decodeCredential(this.options.credential);
      let response: import("node:http").IncomingMessage;
      try {
        response = await sendRelayRequest(
          this.options,
          this.agent,
          providerSandboxId,
          credential,
          body,
          controller.signal
        );
      } finally {
        // The string is not retained by this module; Node owns the transient
        // HTTP header copy until the exchange is torn down.
        body.fill(0);
      }
      if (
        response.statusCode !== 200 ||
        response.headers["content-type"] !== DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE ||
        response.headers["content-encoding"] !== undefined ||
        response.headers.location !== undefined
      ) {
        response.destroy();
        throw new DaytonaSupervisorProtocolError(
          response.statusCode === 401 || response.statusCode === 403
            ? "permission-denied"
            : "unavailable"
        );
      }
      const frames = decodeResponseFrames(
        response,
        controller.signal,
        this.options.maximumFrameBytes
      );
      return Object.freeze({
        requestId,
        frames,
        abort: cleanup,
      });
    } catch (error) {
      cleanup();
      body.fill(0);
      if (error instanceof DaytonaSupervisorProtocolError) throw error;
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
  }
}

interface RelayPtyConnectionConstruction {
  readonly owner: DaytonaSupervisorRelayTransport;
  readonly request: DaytonaSupervisorPtyOpenRequest;
  readonly exchange: RelayExchange;
  readonly iterator: AsyncIterator<DaytonaSupervisorSocketOutboundFrame>;
  readonly maximumPendingOutputBytes: number;
}

class RelayPtyConnection {
  private readonly owner: DaytonaSupervisorRelayTransport;
  private readonly request: DaytonaSupervisorPtyOpenRequest;
  private readonly exchange: RelayExchange;
  private readonly iterator: AsyncIterator<DaytonaSupervisorSocketOutboundFrame>;
  private readonly maximumPendingOutputBytes: number;
  private readonly dataListeners = new Set<(frame: DaytonaSupervisorPtyOutputFrame) => void>();
  private readonly exitListeners = new Set<(frame: DaytonaSupervisorPtyExitFrame) => void>();
  private readonly pendingOutput: DaytonaSupervisorPtyOutputFrame[] = [];
  private pendingOutputBytes = 0;
  private nextOutputSeq = 1;
  private exited = false;
  private destroyed = false;
  private destroyPromise: Promise<void> | null = null;

  constructor(options: RelayPtyConnectionConstruction) {
    this.owner = options.owner;
    this.request = options.request;
    this.exchange = options.exchange;
    this.iterator = options.iterator;
    this.maximumPendingOutputBytes = options.maximumPendingOutputBytes;
  }

  facade(): DaytonaSupervisorPtyConnection {
    return Object.freeze({
      providerSandboxId: this.request.providerSandboxId,
      expectedProviderRevision: this.request.expectedProviderRevision,
      binding: this.request.binding,
      planDigest: this.request.planDigest,
      terminalId: this.request.terminalId,
      onData: (listener: (frame: DaytonaSupervisorPtyOutputFrame) => void) => this.onData(listener),
      onExit: (listener: (frame: DaytonaSupervisorPtyExitFrame) => void) => this.onExit(listener),
      input: (request: DaytonaSupervisorPtyInputRequest, signal: AbortSignal) =>
        this.input(request, signal),
      resize: (request: DaytonaSupervisorPtyResizeRequest, signal: AbortSignal) =>
        this.resize(request, signal),
      interrupt: (request: DaytonaSupervisorPtyInterruptRequest, signal: AbortSignal) =>
        this.interrupt(request, signal),
      destroy: (request: DaytonaSupervisorPtyDestroyRequest, signal: AbortSignal) =>
        this.destroy(request, signal),
    });
  }

  start(): void {
    void this.pump();
  }

  onData(listener: (frame: DaytonaSupervisorPtyOutputFrame) => void): { dispose(): void } {
    const captured = captureListener(listener);
    if (this.destroyed) throw new DaytonaSupervisorProtocolError("unavailable");
    this.dataListeners.add(captured);
    const pending = this.pendingOutput.splice(0);
    this.pendingOutputBytes = 0;
    try {
      for (const frame of pending) captured(frame);
    } catch {
      this.failClosed();
      throw new DaytonaSupervisorProtocolError("unavailable");
    } finally {
      for (const frame of pending) frame.bytes.fill(0);
    }
    return Object.freeze({ dispose: () => this.dataListeners.delete(captured) });
  }

  onExit(listener: (frame: DaytonaSupervisorPtyExitFrame) => void): { dispose(): void } {
    const captured = captureListener(listener);
    this.exitListeners.add(captured);
    if (this.exited) {
      try {
        captured(Object.freeze({ terminalId: this.request.terminalId }));
      } catch {
        // Exit is final even when a consumer callback fails.
      }
    }
    return Object.freeze({ dispose: () => this.exitListeners.delete(captured) });
  }

  async input(request: DaytonaSupervisorPtyInputRequest, signal: AbortSignal): Promise<void> {
    const snapshot = snapshotPtyInputRequest(request);
    this.assertMutationFence(snapshot, signal);
    const bytes = Buffer.from(snapshot.bytes);
    let bytesBase64: string;
    try {
      bytesBase64 = bytes.toString("base64url");
    } finally {
      bytes.fill(0);
      snapshot.bytes.fill(0);
    }
    const wire = Object.freeze({
      ...this.privateFence(),
      inputSeq: snapshot.inputSeq,
      bytesBase64,
    } satisfies DaytonaSupervisorPtyInputWireRequest);
    await this.requireNull(
      this.owner.terminalUnary(this.request.providerSandboxId, "terminal.input", wire, signal)
    );
  }

  async resize(request: DaytonaSupervisorPtyResizeRequest, signal: AbortSignal): Promise<void> {
    const snapshot = snapshotPtyResizeRequest(request);
    this.assertMutationFence(snapshot, signal);
    await this.requireNull(
      this.owner.terminalUnary(
        this.request.providerSandboxId,
        "terminal.resize",
        Object.freeze({
          ...this.privateFence(),
          resizeSeq: snapshot.resizeSeq,
          cols: snapshot.cols,
          rows: snapshot.rows,
        }),
        signal
      )
    );
  }

  async interrupt(
    request: DaytonaSupervisorPtyInterruptRequest,
    signal: AbortSignal
  ): Promise<void> {
    const snapshot = snapshotPtyInterruptRequest(request);
    this.assertMutationFence(snapshot, signal);
    await this.requireNull(
      this.owner.terminalUnary(
        this.request.providerSandboxId,
        "terminal.interrupt",
        Object.freeze({ ...this.privateFence(), interruptSeq: snapshot.interruptSeq }),
        signal
      )
    );
  }

  destroy(request: DaytonaSupervisorPtyDestroyRequest, signal: AbortSignal): Promise<void> {
    const snapshot = snapshotPtyDestroyRequest(request);
    this.assertMutationFence(snapshot, signal, true, true);
    return this.destroyWithSignal(signal);
  }

  closeFromTransport(): Promise<void> {
    return this.destroyWithSignal(AbortSignal.timeout(30_000));
  }

  private destroyWithSignal(signal: AbortSignal): Promise<void> {
    if (this.destroyPromise) return this.destroyPromise;
    this.destroyed = true;
    this.exchange.abort();
    this.destroyPromise = (async () => {
      try {
        await this.iterator.return?.();
        const result = await this.owner.terminalUnary(
          this.request.providerSandboxId,
          "terminal.destroy",
          Object.freeze(this.privateFence()),
          signal
        );
        if (result !== null) throw protocolFailure();
      } finally {
        this.emitExit();
        this.clearPendingOutput();
        this.owner.removeTerminal(this);
      }
    })();
    return this.destroyPromise;
  }

  private async pump(): Promise<void> {
    let wireExit = false;
    let ended = false;
    try {
      while (true) {
        const next = await this.iterator.next();
        if (next.done) break;
        const frame = next.value;
        if (frame.requestId !== this.exchange.requestId) throw protocolFailure();
        if (frame.type === "response" && !frame.ok) {
          throw new DaytonaSupervisorProtocolError(frame.error.code);
        }
        if (frame.type === "stream") {
          if (wireExit) throw protocolFailure();
          const item = snapshotPtyStreamItem(frame.item);
          if (item.kind === "ready") throw protocolFailure();
          if (item.terminalId !== this.request.terminalId) throw protocolFailure();
          if (item.kind === "exit") {
            wireExit = true;
            this.emitExit();
          } else {
            this.receiveOutput(item);
          }
          continue;
        }
        if (frame.type !== "end" || !wireExit) throw protocolFailure();
        ended = true;
      }
      if (!ended) throw new DaytonaSupervisorProtocolError("unavailable");
    } catch {
      this.failClosed();
    } finally {
      this.exchange.abort();
      this.owner.removeTerminal(this);
    }
  }

  private receiveOutput(item: Extract<DaytonaSupervisorPtyStreamItem, { kind: "output" }>): void {
    if (item.outputSeq !== this.nextOutputSeq) throw protocolFailure();
    this.nextOutputSeq += 1;
    const bytes = decodeTerminalBytes(item.bytesBase64);
    const frame = Object.freeze({
      terminalId: item.terminalId,
      outputSeq: item.outputSeq,
      bytes: new Uint8Array(bytes),
    });
    bytes.fill(0);
    if (this.dataListeners.size === 0) {
      if (frame.bytes.byteLength > this.maximumPendingOutputBytes - this.pendingOutputBytes) {
        frame.bytes.fill(0);
        throw new DaytonaSupervisorProtocolError("unavailable");
      }
      this.pendingOutput.push(frame);
      this.pendingOutputBytes += frame.bytes.byteLength;
      return;
    }
    try {
      for (const listener of this.dataListeners) listener(frame);
    } finally {
      frame.bytes.fill(0);
    }
  }

  private emitExit(): void {
    if (this.exited) return;
    this.exited = true;
    const frame = Object.freeze({ terminalId: this.request.terminalId });
    for (const listener of this.exitListeners) {
      try {
        listener(frame);
      } catch {
        // A consumer cannot keep a closed private stream alive.
      }
    }
  }

  private failClosed(): void {
    this.emitExit();
    this.exchange.abort();
    this.clearPendingOutput();
    this.owner.removeTerminal(this);
  }

  private clearPendingOutput(): void {
    for (const frame of this.pendingOutput.splice(0)) frame.bytes.fill(0);
    this.pendingOutputBytes = 0;
  }

  private assertMutationFence(
    request: DaytonaSupervisorPtyDestroyRequest,
    signal: AbortSignal,
    allowExited = false,
    allowDestroyed = false
  ): void {
    if (
      (!allowDestroyed && this.destroyed) ||
      (!allowExited && this.exited) ||
      !(signal instanceof AbortSignal) ||
      nodeTypes.isProxy(signal) ||
      signal.aborted ||
      request.providerSandboxId !== this.request.providerSandboxId ||
      request.expectedProviderRevision !== this.request.expectedProviderRevision ||
      request.planDigest !== this.request.planDigest ||
      request.terminalId !== this.request.terminalId ||
      !samePtyBinding(request.binding, this.request.binding)
    ) {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
  }

  private privateFence(): DaytonaSupervisorPtyDestroyRequest {
    return {
      providerSandboxId: this.request.providerSandboxId,
      expectedProviderRevision: this.request.expectedProviderRevision,
      binding: this.request.binding,
      planDigest: this.request.planDigest,
      terminalId: this.request.terminalId,
    };
  }

  private async requireNull(value: Promise<unknown>): Promise<void> {
    const result = await value;
    if (result !== null) throw protocolFailure();
  }
}

interface RelayExchange {
  readonly requestId: string;
  readonly frames: AsyncIterable<DaytonaSupervisorSocketOutboundFrame>;
  readonly abort: () => void;
}

interface CapturedOptions {
  readonly origin: URL;
  readonly runnerCaPem: string;
  readonly runnerTlsSpkiSha256: string;
  readonly credential: Uint8Array;
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly terminalLifetimeMs: number;
  readonly maximumPendingTerminalOutputBytes: number;
  readonly maximumFrameBytes: number;
}

function captureOptions(value: CreateDaytonaSupervisorRelayTransportOptions): CapturedOptions {
  let unsafeCredential: unknown;
  if (typeof value === "object" && value !== null && !nodeTypes.isProxy(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, "runnerCredential");
    if (descriptor && "value" in descriptor) unsafeCredential = descriptor.value;
  }
  let sourceCredential: Uint8Array | null = ownedCredential(unsafeCredential);
  let credential: Uint8Array | undefined;
  try {
    const record = optionRecord(value);
    const runnerOrigin = optionField(record, "runnerOrigin");
    const runnerCaPem = optionField(record, "runnerCaPem");
    const runnerTlsSpkiSha256 = optionField(record, "runnerTlsSpkiSha256");
    unsafeCredential = optionField(record, "runnerCredential");
    sourceCredential = ownedCredential(unsafeCredential);
    let origin: URL;
    try {
      origin = new URL(typeof runnerOrigin === "string" ? runnerOrigin : "");
    } catch {
      throw new TypeError();
    }
    if (
      typeof runnerOrigin !== "string" ||
      origin.protocol !== "https:" ||
      origin.username !== "" ||
      origin.password !== "" ||
      origin.pathname !== "/" ||
      origin.search !== "" ||
      origin.hash !== "" ||
      origin.hostname.length === 0 ||
      origin.origin !== runnerOrigin.replace(/\/$/u, "") ||
      typeof runnerCaPem !== "string" ||
      !runnerCaPem.startsWith("-----BEGIN CERTIFICATE-----\n") ||
      !runnerCaPem.endsWith("-----END CERTIFICATE-----\n") ||
      Buffer.byteLength(runnerCaPem, "utf8") > MAX_CA_BYTES ||
      typeof runnerTlsSpkiSha256 !== "string" ||
      !SHA256.test(runnerTlsSpkiSha256) ||
      sourceCredential === null ||
      sourceCredential.byteLength < 1 ||
      sourceCredential.byteLength > MAX_CREDENTIAL_BYTES
    ) {
      throw new TypeError();
    }
    credential = new Uint8Array(sourceCredential);
    decodeCredential(credential);
    return Object.freeze({
      origin,
      runnerCaPem,
      runnerTlsSpkiSha256,
      credential,
      connectTimeoutMs: boundedTimeout(optionField(record, "connectTimeoutMs") ?? 5_000),
      requestTimeoutMs: boundedTimeout(optionField(record, "requestTimeoutMs") ?? 30_000),
      terminalLifetimeMs: boundedTerminalLifetime(
        optionField(record, "terminalLifetimeMs") ?? 24 * 60 * 60_000
      ),
      maximumPendingTerminalOutputBytes: boundedPendingTerminalOutput(
        optionField(record, "maximumPendingTerminalOutputBytes") ?? 1024 * 1024
      ),
      maximumFrameBytes: boundedFrameBytes(optionField(record, "maximumFrameBytes") ?? 1024 * 1024),
    });
  } catch (error) {
    credential?.fill(0);
    throw error;
  } finally {
    zeroCredential(sourceCredential);
  }
}

function optionRecord(value: unknown): Record<string, unknown> {
  const required = [
    "runnerOrigin",
    "runnerCaPem",
    "runnerTlsSpkiSha256",
    "runnerCredential",
  ] as const;
  const allowed = new Set([
    ...required,
    "connectTimeoutMs",
    "requestTimeoutMs",
    "terminalLifetimeMs",
    "maximumPendingTerminalOutputBytes",
    "maximumFrameBytes",
  ]);
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new TypeError();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    required.some((name) => !keys.includes(name))
  ) {
    throw new TypeError();
  }
  for (const key of keys) optionField(value as Record<string, unknown>, key as string);
  return value as Record<string, unknown>;
}

function optionField(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (descriptor === undefined) return undefined;
  if (!descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function ownedCredential(value: unknown): Uint8Array | null {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return null;
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) return null;
  return value;
}

function zeroCredential(value: Uint8Array | null): void {
  if (value === null) return;
  try {
    Uint8Array.prototype.fill.call(value, 0);
  } catch {
    // A concurrently detached caller-owned view is already unusable.
  }
}

function sendRelayRequest(
  options: CapturedOptions,
  agent: Agent,
  providerSandboxId: string,
  credential: string,
  body: Buffer,
  signal: AbortSignal
): Promise<import("node:http").IncomingMessage> {
  return new Promise((resolve, reject) => {
    const requestOptions: RequestOptions = {
      protocol: "https:",
      hostname: options.origin.hostname,
      port: options.origin.port || 443,
      method: "POST",
      path: `/sandboxes/${providerSandboxId}/terminalx-supervisor-relay`,
      agent,
      ca: options.runnerCaPem,
      ...(isIP(options.origin.hostname) === 0 ? { servername: options.origin.hostname } : {}),
      rejectUnauthorized: true,
      checkServerIdentity: (hostname, certificate) =>
        verifyServerIdentity(hostname, certificate, options.runnerTlsSpkiSha256),
      headers: {
        accept: DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE,
        authorization: `Bearer ${credential}`,
        "cache-control": "no-store",
        "content-length": String(body.byteLength),
        "content-type": DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE,
      },
      signal,
    };
    let responseReceived = false;
    let writeComplete = false;
    let response: import("node:http").IncomingMessage | undefined;
    const finish = (): void => {
      if (responseReceived && writeComplete && response) resolve(response);
    };
    try {
      const outgoing = httpsRequest(requestOptions, (incoming) => {
        response = incoming;
        responseReceived = true;
        finish();
      });
      outgoing.once("error", () => reject(new DaytonaSupervisorProtocolError("unavailable")));
      outgoing.end(body, () => {
        writeComplete = true;
        finish();
      });
    } catch {
      reject(new DaytonaSupervisorProtocolError("unavailable"));
    }
  });
}

async function* decodeResponseFrames(
  response: import("node:http").IncomingMessage,
  signal: AbortSignal,
  maximumFrameBytes: number
): AsyncIterable<DaytonaSupervisorSocketOutboundFrame> {
  const decoder = new DaytonaSupervisorSocketFrameDecoder(maximumFrameBytes);
  let terminal = false;
  try {
    for await (const chunk of response) {
      if (signal.aborted) throw new DaytonaSupervisorProtocolError("unavailable");
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      try {
        for (const rawFrame of decoder.push(bytes)) {
          if (terminal) throw protocolFailure();
          const frame = snapshotDaytonaSupervisorSocketOutboundFrame(rawFrame);
          terminal =
            frame.type === "end" ||
            (frame.type === "response" && (frame.ok === true || frame.ok === false));
          yield frame;
        }
      } finally {
        bytes.fill(0);
      }
    }
    decoder.finish();
    if (!terminal) throw new DaytonaSupervisorProtocolError("unavailable");
  } catch {
    throw new DaytonaSupervisorProtocolError("unavailable");
  } finally {
    decoder.destroy();
    response.destroy();
  }
}

function verifyServerIdentity(
  hostname: string,
  certificate: DetailedPeerCertificate,
  expectedSpkiSha256: string
): Error | undefined {
  const standard = checkServerIdentity(hostname, certificate);
  if (standard) return standard;
  try {
    if (!Buffer.isBuffer(certificate.pubkey) || certificate.pubkey.byteLength < 1) {
      return new Error("TLS peer key unavailable");
    }
    const actual = createHash("sha256").update(certificate.pubkey).digest();
    const expected = Buffer.from(expectedSpkiSha256, "hex");
    if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) {
      return new Error("TLS peer key mismatch");
    }
    return undefined;
  } catch {
    return new Error("TLS peer verification failed");
  }
}

function decodeCredential(value: Uint8Array): string {
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(value);
  if (decoded.length < 1 || decoded.trim() !== decoded || /[\u0000-\u0020\u007f]/u.test(decoded)) {
    throw new TypeError();
  }
  return decoded;
}

function snapshotPtyOpenRequest(value: unknown): DaytonaSupervisorPtyOpenRequest {
  const record = portableRecord(value, [
    "providerSandboxId",
    "expectedProviderRevision",
    "binding",
    "planDigest",
    "terminalId",
    "cols",
    "rows",
  ]);
  return Object.freeze({
    providerSandboxId: sandboxId(dataValue(record, "providerSandboxId")),
    expectedProviderRevision: positiveInteger(dataValue(record, "expectedProviderRevision")),
    binding: snapshotPtyBinding(dataValue(record, "binding")),
    planDigest: digestValue(dataValue(record, "planDigest")),
    terminalId: terminalIdValue(dataValue(record, "terminalId")),
    cols: boundedPtyDimension(dataValue(record, "cols"), 500),
    rows: boundedPtyDimension(dataValue(record, "rows"), 300),
  });
}

function snapshotPtyInputRequest(value: unknown): DaytonaSupervisorPtyInputRequest {
  const record = exactNativeRecord(value, [
    "providerSandboxId",
    "expectedProviderRevision",
    "binding",
    "planDigest",
    "terminalId",
    "inputSeq",
    "bytes",
  ]);
  const unsafeBytes = dataValue(record, "bytes");
  if (
    !(unsafeBytes instanceof Uint8Array) ||
    nodeTypes.isProxy(unsafeBytes) ||
    !(unsafeBytes.buffer instanceof ArrayBuffer) ||
    unsafeBytes.byteLength < 1 ||
    unsafeBytes.byteLength > 16 * 1024
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return Object.freeze({
    ...snapshotPtyFence(record),
    inputSeq: positiveInteger(dataValue(record, "inputSeq")),
    bytes: new Uint8Array(unsafeBytes),
  });
}

function snapshotPtyResizeRequest(value: unknown): DaytonaSupervisorPtyResizeRequest {
  const record = portableRecord(value, [
    "providerSandboxId",
    "expectedProviderRevision",
    "binding",
    "planDigest",
    "terminalId",
    "resizeSeq",
    "cols",
    "rows",
  ]);
  return Object.freeze({
    ...snapshotPtyFence(record),
    resizeSeq: positiveInteger(dataValue(record, "resizeSeq")),
    cols: boundedPtyDimension(dataValue(record, "cols"), 500),
    rows: boundedPtyDimension(dataValue(record, "rows"), 300),
  });
}

function snapshotPtyInterruptRequest(value: unknown): DaytonaSupervisorPtyInterruptRequest {
  const record = portableRecord(value, [
    "providerSandboxId",
    "expectedProviderRevision",
    "binding",
    "planDigest",
    "terminalId",
    "interruptSeq",
  ]);
  return Object.freeze({
    ...snapshotPtyFence(record),
    interruptSeq: positiveInteger(dataValue(record, "interruptSeq")),
  });
}

function snapshotPtyDestroyRequest(value: unknown): DaytonaSupervisorPtyDestroyRequest {
  const record = portableRecord(value, [
    "providerSandboxId",
    "expectedProviderRevision",
    "binding",
    "planDigest",
    "terminalId",
  ]);
  return Object.freeze(snapshotPtyFence(record));
}

function snapshotPtyFence(record: Record<string, unknown>): DaytonaSupervisorPtyDestroyRequest {
  return {
    providerSandboxId: sandboxId(dataValue(record, "providerSandboxId")),
    expectedProviderRevision: positiveInteger(dataValue(record, "expectedProviderRevision")),
    binding: snapshotPtyBinding(dataValue(record, "binding")),
    planDigest: digestValue(dataValue(record, "planDigest")),
    terminalId: terminalIdValue(dataValue(record, "terminalId")),
  };
}

function snapshotPtyReady(
  value: unknown
): Extract<DaytonaSupervisorPtyStreamItem, { kind: "ready" }> {
  const record = portableRecord(value, [
    "kind",
    "providerSandboxId",
    "expectedProviderRevision",
    "binding",
    "planDigest",
    "terminalId",
  ]);
  if (dataValue(record, "kind") !== "ready") throw protocolFailure();
  return Object.freeze({
    kind: "ready",
    providerSandboxId: sandboxId(dataValue(record, "providerSandboxId")),
    expectedProviderRevision: positiveInteger(dataValue(record, "expectedProviderRevision")),
    binding: snapshotPtyBinding(dataValue(record, "binding")),
    planDigest: digestValue(dataValue(record, "planDigest")),
    terminalId: terminalIdValue(dataValue(record, "terminalId")),
  });
}

function snapshotPtyStreamItem(value: unknown): DaytonaSupervisorPtyStreamItem {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot)) {
    throw protocolFailure();
  }
  const kind = dataValue(snapshot as Record<string, unknown>, "kind");
  if (kind === "ready") return snapshotPtyReady(snapshot);
  if (kind === "exit") {
    const record = portableRecord(snapshot, ["kind", "terminalId"]);
    return Object.freeze({
      kind: "exit",
      terminalId: terminalIdValue(dataValue(record, "terminalId")),
    });
  }
  if (kind !== "output") throw protocolFailure();
  const record = portableRecord(snapshot, ["kind", "terminalId", "outputSeq", "bytesBase64"]);
  const bytesBase64 = dataValue(record, "bytesBase64");
  if (typeof bytesBase64 !== "string") throw protocolFailure();
  const decoded = decodeTerminalBytes(bytesBase64);
  decoded.fill(0);
  return Object.freeze({
    kind: "output",
    terminalId: terminalIdValue(dataValue(record, "terminalId")),
    outputSeq: positiveInteger(dataValue(record, "outputSeq")),
    bytesBase64,
  });
}

function assertReadyMatches(
  ready: Extract<DaytonaSupervisorPtyStreamItem, { kind: "ready" }>,
  request: DaytonaSupervisorPtyOpenRequest
): void {
  if (
    ready.providerSandboxId !== request.providerSandboxId ||
    ready.expectedProviderRevision !== request.expectedProviderRevision ||
    ready.planDigest !== request.planDigest ||
    ready.terminalId !== request.terminalId ||
    !samePtyBinding(ready.binding, request.binding)
  ) {
    throw protocolFailure();
  }
}

function snapshotPtyBinding(value: unknown): RuntimeBinding {
  const record = portableRecord(value, [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ]);
  return Object.freeze({
    teamId: safePtyReference(dataValue(record, "teamId")),
    projectId: safePtyReference(dataValue(record, "projectId")),
    sessionId: safePtyReference(dataValue(record, "sessionId")),
    runtimeAssignmentId: safePtyReference(dataValue(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(dataValue(record, "runtimeAssignmentGeneration")),
    sandboxId: safePtyReference(dataValue(record, "sandboxId")),
    sandboxGeneration: positiveInteger(dataValue(record, "sandboxGeneration")),
    runtimePrincipalId: safePtyReference(dataValue(record, "runtimePrincipalId")),
  });
}

function samePtyBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
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

function portableRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  let snapshot: unknown;
  try {
    snapshot = snapshotRuntimeSupervisorPortableData(value);
  } catch {
    throw protocolFailure();
  }
  if (
    typeof snapshot !== "object" ||
    snapshot === null ||
    Array.isArray(snapshot) ||
    Reflect.ownKeys(snapshot).length !== names.length ||
    Reflect.ownKeys(snapshot).some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw protocolFailure();
  }
  for (const name of names) dataValue(snapshot as Record<string, unknown>, name);
  return snapshot as Record<string, unknown>;
}

function exactNativeRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw protocolFailure();
  }
  const record = value as Record<string, unknown>;
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw protocolFailure();
  }
  for (const name of names) dataValue(record, name);
  return record;
}

function dataValue(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw protocolFailure();
  return descriptor.value;
}

function decodeTerminalBytes(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]{2,87382}$/.test(value)) throw protocolFailure();
  const bytes = Buffer.from(value, "base64url");
  if (
    bytes.byteLength < 1 ||
    bytes.byteLength > 64 * 1024 ||
    bytes.toString("base64url") !== value
  ) {
    bytes.fill(0);
    throw protocolFailure();
  }
  return bytes;
}

function safePtyReference(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 1024 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw protocolFailure();
  }
  return value;
}

function terminalIdValue(value: unknown): string {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw protocolFailure();
  return value;
}

function digestValue(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw protocolFailure();
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw protocolFailure();
  return value as number;
}

function boundedPtyDimension(value: unknown, maximum: number): number {
  const result = positiveInteger(value);
  if (result < 2 || result > maximum) throw protocolFailure();
  return result;
}

function captureListener<T>(value: T): T {
  if (typeof value !== "function" || nodeTypes.isProxy(value)) throw protocolFailure();
  return value;
}

function sandboxId(value: unknown): string {
  if (typeof value !== "string" || !UUID_V4.test(value)) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return value;
}

function boundedTimeout(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < MIN_TIMEOUT_MS ||
    (value as number) > MAX_TIMEOUT_MS
  ) {
    throw new TypeError();
  }
  return value as number;
}

function boundedTerminalLifetime(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 60_000 ||
    (value as number) > MAX_TERMINAL_LIFETIME_MS
  ) {
    throw new TypeError();
  }
  return value as number;
}

function boundedPendingTerminalOutput(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 64 * 1024 ||
    (value as number) > MAX_PENDING_TERMINAL_OUTPUT_BYTES
  ) {
    throw new TypeError();
  }
  return value as number;
}

function boundedFrameBytes(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1024 ||
    (value as number) > 16 * 1024 * 1024
  ) {
    throw new TypeError();
  }
  return value as number;
}

function protocolFailure(): DaytonaSupervisorProtocolError {
  return new DaytonaSupervisorProtocolError("internal");
}
