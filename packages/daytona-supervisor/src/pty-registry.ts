import { timingSafeEqual } from "node:crypto";
import { types as nodeTypes } from "node:util";
import type {
  DaytonaSupervisorPtyDestroyRequest,
  DaytonaSupervisorPtyInterruptRequest,
  DaytonaSupervisorPtyOpenRequest,
  DaytonaSupervisorPtyResizeRequest,
} from "../../../src/lib/runtime/daytona-hosted-terminal-adapter";
import type { RuntimeBinding } from "../../../src/lib/team-sessions/contracts";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import { DaytonaSupervisorProtocolError } from "./supervisor";

const SHA256 = /^[0-9a-f]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,1024}$/u;
const BASE64URL = /^(?:[A-Za-z0-9_-]{2,21846})$/;
const MAX_INPUT_BYTES = 16 * 1024;
const MIN_COLS_ROWS = 2;
const MAX_COLS = 500;
const MAX_ROWS = 300;
const MAX_TERMINALS = 256;
const MAX_PENDING_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_OUTPUT_FRAME_BYTES = 64 * 1024;

export interface DaytonaSupervisorPtyInputWireRequest {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly terminalId: string;
  readonly inputSeq: number;
  readonly bytesBase64: string;
}

export type DaytonaSupervisorPtyWireRequest =
  | DaytonaSupervisorPtyOpenRequest
  | DaytonaSupervisorPtyInputWireRequest
  | DaytonaSupervisorPtyResizeRequest
  | DaytonaSupervisorPtyInterruptRequest
  | DaytonaSupervisorPtyDestroyRequest;

export type DaytonaSupervisorPtyStreamItem =
  | Readonly<{
      kind: "ready";
      providerSandboxId: string;
      expectedProviderRevision: number;
      binding: RuntimeBinding;
      planDigest: string;
      terminalId: string;
    }>
  | Readonly<{
      kind: "output";
      terminalId: string;
      outputSeq: number;
      bytesBase64: string;
    }>
  | Readonly<{
      kind: "exit";
      terminalId: string;
    }>;

export interface DaytonaSupervisorPtyDriverOpenRequest {
  readonly terminalId: string;
  readonly cols: number;
  readonly rows: number;
}

export interface DaytonaSupervisorPtyDriverConnection {
  onData(listener: (bytes: Uint8Array) => void): { dispose(): void };
  onExit(listener: () => void): { dispose(): void };
  input(bytes: Uint8Array, signal: AbortSignal): Promise<void>;
  resize(cols: number, rows: number, signal: AbortSignal): Promise<void>;
  interrupt(signal: AbortSignal): Promise<void>;
  destroy(): Promise<void>;
  pause(): void;
  resume(): void;
}

export interface DaytonaSupervisorPtyDriver {
  open(
    request: DaytonaSupervisorPtyDriverOpenRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorPtyDriverConnection>;
  close(): Promise<void>;
}

export interface DaytonaSupervisorPtyService {
  open(request: unknown, signal: AbortSignal): AsyncIterable<DaytonaSupervisorPtyStreamItem>;
  input(request: unknown, signal: AbortSignal): Promise<void>;
  resize(request: unknown, signal: AbortSignal): Promise<void>;
  interrupt(request: unknown, signal: AbortSignal): Promise<void>;
  destroy(request: unknown, signal: AbortSignal): Promise<void>;
  close(): Promise<void>;
}

export interface CreateDaytonaSupervisorPtyRegistryOptions {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  /** Synchronous, local verification of the freshly installed live isolation evidence. */
  readonly requireCurrentIsolation: () => boolean;
  readonly driver: DaytonaSupervisorPtyDriver;
  readonly maximumTerminals: number;
  readonly maximumTerminalsPerSandbox: number;
  readonly maximumPendingOutputBytes: number;
  readonly maximumOutputFrameBytes: number;
}

interface CapturedOptions {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly requireCurrentIsolation: () => boolean;
  readonly driver: DaytonaSupervisorPtyDriver;
  readonly maximumTerminals: number;
  readonly maximumTerminalsPerSandbox: number;
  readonly maximumPendingOutputBytes: number;
  readonly maximumOutputFrameBytes: number;
}

interface TerminalState {
  readonly request: DaytonaSupervisorPtyOpenRequest;
  readonly connection: DaytonaSupervisorPtyDriverConnection;
  readonly queue: BoundedPtyOutputQueue;
  dataSubscription: { dispose(): void } | null;
  exitSubscription: { dispose(): void } | null;
  nextInputSeq: number;
  nextResizeSeq: number;
  nextInterruptSeq: number;
  nextOutputSeq: number;
  tail: Promise<void>;
  destroying: Promise<void> | null;
  exited: boolean;
}

/**
 * Root-supervisor PTY authority. The registry admits only an exact assignment
 * fence, rechecks fresh isolation before every mutation, and delegates process
 * creation to one captured fixed-shell driver. It has no command/cwd/env input.
 */
export function createDaytonaSupervisorPtyRegistry(
  unsafeOptions: CreateDaytonaSupervisorPtyRegistryOptions
): DaytonaSupervisorPtyService {
  return new DaytonaSupervisorPtyRegistry(unsafeOptions);
}

class DaytonaSupervisorPtyRegistry implements DaytonaSupervisorPtyService {
  private readonly options: CapturedOptions;
  private readonly terminals = new Map<string, TerminalState>();
  private readonly pendingTerminalIds = new Set<string>();
  private closed = false;
  private closePromise: Promise<void> | null = null;

  constructor(unsafeOptions: CreateDaytonaSupervisorPtyRegistryOptions) {
    this.options = captureOptions(unsafeOptions);
  }

  open(unsafeRequest: unknown, signal: AbortSignal): AsyncIterable<DaytonaSupervisorPtyStreamItem> {
    assertSignal(signal);
    const request = snapshotOpenRequest(unsafeRequest);
    this.requireFence(request);
    return Object.freeze({
      [Symbol.asyncIterator]: () => this.openIterator(request, signal),
    });
  }

  private async *openIterator(
    request: DaytonaSupervisorPtyOpenRequest,
    signal: AbortSignal
  ): AsyncGenerator<DaytonaSupervisorPtyStreamItem> {
    const state = await this.openTerminal(request, signal);
    try {
      yield Object.freeze({
        kind: "ready" as const,
        providerSandboxId: request.providerSandboxId,
        expectedProviderRevision: request.expectedProviderRevision,
        binding: request.binding,
        planDigest: request.planDigest,
        terminalId: request.terminalId,
      });
      for await (const item of state.queue) yield item;
    } finally {
      await this.destroyState(state).catch(() => undefined);
    }
  }

  input(unsafeRequest: unknown, signal: AbortSignal): Promise<void> {
    assertSignal(signal);
    const request = snapshotInputRequest(unsafeRequest);
    const bytes = decodeBase64Url(request.bytesBase64, MAX_INPUT_BYTES);
    return this.mutate(request, signal, async (state) => {
      if (request.inputSeq !== state.nextInputSeq) conflict();
      state.nextInputSeq += 1;
      try {
        await state.connection.input(bytes, signal);
        if (signal.aborted) unavailable();
      } catch {
        void this.destroyState(state).catch(() => undefined);
        unavailable();
      }
    }).finally(() => bytes.fill(0));
  }

  resize(unsafeRequest: unknown, signal: AbortSignal): Promise<void> {
    assertSignal(signal);
    const request = snapshotResizeRequest(unsafeRequest);
    return this.mutate(request, signal, async (state) => {
      if (request.resizeSeq !== state.nextResizeSeq) conflict();
      state.nextResizeSeq += 1;
      try {
        await state.connection.resize(request.cols, request.rows, signal);
        if (signal.aborted) unavailable();
      } catch {
        void this.destroyState(state).catch(() => undefined);
        unavailable();
      }
    });
  }

  interrupt(unsafeRequest: unknown, signal: AbortSignal): Promise<void> {
    assertSignal(signal);
    const request = snapshotInterruptRequest(unsafeRequest);
    return this.mutate(request, signal, async (state) => {
      if (request.interruptSeq !== state.nextInterruptSeq) conflict();
      state.nextInterruptSeq += 1;
      try {
        await state.connection.interrupt(signal);
        if (signal.aborted) unavailable();
      } catch {
        void this.destroyState(state).catch(() => undefined);
        unavailable();
      }
    });
  }

  async destroy(unsafeRequest: unknown, signal: AbortSignal): Promise<void> {
    assertSignal(signal);
    const request = snapshotDestroyRequest(unsafeRequest);
    this.requireFence(request);
    this.requireIsolation();
    const state = this.terminals.get(request.terminalId);
    if (!state) return;
    requireSameTerminalFence(state.request, request);
    await this.destroyState(state);
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.closePromise = (async () => {
      const states = [...this.terminals.values()];
      await Promise.allSettled(states.map((state) => this.destroyState(state)));
      this.terminals.clear();
      this.pendingTerminalIds.clear();
      await this.options.driver.close();
    })();
    return this.closePromise;
  }

  private async openTerminal(
    request: DaytonaSupervisorPtyOpenRequest,
    signal: AbortSignal
  ): Promise<TerminalState> {
    if (
      this.closed ||
      signal.aborted ||
      this.terminals.has(request.terminalId) ||
      this.pendingTerminalIds.has(request.terminalId)
    ) {
      conflict();
    }
    this.requireIsolation();
    const matchingSandboxCount = [...this.terminals.values()].filter(
      (state) => state.request.providerSandboxId === request.providerSandboxId
    ).length;
    if (
      this.terminals.size + this.pendingTerminalIds.size >= this.options.maximumTerminals ||
      matchingSandboxCount + this.pendingTerminalIds.size >= this.options.maximumTerminalsPerSandbox
    ) {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    this.pendingTerminalIds.add(request.terminalId);
    let connection: DaytonaSupervisorPtyDriverConnection | null = null;
    let state: TerminalState | null = null;
    try {
      connection = captureConnection(
        await this.options.driver.open(
          Object.freeze({
            terminalId: request.terminalId,
            cols: request.cols,
            rows: request.rows,
          }),
          signal
        )
      );
      if (this.closed || signal.aborted) {
        throw new DaytonaSupervisorProtocolError("unavailable");
      }
      this.requireIsolation();
      const queue = new BoundedPtyOutputQueue(connection, this.options.maximumPendingOutputBytes);
      state = {
        request,
        connection,
        queue,
        dataSubscription: null,
        exitSubscription: null,
        nextInputSeq: 1,
        nextResizeSeq: 1,
        nextInterruptSeq: 1,
        nextOutputSeq: 1,
        tail: Promise.resolve(),
        destroying: null,
        exited: false,
      } satisfies TerminalState;
      const admittedState = state;
      // Publish the reserved identity before subscribing. A hostile driver may
      // synchronously emit from onData/onExit; callbacks must see this exact state.
      this.terminals.set(request.terminalId, admittedState);
      const dataSubscription = captureDisposer(
        connection.onData((bytes) => this.receiveOutput(admittedState, bytes))
      );
      admittedState.dataSubscription = dataSubscription;
      if (
        admittedState.exited ||
        admittedState.destroying ||
        this.terminals.get(request.terminalId) !== admittedState
      ) {
        throw new DaytonaSupervisorProtocolError("unavailable");
      }
      let exitSubscription: { dispose(): void };
      try {
        exitSubscription = captureDisposer(
          connection.onExit(() => this.receiveExit(admittedState))
        );
      } catch (error) {
        dataSubscription.dispose();
        throw error;
      }
      admittedState.exitSubscription = exitSubscription;
      if (
        admittedState.exited ||
        admittedState.destroying ||
        this.terminals.get(request.terminalId) !== admittedState
      ) {
        throw new DaytonaSupervisorProtocolError("unavailable");
      }
      connection = null;
      return admittedState;
    } catch (error) {
      if (state) await this.destroyState(state).catch(() => undefined);
      else await connection?.destroy().catch(() => undefined);
      if (error instanceof DaytonaSupervisorProtocolError) throw error;
      throw new DaytonaSupervisorProtocolError("unavailable");
    } finally {
      this.pendingTerminalIds.delete(request.terminalId);
    }
  }

  private mutate(
    request: DaytonaSupervisorPtyWireRequest,
    signal: AbortSignal,
    operation: (state: TerminalState) => Promise<void>
  ): Promise<void> {
    this.requireFence(request);
    const state = this.terminals.get(request.terminalId);
    if (!state || state.exited || state.destroying) {
      return Promise.reject(new DaytonaSupervisorProtocolError("unavailable"));
    }
    requireSameTerminalFence(state.request, request);
    const result = state.tail.then(async () => {
      if (this.closed || state.exited || state.destroying || signal.aborted) unavailable();
      this.requireIsolation();
      await operation(state);
      if (signal.aborted) {
        void this.destroyState(state).catch(() => undefined);
        unavailable();
      }
    });
    state.tail = result.catch(() => undefined);
    return result.catch((error) => {
      if (error instanceof DaytonaSupervisorProtocolError) throw error;
      throw new DaytonaSupervisorProtocolError("unavailable");
    });
  }

  private receiveOutput(state: TerminalState, unsafeBytes: Uint8Array): void {
    try {
      if (
        state.exited ||
        state.destroying ||
        !(unsafeBytes instanceof Uint8Array) ||
        nodeTypes.isProxy(unsafeBytes) ||
        unsafeBytes.byteLength < 1
      ) {
        unavailable();
      }
      const copy = Buffer.from(unsafeBytes);
      try {
        for (
          let offset = 0;
          offset < copy.byteLength;
          offset += this.options.maximumOutputFrameBytes
        ) {
          const bytes = copy.subarray(
            offset,
            Math.min(copy.byteLength, offset + this.options.maximumOutputFrameBytes)
          );
          const outputSeq = state.nextOutputSeq;
          if (!Number.isSafeInteger(outputSeq) || outputSeq < 1) unavailable();
          state.nextOutputSeq += 1;
          state.queue.push(
            Object.freeze({
              kind: "output" as const,
              terminalId: state.request.terminalId,
              outputSeq,
              bytesBase64: Buffer.from(bytes).toString("base64url"),
            }),
            bytes.byteLength
          );
        }
      } finally {
        copy.fill(0);
      }
    } catch {
      state.queue.fail(new DaytonaSupervisorProtocolError("unavailable"));
      void this.destroyState(state).catch(() => undefined);
    }
  }

  private receiveExit(state: TerminalState): void {
    if (state.exited) return;
    state.exited = true;
    state.queue.push(
      Object.freeze({ kind: "exit" as const, terminalId: state.request.terminalId }),
      0
    );
    state.queue.end();
  }

  private destroyState(state: TerminalState): Promise<void> {
    if (state.destroying) return state.destroying;
    if (this.terminals.get(state.request.terminalId) === state) {
      this.terminals.delete(state.request.terminalId);
    }
    state.destroying = (async () => {
      state.dataSubscription?.dispose();
      state.exitSubscription?.dispose();
      state.dataSubscription = null;
      state.exitSubscription = null;
      state.queue.end();
      await state.tail.catch(() => undefined);
      await state.connection.destroy();
      state.exited = true;
    })();
    return state.destroying;
  }

  private requireFence(request: DaytonaSupervisorPtyWireRequest): void {
    if (this.closed) unavailable();
    if (
      request.providerSandboxId !== this.options.providerSandboxId ||
      request.expectedProviderRevision !== this.options.expectedProviderRevision ||
      !sameDigest(request.planDigest, this.options.planDigest) ||
      !sameBinding(request.binding, this.options.binding)
    ) {
      conflict();
    }
  }

  private requireIsolation(): void {
    let result: unknown;
    try {
      result = this.options.requireCurrentIsolation();
    } catch {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    if (result !== true) {
      if (nodeTypes.isPromise(result)) void result.catch(() => undefined);
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
  }
}

class BoundedPtyOutputQueue implements AsyncIterable<DaytonaSupervisorPtyStreamItem> {
  private readonly values: Array<{
    readonly item: DaytonaSupervisorPtyStreamItem;
    readonly byteLength: number;
  }> = [];
  private readonly readers: Array<{
    resolve(value: IteratorResult<DaytonaSupervisorPtyStreamItem>): void;
    reject(error: DaytonaSupervisorProtocolError): void;
  }> = [];
  private pendingBytes = 0;
  private paused = false;
  private ended = false;
  private failure: DaytonaSupervisorProtocolError | null = null;

  constructor(
    private readonly connection: DaytonaSupervisorPtyDriverConnection,
    private readonly maximumPendingBytes: number
  ) {}

  push(item: DaytonaSupervisorPtyStreamItem, byteLength: number): void {
    if (this.ended || this.failure) return;
    const reader = this.readers.shift();
    if (reader) {
      reader.resolve({ done: false, value: item });
      return;
    }
    this.pendingBytes += byteLength;
    if (this.pendingBytes > this.maximumPendingBytes) {
      this.fail(new DaytonaSupervisorProtocolError("unavailable"));
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    this.values.push({ item, byteLength });
    if (!this.paused && this.pendingBytes >= Math.ceil(this.maximumPendingBytes / 2)) {
      this.paused = true;
      this.connection.pause();
    }
  }

  end(): void {
    if (this.ended || this.failure) return;
    this.ended = true;
    if (this.paused) {
      this.paused = false;
      this.connection.resume();
    }
    for (const reader of this.readers.splice(0)) {
      reader.resolve({ done: true, value: undefined });
    }
  }

  fail(error: DaytonaSupervisorProtocolError): void {
    if (this.ended || this.failure) return;
    this.failure = error;
    this.pendingBytes = 0;
    this.values.length = 0;
    if (this.paused) {
      this.paused = false;
      this.connection.resume();
    }
    for (const reader of this.readers.splice(0)) reader.reject(error);
  }

  [Symbol.asyncIterator](): AsyncIterator<DaytonaSupervisorPtyStreamItem> {
    return {
      next: () => {
        const entry = this.values.shift();
        if (entry) {
          this.pendingBytes -= entry.byteLength;
          if (this.paused && this.pendingBytes < Math.ceil(this.maximumPendingBytes / 4)) {
            this.paused = false;
            this.connection.resume();
          }
          return Promise.resolve({ done: false, value: entry.item });
        }
        if (this.failure) return Promise.reject(this.failure);
        if (this.ended) return Promise.resolve({ done: true, value: undefined });
        return new Promise((resolve, reject) => this.readers.push({ resolve, reject }));
      },
      return: async () => {
        this.end();
        return { done: true, value: undefined };
      },
    };
  }
}

function captureOptions(value: CreateDaytonaSupervisorPtyRegistryOptions): CapturedOptions {
  const record = exactRecord(value, [
    "providerSandboxId",
    "expectedProviderRevision",
    "binding",
    "planDigest",
    "requireCurrentIsolation",
    "driver",
    "maximumTerminals",
    "maximumTerminalsPerSandbox",
    "maximumPendingOutputBytes",
    "maximumOutputFrameBytes",
  ]);
  const requireCurrentIsolation = field(record, "requireCurrentIsolation");
  if (typeof requireCurrentIsolation !== "function" || nodeTypes.isProxy(requireCurrentIsolation)) {
    throw new TypeError();
  }
  const driver = captureDriver(field(record, "driver"));
  const maximumTerminals = boundedInteger(field(record, "maximumTerminals"), 1, MAX_TERMINALS);
  const maximumTerminalsPerSandbox = boundedInteger(
    field(record, "maximumTerminalsPerSandbox"),
    1,
    maximumTerminals
  );
  return Object.freeze({
    providerSandboxId: safeReference(field(record, "providerSandboxId")),
    expectedProviderRevision: positiveInteger(field(record, "expectedProviderRevision")),
    binding: snapshotBinding(field(record, "binding")),
    planDigest: digest(field(record, "planDigest")),
    requireCurrentIsolation: requireCurrentIsolation as () => boolean,
    driver,
    maximumTerminals,
    maximumTerminalsPerSandbox,
    maximumPendingOutputBytes: boundedInteger(
      field(record, "maximumPendingOutputBytes"),
      MAX_OUTPUT_FRAME_BYTES,
      MAX_PENDING_OUTPUT_BYTES
    ),
    maximumOutputFrameBytes: boundedInteger(
      field(record, "maximumOutputFrameBytes"),
      1024,
      MAX_OUTPUT_FRAME_BYTES
    ),
  });
}

function captureDriver(value: unknown): DaytonaSupervisorPtyDriver {
  const record = exactRecord(value, ["open", "close"]);
  const open = functionField(record, "open");
  const close = functionField(record, "close");
  return Object.freeze({
    open: (request: DaytonaSupervisorPtyDriverOpenRequest, signal: AbortSignal) =>
      Reflect.apply(open, value, [
        request,
        signal,
      ]) as Promise<DaytonaSupervisorPtyDriverConnection>,
    close: () => Reflect.apply(close, value, []) as Promise<void>,
  });
}

function captureConnection(value: unknown): DaytonaSupervisorPtyDriverConnection {
  const record = exactRecord(value, [
    "onData",
    "onExit",
    "input",
    "resize",
    "interrupt",
    "destroy",
    "pause",
    "resume",
  ]);
  return Object.freeze(
    Object.fromEntries(
      Reflect.ownKeys(record).map((name) => {
        if (typeof name !== "string") throw new TypeError();
        const method = functionField(record, name);
        return [name, (...args: unknown[]) => Reflect.apply(method, value, args)];
      })
    ) as unknown as DaytonaSupervisorPtyDriverConnection
  );
}

function captureDisposer(value: unknown): { dispose(): void } {
  const record = exactRecord(value, ["dispose"]);
  const dispose = functionField(record, "dispose");
  return Object.freeze({ dispose: () => void Reflect.apply(dispose, value, []) });
}

function snapshotOpenRequest(value: unknown): DaytonaSupervisorPtyOpenRequest {
  const record = requestRecord(value, ["cols", "rows"]);
  return Object.freeze({
    ...snapshotFence(record),
    cols: boundedInteger(field(record, "cols"), MIN_COLS_ROWS, MAX_COLS),
    rows: boundedInteger(field(record, "rows"), MIN_COLS_ROWS, MAX_ROWS),
  });
}

function snapshotInputRequest(value: unknown): DaytonaSupervisorPtyInputWireRequest {
  const record = requestRecord(value, ["inputSeq", "bytesBase64"]);
  const bytesBase64 = field(record, "bytesBase64");
  if (typeof bytesBase64 !== "string" || !BASE64URL.test(bytesBase64)) throwInvalid();
  // Decode at the structural boundary so noncanonical and oversized encodings fail early.
  const decoded = decodeBase64Url(bytesBase64, MAX_INPUT_BYTES);
  decoded.fill(0);
  return Object.freeze({
    ...snapshotFence(record),
    inputSeq: positiveInteger(field(record, "inputSeq")),
    bytesBase64,
  });
}

function snapshotResizeRequest(value: unknown): DaytonaSupervisorPtyResizeRequest {
  const record = requestRecord(value, ["resizeSeq", "cols", "rows"]);
  return Object.freeze({
    ...snapshotFence(record),
    resizeSeq: positiveInteger(field(record, "resizeSeq")),
    cols: boundedInteger(field(record, "cols"), MIN_COLS_ROWS, MAX_COLS),
    rows: boundedInteger(field(record, "rows"), MIN_COLS_ROWS, MAX_ROWS),
  });
}

function snapshotInterruptRequest(value: unknown): DaytonaSupervisorPtyInterruptRequest {
  const record = requestRecord(value, ["interruptSeq"]);
  return Object.freeze({
    ...snapshotFence(record),
    interruptSeq: positiveInteger(field(record, "interruptSeq")),
  });
}

function snapshotDestroyRequest(value: unknown): DaytonaSupervisorPtyDestroyRequest {
  return Object.freeze(snapshotFence(requestRecord(value, [])));
}

function requestRecord(value: unknown, extraFields: readonly string[]): Record<string, unknown> {
  try {
    return exactRecord(snapshotRuntimeSupervisorPortableData(value), [
      "providerSandboxId",
      "expectedProviderRevision",
      "binding",
      "planDigest",
      "terminalId",
      ...extraFields,
    ]);
  } catch {
    throwInvalid();
  }
}

function snapshotFence(record: Record<string, unknown>) {
  return {
    providerSandboxId: safeReference(field(record, "providerSandboxId")),
    expectedProviderRevision: positiveInteger(field(record, "expectedProviderRevision")),
    binding: snapshotBinding(field(record, "binding")),
    planDigest: digest(field(record, "planDigest")),
    terminalId: terminalId(field(record, "terminalId")),
  };
}

function requireSameTerminalFence(
  expected: DaytonaSupervisorPtyOpenRequest,
  actual: DaytonaSupervisorPtyWireRequest
): void {
  if (
    expected.providerSandboxId !== actual.providerSandboxId ||
    expected.expectedProviderRevision !== actual.expectedProviderRevision ||
    !sameDigest(expected.planDigest, actual.planDigest) ||
    expected.terminalId !== actual.terminalId ||
    !sameBinding(expected.binding, actual.binding)
  ) {
    conflict();
  }
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const record = exactRecord(value, [
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
    teamId: safeReference(field(record, "teamId")),
    projectId: safeReference(field(record, "projectId")),
    sessionId: safeReference(field(record, "sessionId")),
    runtimeAssignmentId: safeReference(field(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(record, "runtimeAssignmentGeneration")),
    sandboxId: safeReference(field(record, "sandboxId")),
    sandboxGeneration: positiveInteger(field(record, "sandboxGeneration")),
    runtimePrincipalId: safeReference(field(record, "runtimePrincipalId")),
  });
}

function sameBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
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

function decodeBase64Url(value: string, maximumBytes: number): Buffer {
  let bytes: Buffer;
  try {
    bytes = Buffer.from(value, "base64url");
  } catch {
    throwInvalid();
  }
  if (
    bytes.byteLength < 1 ||
    bytes.byteLength > maximumBytes ||
    bytes.toString("base64url") !== value
  ) {
    bytes.fill(0);
    throwInvalid();
  }
  return bytes;
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function functionField(
  record: Record<string, unknown>,
  name: string
): (...args: never[]) => unknown {
  const value = field(record, name);
  if (typeof value !== "function" || nodeTypes.isProxy(value)) throw new TypeError();
  return value as (...args: never[]) => unknown;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) throwInvalid();
  return value;
}

function terminalId(value: unknown): string {
  if (typeof value !== "string" || !UUID_V4.test(value)) throwInvalid();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throwInvalid();
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throwInvalid();
  return value as number;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throwInvalid();
  }
  return value as number;
}

function assertSignal(signal: unknown): asserts signal is AbortSignal {
  if (!(signal instanceof AbortSignal) || nodeTypes.isProxy(signal) || signal.aborted)
    unavailable();
}

function sameDigest(left: unknown, right: string): boolean {
  if (typeof left !== "string" || !SHA256.test(left)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function conflict(): never {
  throw new DaytonaSupervisorProtocolError("conflict");
}

function unavailable(): never {
  throw new DaytonaSupervisorProtocolError("unavailable");
}

function throwInvalid(): never {
  throw new DaytonaSupervisorProtocolError("invalid-request");
}
