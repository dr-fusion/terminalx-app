import { randomUUID } from "node:crypto";
import { TextDecoder, TextEncoder, types as nodeTypes } from "node:util";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { HostedTeamSessionTerminalBinding } from "../team-session-terminal-gateway";
import { digestHostedRuntimeAssignmentPlan } from "./hosted-runtime-adapter";
import { snapshotHostedRuntimeActivation } from "./hosted-runtime-activation";
import type {
  HostedAssignmentLookup,
  HostedAssignmentPlanSource,
  HostedControlPlaneSandbox,
  HostedRuntimeAssignmentPlan,
  HostedRuntimeControlPlane,
} from "./hosted-runtime-control-plane";
import type { HostedTerminalAdapter, HostedTerminalConnection } from "./hosted-terminal";
import {
  exactRuntimeSupervisorDataRecord,
  runtimeSupervisorDataField,
  snapshotRuntimeSupervisorPortableData,
} from "./runtime-supervisor-snapshot";

const SHA256 = /^[0-9a-f]{64}$/;
const INCARNATION = /^[0-9a-f]{64}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,1024}$/;
const MAX_TERMINAL_INPUT_BYTES = 16 * 1024;
const MAX_TERMINAL_OUTPUT_FRAME_BYTES = 64 * 1024;
const MAX_PENDING_TERMINAL_OUTPUT_BYTES = 1024 * 1024;
const MIN_OPERATION_TIMEOUT_MS = 100;
const MAX_OPERATION_TIMEOUT_MS = 300_000;
const MIN_TERMINAL_DIMENSION = 2;
const MAX_TERMINAL_COLS = 500;
const MAX_TERMINAL_ROWS = 300;
const MAX_PROTOTYPE_DEPTH = 32;

type AnyFunction = (...args: unknown[]) => unknown;

interface CapturedPlanSource {
  readonly receiver: object;
  readonly resolve: AnyFunction;
  readonly isCurrent: AnyFunction;
}

interface CapturedControlPlane {
  readonly receiver: object;
  readonly listExact: AnyFunction;
}

interface CapturedPtyTransport {
  readonly receiver: object;
  readonly open: AnyFunction;
  readonly close: AnyFunction;
}

interface CapturedPtyConnection {
  readonly receiver: object;
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly terminalId: string;
  readonly onData: AnyFunction;
  readonly onExit: AnyFunction;
  readonly input: AnyFunction;
  readonly resize: AnyFunction;
  readonly interrupt: AnyFunction;
  readonly destroy: AnyFunction;
}

export interface DaytonaSupervisorPtyOpenRequest {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly terminalId: string;
  readonly cols: number;
  readonly rows: number;
}

export interface DaytonaSupervisorPtyInputRequest {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly terminalId: string;
  readonly inputSeq: number;
  readonly bytes: Uint8Array;
}

export interface DaytonaSupervisorPtyResizeRequest {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly terminalId: string;
  readonly resizeSeq: number;
  readonly cols: number;
  readonly rows: number;
}

export interface DaytonaSupervisorPtyInterruptRequest {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly terminalId: string;
  readonly interruptSeq: number;
}

export interface DaytonaSupervisorPtyDestroyRequest {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly terminalId: string;
}

export interface DaytonaSupervisorPtyOutputFrame {
  readonly terminalId: string;
  readonly outputSeq: number;
  readonly bytes: Uint8Array;
}

export interface DaytonaSupervisorPtyExitFrame {
  readonly terminalId: string;
}

/**
 * Private, authenticated transport to the pinned in-Sandbox supervisor.
 * Implementations re-check the active Sandbox and every repeated fence
 * immediately before open and every mutation. None of these private requests
 * may be projected into durable events or client responses.
 */
export interface DaytonaSupervisorPtyTransport {
  open(
    request: DaytonaSupervisorPtyOpenRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorPtyConnection>;
  close(): Promise<void>;
}

export interface DaytonaSupervisorPtyConnection {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: RuntimeBinding;
  readonly planDigest: string;
  readonly terminalId: string;
  onData(listener: (frame: DaytonaSupervisorPtyOutputFrame) => void): { dispose(): void };
  onExit(listener: (frame: DaytonaSupervisorPtyExitFrame) => void): { dispose(): void };
  input(request: DaytonaSupervisorPtyInputRequest, signal: AbortSignal): Promise<void>;
  resize(request: DaytonaSupervisorPtyResizeRequest, signal: AbortSignal): Promise<void>;
  interrupt(request: DaytonaSupervisorPtyInterruptRequest, signal: AbortSignal): Promise<void>;
  destroy(request: DaytonaSupervisorPtyDestroyRequest, signal: AbortSignal): Promise<void>;
}

export interface CreateDaytonaHostedTerminalAdapterOptions {
  readonly plans: HostedAssignmentPlanSource;
  readonly controlPlane: HostedRuntimeControlPlane;
  readonly transport: DaytonaSupervisorPtyTransport;
  readonly operationTimeoutMs: number;
}

export interface DaytonaHostedTerminalAdapter extends HostedTerminalAdapter {
  close(): Promise<void>;
}

/** Stable, provider-blind terminal failure. */
export class DaytonaHostedTerminalError extends Error {
  constructor() {
    super("Hosted terminal unavailable");
    this.name = "DaytonaHostedTerminalError";
  }
}

class DaytonaHostedTerminalAdapterImpl implements DaytonaHostedTerminalAdapter {
  private readonly plans: CapturedPlanSource;
  private readonly controlPlane: CapturedControlPlane;
  private readonly transport: CapturedPtyTransport;
  private readonly operationTimeoutMs: number;
  private readonly connections = new Set<DaytonaHostedTerminalConnectionImpl>();
  private readonly shutdown = new AbortController();
  private closed = false;
  private closePromise: Promise<void> | null = null;

  constructor(options: CreateDaytonaHostedTerminalAdapterOptions) {
    const record = exactDataRecord(options, [
      "plans",
      "controlPlane",
      "transport",
      "operationTimeoutMs",
    ]);
    this.plans = capturePlanSource(dataField(record, "plans"));
    this.controlPlane = captureControlPlane(dataField(record, "controlPlane"));
    this.transport = capturePtyTransport(dataField(record, "transport"));
    this.operationTimeoutMs = boundedInteger(
      dataField(record, "operationTimeoutMs"),
      MIN_OPERATION_TIMEOUT_MS,
      MAX_OPERATION_TIMEOUT_MS
    );
  }

  async connect(options: {
    binding: HostedTeamSessionTerminalBinding;
    cols: number;
    rows: number;
    signal: AbortSignal;
  }): Promise<HostedTerminalConnection> {
    if (this.closed) unavailable();
    const request = exactDataRecord(options, ["binding", "cols", "rows", "signal"]);
    const binding = snapshotTerminalBinding(dataField(request, "binding"));
    const cols = terminalDimension(dataField(request, "cols"), MAX_TERMINAL_COLS);
    const rows = terminalDimension(dataField(request, "rows"), MAX_TERMINAL_ROWS);
    const signal = nativeAbortSignal(dataField(request, "signal"));
    const operation = linkedOperation([signal, this.shutdown.signal], this.operationTimeoutMs);
    let privateConnection: CapturedPtyConnection | null = null;
    try {
      const plan = this.resolveCurrentPlan(binding);
      const expected = await this.resolveActiveSandbox(plan, operation.signal);
      this.requireCurrentPlan(binding);
      const terminalId = randomUUID();
      const opened = await invokePromise(
        this.transport.receiver,
        this.transport.open,
        [
          Object.freeze({
            providerSandboxId: expected.providerSandboxId,
            expectedProviderRevision: expected.revision,
            binding: plan.binding,
            planDigest: binding.assignmentPlanDigest,
            terminalId,
            cols,
            rows,
          } satisfies DaytonaSupervisorPtyOpenRequest),
          operation.signal,
        ],
        operation.signal
      );
      privateConnection = capturePtyConnection(opened);
      assertPrivateConnectionIdentity(privateConnection, expected, plan, binding, terminalId);

      // A slow provider connect never turns a stale plan into an admitted PTY.
      const currentPlan = this.resolveCurrentPlan(binding);
      const current = await this.resolveActiveSandbox(currentPlan, operation.signal);
      this.requireCurrentPlan(binding);
      if (!sameSandbox(current, expected)) unavailable();

      const connection = new DaytonaHostedTerminalConnectionImpl({
        publicBinding: binding,
        plan,
        expected,
        terminalId,
        plans: this.plans,
        controlPlane: this.controlPlane,
        privateConnection,
        lifetimeSignal: AbortSignal.any([signal, this.shutdown.signal]),
        operationTimeoutMs: this.operationTimeoutMs,
        onClosed: () => this.connections.delete(connection),
      });
      this.connections.add(connection);
      connection.start();
      privateConnection = null;
      if (operation.signal.aborted || this.closed || this.shutdown.signal.aborted) {
        await connection.destroy();
        unavailable();
      }
      return Object.freeze({
        binding: connection.binding,
        onData: (listener: (data: string) => void) => connection.onData(listener),
        onExit: (listener: () => void) => connection.onExit(listener),
        input: (data: string, mutationSignal: AbortSignal) =>
          connection.input(data, mutationSignal),
        resize: (nextCols: number, nextRows: number, mutationSignal: AbortSignal) =>
          connection.resize(nextCols, nextRows, mutationSignal),
        interrupt: (mutationSignal: AbortSignal) => connection.interrupt(mutationSignal),
        destroy: () => connection.destroy(),
      });
    } catch {
      if (privateConnection !== null) {
        await bestEffortPrivateDestroy(privateConnection, this.operationTimeoutMs);
      }
      unavailable();
    } finally {
      operation.dispose();
    }
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.shutdown.abort();
    const close = (async () => {
      const connectionResults = await Promise.allSettled(
        [...this.connections].map((connection) => connection.destroy())
      );
      this.connections.clear();
      let transportFailed = false;
      try {
        await invokeVoidPromise(this.transport.receiver, this.transport.close, []);
      } catch {
        transportFailed = true;
      }
      if (transportFailed || connectionResults.some((result) => result.status === "rejected")) {
        unavailable();
      }
    })();
    this.closePromise = close;
    return close;
  }

  private resolveCurrentPlan(
    binding: HostedTeamSessionTerminalBinding
  ): HostedRuntimeAssignmentPlan {
    const lookup: HostedAssignmentLookup = Object.freeze({
      kind: "session",
      sessionId: binding.binding.sessionId,
      runtimeAuthorizationGeneration: binding.runtimeAuthorizationGeneration,
    });
    if (Reflect.apply(this.plans.isCurrent, this.plans.receiver, [lookup]) !== true) unavailable();
    const unsafePlan = Reflect.apply(this.plans.resolve, this.plans.receiver, [lookup]);
    if (unsafePlan === null || hasThenableShape(unsafePlan)) unavailable();
    let plan: HostedRuntimeAssignmentPlan;
    let planDigest: string;
    try {
      planDigest = digestHostedRuntimeAssignmentPlan(unsafePlan as HostedRuntimeAssignmentPlan);
      plan = snapshotRuntimeSupervisorPortableData(unsafePlan) as HostedRuntimeAssignmentPlan;
    } catch {
      unavailable();
    }
    if (
      planDigest !== binding.assignmentPlanDigest ||
      plan.runtimeAuthorizationGeneration !== binding.runtimeAuthorizationGeneration ||
      plan.incarnation !== binding.incarnation ||
      plan.specificationDigest !== binding.specificationDigest ||
      !sameBinding(plan.binding, binding.binding)
    ) {
      unavailable();
    }
    return plan;
  }

  private requireCurrentPlan(binding: HostedTeamSessionTerminalBinding): void {
    this.resolveCurrentPlan(binding);
  }

  private async resolveActiveSandbox(
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<HostedControlPlaneSandbox> {
    const result = await invokePromise(
      this.controlPlane.receiver,
      this.controlPlane.listExact,
      [plan, signal],
      signal
    );
    if (!Array.isArray(result) || result.length !== 1) unavailable();
    const sandbox = snapshotSandbox(result[0]);
    if (
      sandbox.state !== "active" ||
      sandbox.runtimeAuthorizationGeneration !== plan.runtimeAuthorizationGeneration ||
      sandbox.incarnation !== plan.incarnation ||
      sandbox.specificationDigest !== plan.specificationDigest ||
      sandbox.adapterConfigurationRef !== plan.adapterConfigurationRef ||
      sandbox.isolationPolicyDigest !== plan.isolation.isolationPolicyDigest ||
      !sameBinding(sandbox.binding, plan.binding)
    ) {
      unavailable();
    }
    return sandbox;
  }
}

interface ConnectionConstruction {
  readonly publicBinding: HostedTeamSessionTerminalBinding;
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly expected: HostedControlPlaneSandbox;
  readonly terminalId: string;
  readonly plans: CapturedPlanSource;
  readonly controlPlane: CapturedControlPlane;
  readonly privateConnection: CapturedPtyConnection;
  readonly lifetimeSignal: AbortSignal;
  readonly operationTimeoutMs: number;
  readonly onClosed: () => void;
}

class DaytonaHostedTerminalConnectionImpl implements HostedTerminalConnection {
  readonly binding: HostedTeamSessionTerminalBinding;
  private readonly plan: HostedRuntimeAssignmentPlan;
  private readonly expected: HostedControlPlaneSandbox;
  private readonly terminalId: string;
  private readonly plans: CapturedPlanSource;
  private readonly controlPlane: CapturedControlPlane;
  private readonly terminal: CapturedPtyConnection;
  private readonly lifetimeSignal: AbortSignal;
  private readonly operationTimeoutMs: number;
  private readonly onClosed: () => void;
  private readonly dataListeners = new Set<(data: string) => void>();
  private readonly exitListeners = new Set<() => void>();
  private readonly pendingOutput: string[] = [];
  private readonly decoder = new TextDecoder("utf-8", { fatal: true });
  private pendingOutputBytes = 0;
  private nextOutputSeq = 1;
  private nextInputSeq = 1;
  private nextResizeSeq = 1;
  private nextInterruptSeq = 1;
  private serial: Promise<void> = Promise.resolve();
  private dataSubscription: { dispose(): void } | null = null;
  private exitSubscription: { dispose(): void } | null = null;
  private destroyed = false;
  private exited = false;
  private destroyPromise: Promise<void> | null = null;

  constructor(options: ConnectionConstruction) {
    this.binding = options.publicBinding;
    this.plan = options.plan;
    this.expected = options.expected;
    this.terminalId = options.terminalId;
    this.plans = options.plans;
    this.controlPlane = options.controlPlane;
    this.terminal = options.privateConnection;
    this.lifetimeSignal = options.lifetimeSignal;
    this.operationTimeoutMs = options.operationTimeoutMs;
    this.onClosed = options.onClosed;
  }

  start(): void {
    if (this.dataSubscription !== null || this.exitSubscription !== null) unavailable();
    const dataSubscription = Reflect.apply(this.terminal.onData, this.terminal.receiver, [
      (frame: unknown) => this.receiveOutput(frame),
    ]);
    this.dataSubscription = captureDisposer(dataSubscription);
    try {
      const exitSubscription = Reflect.apply(this.terminal.onExit, this.terminal.receiver, [
        (frame: unknown) => this.receiveExit(frame),
      ]);
      this.exitSubscription = captureDisposer(exitSubscription);
    } catch {
      this.dataSubscription.dispose();
      this.dataSubscription = null;
      unavailable();
    }
    if (this.lifetimeSignal.aborted) void this.destroy().catch(() => undefined);
    else {
      this.lifetimeSignal.addEventListener(
        "abort",
        () => void this.destroy().catch(() => undefined),
        { once: true }
      );
    }
  }

  onData(listener: (data: string) => void): { dispose(): void } {
    const captured = safeListener(listener);
    if (this.destroyed) unavailable();
    this.dataListeners.add(captured);
    try {
      const pending = this.pendingOutput.splice(0);
      this.pendingOutputBytes = 0;
      for (const data of pending) captured(data);
    } catch {
      this.failClosed();
      unavailable();
    }
    return Object.freeze({ dispose: () => this.dataListeners.delete(captured) });
  }

  onExit(listener: () => void): { dispose(): void } {
    const captured = safeListener(listener);
    this.exitListeners.add(captured);
    if (this.exited) {
      try {
        captured();
      } catch {
        this.failClosed();
      }
    }
    return Object.freeze({ dispose: () => this.exitListeners.delete(captured) });
  }

  input(data: string, signal: AbortSignal): Promise<void> {
    if (typeof data !== "string") return Promise.reject(new DaytonaHostedTerminalError());
    const bytes = new TextEncoder().encode(data);
    if (bytes.byteLength < 1 || bytes.byteLength > MAX_TERMINAL_INPUT_BYTES) {
      bytes.fill(0);
      return Promise.reject(new DaytonaHostedTerminalError());
    }
    return this.enqueueMutation(signal, (operationSignal) => {
      const inputSeq = this.nextInputSeq++;
      return invokeVoidPromise(
        this.terminal.receiver,
        this.terminal.input,
        [
          Object.freeze({
            ...this.privateFence(),
            inputSeq,
            bytes: new Uint8Array(bytes),
          } satisfies DaytonaSupervisorPtyInputRequest),
          operationSignal,
        ],
        operationSignal
      );
    }).finally(() => bytes.fill(0));
  }

  resize(cols: number, rows: number, signal: AbortSignal): Promise<void> {
    let safeCols: number;
    let safeRows: number;
    try {
      safeCols = terminalDimension(cols, MAX_TERMINAL_COLS);
      safeRows = terminalDimension(rows, MAX_TERMINAL_ROWS);
    } catch {
      return Promise.reject(new DaytonaHostedTerminalError());
    }
    return this.enqueueMutation(signal, (operationSignal) => {
      const resizeSeq = this.nextResizeSeq++;
      return invokeVoidPromise(
        this.terminal.receiver,
        this.terminal.resize,
        [
          Object.freeze({
            ...this.privateFence(),
            resizeSeq,
            cols: safeCols,
            rows: safeRows,
          } satisfies DaytonaSupervisorPtyResizeRequest),
          operationSignal,
        ],
        operationSignal
      );
    });
  }

  interrupt(signal: AbortSignal): Promise<void> {
    return this.enqueueMutation(signal, (operationSignal) => {
      const interruptSeq = this.nextInterruptSeq++;
      return invokeVoidPromise(
        this.terminal.receiver,
        this.terminal.interrupt,
        [
          Object.freeze({
            ...this.privateFence(),
            interruptSeq,
          } satisfies DaytonaSupervisorPtyInterruptRequest),
          operationSignal,
        ],
        operationSignal
      );
    });
  }

  destroy(): Promise<void> {
    if (this.destroyPromise) return this.destroyPromise;
    this.destroyed = true;
    this.disposeSubscriptions();
    this.pendingOutput.length = 0;
    this.pendingOutputBytes = 0;
    const operation = linkedOperation([], this.operationTimeoutMs);
    const destroy = invokeVoidPromise(
      this.terminal.receiver,
      this.terminal.destroy,
      [
        Object.freeze(this.privateFence() satisfies DaytonaSupervisorPtyDestroyRequest),
        operation.signal,
      ],
      operation.signal
    )
      .catch(() => unavailable())
      .finally(() => operation.dispose());
    this.destroyPromise = destroy;
    void destroy.then(
      () => this.onClosed(),
      () => undefined
    );
    return destroy;
  }

  private enqueueMutation(
    signalValue: unknown,
    mutation: (signal: AbortSignal) => Promise<void>
  ): Promise<void> {
    let signal: AbortSignal;
    try {
      signal = nativeAbortSignal(signalValue);
      if (this.destroyed || this.exited || this.lifetimeSignal.aborted || signal.aborted) {
        unavailable();
      }
    } catch {
      return Promise.reject(new DaytonaHostedTerminalError());
    }
    const task = this.serial
      .catch(() => undefined)
      .then(async () => {
        if (this.destroyed || this.exited || this.lifetimeSignal.aborted || signal.aborted) {
          unavailable();
        }
        const operation = linkedOperation([signal, this.lifetimeSignal], this.operationTimeoutMs);
        try {
          this.requireCurrentPlan();
          const current = await this.resolveActiveSandbox(operation.signal);
          this.requireCurrentPlan();
          if (!sameSandbox(current, this.expected)) unavailable();
          await mutation(operation.signal);
          if (operation.signal.aborted) unavailable();
        } catch {
          this.failClosed();
          unavailable();
        } finally {
          operation.dispose();
        }
      });
    this.serial = task;
    return task;
  }

  private requireCurrentPlan(): void {
    const lookup = this.planLookup();
    if (Reflect.apply(this.plans.isCurrent, this.plans.receiver, [lookup]) !== true) unavailable();
    const unsafePlan = Reflect.apply(this.plans.resolve, this.plans.receiver, [lookup]);
    if (unsafePlan === null || hasThenableShape(unsafePlan)) unavailable();
    try {
      if (
        digestHostedRuntimeAssignmentPlan(unsafePlan as HostedRuntimeAssignmentPlan) !==
        this.binding.assignmentPlanDigest
      ) {
        unavailable();
      }
    } catch {
      unavailable();
    }
  }

  private async resolveActiveSandbox(signal: AbortSignal): Promise<HostedControlPlaneSandbox> {
    const unsafe = await invokePromise(
      this.controlPlane.receiver,
      this.controlPlane.listExact,
      [this.plan, signal],
      signal
    );
    if (!Array.isArray(unsafe) || unsafe.length !== 1) unavailable();
    const sandbox = snapshotSandbox(unsafe[0]);
    if (sandbox.state !== "active") unavailable();
    return sandbox;
  }

  private planLookup(): HostedAssignmentLookup {
    return Object.freeze({
      kind: "session",
      sessionId: this.binding.binding.sessionId,
      runtimeAuthorizationGeneration: this.binding.runtimeAuthorizationGeneration,
    });
  }

  private privateFence(): DaytonaSupervisorPtyDestroyRequest {
    return {
      providerSandboxId: this.expected.providerSandboxId,
      expectedProviderRevision: this.expected.revision,
      binding: this.plan.binding,
      planDigest: this.binding.assignmentPlanDigest,
      terminalId: this.terminalId,
    };
  }

  private receiveOutput(value: unknown): void {
    if (this.destroyed || this.exited) return;
    try {
      const frame = exactDataRecord(value, ["terminalId", "outputSeq", "bytes"]);
      const terminalId = dataField(frame, "terminalId");
      const outputSeq = dataField(frame, "outputSeq");
      const unsafeBytes = dataField(frame, "bytes");
      if (
        terminalId !== this.terminalId ||
        outputSeq !== this.nextOutputSeq ||
        !(unsafeBytes instanceof Uint8Array) ||
        nodeTypes.isProxy(unsafeBytes) ||
        unsafeBytes.byteLength < 1 ||
        unsafeBytes.byteLength > MAX_TERMINAL_OUTPUT_FRAME_BYTES
      ) {
        unavailable();
      }
      this.nextOutputSeq += 1;
      const bytes = new Uint8Array(unsafeBytes);
      const data = this.decoder.decode(bytes, { stream: true });
      this.dispatchOutput(data);
    } catch {
      this.failClosed();
    }
  }

  private receiveExit(value: unknown): void {
    if (this.destroyed || this.exited) return;
    try {
      const frame = exactDataRecord(value, ["terminalId"]);
      if (dataField(frame, "terminalId") !== this.terminalId) unavailable();
      this.dispatchOutput(this.decoder.decode());
      this.exited = true;
      for (const listener of this.exitListeners) {
        try {
          listener();
        } catch {
          // Terminal exit remains final even when a consumer callback fails.
        }
      }
      void this.destroy().catch(() => undefined);
    } catch {
      this.failClosed();
    }
  }

  private dispatchOutput(data: string): void {
    if (data.length === 0) return;
    const byteLength = Buffer.byteLength(data, "utf8");
    if (this.dataListeners.size === 0) {
      if (byteLength > MAX_PENDING_TERMINAL_OUTPUT_BYTES - this.pendingOutputBytes) unavailable();
      this.pendingOutput.push(data);
      this.pendingOutputBytes += byteLength;
      return;
    }
    for (const listener of this.dataListeners) listener(data);
  }

  private failClosed(): void {
    if (this.exited) return;
    this.exited = true;
    for (const listener of this.exitListeners) {
      try {
        listener();
      } catch {
        // A client callback cannot keep a failed transport alive.
      }
    }
    void this.destroy().catch(() => undefined);
  }

  private disposeSubscriptions(): void {
    try {
      this.dataSubscription?.dispose();
    } catch {
      // Destruction still reaches the private terminal.
    }
    try {
      this.exitSubscription?.dispose();
    } catch {
      // Destruction still reaches the private terminal.
    }
    this.dataSubscription = null;
    this.exitSubscription = null;
  }
}

export function createDaytonaHostedTerminalAdapter(
  options: CreateDaytonaHostedTerminalAdapterOptions
): DaytonaHostedTerminalAdapter {
  const adapter = new DaytonaHostedTerminalAdapterImpl(options);
  return Object.freeze({
    connect: (request: Parameters<HostedTerminalAdapter["connect"]>[0]) => adapter.connect(request),
    close: () => adapter.close(),
  });
}

function capturePlanSource(value: unknown): CapturedPlanSource {
  const receiver = safeObject(value);
  return Object.freeze({
    receiver,
    resolve: captureDataMethod(receiver, "resolve"),
    isCurrent: captureDataMethod(receiver, "isCurrent"),
  });
}

function captureControlPlane(value: unknown): CapturedControlPlane {
  const receiver = safeObject(value);
  return Object.freeze({ receiver, listExact: captureDataMethod(receiver, "listExact") });
}

function capturePtyTransport(value: unknown): CapturedPtyTransport {
  const receiver = safeObject(value);
  return Object.freeze({
    receiver,
    open: captureDataMethod(receiver, "open"),
    close: captureDataMethod(receiver, "close"),
  });
}

function capturePtyConnection(value: unknown): CapturedPtyConnection {
  const receiver = safeObject(value);
  return Object.freeze({
    receiver,
    providerSandboxId: safeReference(captureDataProperty(receiver, "providerSandboxId")),
    expectedProviderRevision: positiveInteger(
      captureDataProperty(receiver, "expectedProviderRevision")
    ),
    binding: snapshotBinding(captureDataProperty(receiver, "binding")),
    planDigest: digest(captureDataProperty(receiver, "planDigest")),
    terminalId: safeReference(captureDataProperty(receiver, "terminalId")),
    onData: captureDataMethod(receiver, "onData"),
    onExit: captureDataMethod(receiver, "onExit"),
    input: captureDataMethod(receiver, "input"),
    resize: captureDataMethod(receiver, "resize"),
    interrupt: captureDataMethod(receiver, "interrupt"),
    destroy: captureDataMethod(receiver, "destroy"),
  });
}

function captureDisposer(value: unknown): { dispose(): void } {
  const receiver = safeObject(value);
  const dispose = captureDataMethod(receiver, "dispose");
  return Object.freeze({
    dispose() {
      const result = Reflect.apply(dispose, receiver, []);
      if (result !== undefined) unavailable();
    },
  });
}

function assertPrivateConnectionIdentity(
  connection: CapturedPtyConnection,
  expected: HostedControlPlaneSandbox,
  plan: HostedRuntimeAssignmentPlan,
  binding: HostedTeamSessionTerminalBinding,
  terminalId: string
): void {
  if (
    connection.providerSandboxId !== expected.providerSandboxId ||
    connection.expectedProviderRevision !== expected.revision ||
    connection.planDigest !== binding.assignmentPlanDigest ||
    connection.terminalId !== terminalId ||
    !sameBinding(connection.binding, plan.binding)
  ) {
    unavailable();
  }
}

function snapshotTerminalBinding(value: unknown): HostedTeamSessionTerminalBinding {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRuntimeSupervisorDataRecord(snapshot, [
    "kind",
    "binding",
    "runtimeAuthorizationGeneration",
    "assignmentPlanDigest",
    "incarnation",
    "specificationDigest",
  ]);
  if (runtimeSupervisorDataField(record, "kind") !== "hosted") unavailable();
  const runtimeAuthorizationGeneration = positiveInteger(
    runtimeSupervisorDataField(record, "runtimeAuthorizationGeneration")
  );
  return Object.freeze({
    kind: "hosted",
    binding: snapshotBinding(runtimeSupervisorDataField(record, "binding")),
    runtimeAuthorizationGeneration,
    assignmentPlanDigest: digest(runtimeSupervisorDataField(record, "assignmentPlanDigest")),
    incarnation: incarnation(runtimeSupervisorDataField(record, "incarnation")),
    specificationDigest: digest(runtimeSupervisorDataField(record, "specificationDigest")),
  });
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const record = exactRuntimeSupervisorDataRecord(value, [
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
    teamId: safeReference(runtimeSupervisorDataField(record, "teamId")),
    projectId: safeReference(runtimeSupervisorDataField(record, "projectId")),
    sessionId: safeReference(runtimeSupervisorDataField(record, "sessionId")),
    runtimeAssignmentId: safeReference(runtimeSupervisorDataField(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(
      runtimeSupervisorDataField(record, "runtimeAssignmentGeneration")
    ),
    sandboxId: safeReference(runtimeSupervisorDataField(record, "sandboxId")),
    sandboxGeneration: positiveInteger(runtimeSupervisorDataField(record, "sandboxGeneration")),
    runtimePrincipalId: safeReference(runtimeSupervisorDataField(record, "runtimePrincipalId")),
  });
}

function snapshotSandbox(value: unknown): HostedControlPlaneSandbox {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRuntimeSupervisorDataRecord(snapshot, [
    "providerSandboxId",
    "binding",
    "runtimeAuthorizationGeneration",
    "incarnation",
    "specificationDigest",
    "effectEnforcerPolicyDigest",
    "adapterConfigurationRef",
    "isolationPolicyDigest",
    "state",
    "revision",
    "activation",
  ]);
  const state = runtimeSupervisorDataField(record, "state");
  if (state !== "active" && state !== "fenced") unavailable();
  return Object.freeze({
    providerSandboxId: safeReference(runtimeSupervisorDataField(record, "providerSandboxId")),
    binding: snapshotBinding(runtimeSupervisorDataField(record, "binding")),
    runtimeAuthorizationGeneration: positiveInteger(
      runtimeSupervisorDataField(record, "runtimeAuthorizationGeneration")
    ),
    incarnation: incarnation(runtimeSupervisorDataField(record, "incarnation")),
    specificationDigest: digest(runtimeSupervisorDataField(record, "specificationDigest")),
    effectEnforcerPolicyDigest: digest(
      runtimeSupervisorDataField(record, "effectEnforcerPolicyDigest")
    ),
    adapterConfigurationRef: safeReference(
      runtimeSupervisorDataField(record, "adapterConfigurationRef")
    ),
    isolationPolicyDigest: digest(runtimeSupervisorDataField(record, "isolationPolicyDigest")),
    state,
    revision: positiveInteger(runtimeSupervisorDataField(record, "revision")),
    activation: snapshotHostedRuntimeActivation(runtimeSupervisorDataField(record, "activation")),
  });
}

function sameSandbox(left: HostedControlPlaneSandbox, right: HostedControlPlaneSandbox): boolean {
  return (
    left.providerSandboxId === right.providerSandboxId &&
    left.revision === right.revision &&
    left.state === "active" &&
    right.state === "active" &&
    left.runtimeAuthorizationGeneration === right.runtimeAuthorizationGeneration &&
    left.effectEnforcerPolicyDigest === right.effectEnforcerPolicyDigest &&
    left.incarnation === right.incarnation &&
    left.specificationDigest === right.specificationDigest &&
    left.adapterConfigurationRef === right.adapterConfigurationRef &&
    left.isolationPolicyDigest === right.isolationPolicyDigest &&
    sameBinding(left.binding, right.binding)
  );
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

async function bestEffortPrivateDestroy(
  connection: CapturedPtyConnection,
  timeoutMs: number
): Promise<void> {
  const operation = linkedOperation([], timeoutMs);
  try {
    await invokeVoidPromise(
      connection.receiver,
      connection.destroy,
      [
        Object.freeze({
          providerSandboxId: connection.providerSandboxId,
          expectedProviderRevision: connection.expectedProviderRevision,
          binding: connection.binding,
          planDigest: connection.planDigest,
          terminalId: connection.terminalId,
        } satisfies DaytonaSupervisorPtyDestroyRequest),
        operation.signal,
      ],
      operation.signal
    );
  } catch {
    // Admission still fails closed; no private failure is projected.
  } finally {
    operation.dispose();
  }
}

function linkedOperation(
  signals: readonly AbortSignal[],
  timeoutMs: number
): { readonly signal: AbortSignal; dispose(): void } {
  for (const signal of signals) nativeAbortSignal(signal);
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), timeoutMs);
  timer.unref();
  const signal = AbortSignal.any([...signals, timeout.signal]);
  return Object.freeze({
    signal,
    dispose() {
      clearTimeout(timer);
    },
  });
}

function invokePromise(
  receiver: object,
  method: AnyFunction,
  args: readonly unknown[],
  signal?: AbortSignal
): Promise<unknown> {
  let value: unknown;
  try {
    value = Reflect.apply(method, receiver, args);
  } catch {
    unavailable();
  }
  if (!nodeTypes.isPromise(value)) unavailable();
  const normalized = value.catch(() => unavailable());
  return signal === undefined ? normalized : settleWithAbort(normalized, signal);
}

async function invokeVoidPromise(
  receiver: object,
  method: AnyFunction,
  args: readonly unknown[],
  signal?: AbortSignal
): Promise<void> {
  const value = await invokePromise(receiver, method, args, signal);
  if (value !== undefined) unavailable();
}

function settleWithAbort(value: Promise<unknown>, signal: AbortSignal): Promise<unknown> {
  nativeAbortSignal(signal);
  if (signal.aborted) return Promise.reject(new DaytonaHostedTerminalError());
  return new Promise((resolve, reject) => {
    let settled = false;
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      reject(new DaytonaHostedTerminalError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    void value.then(
      (result) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        resolve(result);
      },
      () => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        reject(new DaytonaHostedTerminalError());
      }
    );
  });
}

function exactDataRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const record = safeObject(value) as Record<string, unknown>;
  const prototype = Object.getPrototypeOf(record);
  if (prototype !== Object.prototype && prototype !== null) unavailable();
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    unavailable();
  }
  for (const field of fields) dataField(record, field);
  return record;
}

function dataField(record: Record<string, unknown>, field: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) unavailable();
  return descriptor.value;
}

function captureDataProperty(receiver: object, name: string): unknown {
  const descriptor = findPropertyDescriptor(receiver, name);
  if (!("value" in descriptor)) unavailable();
  return descriptor.value;
}

function captureDataMethod(receiver: object, name: string): AnyFunction {
  const descriptor = findPropertyDescriptor(receiver, name);
  if (!("value" in descriptor) || typeof descriptor.value !== "function") unavailable();
  return descriptor.value as AnyFunction;
}

function findPropertyDescriptor(receiver: object, name: string): PropertyDescriptor {
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) unavailable();
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) return descriptor;
    current = Object.getPrototypeOf(current) as object | null;
  }
  unavailable();
}

function safeObject(value: unknown): object {
  if (
    (typeof value !== "object" && typeof value !== "function") ||
    value === null ||
    nodeTypes.isProxy(value)
  ) {
    unavailable();
  }
  return value;
}

function safeListener<T>(value: T): T {
  if (typeof value !== "function" || nodeTypes.isProxy(value)) unavailable();
  return value;
}

function nativeAbortSignal(value: unknown): AbortSignal {
  if (!(value instanceof AbortSignal) || nodeTypes.isProxy(value)) unavailable();
  return value;
}

function hasThenableShape(value: unknown): boolean {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) return false;
  try {
    return "then" in value;
  } catch {
    return true;
  }
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) unavailable();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) unavailable();
  return value;
}

function incarnation(value: unknown): string {
  if (typeof value !== "string" || !INCARNATION.test(value)) unavailable();
  return value;
}

function positiveInteger(value: unknown): number {
  return boundedInteger(value, 1, Number.MAX_SAFE_INTEGER);
}

function terminalDimension(value: unknown, maximum: number): number {
  return boundedInteger(value, MIN_TERMINAL_DIMENSION, maximum);
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    unavailable();
  }
  return value as number;
}

function unavailable(): never {
  throw new DaytonaHostedTerminalError();
}
