import { describe, expect, it, vi } from "vitest";
import {
  createDaytonaSupervisorPtyRegistry,
  type DaytonaSupervisorPtyDriver,
  type DaytonaSupervisorPtyDriverConnection,
  type DaytonaSupervisorPtyDriverOpenRequest,
} from "../../packages/daytona-supervisor/src/pty-registry";

const PROVIDER_ID = "123e4567-e89b-42d3-a456-426614174000";
const TERMINAL_ID = "223e4567-e89b-42d3-a456-426614174001";
const SECOND_TERMINAL_ID = "323e4567-e89b-42d3-a456-426614174002";
const PLAN_DIGEST = "a".repeat(64);
const binding = Object.freeze({
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 1,
  sandboxId: "sandbox-1",
  sandboxGeneration: 1,
  runtimePrincipalId: "principal-1",
});

describe("Daytona root supervisor PTY registry", () => {
  it("fences every mutation, enforces independent monotonic sequences, and streams ordered chunks", async () => {
    const driver = new FakeDriver();
    let isolationChecks = 0;
    const terminal = createRegistry(driver, () => {
      isolationChecks += 1;
      return true;
    });
    const iterator = terminal
      .open(openRequest(), new AbortController().signal)
      [Symbol.asyncIterator]();
    await expect(iterator.next()).resolves.toEqual({
      done: false,
      value: { kind: "ready", ...fence() },
    });
    const connection = driver.connections[0]!;

    const input = Buffer.from("echo safe\n");
    await terminal.input(
      { ...fence(), inputSeq: 1, bytesBase64: input.toString("base64url") },
      new AbortController().signal
    );
    await terminal.resize(
      { ...fence(), resizeSeq: 1, cols: 132, rows: 42 },
      new AbortController().signal
    );
    await terminal.interrupt({ ...fence(), interruptSeq: 1 }, new AbortController().signal);
    expect(connection.inputs.map((value) => value.toString("utf8"))).toEqual(["echo safe\n"]);
    expect(connection.resizes).toEqual([{ cols: 132, rows: 42 }]);
    expect(connection.interrupts).toBe(1);
    expect(isolationChecks).toBeGreaterThanOrEqual(5);

    await expect(
      terminal.input(
        { ...fence(), inputSeq: 1, bytesBase64: Buffer.from("replay").toString("base64url") },
        new AbortController().signal
      )
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      terminal.resize(
        { ...fence(), terminalId: SECOND_TERMINAL_ID, resizeSeq: 2, cols: 80, rows: 24 },
        new AbortController().signal
      )
    ).rejects.toMatchObject({ code: "unavailable" });

    connection.emitData(Buffer.alloc(40_000, 0x78));
    const first = await iterator.next();
    const second = await iterator.next();
    expect(first.value).toMatchObject({ kind: "output", terminalId: TERMINAL_ID, outputSeq: 1 });
    expect(second.value).toMatchObject({ kind: "output", terminalId: TERMINAL_ID, outputSeq: 2 });
    expect(
      Buffer.from((first.value as { bytesBase64: string }).bytesBase64, "base64url")
    ).toHaveLength(32 * 1024);
    expect(
      Buffer.from((second.value as { bytesBase64: string }).bytesBase64, "base64url")
    ).toHaveLength(40_000 - 32 * 1024);

    connection.emitExit();
    await expect(iterator.next()).resolves.toEqual({
      done: false,
      value: { kind: "exit", terminalId: TERMINAL_ID },
    });
    await expect(iterator.next()).resolves.toEqual({ done: true, value: undefined });
    expect(connection.destroyCount).toBe(1);
    await terminal.close();
  });

  it("reserves capacity during open and cannot publish a terminal after close wins the race", async () => {
    let resolveOpen!: (connection: DaytonaSupervisorPtyDriverConnection) => void;
    const pendingOpen = new Promise<DaytonaSupervisorPtyDriverConnection>((resolve) => {
      resolveOpen = resolve;
    });
    const racedConnection = new FakeConnection();
    const driver: DaytonaSupervisorPtyDriver = {
      open: vi.fn(() => pendingOpen),
      close: vi.fn(async () => undefined),
    };
    const terminal = createRegistry(driver);
    const first = terminal
      .open(openRequest(), new AbortController().signal)
      [Symbol.asyncIterator]();
    const opening = first.next();
    await vi.waitFor(() => expect(driver.open).toHaveBeenCalledOnce());

    const second = terminal
      .open(openRequest(SECOND_TERMINAL_ID), new AbortController().signal)
      [Symbol.asyncIterator]();
    await expect(second.next()).rejects.toMatchObject({ code: "not-ready" });

    await terminal.close();
    resolveOpen(racedConnection.facade());
    await expect(opening).rejects.toMatchObject({ code: "unavailable" });
    expect(racedConnection.destroyCount).toBe(1);
    expect(driver.close).toHaveBeenCalledOnce();
  });

  it("applies bounded output backpressure and destroys an overflowing stream", async () => {
    const driver = new FakeDriver();
    const terminal = createRegistry(driver, () => true, {
      maximumPendingOutputBytes: 64 * 1024,
      maximumOutputFrameBytes: 16 * 1024,
    });
    const iterator = terminal
      .open(openRequest(), new AbortController().signal)
      [Symbol.asyncIterator]();
    await iterator.next();
    const connection = driver.connections[0]!;
    connection.emitData(Buffer.alloc(48 * 1024, 0x61));
    expect(connection.pauseCount).toBe(1);
    await iterator.next();
    await iterator.next();
    expect(connection.resumeCount).toBe(0);
    await iterator.next();
    expect(connection.resumeCount).toBe(1);

    connection.emitData(Buffer.alloc(80 * 1024, 0x62));
    await expect(iterator.next()).rejects.toMatchObject({ code: "unavailable" });
    await vi.waitFor(() => expect(connection.destroyCount).toBe(1));
    await terminal.close();
  });

  it("fails an ambiguous dispatched mutation closed when isolation or the driver changes", async () => {
    const driver = new FakeDriver();
    let isolated = true;
    const terminal = createRegistry(driver, () => isolated);
    const iterator = terminal
      .open(openRequest(), new AbortController().signal)
      [Symbol.asyncIterator]();
    await iterator.next();
    const connection = driver.connections[0]!;
    connection.inputFailure = true;
    await expect(
      terminal.input(
        { ...fence(), inputSeq: 1, bytesBase64: Buffer.from("x").toString("base64url") },
        new AbortController().signal
      )
    ).rejects.toMatchObject({ code: "unavailable" });
    await vi.waitFor(() => expect(connection.destroyCount).toBe(1));

    const secondIterator = terminal
      .open(openRequest(SECOND_TERMINAL_ID), new AbortController().signal)
      [Symbol.asyncIterator]();
    await secondIterator.next();
    isolated = false;
    await expect(
      terminal.interrupt(
        { ...fence(SECOND_TERMINAL_ID), interruptSeq: 1 },
        new AbortController().signal
      )
    ).rejects.toMatchObject({ code: "not-ready" });
    await secondIterator.return?.();
    await terminal.close();
  });
});

class FakeDriver implements DaytonaSupervisorPtyDriver {
  readonly connections: FakeConnection[] = [];

  async open(
    _request: DaytonaSupervisorPtyDriverOpenRequest,
    _signal?: AbortSignal
  ): Promise<DaytonaSupervisorPtyDriverConnection> {
    const connection = new FakeConnection();
    this.connections.push(connection);
    return connection.facade();
  }

  async close(): Promise<void> {
    await Promise.all(this.connections.map((connection) => connection.destroy()));
  }

  facade(): DaytonaSupervisorPtyDriver {
    return Object.freeze({
      open: (request: DaytonaSupervisorPtyDriverOpenRequest, signal: AbortSignal) =>
        this.open(request, signal),
      close: () => this.close(),
    });
  }
}

class FakeConnection implements DaytonaSupervisorPtyDriverConnection {
  readonly inputs: Buffer[] = [];
  readonly resizes: Array<{ cols: number; rows: number }> = [];
  interrupts = 0;
  pauseCount = 0;
  resumeCount = 0;
  destroyCount = 0;
  inputFailure = false;
  private readonly dataListeners = new Set<(bytes: Uint8Array) => void>();
  private readonly exitListeners = new Set<() => void>();

  onData(listener: (bytes: Uint8Array) => void) {
    this.dataListeners.add(listener);
    return { dispose: () => this.dataListeners.delete(listener) };
  }

  onExit(listener: () => void) {
    this.exitListeners.add(listener);
    return { dispose: () => this.exitListeners.delete(listener) };
  }

  async input(bytes: Uint8Array, _signal?: AbortSignal): Promise<void> {
    this.inputs.push(Buffer.from(bytes));
    if (this.inputFailure) throw new Error("ambiguous driver failure");
  }

  async resize(cols: number, rows: number, _signal?: AbortSignal): Promise<void> {
    this.resizes.push({ cols, rows });
  }

  async interrupt(_signal?: AbortSignal): Promise<void> {
    this.interrupts += 1;
  }

  async destroy(): Promise<void> {
    this.destroyCount += 1;
  }

  pause(): void {
    this.pauseCount += 1;
  }

  resume(): void {
    this.resumeCount += 1;
  }

  emitData(bytes: Uint8Array): void {
    for (const listener of this.dataListeners) listener(bytes);
  }

  emitExit(): void {
    for (const listener of this.exitListeners) listener();
  }

  facade(): DaytonaSupervisorPtyDriverConnection {
    return Object.freeze({
      onData: (listener: (bytes: Uint8Array) => void) => this.onData(listener),
      onExit: (listener: () => void) => this.onExit(listener),
      input: (bytes: Uint8Array, signal: AbortSignal) => this.input(bytes, signal),
      resize: (cols: number, rows: number, signal: AbortSignal) => this.resize(cols, rows, signal),
      interrupt: (signal: AbortSignal) => this.interrupt(signal),
      destroy: () => this.destroy(),
      pause: () => this.pause(),
      resume: () => this.resume(),
    });
  }
}

function createRegistry(
  driver: DaytonaSupervisorPtyDriver,
  requireCurrentIsolation: () => boolean = () => true,
  limits: { maximumPendingOutputBytes: number; maximumOutputFrameBytes: number } = {
    maximumPendingOutputBytes: 1024 * 1024,
    maximumOutputFrameBytes: 32 * 1024,
  }
) {
  return createDaytonaSupervisorPtyRegistry({
    providerSandboxId: PROVIDER_ID,
    expectedProviderRevision: 7,
    binding,
    planDigest: PLAN_DIGEST,
    requireCurrentIsolation,
    driver: driver instanceof FakeDriver ? driver.facade() : driver,
    maximumTerminals: 1,
    maximumTerminalsPerSandbox: 1,
    ...limits,
  });
}

function fence(terminalId = TERMINAL_ID) {
  return Object.freeze({
    providerSandboxId: PROVIDER_ID,
    expectedProviderRevision: 7,
    binding,
    planDigest: PLAN_DIGEST,
    terminalId,
  });
}

function openRequest(terminalId = TERMINAL_ID) {
  return Object.freeze({ ...fence(terminalId), cols: 120, rows: 36 });
}
