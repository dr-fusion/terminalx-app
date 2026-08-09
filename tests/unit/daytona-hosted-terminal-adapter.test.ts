import { describe, expect, it, vi } from "vitest";
import {
  createDaytonaHostedTerminalAdapter,
  DaytonaHostedTerminalError,
  type DaytonaSupervisorPtyConnection,
  type DaytonaSupervisorPtyDestroyRequest,
  type DaytonaSupervisorPtyExitFrame,
  type DaytonaSupervisorPtyInputRequest,
  type DaytonaSupervisorPtyInterruptRequest,
  type DaytonaSupervisorPtyOpenRequest,
  type DaytonaSupervisorPtyOutputFrame,
  type DaytonaSupervisorPtyResizeRequest,
  type DaytonaSupervisorPtyTransport,
} from "@/lib/runtime/daytona-hosted-terminal-adapter";
import { digestHostedRuntimeAssignmentPlan } from "@/lib/runtime/hosted-runtime-adapter";
import type {
  HostedAssignmentLookup,
  HostedAssignmentPlanSource,
  HostedControlPlaneCommandRequest,
  HostedControlPlaneCommandResult,
  HostedControlPlaneCreateRequest,
  HostedControlPlaneFollowRequest,
  HostedControlPlaneMutationRequest,
  HostedControlPlaneSandbox,
  HostedRuntimeAssignmentPlan,
  HostedRuntimeControlPlane,
} from "@/lib/runtime/hosted-runtime-control-plane";
import type { HostedTeamSessionTerminalBinding } from "@/lib/team-session-terminal-gateway";

const PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFf4/tX72aI7ln4nW9XH7z9xWMNJm9Q7A7jTZSlmWyNg=\n-----END PUBLIC KEY-----\n";

describe("Daytona hosted terminal adapter", () => {
  it("opens only one exact active Sandbox and returns a provider-blind connection", async () => {
    const fixture = makeFixture();
    const connection = await fixture.adapter.connect(connectRequest(fixture.binding));

    expect(fixture.controlPlane.listCalls).toHaveLength(2);
    expect(fixture.transport.openCalls).toHaveLength(1);
    expect(fixture.transport.openCalls[0]).toMatchObject({
      providerSandboxId: "provider-private-sandbox",
      expectedProviderRevision: 19,
      binding: fixture.plan.binding,
      planDigest: fixture.binding.assignmentPlanDigest,
      cols: 80,
      rows: 24,
    });
    expect(Object.keys(connection).sort()).toEqual([
      "binding",
      "destroy",
      "input",
      "interrupt",
      "onData",
      "onExit",
      "resize",
    ]);
    expect(JSON.stringify(connection)).not.toContain("provider-private-sandbox");
    expect(connection.binding).toEqual(fixture.binding);
  });

  it("rechecks the current plan and exact active revision around a slow connect", async () => {
    const revoked = makeFixture();
    revoked.transport.onOpen = async () => {
      revoked.plans.current = false;
    };

    await expect(revoked.adapter.connect(connectRequest(revoked.binding))).rejects.toBeInstanceOf(
      DaytonaHostedTerminalError
    );
    expect(revoked.transport.connection?.destroyCalls).toHaveLength(1);

    const revised = makeFixture();
    revised.controlPlane.onList = (call) =>
      call === 2 ? { ...revised.sandbox, revision: 20 } : revised.sandbox;
    await expect(revised.adapter.connect(connectRequest(revised.binding))).rejects.toBeInstanceOf(
      DaytonaHostedTerminalError
    );
    expect(revised.transport.connection?.destroyCalls).toHaveLength(1);
  });

  it("repeats every private fence and uses monotonic per-operation sequences", async () => {
    const fixture = makeFixture();
    const connection = await fixture.adapter.connect(connectRequest(fixture.binding));
    const signal = new AbortController().signal;

    const aborted = new AbortController();
    aborted.abort();
    await expect(connection.input("rejected", aborted.signal)).rejects.toBeInstanceOf(
      DaytonaHostedTerminalError
    );

    await connection.input("echo safe\n", signal);
    await connection.input("pwd\n", signal);
    await connection.resize(120, 40, signal);
    await connection.interrupt(signal);

    const terminal = fixture.transport.connection!;
    expect(fixture.controlPlane.listCalls).toHaveLength(6);
    expect(terminal.inputCalls.map((call) => call.inputSeq)).toEqual([1, 2]);
    expect(terminal.resizeCalls.map((call) => call.resizeSeq)).toEqual([1]);
    expect(terminal.interruptCalls.map((call) => call.interruptSeq)).toEqual([1]);
    for (const request of [
      ...terminal.inputCalls,
      ...terminal.resizeCalls,
      ...terminal.interruptCalls,
    ]) {
      expect(request).toMatchObject({
        providerSandboxId: fixture.sandbox.providerSandboxId,
        expectedProviderRevision: fixture.sandbox.revision,
        binding: fixture.plan.binding,
        planDigest: fixture.binding.assignmentPlanDigest,
        terminalId: terminal.terminalId,
      });
    }
    expect(new TextDecoder().decode(terminal.inputCalls[0]?.bytes)).toBe("echo safe\n");
  });

  it("serializes concurrent mutations and fences again immediately before dispatch", async () => {
    const fixture = makeFixture();
    const firstList = deferred<void>();
    const releaseFirst = deferred<void>();
    fixture.controlPlane.onListAsync = async (call) => {
      if (call === 3) {
        firstList.resolve();
        await releaseFirst.promise;
      }
      return fixture.sandbox;
    };
    const connection = await fixture.adapter.connect(connectRequest(fixture.binding));
    const signal = new AbortController().signal;

    const first = connection.input("first", signal);
    await firstList.promise;
    const second = connection.input("second", signal);
    expect(fixture.transport.connection?.inputCalls).toEqual([]);
    releaseFirst.resolve();
    await Promise.all([first, second]);

    expect(fixture.transport.connection?.inputCalls.map((call) => call.inputSeq)).toEqual([1, 2]);
    expect(fixture.controlPlane.listCalls).toHaveLength(4);
  });

  it("fails a queued mutation closed when the durable plan or Sandbox changes", async () => {
    const stale = makeFixture();
    const staleConnection = await stale.adapter.connect(connectRequest(stale.binding));
    stale.plans.current = false;
    await expect(
      staleConnection.input("must-not-run", new AbortController().signal)
    ).rejects.toBeInstanceOf(DaytonaHostedTerminalError);
    expect(stale.transport.connection?.inputCalls).toEqual([]);
    await waitFor(() => (stale.transport.connection?.destroyCalls.length ?? 0) === 1);

    const fenced = makeFixture();
    const fencedConnection = await fenced.adapter.connect(connectRequest(fenced.binding));
    fenced.controlPlane.onList = () => ({ ...fenced.sandbox, state: "fenced" });
    await expect(fencedConnection.interrupt(new AbortController().signal)).rejects.toBeInstanceOf(
      DaytonaHostedTerminalError
    );
    expect(fenced.transport.connection?.interruptCalls).toEqual([]);
  });

  it("preserves output order, buffers pre-subscription output, and rejects gaps", async () => {
    const fixture = makeFixture();
    const connection = await fixture.adapter.connect(connectRequest(fixture.binding));
    const terminal = fixture.transport.connection!;

    terminal.emitData(1, "before-");
    terminal.emitData(2, "listener");
    const output: string[] = [];
    const exits = vi.fn();
    connection.onExit(exits);
    connection.onData((data) => output.push(data));
    expect(output).toEqual(["before-", "listener"]);

    terminal.emitData(4, "gap");
    expect(exits).toHaveBeenCalledOnce();
    await waitFor(() => terminal.destroyCalls.length === 1);
  });

  it("fails closed on invalid UTF-8 and bounded pre-listener backpressure", async () => {
    const invalid = makeFixture();
    const invalidConnection = await invalid.adapter.connect(connectRequest(invalid.binding));
    const invalidExit = vi.fn();
    invalidConnection.onExit(invalidExit);
    invalid.transport.connection!.emitBytes(1, new Uint8Array([0xff]));
    expect(invalidExit).toHaveBeenCalledOnce();

    const overflow = makeFixture();
    const overflowConnection = await overflow.adapter.connect(connectRequest(overflow.binding));
    const overflowExit = vi.fn();
    overflowConnection.onExit(overflowExit);
    const fullFrame = new Uint8Array(64 * 1024).fill(65);
    for (let sequence = 1; sequence <= 17; sequence += 1) {
      overflow.transport.connection!.emitBytes(sequence, fullFrame);
    }
    expect(overflowExit).toHaveBeenCalledOnce();
    await waitFor(() => overflow.transport.connection!.destroyCalls.length === 1);
  });

  it("uses the original captured methods after adversarial substitution", async () => {
    const fixture = makeFixture();
    const substitutedOpen = vi.fn();
    fixture.transport.open = substitutedOpen as never;
    const connection = await fixture.adapter.connect(connectRequest(fixture.binding));
    expect(substitutedOpen).not.toHaveBeenCalled();

    const substitutedInput = vi.fn();
    fixture.transport.connection!.input = substitutedInput as never;
    await connection.input("captured", new AbortController().signal);
    expect(substitutedInput).not.toHaveBeenCalled();
    expect(fixture.transport.connection!.inputCalls).toHaveLength(1);
  });

  it("destroys the exact historical terminal even after current authorization is revoked", async () => {
    const fixture = makeFixture();
    const connection = await fixture.adapter.connect(connectRequest(fixture.binding));
    fixture.plans.current = false;

    await connection.destroy();
    expect(fixture.transport.connection?.destroyCalls).toEqual([
      expect.objectContaining({
        providerSandboxId: fixture.sandbox.providerSandboxId,
        expectedProviderRevision: fixture.sandbox.revision,
        planDigest: fixture.binding.assignmentPlanDigest,
      }),
    ]);
  });

  it("reauthorizes reconnects and allocates a fresh terminal fence", async () => {
    const fixture = makeFixture();
    const first = await fixture.adapter.connect(connectRequest(fixture.binding));
    const firstExit = vi.fn();
    first.onExit(firstExit);
    const firstTerminalId = fixture.transport.openCalls[0]?.terminalId;
    const firstPrivateConnection = fixture.transport.connection!;
    firstPrivateConnection.emitExit();
    await waitFor(() => firstPrivateConnection.destroyCalls.length === 1);
    expect(firstExit).toHaveBeenCalledOnce();

    const second = await fixture.adapter.connect(connectRequest(fixture.binding));
    const secondTerminalId = fixture.transport.openCalls[1]?.terminalId;
    expect(fixture.controlPlane.listCalls).toHaveLength(4);
    expect(secondTerminalId).not.toBe(firstTerminalId);
    expect(secondTerminalId).toBeTruthy();
    await second.destroy();
  });

  it("retains a failed destroy so adapter shutdown cannot report a false clean close", async () => {
    const fixture = makeFixture();
    const connection = await fixture.adapter.connect(connectRequest(fixture.binding));
    fixture.transport.connection!.onDestroy = async () => {
      throw new Error("private destroy failure");
    };

    await expect(connection.destroy()).rejects.toBeInstanceOf(DaytonaHostedTerminalError);
    await expect(fixture.adapter.close()).rejects.toBeInstanceOf(DaytonaHostedTerminalError);
    expect(fixture.transport.closed).toBe(1);
  });

  it("bounds an uncooperative open and rejects accessor/proxy capabilities", async () => {
    const hanging = makeFixture({ operationTimeoutMs: 100 });
    hanging.transport.onOpen = async () => new Promise<void>(() => undefined);
    await expect(hanging.adapter.connect(connectRequest(hanging.binding))).rejects.toBeInstanceOf(
      DaytonaHostedTerminalError
    );

    const privateFailure = makeFixture();
    privateFailure.transport.onOpen = async () => {
      throw new Error("provider-private-sandbox /secret/path credential=private");
    };
    await expect(
      privateFailure.adapter.connect(connectRequest(privateFailure.binding))
    ).rejects.toEqual(
      expect.objectContaining({
        name: "DaytonaHostedTerminalError",
        message: "Hosted terminal unavailable",
      })
    );

    const fixture = makeFixture();
    const accessor = Object.create(Object.getPrototypeOf(fixture.transport));
    Object.defineProperty(accessor, "open", { get: () => fixture.transport.open });
    expect(() =>
      createDaytonaHostedTerminalAdapter({
        plans: fixture.plans,
        controlPlane: fixture.controlPlane,
        transport: accessor,
        operationTimeoutMs: 1_000,
      })
    ).toThrow(DaytonaHostedTerminalError);
    expect(() =>
      createDaytonaHostedTerminalAdapter({
        plans: fixture.plans,
        controlPlane: new Proxy(fixture.controlPlane, {}),
        transport: fixture.transport,
        operationTimeoutMs: 1_000,
      })
    ).toThrow(DaytonaHostedTerminalError);
  });
});

class FakePlans implements HostedAssignmentPlanSource {
  current = true;
  readonly lookups: HostedAssignmentLookup[] = [];

  constructor(readonly plan: HostedRuntimeAssignmentPlan) {}

  resolve(lookup: HostedAssignmentLookup): HostedRuntimeAssignmentPlan | null {
    this.lookups.push(lookup);
    return this.current ? this.plan : null;
  }

  isCurrent(lookup: HostedAssignmentLookup): boolean {
    this.lookups.push(lookup);
    return this.current;
  }
}

class FakeControlPlane implements HostedRuntimeControlPlane {
  readonly listCalls: HostedRuntimeAssignmentPlan[] = [];
  onList: ((call: number) => HostedControlPlaneSandbox) | undefined;
  onListAsync: ((call: number) => Promise<HostedControlPlaneSandbox>) | undefined;

  constructor(readonly sandbox: HostedControlPlaneSandbox) {}

  async listExact(
    plan: HostedRuntimeAssignmentPlan
  ): Promise<readonly HostedControlPlaneSandbox[]> {
    this.listCalls.push(plan);
    const call = this.listCalls.length;
    const sandbox = this.onListAsync
      ? await this.onListAsync(call)
      : (this.onList?.(call) ?? this.sandbox);
    return [sandbox];
  }

  async create(_request: HostedControlPlaneCreateRequest): Promise<HostedControlPlaneSandbox> {
    return this.sandbox;
  }

  async fence(_request: HostedControlPlaneMutationRequest): Promise<HostedControlPlaneSandbox> {
    return { ...this.sandbox, state: "fenced" };
  }

  async retire(_request: HostedControlPlaneMutationRequest): Promise<void> {}

  async command(
    _request: HostedControlPlaneCommandRequest
  ): Promise<HostedControlPlaneCommandResult> {
    throw new Error("unused");
  }

  async *follow(_request: HostedControlPlaneFollowRequest): AsyncIterable<unknown> {}

  async close(): Promise<void> {}
}

class FakePtyTransport implements DaytonaSupervisorPtyTransport {
  readonly openCalls: DaytonaSupervisorPtyOpenRequest[] = [];
  connection: FakePtyConnection | null = null;
  onOpen: ((request: DaytonaSupervisorPtyOpenRequest) => Promise<void>) | undefined;
  closed = 0;

  async open(request: DaytonaSupervisorPtyOpenRequest): Promise<DaytonaSupervisorPtyConnection> {
    this.openCalls.push(request);
    await this.onOpen?.(request);
    this.connection = new FakePtyConnection(request);
    return this.connection;
  }

  async close(): Promise<void> {
    this.closed += 1;
  }
}

class FakePtyConnection implements DaytonaSupervisorPtyConnection {
  readonly providerSandboxId: string;
  readonly expectedProviderRevision: number;
  readonly binding: DaytonaSupervisorPtyOpenRequest["binding"];
  readonly planDigest: string;
  readonly terminalId: string;
  readonly inputCalls: DaytonaSupervisorPtyInputRequest[] = [];
  readonly resizeCalls: DaytonaSupervisorPtyResizeRequest[] = [];
  readonly interruptCalls: DaytonaSupervisorPtyInterruptRequest[] = [];
  readonly destroyCalls: DaytonaSupervisorPtyDestroyRequest[] = [];
  onDestroy: (() => Promise<void>) | undefined;
  private readonly dataListeners = new Set<(frame: DaytonaSupervisorPtyOutputFrame) => void>();
  private readonly exitListeners = new Set<(frame: DaytonaSupervisorPtyExitFrame) => void>();

  constructor(request: DaytonaSupervisorPtyOpenRequest) {
    this.providerSandboxId = request.providerSandboxId;
    this.expectedProviderRevision = request.expectedProviderRevision;
    this.binding = request.binding;
    this.planDigest = request.planDigest;
    this.terminalId = request.terminalId;
  }

  onData(listener: (frame: DaytonaSupervisorPtyOutputFrame) => void): { dispose(): void } {
    this.dataListeners.add(listener);
    return { dispose: () => this.dataListeners.delete(listener) };
  }

  onExit(listener: (frame: DaytonaSupervisorPtyExitFrame) => void): { dispose(): void } {
    this.exitListeners.add(listener);
    return { dispose: () => this.exitListeners.delete(listener) };
  }

  async input(request: DaytonaSupervisorPtyInputRequest): Promise<void> {
    this.inputCalls.push(request);
  }

  async resize(request: DaytonaSupervisorPtyResizeRequest): Promise<void> {
    this.resizeCalls.push(request);
  }

  async interrupt(request: DaytonaSupervisorPtyInterruptRequest): Promise<void> {
    this.interruptCalls.push(request);
  }

  async destroy(request: DaytonaSupervisorPtyDestroyRequest): Promise<void> {
    this.destroyCalls.push(request);
    await this.onDestroy?.();
  }

  emitData(outputSeq: number, data: string): void {
    this.emitBytes(outputSeq, new TextEncoder().encode(data));
  }

  emitBytes(outputSeq: number, bytes: Uint8Array): void {
    const frame = { terminalId: this.terminalId, outputSeq, bytes };
    for (const listener of this.dataListeners) listener(frame);
  }

  emitExit(): void {
    const frame = { terminalId: this.terminalId };
    for (const listener of this.exitListeners) listener(frame);
  }
}

function makeFixture(options: { operationTimeoutMs?: number } = {}) {
  const plan = makePlan();
  const binding: HostedTeamSessionTerminalBinding = Object.freeze({
    kind: "hosted",
    binding: plan.binding,
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(plan),
    incarnation: plan.incarnation,
    specificationDigest: plan.specificationDigest,
  });
  const sandbox: HostedControlPlaneSandbox = Object.freeze({
    providerSandboxId: "provider-private-sandbox",
    binding: plan.binding,
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    incarnation: plan.incarnation,
    specificationDigest: plan.specificationDigest,
    effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
    adapterConfigurationRef: plan.adapterConfigurationRef,
    isolationPolicyDigest: plan.isolation.isolationPolicyDigest,
    state: "active",
    revision: 19,
    activation: Object.freeze({
      version: 1,
      kind: "hosted-runtime.activation",
      binding: plan.binding,
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(plan),
      effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
      providerIdentityCommitment: "d".repeat(64),
      providerRevision: 1,
      effectManifestBindingDigest: "e".repeat(64),
      effectEnforcerSetDigest: "f".repeat(64),
    }),
  });
  const plans = new FakePlans(plan);
  const controlPlane = new FakeControlPlane(sandbox);
  const transport = new FakePtyTransport();
  const adapter = createDaytonaHostedTerminalAdapter({
    plans,
    controlPlane,
    transport,
    operationTimeoutMs: options.operationTimeoutMs ?? 1_000,
  });
  return { plan, binding, sandbox, plans, controlPlane, transport, adapter };
}

function makePlan(): HostedRuntimeAssignmentPlan {
  return Object.freeze({
    binding: Object.freeze({
      teamId: "team-1",
      projectId: "project-1",
      sessionId: "session-1",
      runtimeAssignmentId: "assignment-1",
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-1",
      sandboxGeneration: 1,
      runtimePrincipalId: "principal-1",
    }),
    runtimeAuthorizationGeneration: 7,
    incarnation: "a".repeat(64),
    specificationDigest: "b".repeat(64),
    effectEnforcerPolicyDigest: "c".repeat(64),
    adapterConfigurationRef: "daytona-adapter:v1",
    observation: Object.freeze({
      keyProvisioningRef: "observation-key-provisioning:assignment-1:g7",
      issuerKeyId: "observation-key:assignment-1:g7",
      publicKeySpkiPem: PUBLIC_KEY,
    }),
    isolation: Object.freeze({
      isolationPolicyDigest: "c".repeat(64),
      publicAccess: false,
      hostMounts: false,
      linkedSandbox: false,
      rootIdentity: false,
      network: Object.freeze({
        mode: "blocked",
        policyDigest: "d".repeat(64),
        allowedDestinations: Object.freeze([]),
      }),
      resources: Object.freeze({ cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 512 }),
    }),
    capabilities: Object.freeze({
      isolatedExecution: true,
      brokeredCredentials: false,
      proxyOnlyEgress: false,
      checkpoints: true,
      yoloEligible: false,
    }),
  });
}

function connectRequest(binding: HostedTeamSessionTerminalBinding) {
  return { binding, cols: 80, rows: 24, signal: new AbortController().signal };
}

function deferred<T = void>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((innerResolve) => {
    resolve = innerResolve;
  });
  return { promise, resolve };
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("Timed out waiting for condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
