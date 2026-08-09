import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TeamSessionKernel } from "@/lib/team-sessions/module";

const mocks = vi.hoisted(() => ({
  createTeamSessionKernel: vi.fn(),
}));

vi.mock("@/lib/team-sessions/module", () => ({
  createTeamSessionKernel: mocks.createTeamSessionKernel,
}));

const REGISTRY_KEYS = [
  "__terminalxTeamSessionKernel",
  "__terminalxTeamSessionKernelClose",
  "__terminalxTeamSessionKernelInstallation",
  "__terminalxTeamSessionKernelPhase",
  "__terminalxHostedMultiplayerServiceFactory",
] as const;

function fakeKernel(close: () => void = vi.fn()): TeamSessionKernel {
  return {
    teamSessions: { close },
  } as unknown as TeamSessionKernel;
}

describe("Team Session process service", () => {
  beforeEach(() => {
    mocks.createTeamSessionKernel.mockReset();
    for (const key of REGISTRY_KEYS) Reflect.deleteProperty(globalThis, key);
    vi.resetModules();
  });

  it("reuses one kernel across module reloads", async () => {
    const kernel = fakeKernel();
    mocks.createTeamSessionKernel.mockReturnValue(kernel);
    const firstModule = await import("@/lib/team-sessions/service");
    const first = firstModule.getTeamSessionKernel();

    vi.resetModules();
    const reloadedModule = await import("@/lib/team-sessions/service");
    expect(reloadedModule.getTeamSessionKernel()).toBe(first);
    expect(mocks.createTeamSessionKernel).toHaveBeenCalledTimes(1);

    reloadedModule.closeTeamSessions(kernel);
  });

  it("does not let a stale service owner close a replacement kernel", async () => {
    const closeFirst = vi.fn();
    const closeSecond = vi.fn();
    const first = fakeKernel(closeFirst);
    const second = fakeKernel(closeSecond);
    mocks.createTeamSessionKernel.mockReturnValueOnce(first).mockReturnValueOnce(second);
    const service = await import("@/lib/team-sessions/service");

    expect(service.getTeamSessionKernel()).toBe(first);
    service.closeTeamSessions(first);
    expect(closeFirst).toHaveBeenCalledTimes(1);
    expect(service.getTeamSessionKernel()).toBe(second);

    service.closeTeamSessions(first);
    expect(closeSecond).not.toHaveBeenCalled();
    expect(service.getTeamSessionKernel()).toBe(second);

    service.closeTeamSessions(second);
    expect(closeSecond).toHaveBeenCalledTimes(1);
  });

  it("pins the close capability and blocks reentrant construction while closing", async () => {
    const service = await import("@/lib/team-sessions/service");
    const replacementClose = vi.fn();
    const originalClose = vi.fn(() => {
      expect(() => service.getTeamSessionKernel()).toThrow(
        "Team Session kernel lifecycle is in progress"
      );
    });
    const kernel = fakeKernel(originalClose);
    mocks.createTeamSessionKernel.mockReturnValue(kernel);

    service.getTeamSessionKernel();
    Object.defineProperty(kernel.teamSessions, "close", {
      configurable: true,
      enumerable: true,
      value: replacementClose,
      writable: true,
    });
    service.closeTeamSessions(kernel);

    expect(originalClose).toHaveBeenCalledTimes(1);
    expect(replacementClose).not.toHaveBeenCalled();
    expect(mocks.createTeamSessionKernel).toHaveBeenCalledTimes(1);
  });

  it("rejects accessor-backed close capabilities without invoking them or retaining the kernel", async () => {
    let getterCalls = 0;
    const hostile = fakeKernel();
    Object.defineProperty(hostile.teamSessions, "close", {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("private database path");
      },
    });
    const recovered = fakeKernel();
    mocks.createTeamSessionKernel.mockReturnValueOnce(hostile).mockReturnValueOnce(recovered);
    const service = await import("@/lib/team-sessions/service");

    expect(() => service.getTeamSessionKernel()).toThrow(
      "Team Session kernel could not be constructed"
    );
    expect(getterCalls).toBe(0);
    expect(service.getTeamSessionKernel()).toBe(recovered);

    service.closeTeamSessions(recovered);
  });

  it("clears ownership and sanitizes a close failure", async () => {
    const failed = fakeKernel(() => {
      throw new Error("private sqlite filename");
    });
    const recovered = fakeKernel();
    mocks.createTeamSessionKernel.mockReturnValueOnce(failed).mockReturnValueOnce(recovered);
    const service = await import("@/lib/team-sessions/service");

    service.getTeamSessionKernel();
    expect(() => service.closeTeamSessions(failed)).toThrow(
      "Team Session kernel could not be closed"
    );
    expect(service.getTeamSessionKernel()).toBe(recovered);

    service.closeTeamSessions(recovered);
  });

  it("keeps the explicit hosted factory absent without constructing a local kernel", async () => {
    const service = await import("@/lib/team-sessions/service");

    expect(service.getHostedMultiplayerServiceFactory()).toBeNull();
    expect(mocks.createTeamSessionKernel).not.toHaveBeenCalled();
  });

  it("registers a hosted one-call factory with owner-scoped removal", async () => {
    const service = await import("@/lib/team-sessions/service");
    const hosted = {} as never;
    const factory = vi.fn(async () => hosted);
    const remove = service.installHostedMultiplayerServiceFactory(factory);

    expect(service.getHostedMultiplayerServiceFactory()).toBe(factory);
    expect(() => service.installHostedMultiplayerServiceFactory(vi.fn(async () => hosted))).toThrow(
      "Hosted multiplayer factory conflicts"
    );

    remove();
    expect(service.getHostedMultiplayerServiceFactory()).toBeNull();
    expect(mocks.createTeamSessionKernel).not.toHaveBeenCalled();
  });

  it("installs one deployment-owned kernel without constructing or closing a fallback", async () => {
    const service = await import("@/lib/team-sessions/service");
    const close = vi.fn();
    const hosted = fakeKernel(close);
    const dispose = service.installTeamSessionKernel(hosted);

    expect(service.getRegisteredTeamSessionKernel()).toBe(hosted);
    expect(service.getRegisteredTeamSessions()).toBe(hosted.teamSessions);
    expect(service.getTeamSessionKernel()).toBe(hosted);
    expect(mocks.createTeamSessionKernel).not.toHaveBeenCalled();
    expect(() => service.closeTeamSessions()).toThrow(
      "Installed Team Session kernel is externally owned"
    );

    dispose();
    dispose();
    expect(service.getRegisteredTeamSessionKernel()).toBeNull();
    expect(close).not.toHaveBeenCalled();
  });

  it("rejects a hosted install over a lazy LocalTmux owner without replacing either identity", async () => {
    const localClose = vi.fn();
    const hostedClose = vi.fn();
    const local = fakeKernel(localClose);
    const hosted = fakeKernel(hostedClose);
    mocks.createTeamSessionKernel.mockReturnValue(local);
    const service = await import("@/lib/team-sessions/service");

    expect(service.getTeamSessionKernel()).toBe(local);
    expect(() => service.installTeamSessionKernel(hosted)).toThrow(
      "Team Session kernel installation conflicts"
    );
    expect(service.getRegisteredTeamSessionKernel()).toBe(local);
    expect(hostedClose).not.toHaveBeenCalled();

    service.closeTeamSessions(local);
    expect(localClose).toHaveBeenCalledTimes(1);
  });

  it("does not let a stale installation disposer remove its replacement", async () => {
    const service = await import("@/lib/team-sessions/service");
    const first = fakeKernel();
    const second = fakeKernel();
    const disposeFirst = service.installTeamSessionKernel(first);
    disposeFirst();
    const disposeSecond = service.installTeamSessionKernel(second);

    disposeFirst();
    expect(service.getRegisteredTeamSessionKernel()).toBe(second);
    disposeSecond();
    expect(service.getRegisteredTeamSessionKernel()).toBeNull();
  });

  it("fails closed on a partial registry instead of serving or overwriting it", async () => {
    const service = await import("@/lib/team-sessions/service");
    const stranded = fakeKernel();
    Object.defineProperty(globalThis, "__terminalxTeamSessionKernelClose", {
      configurable: true,
      enumerable: false,
      value: Object.freeze({ kernel: stranded, close: vi.fn() }),
      writable: true,
    });

    expect(() => service.getRegisteredTeamSessionKernel()).toThrow(
      "Invalid Team Session kernel registry"
    );
    expect(() => service.installTeamSessionKernel(fakeKernel())).toThrow(
      "Team Session kernel installation conflicts"
    );
    expect(mocks.createTeamSessionKernel).not.toHaveBeenCalled();
  });
});
