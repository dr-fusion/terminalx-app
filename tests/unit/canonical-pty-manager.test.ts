import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { spawn } = vi.hoisted(() => ({ spawn: vi.fn() }));

vi.mock("node-pty", () => ({ spawn }));
vi.mock("@/lib/tmux", () => ({
  hasSession: () => true,
  isValidTmuxSessionName: (name: unknown) =>
    typeof name === "string" && /^[a-zA-Z0-9_.-]{1,128}$/.test(name),
  tmuxTarget: (name: string) => `=${name}:`,
}));

import {
  createCanonicalPty,
  createPty,
  destroyAllPtys,
  destroyCanonicalPtys,
  setMaxSessions,
} from "@/lib/pty-manager";

interface FakeProcess {
  kill: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
  write: ReturnType<typeof vi.fn>;
  onExit: ReturnType<typeof vi.fn>;
}

function fakeProcess(): FakeProcess {
  return {
    kill: vi.fn(),
    resize: vi.fn(),
    write: vi.fn(),
    onExit: vi.fn(() => ({ dispose: vi.fn() })),
  };
}

describe("canonical PTY manager", () => {
  const originalEnvironment = { ...process.env };

  beforeEach(() => {
    process.env = {
      ...originalEnvironment,
      PATH: "/safe/bin",
      HOME: "/safe/home",
      SHELL: "/bin/bash",
      TERMINALX_JWT_SECRET: "must-not-reach-pty",
      TERMINALX_ADMIN_PASSWORD: "must-not-reach-pty",
      TERMINALX_TELEGRAM_BOT_TOKEN: "must-not-reach-pty",
      OP_CONNECT_TOKEN: "must-not-reach-pty",
    };
    setMaxSessions(20);
    spawn.mockReset();
    spawn.mockImplementation(() => fakeProcess());
  });

  afterEach(() => {
    destroyAllPtys();
    process.env = { ...originalEnvironment };
  });

  it("attaches an observer read-only to the dedicated canonical tmux server", () => {
    const instance = createCanonicalPty("runtime-one", "/bin/bash", 120, 40, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      tmuxSocketName: "terminalx-multiplayer",
      readOnly: true,
    });

    expect(spawn).toHaveBeenCalledWith(
      "tmux",
      [
        "-L",
        "terminalx-multiplayer",
        "-f",
        "/dev/null",
        "attach-session",
        "-E",
        "-r",
        "-f",
        "ignore-size",
        "-t",
        "=runtime-one:",
      ],
      expect.objectContaining({ cols: 120, rows: 40 })
    );
    const options = spawn.mock.calls[0]?.[2] as { env: Record<string, string> };
    expect(options.env).not.toHaveProperty("TERMINALX_JWT_SECRET");
    expect(options.env).not.toHaveProperty("TERMINALX_ADMIN_PASSWORD");
    expect(options.env).not.toHaveProperty("TERMINALX_TELEGRAM_BOT_TOKEN");
    expect(options.env).not.toHaveProperty("OP_CONNECT_TOKEN");
    expect(instance.canonicalBinding).toEqual({
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      tmuxSocketName: "terminalx-multiplayer",
      readOnly: true,
    });
  });

  it("keeps writable canonical clients explicit and gives concurrent clients unique ids", () => {
    const binding = {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      tmuxSocketName: "terminalx-multiplayer",
      readOnly: false,
    } as const;
    const first = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, binding);
    const second = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, binding);

    expect(first.id).not.toBe(second.id);
    expect(spawn.mock.calls[0]?.[1]).toEqual([
      "-L",
      "terminalx-multiplayer",
      "-f",
      "/dev/null",
      "attach-session",
      "-E",
      "-t",
      "=runtime-one:",
    ]);
  });

  it("terminates only stale canonical generations and leaves legacy PTYs untouched", () => {
    const stale = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 1,
      tmuxSocketName: "terminalx-multiplayer",
      readOnly: false,
    });
    const current = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 2,
      tmuxSocketName: "terminalx-multiplayer",
      readOnly: false,
    });
    const legacy = createPty("legacy", "/bin/bash", 80, 24);

    expect(
      destroyCanonicalPtys({
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 2,
      })
    ).toBe(1);
    expect(stale.process.kill).toHaveBeenCalledOnce();
    expect(current.process.kill).not.toHaveBeenCalled();
    expect(legacy.process.kill).not.toHaveBeenCalled();

    expect(
      destroyCanonicalPtys({
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 2,
        includeCurrentGeneration: true,
      })
    ).toBe(1);
    expect(current.process.kill).toHaveBeenCalledOnce();
    expect(legacy.process.kill).not.toHaveBeenCalled();
  });

  it("rejects malformed canonical bindings before spawning", () => {
    expect(() =>
      createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 0,
        tmuxSocketName: "bad/socket",
        readOnly: false,
      })
    ).toThrow("Invalid canonical PTY binding");
    expect(() =>
      createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 1,
        tmuxSocketName: "terminalx-multiplayer",
        readOnly: undefined as unknown as boolean,
      })
    ).toThrow("Invalid canonical PTY binding");
    expect(spawn).not.toHaveBeenCalled();
  });
});
