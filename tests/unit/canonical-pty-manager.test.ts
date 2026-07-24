import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { execFileSync, spawn } = vi.hoisted(() => ({
  execFileSync: vi.fn(),
  spawn: vi.fn(),
}));

vi.mock("node-pty", () => ({ spawn }));
vi.mock("node:child_process", () => ({ execFileSync }));
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
  resolveCanonicalTmuxSessionRef,
  setMaxSessions,
} from "@/lib/pty-manager";

const SESSION_INCARNATION = "a".repeat(64);
const REPLACEMENT_SESSION_INCARNATION = "b".repeat(64);

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
    execFileSync.mockReset();
    execFileSync.mockReturnValue(
      `$1\t1\tsession-one\t3\t${SESSION_INCARNATION}\tv2:session-one:${SESSION_INCARNATION}\n`
    );
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
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: SESSION_INCARNATION,
      readOnly: true,
    });

    expect(spawn).toHaveBeenCalledWith(
      "tmux",
      [
        "-L",
        "terminalx-multiplayer",
        "-f",
        "/dev/null",
        "if-shell",
        "-F",
        "-t",
        "$1",
        expect.stringContaining(`@terminalx_session_incarnation},${SESSION_INCARNATION}`),
        "attach-session -E -r -f ignore-size -t $1",
        "display-message -p terminalx-runtime-binding-unavailable",
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
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: SESSION_INCARNATION,
      readOnly: true,
    });
  });

  it("keeps writable canonical clients explicit and gives concurrent clients unique ids", () => {
    const binding = {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      tmuxSocketName: "terminalx-multiplayer",
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: SESSION_INCARNATION,
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
      "if-shell",
      "-F",
      "-t",
      "$1",
      expect.stringContaining(SESSION_INCARNATION),
      "attach-session -E -t $1",
      "display-message -p terminalx-runtime-binding-unavailable",
    ]);
  });

  it("terminates only stale canonical generations and leaves legacy PTYs untouched", () => {
    const stale = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 1,
      tmuxSocketName: "terminalx-multiplayer",
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: SESSION_INCARNATION,
      readOnly: false,
    });
    const current = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 2,
      tmuxSocketName: "terminalx-multiplayer",
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: SESSION_INCARNATION,
      readOnly: false,
    });
    const legacy = createPty("legacy", "/bin/bash", 80, 24);

    expect(
      destroyCanonicalPtys({
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 2,
        tmuxSessionRef: "$1",
        tmuxSessionIncarnation: SESSION_INCARNATION,
      })
    ).toBe(1);
    expect(stale.process.kill).toHaveBeenCalledOnce();
    expect(current.process.kill).not.toHaveBeenCalled();
    expect(legacy.process.kill).not.toHaveBeenCalled();

    expect(
      destroyCanonicalPtys({
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 2,
        tmuxSessionRef: "$1",
        tmuxSessionIncarnation: SESSION_INCARNATION,
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
        tmuxSessionRef: "runtime-one",
        tmuxSessionIncarnation: "invalid",
        readOnly: false,
      })
    ).toThrow("Invalid canonical PTY binding");
    expect(() =>
      createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 1,
        tmuxSocketName: "terminalx-multiplayer",
        tmuxSessionRef: "$1",
        tmuxSessionIncarnation: SESSION_INCARNATION,
        readOnly: undefined as unknown as boolean,
      })
    ).toThrow("Invalid canonical PTY binding");
    expect(spawn).not.toHaveBeenCalled();
  });

  it("resolves and validates the immutable tmux ref without exposing server secrets", () => {
    expect(
      resolveCanonicalTmuxSessionRef({
        teamSessionId: "session-one",
        tmuxName: "runtime-one",
        runtimeAuthorizationGeneration: 3,
        tmuxSocketName: "terminalx-multiplayer",
      })
    ).toEqual({
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: SESSION_INCARNATION,
    });
    expect(execFileSync).toHaveBeenCalledWith(
      "tmux",
      expect.arrayContaining(["-L", "terminalx-multiplayer", "-t", "=runtime-one:"]),
      expect.objectContaining({ env: expect.any(Object) })
    );
    const environment = execFileSync.mock.calls[0]?.[2]?.env as Record<string, string>;
    expect(environment).not.toHaveProperty("TERMINALX_JWT_SECRET");
    expect(environment).not.toHaveProperty("OP_CONNECT_TOKEN");

    execFileSync.mockReturnValueOnce(
      `$2\t1\tsession-one\t4\t${SESSION_INCARNATION}\tv2:session-one:${SESSION_INCARNATION}\n`
    );
    expect(() =>
      resolveCanonicalTmuxSessionRef({
        teamSessionId: "session-one",
        tmuxName: "runtime-one",
        runtimeAuthorizationGeneration: 3,
        tmuxSocketName: "terminalx-multiplayer",
      })
    ).toThrow("Canonical tmux binding is unavailable");

    execFileSync.mockReturnValueOnce(
      `$1\t1\tsession-one\t3\t${SESSION_INCARNATION}\tv2:session-one:${REPLACEMENT_SESSION_INCARNATION}\n`
    );
    expect(() =>
      resolveCanonicalTmuxSessionRef({
        teamSessionId: "session-one",
        tmuxName: "runtime-one",
        runtimeAuthorizationGeneration: 3,
        tmuxSocketName: "terminalx-multiplayer",
      })
    ).toThrow("Canonical tmux binding is unavailable");
  });

  it("does not terminate a same-generation ABA replacement with a different tmux ref", () => {
    const original = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      tmuxSocketName: "terminalx-multiplayer",
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: SESSION_INCARNATION,
      readOnly: false,
    });
    const replacement = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      tmuxSocketName: "terminalx-multiplayer",
      tmuxSessionRef: "$2",
      tmuxSessionIncarnation: REPLACEMENT_SESSION_INCARNATION,
      readOnly: false,
    });

    expect(
      destroyCanonicalPtys({
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 3,
        tmuxSessionRef: "$1",
        tmuxSessionIncarnation: SESSION_INCARNATION,
        includeCurrentGeneration: true,
      })
    ).toBe(1);
    expect(original.process.kill).toHaveBeenCalledOnce();
    expect(replacement.process.kill).not.toHaveBeenCalled();
  });

  it("does not terminate a restarted-server ABA replacement that reused the same tmux ref", () => {
    const original = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      tmuxSocketName: "terminalx-multiplayer",
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: SESSION_INCARNATION,
      readOnly: false,
    });
    const replacement = createCanonicalPty("runtime-one", "/bin/bash", 80, 24, {
      teamSessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      tmuxSocketName: "terminalx-multiplayer",
      tmuxSessionRef: "$1",
      tmuxSessionIncarnation: REPLACEMENT_SESSION_INCARNATION,
      readOnly: false,
    });

    expect(
      destroyCanonicalPtys({
        teamSessionId: "session-one",
        runtimeAuthorizationGeneration: 3,
        tmuxSessionRef: "$1",
        tmuxSessionIncarnation: SESSION_INCARNATION,
        includeCurrentGeneration: true,
      })
    ).toBe(1);
    expect(original.process.kill).toHaveBeenCalledOnce();
    expect(replacement.process.kill).not.toHaveBeenCalled();
  });
});
