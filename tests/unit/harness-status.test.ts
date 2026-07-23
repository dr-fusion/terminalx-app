import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ESM mocking rule: vi.mock('child_process'), not vi.spyOn(cp, ...).
const execFileSync = vi.fn();
vi.mock("child_process", () => ({
  execFileSync: (...args: unknown[]) => execFileSync(...args),
}));

import { probeHarness, clearHarnessStatusCache } from "@/lib/harnesses/status";

beforeEach(() => {
  execFileSync.mockReset();
  clearHarnessStatusCache();
});

afterEach(() => {
  delete process.env.ANTHROPIC_API_KEY;
  delete process.env.TERMINALX_OPENCODE_BIN;
});

describe("probeHarness", () => {
  it("reports bash as always installed + connected without shelling out", () => {
    const s = probeHarness("bash");
    expect(s).toMatchObject({ id: "bash", installed: true, connected: true, authMethod: "none" });
    expect(execFileSync).not.toHaveBeenCalled();
  });

  it("reports an unknown harness as not installed", () => {
    const s = probeHarness("nope");
    expect(s).toMatchObject({ installed: false, connected: false, authMethod: "none" });
  });

  it("marks a CLI harness installed with a version + a login command, not-connected by default", () => {
    // command -v claude -> path, claude --version -> version string
    execFileSync
      .mockImplementationOnce(() => "/usr/local/bin/claude\n")
      .mockImplementationOnce(() => "claude 1.2.3\n");
    const s = probeHarness("claude");
    expect(s.installed).toBe(true);
    expect(s.binPath).toBe("/usr/local/bin/claude");
    expect(s.version).toBe("claude 1.2.3");
    expect(s.authMethod).toBe("cli");
    expect(s.connected).toBe(false);
    expect(s.loginCommand).toBe("claude /login");
    // account fields are never fabricated
    expect(s.account).toBeUndefined();
  });

  it("flips claude to api-key + connected when ANTHROPIC_API_KEY is set", () => {
    process.env.ANTHROPIC_API_KEY = "sk-test";
    execFileSync
      .mockImplementationOnce(() => "/usr/local/bin/claude\n")
      .mockImplementationOnce(() => "claude 1.2.3\n");
    const s = probeHarness("claude");
    expect(s.authMethod).toBe("api-key");
    expect(s.connected).toBe(true);
  });

  it("reports a missing binary as not installed (command -v fails)", () => {
    execFileSync.mockImplementation(() => {
      throw new Error("not found");
    });
    const s = probeHarness("codex");
    expect(s.installed).toBe(false);
    expect(s.version).toBeUndefined();
    expect(s.loginCommand).toBe("codex /login");
  });

  it("treats opencode as connected (auth is per-provider) and version-probes it", () => {
    execFileSync
      .mockImplementationOnce(() => "/usr/local/bin/opencode\n")
      .mockImplementationOnce(() => "1.17.7\n");
    const s = probeHarness("opencode");
    expect(s.installed).toBe(true);
    expect(s.version).toBe("1.17.7");
    expect(s.connected).toBe(true);
    expect(s.authMethod).toBe("none");
  });

  it("does not interpolate an unsafe OpenCode executable override into the status shell", () => {
    process.env.TERMINALX_OPENCODE_BIN = "/opt/opencode;touch-pwned";
    execFileSync
      .mockImplementationOnce(() => "/usr/local/bin/opencode\n")
      .mockImplementationOnce(() => "1.17.7\n");

    const s = probeHarness("opencode");

    expect(s.installed).toBe(true);
    expect(execFileSync.mock.calls[0]?.[1]).toEqual(["-lc", "command -v opencode"]);
    expect(s.loginCommand).toBeUndefined();
  });

  it("never throws into the request path even if shellouts blow up", () => {
    execFileSync.mockImplementation(() => {
      throw new Error("boom");
    });
    expect(() => probeHarness("claude")).not.toThrow();
  });
});
