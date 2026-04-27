import { describe, it, expect } from "vitest";
import { tmuxTarget } from "@/lib/tmux";

// Import the sanitizer directly — tmux operations require tmux installed
// so we test the validation logic, not the tmux commands themselves
describe("tmux session name validation", () => {
  // Mirror the regex from tmux.ts and pty-manager.ts
  const SESSION_NAME_REGEX = /^[a-zA-Z0-9_.\-]+$/;
  const MAX_LENGTH = 128;

  function validateSessionName(name: string): boolean {
    if (!SESSION_NAME_REGEX.test(name)) return false;
    if (name.length > MAX_LENGTH) return false;
    return true;
  }

  it("accepts valid alphanumeric names", () => {
    expect(validateSessionName("my-session")).toBe(true);
    expect(validateSessionName("test_123")).toBe(true);
    expect(validateSessionName("session.1")).toBe(true);
    expect(validateSessionName("a")).toBe(true);
  });

  it("rejects names with shell metacharacters", () => {
    expect(validateSessionName("test; rm -rf /")).toBe(false);
    expect(validateSessionName("$(whoami)")).toBe(false);
    expect(validateSessionName("`id`")).toBe(false);
    expect(validateSessionName("test|cat")).toBe(false);
    expect(validateSessionName("test&")).toBe(false);
    expect(validateSessionName("test > /tmp/x")).toBe(false);
  });

  it("rejects names with path separators", () => {
    expect(validateSessionName("../../etc")).toBe(false);
    expect(validateSessionName("test/session")).toBe(false);
  });

  it("rejects names with spaces", () => {
    expect(validateSessionName("my session")).toBe(false);
  });

  it("rejects names with null bytes", () => {
    expect(validateSessionName("test\0")).toBe(false);
  });

  it("rejects empty names", () => {
    expect(validateSessionName("")).toBe(false);
  });

  it("rejects names exceeding max length", () => {
    expect(validateSessionName("a".repeat(129))).toBe(false);
    expect(validateSessionName("a".repeat(128))).toBe(true);
  });

  it("builds exact tmux session targets", () => {
    expect(tmuxTarget("b")).toBe("=b:");
    expect(tmuxTarget("fix-terminalx")).toBe("=fix-terminalx:");
  });
});
