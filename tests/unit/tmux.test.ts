import { describe, it, expect } from "vitest";
import { isValidTmuxSessionName, tmuxTarget } from "@/lib/tmux";

// Import the sanitizer directly — tmux operations require tmux installed
// so we test the validation logic, not the tmux commands themselves
describe("tmux session name validation", () => {
  it("accepts valid alphanumeric names", () => {
    expect(isValidTmuxSessionName("my-session")).toBe(true);
    expect(isValidTmuxSessionName("test_123")).toBe(true);
    expect(isValidTmuxSessionName("session.1")).toBe(true);
    expect(isValidTmuxSessionName("a")).toBe(true);
  });

  it("rejects names with shell metacharacters", () => {
    expect(isValidTmuxSessionName("test; rm -rf /")).toBe(false);
    expect(isValidTmuxSessionName("$(whoami)")).toBe(false);
    expect(isValidTmuxSessionName("`id`")).toBe(false);
    expect(isValidTmuxSessionName("test|cat")).toBe(false);
    expect(isValidTmuxSessionName("test&")).toBe(false);
    expect(isValidTmuxSessionName("test > /tmp/x")).toBe(false);
  });

  it("rejects names with path separators", () => {
    expect(isValidTmuxSessionName("../../etc")).toBe(false);
    expect(isValidTmuxSessionName("test/session")).toBe(false);
  });

  it("rejects names with spaces", () => {
    expect(isValidTmuxSessionName("my session")).toBe(false);
  });

  it("rejects names with null bytes", () => {
    expect(isValidTmuxSessionName("test\0")).toBe(false);
  });

  it("rejects empty names", () => {
    expect(isValidTmuxSessionName("")).toBe(false);
  });

  it("rejects names exceeding max length", () => {
    expect(isValidTmuxSessionName("a".repeat(129))).toBe(false);
    expect(isValidTmuxSessionName("a".repeat(128))).toBe(true);
  });

  it("builds exact tmux session targets", () => {
    expect(tmuxTarget("b")).toBe("=b:");
    expect(tmuxTarget("fix-terminalx")).toBe("=fix-terminalx:");
  });
});
