import { describe, it, expect } from "vitest";
import { isValidKind, commandForKind } from "@/lib/ai-sessions";

describe("isValidKind", () => {
  it("accepts known kinds", () => {
    expect(isValidKind("bash")).toBe(true);
    expect(isValidKind("claude")).toBe(true);
    expect(isValidKind("codex")).toBe(true);
  });

  it("rejects unknown values", () => {
    expect(isValidKind("unknown")).toBe(false);
    expect(isValidKind("")).toBe(false);
    expect(isValidKind(null)).toBe(false);
    expect(isValidKind(undefined)).toBe(false);
    expect(isValidKind(42)).toBe(false);
  });
});

describe("commandForKind", () => {
  it("returns null for bash (no wrapper needed)", () => {
    expect(commandForKind("bash")).toBeNull();
  });

  it("wraps claude in a bash shell that keeps session alive on exit", () => {
    const cmd = commandForKind("claude");
    expect(cmd).toBeTruthy();
    expect(cmd).toContain("claude");
    expect(cmd).toContain("exec bash -l");
    expect(cmd).not.toContain("--dangerously-skip-permissions");
  });

  it("wraps codex similarly", () => {
    const cmd = commandForKind("codex");
    expect(cmd).toBeTruthy();
    expect(cmd).toContain("codex");
    expect(cmd).toContain("exec bash -l");
  });

  it("appends --dangerously-skip-permissions to claude when opted in", () => {
    const cmd = commandForKind("claude", { dangerouslySkipPermissions: true });
    expect(cmd).toContain("claude --dangerously-skip-permissions");
  });

  it("ignores dangerouslySkipPermissions for codex", () => {
    const cmd = commandForKind("codex", { dangerouslySkipPermissions: true });
    expect(cmd).not.toContain("--dangerously-skip-permissions");
  });

  it("ignores dangerouslySkipPermissions for bash", () => {
    expect(
      commandForKind("bash", { dangerouslySkipPermissions: true })
    ).toBeNull();
  });
});
