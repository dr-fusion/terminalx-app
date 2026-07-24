import { describe, it, expect } from "vitest";
import {
  HARNESSES,
  HARNESS_IDS,
  listHarnesses,
  getHarness,
  isValidHarnessId,
} from "@/lib/harnesses/registry";

describe("harness registry", () => {
  it("ships bash, claude, codex, cursor, opencode as selectable ids", () => {
    expect(HARNESS_IDS).toEqual(["bash", "claude", "codex", "cursor", "opencode"]);
  });

  it("keeps legacy ids (back-compat with persisted SessionMeta.kind)", () => {
    expect(getHarness("bash")).toBeDefined();
    expect(getHarness("claude")).toBeDefined();
    expect(getHarness("codex")).toBeDefined();
  });

  it("labels claude as 'Claude Code' while keeping the persisted id 'claude'", () => {
    const claude = getHarness("claude");
    expect(claude?.id).toBe("claude");
    expect(claude?.label).toBe("Claude Code");
  });

  it("marks the OpenCode tab with a NEW badge and as a provider host", () => {
    const oc = getHarness("opencode");
    expect(oc?.badge).toBe("NEW");
    expect(oc?.hostsProviders).toBe(true);
    expect(oc?.docsUrl).toContain("opencode");
  });

  it("bash has no binary (null) and no harness-level auth", () => {
    const bash = getHarness("bash");
    expect(bash?.command.bin).toBeNull();
    expect(bash?.auth).toBe("none");
  });

  it("does not register permission-skipping flags for LocalTmux harnesses", () => {
    const registry = JSON.stringify(HARNESSES);
    expect(registry).not.toContain("dangerouslySkipPermissions");
    expect(registry).not.toContain("--dangerously-skip-permissions");
    for (const harness of HARNESSES) {
      expect(harness.command.baseArgs ?? []).not.toContain("--yolo");
    }
  });

  it("listHarnesses returns the full descriptor list", () => {
    expect(listHarnesses()).toBe(HARNESSES);
    expect(listHarnesses().map((h) => h.id)).toEqual(HARNESS_IDS);
  });

  describe("isValidHarnessId", () => {
    it("accepts every registry id", () => {
      for (const id of HARNESS_IDS) expect(isValidHarnessId(id)).toBe(true);
    });
    it("rejects unknown / non-string values", () => {
      expect(isValidHarnessId("unknown")).toBe(false);
      expect(isValidHarnessId("")).toBe(false);
      expect(isValidHarnessId(null)).toBe(false);
      expect(isValidHarnessId(undefined)).toBe(false);
      expect(isValidHarnessId(42)).toBe(false);
    });
  });
});
