import { describe, it, expect, afterEach } from "vitest";
import { commandForHarness } from "@/lib/harnesses/command";

/**
 * Byte-identical parity: commandForHarness must emit the EXACT wrapper the old
 * commandForKind produced for bash/claude/codex, so existing tmux behavior and
 * any downstream snapshots stay stable.
 */
function legacyWrapper(bin: string, args: string[] = []): string {
  const invocation = [bin, ...args].join(" ");
  const pathPrefix =
    'export PATH="$HOME/.local/bin:$HOME/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"; ';
  return `bash -lc '${pathPrefix}${invocation}; ec=$?; echo; echo "[${bin} exited with code $ec — dropping to bash]"; exec bash -l'`;
}

describe("commandForHarness", () => {
  it("returns null for bash (no wrapper needed)", () => {
    expect(commandForHarness("bash")).toBeNull();
  });

  it("returns null for unknown harness ids", () => {
    expect(commandForHarness("does-not-exist")).toBeNull();
  });

  it("emits the byte-identical legacy wrapper for claude", () => {
    expect(commandForHarness("claude")).toBe(legacyWrapper("claude"));
  });

  it("runs codex without --yolo", () => {
    expect(commandForHarness("codex")).toBe(legacyWrapper("codex"));
  });

  it("wraps the new cursor harness with the cursor-agent binary", () => {
    expect(commandForHarness("cursor")).toBe(legacyWrapper("cursor-agent"));
  });

  it("wraps the new opencode harness with the opencode binary", () => {
    expect(commandForHarness("opencode")).toBe(legacyWrapper("opencode"));
  });

  // --- Feature #11: model + plan-mode threading (data-driven via registry) ---
  describe("model threading (#11)", () => {
    it("appends the claude model flag when a model is set", () => {
      const cmd = commandForHarness("claude", { model: "opus-4-8-1m" });
      expect(cmd).toBe(legacyWrapper("claude", ["--model", "opus-4-8-1m"]));
    });

    it("appends the codex model flag (-m) when a model is set", () => {
      const cmd = commandForHarness("codex", { model: "gpt-5-codex" });
      expect(cmd).toBe(legacyWrapper("codex", ["-m", "gpt-5-codex"]));
    });

    it("appends the opencode model flag when a model is set", () => {
      const cmd = commandForHarness("opencode", { model: "anthropic/claude-sonnet" });
      expect(cmd).toBe(legacyWrapper("opencode", ["--model", "anthropic/claude-sonnet"]));
    });

    it("preserves safe provider/model slug punctuation", () => {
      const model = "anthropic/claude:sonnet.4@2026_07+beta-1";
      expect(commandForHarness("opencode", { model })).toBe(
        legacyWrapper("opencode", ["--model", model])
      );
    });

    it("omits a model value that tries to enable Codex yolo mode", () => {
      expect(commandForHarness("codex", { model: "gpt-5 --yolo" })).toBe(legacyWrapper("codex"));
    });

    it("omits a model value that tries to skip Claude permissions", () => {
      const cmd = commandForHarness("claude", {
        model: "sonnet --dangerously-skip-permissions",
      });
      expect(cmd).toBe(legacyWrapper("claude"));
      expect(cmd).not.toContain("--dangerously-skip-permissions");
    });

    it.each(["gpt-5;touch-pwned", "gpt-5$(touch-pwned)", "gpt-5'\\'';touch-pwned", "gpt-5\n"])(
      "omits a model value containing shell syntax: %s",
      (model) => {
        expect(commandForHarness("codex", { model })).toBe(legacyWrapper("codex"));
      }
    );

    it("omits a leading-option model value", () => {
      expect(commandForHarness("claude", { model: "--dangerously-skip-permissions" })).toBe(
        legacyWrapper("claude")
      );
    });

    it("leaves the command unchanged when no model is set (back-compat)", () => {
      expect(commandForHarness("claude")).toBe(legacyWrapper("claude"));
      expect(commandForHarness("claude", { model: undefined })).toBe(legacyWrapper("claude"));
      expect(commandForHarness("claude", { model: "" })).toBe(legacyWrapper("claude"));
    });

    it("ignores a model for bash (no binary, no flag)", () => {
      expect(commandForHarness("bash", { model: "opus-4-8-1m" })).toBeNull();
    });

    it("ignores a model when the harness declares no model flag", () => {
      // cursor has a binary but no modelFlag in the registry → command unchanged.
      expect(commandForHarness("cursor", { model: "cursor-default" })).toBe(
        legacyWrapper("cursor-agent")
      );
    });

    it("appends the claude plan-mode flag when planMode is set", () => {
      const cmd = commandForHarness("claude", { planMode: true });
      expect(cmd).toBe(legacyWrapper("claude", ["--permission-mode", "plan"]));
    });

    it("does not append a plan-mode flag for harnesses that do not support it", () => {
      expect(commandForHarness("codex", { planMode: true })).toBe(legacyWrapper("codex"));
    });
  });

  describe("opencode executable-path override", () => {
    const prev = process.env.TERMINALX_OPENCODE_BIN;
    afterEach(() => {
      if (prev === undefined) delete process.env.TERMINALX_OPENCODE_BIN;
      else process.env.TERMINALX_OPENCODE_BIN = prev;
    });

    it("honors TERMINALX_OPENCODE_BIN when set", () => {
      process.env.TERMINALX_OPENCODE_BIN = "/opt/oc/opencode";
      expect(commandForHarness("opencode")).toBe(legacyWrapper("/opt/oc/opencode"));
    });

    it("falls back to the bundled bin when the override is blank", () => {
      process.env.TERMINALX_OPENCODE_BIN = "   ";
      expect(commandForHarness("opencode")).toBe(legacyWrapper("opencode"));
    });

    it.each([
      "/opt/oc/opencode --model attacker/model",
      "/opt/oc/opencode;touch-pwned",
      "$(touch-pwned)",
      "--help",
      "/opt/oc/opencode\n",
    ])("falls back to the bundled bin for an unsafe override: %s", (override) => {
      process.env.TERMINALX_OPENCODE_BIN = override;
      const cmd = commandForHarness("opencode");
      expect(cmd).toBe(legacyWrapper("opencode"));
      expect(cmd).not.toContain(override);
    });
  });
});

/**
 * Back-compat: the legacy commandForKind / isValidKind names still resolve
 * (via the ai-sessions shim) and behave like the new registry functions.
 */
describe("ai-sessions back-compat shim", () => {
  it("re-exports commandForKind/isValidKind with registry behavior", async () => {
    const { commandForKind, isValidKind } = await import("@/lib/ai-sessions");
    expect(commandForKind("bash")).toBeNull();
    expect(commandForKind("claude")).toBe(legacyWrapper("claude"));
    expect(commandForKind("codex")).toBe(legacyWrapper("codex"));
    expect(isValidKind("bash")).toBe(true);
    expect(isValidKind("claude")).toBe(true);
    expect(isValidKind("codex")).toBe(true);
    // newly registered ids are now valid kinds too
    expect(isValidKind("cursor")).toBe(true);
    expect(isValidKind("opencode")).toBe(true);
    expect(isValidKind("nope")).toBe(false);
  });
});
