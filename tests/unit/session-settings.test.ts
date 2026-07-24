import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// Feature #11: the effective Models settings persisted onto a new SessionMeta +
// threaded into the harness command. The user store captures DATA_DIR from cwd
// at module load, so we chdir into a tmp dir and load fresh modules.

async function freshModules() {
  vi.resetModules();
  return import("@/lib/settings/session-settings");
}

function writeUserSettings(cwd: string, models: unknown) {
  const dir = path.join(cwd, "data", "settings");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "user.json"), JSON.stringify({ version: 1, models }, null, 2));
}

describe("resolveSessionModelSettings (feature #11)", () => {
  let cwd: string;
  let prevCwd: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    cwd = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-modelsettings-")));
    process.chdir(cwd);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  it("falls back to the registry default when nothing is configured", async () => {
    const { resolveSessionModelSettings } = await freshModules();
    const s = resolveSessionModelSettings(null);
    // Registry default is the first catalog model at effort "high".
    expect(s.modelId).toBe("claude:opus-4-8-1m");
    expect(s.effort).toBe("high");
    expect(s.planMode).toBe(false);
    expect(s.fastMode).toBe(false);
    expect(s.personality).toBe("pragmatic");
    // Nothing configured → the model is NOT explicit, so the command stays legacy.
    expect(s.modelExplicit).toBe(false);
  });

  it("reflects the user-scope default model + effort + plan/fast/personality", async () => {
    writeUserSettings(cwd, {
      defaultModel: { modelId: "codex:gpt-5-codex", effort: "low" },
      defaultToPlanMode: true,
      defaultToFastMode: true,
      codexPersonality: "thorough",
    });
    const { resolveSessionModelSettings } = await freshModules();
    const s = resolveSessionModelSettings(null);
    expect(s.modelId).toBe("codex:gpt-5-codex");
    expect(s.effort).toBe("low");
    expect(s.planMode).toBe(true);
    expect(s.fastMode).toBe(true);
    expect(s.personality).toBe("thorough");
    // Explicitly chosen at user scope → command threads `--model`.
    expect(s.modelExplicit).toBe(true);
  });

  it("never throws on a missing repo root (degrades to user/default)", async () => {
    const { resolveSessionModelSettings } = await freshModules();
    expect(() => resolveSessionModelSettings("/path/that/does/not/exist")).not.toThrow();
  });
});
