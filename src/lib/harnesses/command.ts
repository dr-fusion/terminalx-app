// Command builder (issue #4) — replaces commandForKind() in ai-sessions.ts.
//
// Retains the single-quoted `bash -lc` lifecycle wrapper from commandForKind
// (exit-code capture + `exec bash -l` fallback) so tmux sessions stay alive on
// CLI exit while the harness arguments remain policy-controlled.

import { getHarness } from "./registry";
import { isSafeHarnessArgumentToken } from "./session-model";
import type { CommandOptions } from "./types";

const SAFE_EXECUTABLE_TOKEN = /^[A-Za-z0-9./][A-Za-z0-9./_+-]*$/;

/**
 * Executable overrides are shell tokens, not command lines. Accept bare names
 * and Unix paths, while rejecting whitespace, leading options, and shell
 * metacharacters. The alphanumeric check also rejects path-only punctuation.
 */
export function isSafeExecutableToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    !/\s/.test(value) &&
    SAFE_EXECUTABLE_TOKEN.test(value) &&
    /[A-Za-z0-9]/.test(value) &&
    !value.startsWith("-")
  );
}

/**
 * Resolve the binary for a harness, honoring the per-harness executable-path
 * override (OpenCode "executable path" field). Env var wins; empty => bundled/PATH.
 * Mirrors the spec's precedence (env > repo TOML > user TOML > built-in); only
 * the env layer is wired here since TOML is read in the settings/API layer.
 */
function resolveBin(id: string, declared: string | null): string | null {
  if (declared === null) return null;
  if (id === "opencode") {
    const override = process.env.TERMINALX_OPENCODE_BIN;
    if (override && isSafeExecutableToken(override)) return override;
  }
  return isSafeExecutableToken(declared) ? declared : null;
}

const HARNESS_PATH_PREFIX =
  'export PATH="$HOME/.local/bin:$HOME/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"; ';

/**
 * Build the tmux session command for a harness id.
 * Returns null for harnesses with no binary (bash), matching the existing
 * commandForKind contract used by createSession().
 */
export function commandForHarness(id: string, opts: CommandOptions = {}): string | null {
  const h = getHarness(id);
  if (!h || h.command.bin === null) return null;

  const bin = resolveBin(id, h.command.bin);
  if (!bin) return null;

  const args = [...(h.command.baseArgs ?? [])];

  // Issue #11: thread the chosen model + plan mode in, data-driven via the
  // harness descriptor. A model only lands when the harness declares a modelFlag
  // (bash/cursor have none → command stays byte-identical to before).
  if (h.command.planModeFlag && opts.planMode) {
    args.push(h.command.planModeFlag);
  }
  if (h.command.modelFlag && isSafeHarnessArgumentToken(opts.model)) {
    args.push(h.command.modelFlag, opts.model);
  }

  const invocation = HARNESS_PATH_PREFIX + [bin, ...args].join(" ");
  // Identical fallback-to-bash wrapper as the old commandForKind (keeps the
  // tmux session alive so the user can inspect the error and retry).
  return `bash -lc '${invocation}; ec=$?; echo; echo "[${bin} exited with code $ec — dropping to bash]"; exec bash -l'`;
}
