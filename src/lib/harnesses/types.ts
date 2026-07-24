// Harness/provider registry types (issue #4).
//
// A "harness" is a CLI runtime that drives a tmux session. This replaces the
// old hard-coded `SessionKind` union + `CLI_BINS` table + `commandForKind`
// switch in `src/lib/ai-sessions.ts` with a data-driven descriptor list so
// adding a runtime is a single registry edit (see registry.ts).

/** Authentication strategy mirrored from Conductor's Claude Code tab. */
export type HarnessAuthMethod = "cli" | "api-key" | "none";

/** Options consumed by the command builder. */
export interface CommandOptions {
  /**
   * Issue #11: the harness-native model slug to launch (e.g. "opus-4-8-1m"),
   * already stripped of its provider prefix. Emitted only when the harness
   * declares a `modelFlag`. Empty/undefined leaves the command unchanged.
   */
  model?: string;
  /**
   * Issue #11: start the session in plan mode. Emitted only for harnesses that
   * declare a `planModeFlag` (claude today); a no-op elsewhere.
   */
  planMode?: boolean;
}

/** How the session command is built for a harness. */
export interface HarnessCommandSpec {
  /** Binary resolved from PATH, e.g. "claude". null => plain login shell (bash). */
  bin: string | null;
  /** Extra args appended unconditionally. */
  baseArgs?: string[];
  /**
   * Issue #11: the CLI flag that selects a model, e.g. "--model" (claude/opencode)
   * or "-m" (codex). When set AND CommandOptions.model is non-empty, the builder
   * appends `<modelFlag> <model>`. Absent => this harness ignores a chosen model
   * (e.g. bash, cursor) so the launched command is unchanged. Data-driven so the
   * sessions route never hard-codes a per-CLI model flag.
   */
  modelFlag?: string;
  /**
   * Issue #11: the CLI flag (with any value, space-joined) that starts the
   * session in plan mode, e.g. "--permission-mode plan" for claude. Appended
   * only when CommandOptions.planMode is true. Absent => plan mode is a no-op.
   */
  planModeFlag?: string;
}

export interface HarnessDescriptor {
  /** Stable id, persisted as SessionMeta.kind. e.g. "bash" | "claude" | "codex" | "opencode". */
  id: string;
  /** Tab/button label, e.g. "Claude Code", "Codex", "Cursor", "OpenCode". */
  label: string;
  /** Conductor-style "NEW" badge on the tab. */
  badge?: "NEW";
  /** Theme color used by the dashboard toggle + session-row chip. */
  color: string;
  /** Authentication descriptor surfaced in the settings tab. */
  auth: HarnessAuthMethod;
  /** Command-builder spec. */
  command: HarnessCommandSpec;
  /**
   * Marks the OpenCode-style harness that hosts a nested provider registry
   * + install/version detection + executable-path override (see opencode-providers.ts).
   */
  hostsProviders?: boolean;
  /** Docs link shown in the harness tab header (Conductor "Docs ↗"). */
  docsUrl?: string;
}
