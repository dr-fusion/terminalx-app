// Effective Models settings for a launched session (issue #11).
//
// SERVER-ONLY (reads the user.json + repo settings.toml stores). Resolves the
// Models settings that apply to a NEW session created under `repoRoot`, in the
// same registry-default < user < repo precedence the settings UI uses, and
// flattens them into the small field set persisted on SessionMeta + threaded
// into the harness command. Never throws — degrades to user-only / defaults so
// session creation is never blocked by a malformed repo TOML (spec §5.2).

import { readRepoSettings, readUserSettings } from "./store";
import { resolveModelSettings } from "./resolve";

/** The Models fields persisted on SessionMeta + threaded into the command. */
export interface SessionModelSettings {
  /** Provider-qualified default model id, e.g. "claude:opus-4-8-1m". */
  modelId: string;
  /** Resolved reasoning/effort level. */
  effort: string;
  /** Resolved Codex personality preset. */
  personality: string;
  /** Start in plan mode. */
  planMode: boolean;
  /** Start in fast mode. */
  fastMode: boolean;
  /**
   * True only when the default model was EXPLICITLY chosen at the user or repo
   * scope (not the bare registry default). The command builder threads
   * `--model` only when this is true so a vanilla session (nothing configured)
   * still launches the legacy command and lets the CLI pick its own default —
   * "no model → unchanged command" (issue #11).
   */
  modelExplicit: boolean;
}

/**
 * Resolve the effective Models settings for a session created under `repoRoot`.
 * `repoRoot` null/undefined (no repo context) resolves user-scope + defaults
 * only. Any read/parse error degrades to the lower scope rather than throwing.
 */
export function resolveSessionModelSettings(
  repoRoot: string | null | undefined
): SessionModelSettings {
  const user = safe(() => readUserSettings()?.models, undefined);
  const repo = repoRoot
    ? safe(() => readRepoSettings(repoRoot).settings.models, undefined)
    : undefined;

  const resolved = resolveModelSettings(user, repo);
  return {
    modelId: resolved.defaultModel.modelId,
    effort: resolved.defaultModel.effort,
    personality: resolved.codexPersonality,
    planMode: resolved.defaultToPlanMode,
    fastMode: resolved.defaultToFastMode,
    modelExplicit: resolved.source.defaultModel !== "default",
  };
}

function safe<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}
