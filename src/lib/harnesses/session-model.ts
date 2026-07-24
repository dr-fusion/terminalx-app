// Session model threading (issue #11).
//
// Maps the resolved Models settings (a provider-qualified `<harness>:<slug>`
// modelId + planMode) into the CommandOptions the harness command builder
// consumes — but ONLY when the model's harness matches the session kind, so a
// Codex default never leaks its slug into a `claude --model` invocation. Pure /
// client-safe (registry + string ops only, no Node built-ins) so both the
// sessions API (server) and any future client preview share one source of truth.

import type { CommandOptions } from "./types";

const SAFE_HARNESS_ID = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;
const SAFE_HARNESS_ARGUMENT = /^[A-Za-z0-9][A-Za-z0-9.\/:@_+-]*$/;

/**
 * Return whether an untrusted value is safe to append as one unquoted harness
 * argument. Model slugs may use common provider syntax (`/`, `:`, `.`, `@`,
 * `_`, `+`, `-`), but must start with an alphanumeric character and may never
 * contain whitespace or shell syntax. Invalid values are omitted, not thrown,
 * because session creation may already have produced worktree side effects.
 */
export function isSafeHarnessArgumentToken(value: unknown): value is string {
  return typeof value === "string" && !/\s/.test(value) && SAFE_HARNESS_ARGUMENT.test(value);
}

export interface SplitModelId {
  /** Harness id prefix, e.g. "claude". */
  harness: string;
  /** Harness-native slug, e.g. "opus-4-8-1m" (may contain "/" for opencode). */
  slug: string;
}

/**
 * Parse a provider-qualified model id (`<harness>:<slug>`) into its parts.
 * Only the FIRST ":" is the separator so opencode slugs like
 * "anthropic/claude-sonnet" survive intact. Returns null for an unqualified or
 * empty id (graceful degradation — spec §5.2).
 */
export function splitModelId(modelId: string | null | undefined): SplitModelId | null {
  if (typeof modelId !== "string") return null;
  const idx = modelId.indexOf(":");
  if (idx <= 0 || idx === modelId.length - 1) return null;

  const harness = modelId.slice(0, idx);
  const slug = modelId.slice(idx + 1);
  if (/\s/.test(harness) || !SAFE_HARNESS_ID.test(harness) || !isSafeHarnessArgumentToken(slug)) {
    return null;
  }

  return { harness, slug };
}

/** The resolved Models settings relevant to launching a session. */
export interface SessionModelInput {
  /** Provider-qualified default model id, or undefined when unset. */
  modelId: string | null | undefined;
  /** Whether the session should start in plan mode. */
  planMode: boolean;
}

/**
 * Build the model-related CommandOptions for a session of the given kind. The
 * model slug is threaded ONLY when its harness prefix equals the session kind;
 * otherwise the model is dropped (the chosen default belongs to a different
 * harness) so we never emit a mismatched `--model`. planMode passes through
 * verbatim — the command builder gates it on the harness's planModeFlag.
 */
export function modelOptionsForKind(
  kind: string,
  input: SessionModelInput
): Pick<CommandOptions, "model" | "planMode"> {
  const split = splitModelId(input.modelId);
  const model = split && split.harness === kind ? split.slug : undefined;
  return { model, planMode: input.planMode };
}
