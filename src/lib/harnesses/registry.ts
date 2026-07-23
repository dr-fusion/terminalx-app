// Built-in harness table (issue #4).
//
// This IS the new CLI_BINS / commandForKind / isValidKind source of truth. The
// dashboard toggle, the session API validator, the settings UI, and useSessions
// all read from here. Adding a harness = adding a row here (and, if it hosts a
// nested provider registry, the OpenCode files) — nothing else.
//
// This module is client-safe (no Node built-ins) so DashboardView / useSessions
// can import it directly.

import type { HarnessDescriptor } from "./types";

export const HARNESSES: HarnessDescriptor[] = [
  {
    id: "bash",
    label: "bash",
    color: "#00cc6e",
    auth: "none",
    command: { bin: null },
  },
  {
    id: "claude",
    // Conductor names Anthropic's harness "Claude Code"; the persisted id stays
    // "claude" for back-compat with existing SessionMeta records + Telegram topics.
    label: "Claude Code",
    color: "#d58fff",
    auth: "cli", // CLI (claude /login) or API key (ANTHROPIC_API_KEY)
    docsUrl: "https://docs.claude.com/claude-code",
    command: {
      bin: "claude",
      // Issue #11: `claude --model <id>` selects the model; plan mode maps to the
      // permission-mode flag. Data-driven so the route never special-cases claude.
      modelFlag: "--model",
      planModeFlag: "--permission-mode plan",
    },
  },
  {
    id: "codex",
    label: "Codex",
    color: "#5ccfe6",
    auth: "cli",
    // Terminal X does not request Codex YOLO for LocalTmux. The trusted local
    // operator remains responsible for user/project Codex configuration.
    // Model selection still uses `-m <id>` when explicitly configured.
    command: { bin: "codex", modelFlag: "-m" },
  },
  {
    id: "cursor",
    label: "Cursor",
    color: "#7dd3fc",
    auth: "cli",
    command: { bin: "cursor-agent" },
  },
  {
    id: "opencode",
    label: "OpenCode",
    badge: "NEW",
    color: "#ffa657",
    auth: "none", // auth lives inside OpenCode's own per-provider config
    hostsProviders: true,
    docsUrl: "https://opencode.ai/docs",
    // Issue #11: OpenCode selects its model with `--model <provider/model>`.
    command: { bin: "opencode", modelFlag: "--model" },
  },
];

const BY_ID = new Map(HARNESSES.map((h) => [h.id, h]));

/** Shared id list consumed by both server and client (see useSessions). */
export const HARNESS_IDS: string[] = HARNESSES.map((h) => h.id);

export function listHarnesses(): HarnessDescriptor[] {
  return HARNESSES;
}

export function getHarness(id: string): HarnessDescriptor | undefined {
  return BY_ID.get(id);
}

/** Replaces the old isValidKind(). */
export function isValidHarnessId(id: unknown): id is string {
  return typeof id === "string" && BY_ID.has(id);
}
