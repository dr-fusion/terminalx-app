"use client";

// Settings shell scope tabs (issue #11, §4.1). User | Repo. The Repo tab is
// disabled with a hint when no repo context is active; on Repo scope an
// "Edit settings.toml" affordance appears (§4.1 / acceptance criteria).

import type { SettingsScope } from "@/lib/settings/types";

export function SettingsScopeTabs({
  scope,
  onScope,
  repoAvailable,
  onEditToml,
}: {
  scope: SettingsScope;
  onScope: (s: SettingsScope) => void;
  /** false when the selected session has no repo context (Repo tab disabled). */
  repoAvailable: boolean;
  onEditToml?: () => void;
}) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div
        data-testid="settings-scope-tabs"
        className="inline-flex rounded bg-[#07080c] border border-[#1a1d24] p-0.5"
      >
        {(["user", "repo"] as const).map((s) => {
          const disabled = s === "repo" && !repoAvailable;
          return (
            <button
              key={s}
              data-testid={`settings-scope-${s}`}
              disabled={disabled}
              title={disabled ? "Open a session in a Git repo to edit repo settings" : undefined}
              onClick={() => !disabled && onScope(s)}
              className={`px-3 py-1 rounded text-[11px] capitalize transition-colors ${
                scope === s
                  ? "bg-[#1a1d24] text-[#e6f0e4] font-medium"
                  : disabled
                    ? "text-[#3a3f3a] cursor-not-allowed"
                    : "text-[#899384] hover:text-[#e6f0e4]"
              }`}
            >
              {s}
            </button>
          );
        })}
      </div>
      {scope === "repo" && repoAvailable && (
        <button
          data-testid="settings-edit-toml"
          onClick={onEditToml}
          className="inline-flex items-center gap-1 text-[10px] text-[#899384] hover:text-[#e6f0e4]"
          title=".terminalx/settings.toml"
        >
          Edit{" "}
          <code className="text-[#00cc6e] bg-transparent border-0 px-0">
            .terminalx/settings.toml
          </code>
        </button>
      )}
    </div>
  );
}
