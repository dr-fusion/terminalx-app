"use client";

// Issue #4 (§6.1): User | Repo scope toggle for the Harnesses section. Repo
// scope surfaces an "Edit settings.toml" affordance bound to
// .terminalx/settings.toml (Conductor analog: the repo "Edit settings.toml"
// button → .conductor/settings.toml).

export type HarnessScope = "user" | "repo";

export function ScopeTabs({
  scope,
  onScope,
}: {
  scope: HarnessScope;
  onScope: (s: HarnessScope) => void;
}) {
  return (
    <div className="flex items-center justify-between mb-3">
      <div
        data-testid="harness-scope-tabs"
        className="inline-flex rounded bg-[#07080c] border border-[#1a1d24] p-0.5"
      >
        {(["user", "repo"] as const).map((s) => (
          <button
            key={s}
            data-testid={`harness-scope-${s}`}
            onClick={() => onScope(s)}
            className={`px-3 py-1 rounded text-[11px] capitalize transition-colors ${
              scope === s
                ? "bg-[#1a1d24] text-[#e6f0e4] font-medium"
                : "text-[#899384] hover:text-[#e6f0e4]"
            }`}
          >
            {s}
          </button>
        ))}
      </div>
      {scope === "repo" && (
        <span
          data-testid="harness-edit-settings-toml"
          className="inline-flex items-center gap-1 text-[10px] text-[#899384]"
          title=".terminalx/settings.toml"
        >
          Edit{" "}
          <code className="text-[#00cc6e] bg-transparent border-0 px-0">
            .terminalx/settings.toml
          </code>
        </span>
      )}
    </div>
  );
}
