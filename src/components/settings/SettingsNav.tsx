"use client";

// Settings shell left-nav (issue #11, §4.1 + fidelity pass). General · Account ·
// Models · Harnesses · Providers · Environment · Git · Appearance, then a "More"
// group: Experimental, Advanced (Conductor parity). Selecting an entry shows that
// section's page in SettingsShell.

export type SettingsNavKey =
  | "general"
  | "account"
  | "models"
  | "harnesses"
  | "providers"
  | "environment"
  | "git"
  | "appearance"
  | "experimental"
  | "advanced";

const PRIMARY: Array<{ key: SettingsNavKey; label: string }> = [
  { key: "general", label: "General" },
  { key: "account", label: "Account" },
  { key: "models", label: "Models" },
  { key: "harnesses", label: "Harnesses" },
  { key: "providers", label: "Providers" },
  { key: "environment", label: "Environment" },
  { key: "git", label: "Git" },
  { key: "appearance", label: "Appearance" },
];

const MORE: Array<{ key: SettingsNavKey; label: string }> = [
  { key: "experimental", label: "Experimental" },
  { key: "advanced", label: "Advanced" },
];

export function SettingsNav({
  active,
  onSelect,
}: {
  active: SettingsNavKey;
  onSelect: (key: SettingsNavKey) => void;
}) {
  const item = (entry: { key: SettingsNavKey; label: string }) => (
    <button
      key={entry.key}
      data-testid={`settings-nav-${entry.key}`}
      data-active={active === entry.key ? "true" : "false"}
      onClick={() => onSelect(entry.key)}
      className={`w-full text-left px-2.5 py-1.5 rounded text-[11px] transition-colors ${
        active === entry.key
          ? "bg-[#1a1d24] text-[#e6f0e4] font-medium"
          : "text-[#899384] hover:text-[#e6f0e4] hover:bg-[#1a1d24]/50"
      }`}
    >
      {entry.label}
    </button>
  );

  return (
    <nav data-testid="settings-nav" className="flex flex-col gap-0.5">
      {PRIMARY.map(item)}
      <div className="mt-3 mb-1 px-2.5 text-[9px] uppercase tracking-wider text-[#3a3f3a]">
        More
      </div>
      {MORE.map(item)}
    </nav>
  );
}
