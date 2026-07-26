"use client";

// Models settings page (issue #11, §4.2). Renders Default model + Review model
// (each model + effort, independently configurable), Codex personality, and the
// plan/fast/Chrome toggles. Seeds from GET /api/settings (resolved), accumulates
// edits in `dirty`, persists via PUT /api/settings. Pure client component — it
// imports ONLY types + the client-safe catalog/personality tables (no Node
// built-ins), and talks to the server exclusively over fetch.
//
// All controls carry data-testids for e2e robustness.

import { useCallback, useEffect, useState } from "react";
import { ExternalLink, Save } from "lucide-react";
import {
  CODEX_PERSONALITIES,
  type CodexPersonality,
  type EffortLevel,
  type ModelOption,
  type ModelSettings,
  type ResolvedModelSettings,
  type SettingsScope,
} from "@/lib/settings/types";

interface OptionsPayload {
  models: ModelOption[];
  efforts: EffortLevel[];
  codexPersonalities: Array<{ id: CodexPersonality; label: string }>;
}

const CHROME_EXTENSION_URL = "https://chromewebstore.google.com/";
const CHROME_DOCS_URL = "https://docs.claude.com/claude-code";

function effortLabel(e: EffortLevel): string {
  return `Effort ${e}`;
}

function SourceHint({ source }: { source: "user" | "repo" | "default" }) {
  if (source === "repo") return null; // value set at the current (highest) scope
  const text = source === "user" ? "inherited from User" : "default";
  return (
    <span data-testid="models-source-hint" className="text-[10px] text-[#899384] ml-2">
      {text}
    </span>
  );
}

function selectClass(disabled?: boolean): string {
  return `rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88] ${
    disabled ? "opacity-50 cursor-not-allowed" : ""
  }`;
}

function Section({
  title,
  desc,
  children,
}: {
  title: string;
  desc?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-[#0f1117] border border-[#1a1d24] rounded p-4 mb-3">
      <div className="flex items-baseline gap-3 mb-3">
        <h2 className="text-[13px] font-medium text-[#e6f0e4]">{title}</h2>
        {desc && <span className="text-[10px] text-[#899384]">{desc}</span>}
      </div>
      {children}
    </div>
  );
}

function ModelRow({
  testid,
  options,
  efforts,
  modelId,
  effort,
  source,
  readOnly,
  onModel,
  onEffort,
}: {
  testid: string;
  options: ModelOption[];
  efforts: EffortLevel[];
  modelId: string;
  effort: EffortLevel;
  source: "user" | "repo" | "default";
  readOnly: boolean;
  onModel: (id: string) => void;
  onEffort: (e: EffortLevel) => void;
}) {
  // Retain a stored-but-unavailable modelId as a disabled option (spec Edge Case)
  const known = options.some((o) => o.id === modelId);
  const harnesses = Array.from(new Set(options.map((o) => o.harness)));

  return (
    <div className="flex flex-wrap items-center gap-2">
      <select
        data-testid={`${testid}-model`}
        value={modelId}
        disabled={readOnly}
        onChange={(e) => onModel(e.target.value)}
        className={selectClass(readOnly)}
      >
        {!known && modelId && (
          <option value={modelId} disabled>
            {modelId} (unavailable)
          </option>
        )}
        {harnesses.map((h) => (
          <optgroup key={h} label={h}>
            {options
              .filter((o) => o.harness === h)
              .map((o) => (
                <option key={o.id} value={o.id} disabled={!o.available}>
                  {o.label}
                  {o.available ? "" : " (unavailable)"}
                </option>
              ))}
          </optgroup>
        ))}
      </select>
      <select
        data-testid={`${testid}-effort`}
        value={effort}
        disabled={readOnly}
        onChange={(e) => onEffort(e.target.value as EffortLevel)}
        className={selectClass(readOnly)}
      >
        {efforts.map((e) => (
          <option key={e} value={e}>
            {effortLabel(e)}
          </option>
        ))}
      </select>
      <SourceHint source={source} />
    </div>
  );
}

function ToggleRow({
  testid,
  label,
  sublabel,
  checked,
  source,
  readOnly,
  onChange,
  children,
}: {
  testid: string;
  label: string;
  sublabel?: string;
  checked: boolean;
  source: "user" | "repo" | "default";
  readOnly: boolean;
  onChange: (v: boolean) => void;
  children?: React.ReactNode;
}) {
  return (
    <div className="bg-[#0f1117] border border-[#1a1d24] rounded p-4 mb-3">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center">
            <span className="text-[13px] font-medium text-[#e6f0e4]">{label}</span>
            <SourceHint source={source} />
          </div>
          {sublabel && <p className="text-[10px] text-[#899384] mt-0.5">{sublabel}</p>}
          {children}
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={checked}
          aria-label={label}
          data-testid={testid}
          disabled={readOnly}
          onClick={() => onChange(!checked)}
          className={`relative inline-flex h-[22px] w-[38px] shrink-0 cursor-pointer items-center rounded-full border transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
            checked ? "bg-[#00cc6e] border-[#00cc6e]" : "bg-[#1a1d24] border-[#252933]"
          }`}
        >
          <span
            aria-hidden="true"
            className={`pointer-events-none inline-block h-[16px] w-[16px] transform rounded-full bg-white shadow transition-transform ${
              checked ? "translate-x-[18px]" : "translate-x-[3px]"
            }`}
          />
        </button>
      </div>
    </div>
  );
}

export function ModelsSettingsPage({
  scope,
  session,
  readOnly = false,
}: {
  scope: SettingsScope;
  session?: string;
  /** Repo scope without admin → controls render read-only (spec Edge Cases). */
  readOnly?: boolean;
}) {
  const [resolved, setResolved] = useState<ResolvedModelSettings | null>(null);
  const [options, setOptions] = useState<OptionsPayload | null>(null);
  const [dirty, setDirty] = useState<Partial<ModelSettings>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [parseError, setParseError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const q =
      scope === "repo" ? `scope=repo&session=${encodeURIComponent(session ?? "")}` : "scope=user";
    fetch(`/api/settings?${q}`)
      .then((r) => r.json())
      .then((d) => {
        if (cancelled) return;
        if (d?.resolved) setResolved(d.resolved);
        setParseError(Boolean(d?.parseError));
      })
      .catch(() => {});
    fetch("/api/settings/models/options")
      .then((r) => r.json())
      .then((d) => {
        if (!cancelled) setOptions(d);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [scope, session]);

  const save = useCallback(async () => {
    setStatus("saving…");
    try {
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scope, session, models: dirty }),
      });
      const d = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(d?.error ?? "save failed");
        return;
      }
      setResolved(d.resolved);
      setDirty({});
      setStatus("saved");
      setTimeout(() => setStatus(null), 2000);
    } catch {
      setStatus("save failed");
    }
  }, [scope, session, dirty]);

  if (!resolved || !options) {
    return (
      <div data-testid="models-page-loading" className="text-[11px] text-[#899384] p-4">
        loading models…
      </div>
    );
  }

  const dirtyKeys = Object.keys(dirty).length;

  // Merge a ModelChoice patch into dirty (independent modelId/effort edits).
  const patchChoice = (
    field: "defaultModel" | "reviewModel",
    part: Partial<{ modelId: string; effort: EffortLevel }>
  ) => {
    setDirty((d) => {
      const prevDirty = (d[field] ?? {}) as { modelId?: string; effort?: EffortLevel };
      const base = resolved[field];
      return {
        ...d,
        [field]: {
          modelId: part.modelId ?? prevDirty.modelId ?? base.modelId,
          effort: part.effort ?? prevDirty.effort ?? base.effort,
        },
      };
    });
  };

  // Effective (resolved + pending-dirty) values for rendering. A pending edit
  // may carry null sub-fields (cleared); fall back to the resolved value so the
  // selects always have a concrete string/effort.
  const mergeChoice = (
    base: { modelId: string; effort: EffortLevel },
    patch?: { modelId?: string | null; effort?: EffortLevel | null }
  ): { modelId: string; effort: EffortLevel } => ({
    modelId: patch?.modelId ?? base.modelId,
    effort: patch?.effort ?? base.effort,
  });
  const eff = {
    defaultModel: mergeChoice(resolved.defaultModel, dirty.defaultModel),
    reviewModel: mergeChoice(resolved.reviewModel, dirty.reviewModel),
    codexPersonality: (dirty.codexPersonality ?? resolved.codexPersonality) as CodexPersonality,
    defaultToPlanMode: dirty.defaultToPlanMode ?? resolved.defaultToPlanMode,
    defaultToFastMode: dirty.defaultToFastMode ?? resolved.defaultToFastMode,
    useClaudeCodeWithChrome: dirty.useClaudeCodeWithChrome ?? resolved.useClaudeCodeWithChrome,
  };

  return (
    <div data-testid="models-settings-page">
      <div className="mb-4">
        <h1 className="text-[20px] font-bold tracking-tight text-[#e6f0e4]">Models</h1>
      </div>

      {parseError && (
        <div
          data-testid="models-parse-warning"
          className="mb-3 rounded border border-[#ffb454]/40 bg-[#ffb454]/10 px-3 py-2 text-[11px] text-[#ffb454]"
        >
          .terminalx/settings.toml could not be fully parsed; showing resolved defaults. Use “Edit
          settings.toml” to fix it.
        </div>
      )}

      {readOnly && (
        <div
          data-testid="models-admin-note"
          className="mb-3 rounded border border-[#5ccfe6]/40 bg-[#5ccfe6]/10 px-3 py-2 text-[11px] text-[#5ccfe6]"
        >
          Repo settings are admin-only; controls are read-only.
        </div>
      )}

      <Section title="Default model" desc="Model for new chats">
        <ModelRow
          testid="models-default"
          options={options.models}
          efforts={options.efforts}
          modelId={eff.defaultModel.modelId}
          effort={eff.defaultModel.effort}
          source={resolved.source.defaultModel}
          readOnly={readOnly}
          onModel={(modelId) => patchChoice("defaultModel", { modelId })}
          onEffort={(effort) => patchChoice("defaultModel", { effort })}
        />
      </Section>

      <Section title="Review model" desc="Model for code reviews">
        <ModelRow
          testid="models-review"
          options={options.models}
          efforts={options.efforts}
          modelId={eff.reviewModel.modelId}
          effort={eff.reviewModel.effort}
          source={resolved.source.reviewModel}
          readOnly={readOnly}
          onModel={(modelId) => patchChoice("reviewModel", { modelId })}
          onEffort={(effort) => patchChoice("reviewModel", { effort })}
        />
      </Section>

      <Section
        title="Codex personality for new chats"
        desc="Style to use when a new chat starts with a Codex model"
      >
        <div className="flex items-center gap-2">
          <select
            data-testid="models-codex-personality"
            value={eff.codexPersonality}
            disabled={readOnly}
            onChange={(e) =>
              setDirty((d) => ({
                ...d,
                codexPersonality: e.target.value as CodexPersonality,
              }))
            }
            className={selectClass(readOnly)}
          >
            {(options.codexPersonalities ?? CODEX_PERSONALITIES).map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
          <SourceHint source={resolved.source.codexPersonality} />
        </div>
      </Section>

      <ToggleRow
        testid="models-plan-mode"
        label="Default to plan mode"
        sublabel="Start new chats in plan mode"
        checked={eff.defaultToPlanMode}
        source={resolved.source.defaultToPlanMode}
        readOnly={readOnly}
        onChange={(v) => setDirty((d) => ({ ...d, defaultToPlanMode: v }))}
      />

      <ToggleRow
        testid="models-fast-mode"
        label="Default to fast mode"
        sublabel="Start new chats in fast mode"
        checked={eff.defaultToFastMode}
        source={resolved.source.defaultToFastMode}
        readOnly={readOnly}
        onChange={(v) => setDirty((d) => ({ ...d, defaultToFastMode: v }))}
      />

      <ToggleRow
        testid="models-chrome"
        label="Use Claude Code with Chrome"
        checked={eff.useClaudeCodeWithChrome}
        source={resolved.source.useClaudeCodeWithChrome}
        readOnly={readOnly}
        onChange={(v) => setDirty((d) => ({ ...d, useClaudeCodeWithChrome: v }))}
      >
        <div className="flex items-center gap-3 mt-2">
          <a
            data-testid="models-chrome-extension-link"
            href={CHROME_EXTENSION_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-[10px] text-[#00ff88] hover:underline"
          >
            Chrome extension <ExternalLink size={9} />
          </a>
          <a
            data-testid="models-chrome-docs-link"
            href={CHROME_DOCS_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-[10px] text-[#5ccfe6] hover:underline"
          >
            Docs <ExternalLink size={9} />
          </a>
        </div>
      </ToggleRow>

      {!readOnly && (
        <div className="flex items-center gap-3 mt-2">
          <button
            data-testid="models-save"
            onClick={save}
            disabled={dirtyKeys === 0}
            className="inline-flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-3 py-1.5 text-[11px] text-[#00ff88] hover:bg-[#00ff88]/10 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <Save size={12} /> Save
          </button>
          {status && (
            <span data-testid="models-save-status" className="text-[11px] text-[#899384]">
              {status}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
