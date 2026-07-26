"use client";

// Issue #4 (§5.1): the OpenCode harness tab body. Mirrors Conductor's OpenCode
// screen: header + Docs↗, Providers ("N configured" → picker), Models
// ("N selected"), and a collapsible Advanced block with an install/version
// pill, Open-in-Finder, Docs, Refresh, and the executable-path override.

import { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, ExternalLink, FolderOpen, Plus, RefreshCw } from "lucide-react";
import { ProvidersPickerModal } from "@/components/settings/ProvidersPickerModal";
import type { HarnessScope } from "@/components/settings/ScopeTabs";
import type { HarnessApi } from "@/components/settings/HarnessTabs";

export function OpenCodePanel({
  harness,
  scope,
  repoSession,
  onRefresh,
}: {
  harness: HarnessApi;
  /** Active settings scope (User | Repo) — drives where providers persist. */
  scope: HarnessScope;
  /** When repo-scoped, the session whose repo backs the config write. */
  repoSession?: string | null;
  onRefresh: () => void;
}) {
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [showProviders, setShowProviders] = useState(false);
  const [execPath, setExecPath] = useState("");
  // Configured providers / selected models for the current scope (drives the
  // "N configured" / "N selected" labels, AC-11).
  const [configuredCount, setConfiguredCount] = useState(0);
  const [selectedModelCount, setSelectedModelCount] = useState(0);

  const status = harness.status;
  const installed = status?.installed;
  const version = status?.version;

  // Load the scoped configured providers + selected models from the API.
  const loadConfigured = useCallback(async () => {
    const params = new URLSearchParams({ configured: "1", scope });
    if (scope === "repo" && repoSession) params.set("session", repoSession);
    try {
      const res = await fetch(`/api/harnesses/opencode/providers?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      setConfiguredCount(Number(data?.configuredCount ?? 0));
      setSelectedModelCount(Number(data?.selectedModelCount ?? 0));
    } catch {
      /* best-effort: leave counts as-is */
    }
  }, [scope, repoSession]);

  useEffect(() => {
    // Fetch-then-setState (the state update happens after the awaited fetch, in
    // a callback — the recommended "subscribe to an external system" shape, same
    // as HarnessTabs' load effect). loadConfigured is reused by onConfigured.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadConfigured();
  }, [loadConfigured]);

  const openInFinder = async () => {
    await fetch("/api/harnesses", { method: "GET" }).catch(() => {});
    // Best-effort: Open-in-Finder is wired to a server reveal in integration;
    // here we just no-op gracefully so the UI stays robust.
  };

  return (
    <div data-testid="opencode-panel">
      <div className="flex items-center justify-between mb-3">
        <div className="min-w-0">
          <div className="text-[13px] font-medium text-[#e6f0e4]">OpenCode</div>
          <div className="text-[10px] text-[#899384]">The open source AI coding agent</div>
        </div>
        {harness.docsUrl && (
          <a
            data-testid="opencode-docs"
            href={harness.docsUrl}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-[11px] text-[#ffa657] hover:underline shrink-0"
          >
            Docs <ExternalLink size={10} />
          </a>
        )}
      </div>

      {/* Providers row */}
      <div
        data-testid="opencode-providers-row"
        className="flex items-center justify-between rounded border border-[#1a1d24] bg-[#07080c] px-3 py-2.5 mb-2"
      >
        <div className="min-w-0">
          <div className="text-[11px] text-[#e6f0e4]">Providers</div>
          <div data-testid="opencode-providers-count" className="text-[10px] text-[#899384]">
            {configuredCount} configured
          </div>
        </div>
        <button
          data-testid="opencode-add-provider"
          onClick={() => setShowProviders(true)}
          className="inline-flex items-center gap-1.5 rounded border border-[#ffa657]/60 bg-[#ffa657]/10 px-2.5 py-1 text-[11px] text-[#ffa657] hover:bg-[#ffa657]/20 transition-colors"
        >
          <Plus size={11} /> {configuredCount > 0 ? "Add provider" : "Add your first provider"}
        </button>
      </div>

      {/* Models row */}
      <div
        data-testid="opencode-models-row"
        className="flex items-center justify-between rounded border border-[#1a1d24] bg-[#07080c] px-3 py-2.5 mb-2"
      >
        <div className="min-w-0">
          <div className="text-[11px] text-[#e6f0e4]">Models</div>
          <div data-testid="opencode-models-count" className="text-[10px] text-[#899384]">
            {selectedModelCount} selected
          </div>
        </div>
        <button
          data-testid="opencode-add-model"
          className="inline-flex items-center gap-1.5 rounded border border-[#252933] bg-[#14161e] px-2.5 py-1 text-[11px] text-[#a8b3a6] hover:border-[#363b47] transition-colors"
        >
          <Plus size={11} /> Add your first OpenCode model
        </button>
      </div>

      {/* Advanced (collapsible) */}
      <div className="rounded border border-[#1a1d24] bg-[#07080c]">
        <button
          data-testid="opencode-advanced-toggle"
          onClick={() => setAdvancedOpen((v) => !v)}
          className="w-full flex items-center gap-1.5 px-3 py-2 text-[11px] text-[#a8b3a6] hover:text-[#e6f0e4] transition-colors"
        >
          {advancedOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />} Advanced
        </button>
        {advancedOpen && (
          <div data-testid="opencode-advanced" className="px-3 pb-3 pt-1 space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                data-testid="opencode-installed-pill"
                className={`px-1.5 py-0.5 text-[9px] rounded uppercase tracking-wider font-medium ${
                  installed ? "bg-[#00ff88]/20 text-[#00ff88]" : "bg-[#ff5c5c]/20 text-[#ff5c5c]"
                }`}
              >
                {installed ? `Installed ${version ?? ""}`.trim() : "Not installed"}
              </span>
              <button
                data-testid="opencode-open-finder"
                onClick={openInFinder}
                className="inline-flex items-center gap-1 text-[11px] text-[#ffa657] hover:underline"
              >
                <FolderOpen size={11} /> Open in Finder <ExternalLink size={10} />
              </button>
              {harness.docsUrl && (
                <a
                  href={harness.docsUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-[11px] text-[#ffa657] hover:underline"
                >
                  Docs <ExternalLink size={10} />
                </a>
              )}
              <button
                data-testid="opencode-refresh"
                onClick={onRefresh}
                className="inline-flex items-center gap-1 text-[11px] text-[#899384] hover:text-[#00ff88] transition-colors"
              >
                <RefreshCw size={11} /> Refresh
              </button>
            </div>

            <div>
              <label
                htmlFor="opencode-exec-path"
                className="block text-[10px] uppercase tracking-wider text-[#899384] mb-1.5"
              >
                OpenCode executable path
              </label>
              <input
                id="opencode-exec-path"
                data-testid="opencode-exec-path"
                value={execPath}
                onChange={(e) => setExecPath(e.target.value)}
                placeholder="/usr/local/bin/opencode"
                spellCheck={false}
                autoComplete="off"
                className="w-full px-2 py-1.5 rounded bg-[#0f1117] border border-[#252933]
                  text-[#e6f0e4] text-[12px] placeholder:text-[#899384]/50 font-mono
                  focus:outline-none focus:border-[#ffa657] transition-colors"
              />
              <p className="mt-1 text-[10px] text-[#899384] leading-tight">
                Override the bundled OpenCode executable with a custom one. Leave empty to use the
                bundled version (recommended).
              </p>
            </div>
          </div>
        )}
      </div>

      {showProviders && (
        <ProvidersPickerModal
          scope={scope}
          repoSession={repoSession}
          onClose={() => setShowProviders(false)}
          onConfigured={() => {
            // Refresh the scoped counts after a successful add (AC-11).
            void loadConfigured();
          }}
        />
      )}
    </div>
  );
}
