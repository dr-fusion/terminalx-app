"use client";

// Issue #4 (§5.2) + #8 (§5/§6): the functional OpenCode "Providers" picker.
// Mirrors Conductor's modal — a search box, brand-iconed rows, and a "View all
// providers (96)" footer. Selecting a row expands the per-provider config form
// inline (it does NOT navigate away, AC-5); saving POSTs the NON-SECRET stanza
// to /api/harnesses/opencode/providers, which writes it into the scoped
// .terminalx/settings.toml. The full 96-entry catalog is fetched lazily on
// search / "View all"; only the seven featured rows are shown initially.
//
// Selecting a provider does NOT make TerminalX speak that provider's API; it
// records config OpenCode's CLI later reads. TerminalX stores no secret.
//
// Client-safe: imports only React, lucide icons, the browser-safe catalog, and
// the config form (no Node builtins transitively).

import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search, X } from "lucide-react";
import {
  FEATURED_OPENCODE_PROVIDERS,
  TOTAL_OPENCODE_PROVIDERS,
  type ConfiguredOpenCodeProvider,
  type OpenCodeProviderEntry,
} from "@/lib/harnesses/opencode-providers";
import { ProviderConfigForm } from "@/components/settings/ProviderConfigForm";

export function ProvidersPickerModal({
  scope,
  repoSession,
  onClose,
  onConfigured,
}: {
  scope: "user" | "repo";
  /** When repo-scoped, the session whose repo backs the write (server resolves it). */
  repoSession?: string | null;
  onClose: () => void;
  /** Fired after a successful save so the panel can refresh its counts. */
  onConfigured?: (result: { providers: string[]; models: string[] }) => void;
}) {
  const [query, setQuery] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [allProviders, setAllProviders] = useState<OpenCodeProviderEntry[] | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [savingId, setSavingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const q = query.trim().toLowerCase();
  const wantsFull = showAll || q.length > 0;

  // Lazily fetch the full 96-entry catalog the first time the user searches or
  // hits "View all" (spec §3.3 — the tail is fetched, not bundled into the row).
  useEffect(() => {
    if (!wantsFull || allProviders) return;
    let cancelled = false;
    fetch("/api/harnesses/opencode/providers?all=1")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("catalog unavailable"))))
      .then((data) => {
        if (!cancelled && Array.isArray(data.providers)) setAllProviders(data.providers);
      })
      .catch(() => {
        // Fall back to the featured rows if the catalog can't be fetched.
        if (!cancelled) setAllProviders(FEATURED_OPENCODE_PROVIDERS);
      });
    return () => {
      cancelled = true;
    };
  }, [wantsFull, allProviders]);

  const rows = useMemo(() => {
    const source = wantsFull
      ? (allProviders ?? FEATURED_OPENCODE_PROVIDERS)
      : FEATURED_OPENCODE_PROVIDERS;
    if (!q) return source;
    return source.filter((p) => {
      if (p.label.toLowerCase().includes(q)) return true;
      if (p.id.toLowerCase().includes(q)) return true;
      const brands = p.brands ?? [p.label];
      return brands.some((b) => b.toLowerCase().includes(q));
    });
  }, [wantsFull, allProviders, q]);

  const save = useCallback(
    async (draft: ConfiguredOpenCodeProvider) => {
      setSavingId(draft.providerId);
      setError(null);
      try {
        const res = await fetch("/api/harnesses/opencode/providers", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            providerId: draft.providerId,
            endpoint: draft.endpoint,
            models: draft.models,
            scope,
            ...(scope === "repo" && repoSession ? { session: repoSession } : {}),
          }),
        });
        const data = await res.json().catch(() => null);
        if (!res.ok) {
          setError(data?.error ?? "Failed to save provider");
          return;
        }
        onConfigured?.({ providers: data?.providers ?? [], models: data?.models ?? [] });
        onClose();
      } catch {
        setError("Failed to save provider");
      } finally {
        setSavingId(null);
      }
    },
    [scope, repoSession, onConfigured, onClose]
  );

  return (
    <div
      data-testid="opencode-providers-modal"
      onClick={onClose}
      className="fixed inset-0 z-[210] flex items-start justify-center pt-[14vh]"
      style={{ background: "rgba(5, 6, 10, 0.7)", backdropFilter: "blur(6px)" }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[480px] max-w-[92vw] rounded bg-[#14161e] border border-[#363b47] p-4"
        style={{ boxShadow: "0 8px 24px rgba(0, 0, 0, 0.6)" }}
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-[13px] font-medium text-[#e6f0e4]">Providers</span>
          <button
            data-testid="opencode-providers-close"
            onClick={onClose}
            className="p-0.5 text-[#899384] hover:text-[#e6f0e4] transition-colors"
            aria-label="close providers"
          >
            <X size={12} />
          </button>
        </div>

        <div className="flex items-center gap-2 rounded bg-[#07080c] border border-[#252933] px-2 py-1.5 mb-3">
          <Search size={12} className="text-[#899384] shrink-0" />
          <input
            data-testid="opencode-providers-search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search providers"
            className="flex-1 bg-transparent text-[12px] text-[#e6f0e4] placeholder:text-[#899384]/60 outline-none"
          />
        </div>

        {error && (
          <div
            data-testid="opencode-providers-error"
            className="mb-3 rounded border border-[#ff5c5c]/40 bg-[#ff5c5c]/10 px-2 py-1.5 text-[11px] text-[#ff5c5c]"
          >
            {error}
          </div>
        )}

        <div className="max-h-[320px] overflow-y-auto rounded border border-[#1a1d24] bg-[#07080c]">
          {rows.length === 0 ? (
            <div className="px-2 py-3 text-[11px] text-[#899384]">no matching providers</div>
          ) : (
            rows.map((p) => {
              const isOpen = expanded === p.id;
              return (
                <div
                  key={p.id}
                  className="border-b border-[#10131a] last:border-b-0"
                  data-testid={`opencode-provider-row-${p.id}`}
                >
                  <button
                    data-testid={`opencode-provider-${p.id}`}
                    onClick={() => setExpanded((cur) => (cur === p.id ? null : p.id))}
                    aria-expanded={isOpen}
                    className="w-full flex items-center gap-2 px-2 py-2 text-left text-[12px] text-[#a8b3a6]
                      hover:bg-[#10131a] hover:text-[#e6f0e4] transition-colors"
                  >
                    <span
                      aria-hidden
                      className="grid place-items-center w-5 h-5 shrink-0 rounded bg-[#1a1d24] text-[9px] uppercase text-[#ffa657]"
                    >
                      {p.icon.slice(0, 2)}
                    </span>
                    <span className="min-w-0 truncate flex-1">{p.label}</span>
                    {isOpen ? (
                      <ChevronDown size={12} className="shrink-0 text-[#899384]" />
                    ) : (
                      <ChevronRight size={12} className="shrink-0 text-[#899384]" />
                    )}
                  </button>
                  {isOpen && (
                    <ProviderConfigForm
                      entry={p}
                      scope={scope}
                      saving={savingId === p.id}
                      onSave={save}
                    />
                  )}
                </div>
              );
            })
          )}
        </div>

        <div className="mt-3 text-center">
          <button
            data-testid="opencode-providers-view-all"
            onClick={() => {
              setShowAll(true);
              setQuery("");
            }}
            className="text-[11px] text-[#ffa657] hover:underline"
          >
            View all providers ({TOTAL_OPENCODE_PROVIDERS})
          </button>
        </div>
      </div>
    </div>
  );
}
