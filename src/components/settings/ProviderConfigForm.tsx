"use client";

// Issue #8 (§6): per-provider OpenCode config form, opened inline when a row in
// the Providers picker is selected. Collects only the NON-SECRET fields OpenCode
// needs to write its provider stanza:
//   - Standard providers (OpenAI/Anthropic/Google/GitHub) → Model(s) only.
//   - Gateways (Vercel AI Gateway / OpenRouter, endpointEditable) → Endpoint URL
//     + Model(s).
//   - Bundled (OpenCode Go/Zen) → nothing required.
// There is NO API-key / credential field and NO Effort field (Effort lives on
// the Models settings page). Auth is delegated to OpenCode's own config / .env;
// TerminalX never stores a provider secret (spec §6, AC-7/AC-8/AC-9).
//
// Client-safe: imports only React, lucide icons, and the browser-safe catalog
// TYPES + the ConfiguredOpenCodeProvider shape (no Node builtins transitively).

import { useState } from "react";
import { Loader2, Save } from "lucide-react";
import type {
  ConfiguredOpenCodeProvider,
  OpenCodeProviderEntry,
} from "@/lib/harnesses/opencode-providers";

export interface ProviderConfigDraft {
  providerId: string;
  endpoint?: string;
  models?: string[];
  scope: "user" | "repo";
}

export function ProviderConfigForm({
  entry,
  scope,
  saving,
  onSave,
}: {
  entry: OpenCodeProviderEntry;
  scope: "user" | "repo";
  saving?: boolean;
  onSave: (draft: ConfiguredOpenCodeProvider) => void;
}) {
  const isGateway = Boolean(entry.endpointEditable);
  const isBundled = entry.id === "opencode-zen";

  const [endpoint, setEndpoint] = useState("");
  const [modelsText, setModelsText] = useState("");

  const submit = () => {
    const models = modelsText
      .split(",")
      .map((m) => m.trim())
      .filter(Boolean);
    onSave({
      providerId: entry.id,
      endpoint: isGateway && endpoint.trim() ? endpoint.trim() : undefined,
      models: models.length ? models : undefined,
      scope,
    });
  };

  return (
    <div
      data-testid={`opencode-provider-config-${entry.id}`}
      className="border-t border-[#1a1d24] bg-[#0a0c12] px-3 py-3 space-y-3"
    >
      {isBundled ? (
        <p className="text-[10px] text-[#899384] leading-tight">
          Uses the bundled OpenCode binary. Override the executable path in Advanced if needed.
        </p>
      ) : (
        <p className="text-[10px] text-[#899384] leading-tight">
          Authentication is handled by OpenCode (its own login / <code>.env</code>). No credentials
          are stored here.
        </p>
      )}

      {isGateway && (
        <div>
          <label
            htmlFor={`endpoint-${entry.id}`}
            className="block text-[10px] uppercase tracking-wider text-[#899384] mb-1.5"
          >
            Endpoint URL
          </label>
          <input
            id={`endpoint-${entry.id}`}
            data-testid={`opencode-provider-endpoint-${entry.id}`}
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="https://gateway.example.com/v1"
            spellCheck={false}
            autoComplete="off"
            className="w-full px-2 py-1.5 rounded bg-[#0f1117] border border-[#252933]
              text-[#e6f0e4] text-[12px] placeholder:text-[#899384]/50 font-mono
              focus:outline-none focus:border-[#ffa657] transition-colors"
          />
          <p className="mt-1 text-[10px] text-[#899384] leading-tight">
            Written into OpenCode&apos;s config so it can target this gateway. Must be https:// (or
            http://localhost for development).
          </p>
        </div>
      )}

      {!isBundled && (
        <div>
          <label
            htmlFor={`models-${entry.id}`}
            className="block text-[10px] uppercase tracking-wider text-[#899384] mb-1.5"
          >
            Model{isGateway ? "(s)" : ""}
          </label>
          <input
            id={`models-${entry.id}`}
            data-testid={`opencode-provider-models-${entry.id}`}
            value={modelsText}
            onChange={(e) => setModelsText(e.target.value)}
            placeholder={isGateway ? "model-id, another-model" : "claude-opus-4-8"}
            spellCheck={false}
            autoComplete="off"
            className="w-full px-2 py-1.5 rounded bg-[#0f1117] border border-[#252933]
              text-[#e6f0e4] text-[12px] placeholder:text-[#899384]/50 font-mono
              focus:outline-none focus:border-[#ffa657] transition-colors"
          />
          <p className="mt-1 text-[10px] text-[#899384] leading-tight">
            Comma-separated models to enable in OpenCode. Drives the &quot;Models · N selected&quot;
            count.
          </p>
        </div>
      )}

      <div className="flex items-center justify-end">
        <button
          data-testid={`opencode-provider-save-${entry.id}`}
          onClick={submit}
          disabled={saving}
          className="inline-flex items-center gap-1.5 rounded border border-[#ffa657]/60 bg-[#ffa657]/10
            px-2.5 py-1 text-[11px] text-[#ffa657] hover:bg-[#ffa657]/20 transition-colors
            disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving ? <Loader2 size={11} className="animate-spin" /> : <Save size={11} />}
          Add provider
        </button>
      </div>
    </div>
  );
}
