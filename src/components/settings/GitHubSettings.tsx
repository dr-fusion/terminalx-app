"use client";

import { useEffect, useState } from "react";
import { GitPullRequest, Link2, Plug, Trash2 } from "lucide-react";

interface Integration {
  id: string;
  displayName: string;
  authType: "PAT" | "GITHUB_APP";
  githubServerUrl: string;
  enabled: boolean;
}

/**
 * GitHub "Connect" settings surface (§6 / §0.2 — user-scoped integrations).
 * Token input + live connection status, with data-testids so the connect flow is
 * screenshottable / e2e-driveable. Matches the dark shadcn/Tailwind look used by
 * the rest of SettingsView.
 */
export function GitHubSettings() {
  const [integrations, setIntegrations] = useState<Integration[] | null>(null);
  const [token, setToken] = useState("");
  const [serverUrl, setServerUrl] = useState("https://github.com");
  const [displayName, setDisplayName] = useState("GitHub (Personal)");
  const [status, setStatus] = useState<{ kind: "idle" | "saving" | "ok" | "error"; msg?: string }>({
    kind: "idle",
  });

  const load = () => {
    fetch("/api/github/integrations")
      .then((r) => (r.ok ? r.json() : { integrations: [] }))
      .then((d: { integrations: Integration[] }) => setIntegrations(d.integrations ?? []))
      .catch(() => setIntegrations([]));
  };

  useEffect(() => {
    load();
  }, []);

  const connected = (integrations?.length ?? 0) > 0;

  const connect = async () => {
    if (!token.trim()) {
      setStatus({ kind: "error", msg: "enter a token" });
      return;
    }
    setStatus({ kind: "saving" });
    try {
      const res = await fetch("/api/github/integrations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token.trim(), serverUrl, displayName }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus({ kind: "error", msg: data?.error ?? "connection failed" });
        return;
      }
      setStatus({ kind: "ok", msg: `connected as ${data?.authenticatedAs ?? "user"}` });
      setToken("");
      load();
    } catch {
      setStatus({ kind: "error", msg: "network error" });
    }
  };

  const disconnect = async (id: string) => {
    await fetch("/api/github/integrations", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ integrationId: id }),
    }).catch(() => {});
    setStatus({ kind: "idle" });
    load();
  };

  return (
    <div
      className="bg-[#0f1117] border border-[#1a1d24] rounded p-4 mb-3"
      data-testid="github-settings"
    >
      <div className="flex items-baseline gap-3 mb-3">
        <h2 className="flex items-center gap-1.5 text-[13px] font-medium text-[#e6f0e4]">
          <GitPullRequest size={13} /> github
        </h2>
        <span
          data-testid="github-connection-status"
          data-connected={connected ? "true" : "false"}
          className={`px-1.5 py-0.5 text-[9px] rounded uppercase tracking-wider font-medium ${
            connected ? "bg-[#00ff88]/20 text-[#00ff88]" : "bg-[#899384]/20 text-[#899384]"
          }`}
        >
          {connected ? "connected" : "not connected"}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <input
          data-testid="github-display-name"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder="display name"
          className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88]"
        />
        <input
          data-testid="github-server-url"
          value={serverUrl}
          onChange={(e) => setServerUrl(e.target.value)}
          placeholder="https://github.com"
          className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88]"
        />
        <input
          data-testid="github-token-input"
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="personal access token (ghp_…)"
          className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88] sm:col-span-2"
        />
      </div>

      <div className="mt-3 flex items-center gap-3">
        <button
          data-testid="github-connect-button"
          onClick={connect}
          disabled={status.kind === "saving"}
          className="inline-flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-3 py-1.5 text-[11px] text-[#00ff88] hover:bg-[#00ff88]/10 disabled:opacity-50"
        >
          <Plug size={12} /> {status.kind === "saving" ? "connecting…" : "connect"}
        </button>
        {status.msg && (
          <span
            data-testid="github-status-message"
            className={`text-[11px] ${
              status.kind === "error" ? "text-[#ff5c5c]" : "text-[#899384]"
            }`}
          >
            {status.msg}
          </span>
        )}
      </div>

      <div className="mt-4 space-y-1" data-testid="github-integration-list">
        {integrations?.map((it) => (
          <div
            key={it.id}
            data-testid="github-integration-row"
            className="flex items-center gap-2 rounded border border-[#1a1d24] bg-[#07080c] px-2 py-1.5 text-[11px]"
          >
            <Link2 size={12} className="text-[#5ccfe6]" />
            <span className="min-w-0 flex-1 truncate text-[#e6f0e4]">{it.displayName}</span>
            <span className="text-[#899384]">{it.githubServerUrl}</span>
            <span className="px-1 py-0.5 rounded bg-[#5ccfe6]/15 text-[9px] uppercase tracking-wider text-[#5ccfe6]">
              {it.authType}
            </span>
            <button
              data-testid="github-disconnect-button"
              onClick={() => disconnect(it.id)}
              aria-label={`disconnect ${it.displayName}`}
              className="text-[#ff5c5c] hover:text-[#ff8080]"
            >
              <Trash2 size={12} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
