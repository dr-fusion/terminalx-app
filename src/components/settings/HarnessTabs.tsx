"use client";

// Issue #4 (§6.2): the Harnesses settings surface. Fetches GET /api/harnesses
// (registry list + status probe) and renders one tab per harness — Claude Code
// / Codex / Cursor / OpenCode[NEW] — plus the selected harness panel:
//  - auth:"cli" harnesses → CLI vs API-key choice (✓ on active), Connected /
//    Not-installed pill, Provider/Plan/Org/Account table (dashes when unknown),
//    "Run <cli> /login".
//  - hostsProviders (opencode) → the OpenCodePanel.
// Tabs/controls carry data-testids so e2e is robust.

import { useCallback, useEffect, useMemo, useState } from "react";
import { KeyRound, Play, Terminal } from "lucide-react";
import { ScopeTabs, type HarnessScope } from "@/components/settings/ScopeTabs";
import { OpenCodePanel } from "@/components/settings/OpenCodePanel";
import { useSessions } from "@/hooks/useSessions";

export interface HarnessStatusApi {
  id: string;
  installed: boolean;
  binPath?: string;
  version?: string;
  connected: boolean;
  authMethod: "cli" | "api-key" | "none";
  account?: {
    provider?: string;
    plan?: string;
    org?: string;
    account?: string;
  };
  loginCommand?: string;
}

export interface HarnessApi {
  id: string;
  label: string;
  badge?: "NEW";
  color: string;
  auth: "cli" | "api-key" | "none";
  hostsProviders: boolean;
  docsUrl?: string;
  status?: HarnessStatusApi;
}

function StatusPill({ status }: { status?: HarnessStatusApi }) {
  if (!status) return null;
  if (!status.installed) {
    return (
      <span
        data-testid="harness-status-pill"
        className="px-1.5 py-0.5 text-[9px] rounded uppercase tracking-wider font-medium bg-[#ff5c5c]/20 text-[#ff5c5c]"
      >
        Not installed
      </span>
    );
  }
  return (
    <span
      data-testid="harness-status-pill"
      className={`px-1.5 py-0.5 text-[9px] rounded uppercase tracking-wider font-medium ${
        status.connected ? "bg-[#00ff88]/20 text-[#00ff88]" : "bg-[#ffb454]/20 text-[#ffb454]"
      }`}
    >
      {status.connected ? "Connected" : "Not connected"}
    </span>
  );
}

function AuthChoice({ status }: { status?: HarnessStatusApi }) {
  const active = status?.authMethod;
  return (
    <div data-testid="harness-auth-choice" className="grid grid-cols-2 gap-2 mb-3">
      <div
        data-testid="harness-auth-cli"
        data-active={active === "cli" ? "true" : "false"}
        className={`flex items-center gap-2 rounded border px-3 py-2 text-[11px] ${
          active === "cli"
            ? "border-[#00cc6e] bg-[#00ff88]/10 text-[#e6f0e4]"
            : "border-[#252933] bg-[#07080c] text-[#a8b3a6]"
        }`}
      >
        <Terminal size={13} className="shrink-0" /> CLI
        {active === "cli" && <span className="ml-auto text-[#00ff88]">✓</span>}
      </div>
      <div
        data-testid="harness-auth-api-key"
        data-active={active === "api-key" ? "true" : "false"}
        className={`flex items-center gap-2 rounded border px-3 py-2 text-[11px] ${
          active === "api-key"
            ? "border-[#00cc6e] bg-[#00ff88]/10 text-[#e6f0e4]"
            : "border-[#252933] bg-[#07080c] text-[#a8b3a6]"
        }`}
      >
        <KeyRound size={13} className="shrink-0" /> API key
        {active === "api-key" && <span className="ml-auto text-[#00ff88]">✓</span>}
      </div>
    </div>
  );
}

function AccountTable({ status }: { status?: HarnessStatusApi }) {
  const a = status?.account;
  const cell = (v?: string) => v || "—";
  return (
    <div
      data-testid="harness-account-table"
      className="rounded border border-[#1a1d24] bg-[#07080c] px-3 py-2 mb-3"
    >
      {(
        [
          ["Provider", a?.provider],
          ["Plan", a?.plan],
          ["Org", a?.org],
          ["Account", a?.account],
        ] as const
      ).map(([label, value]) => (
        <div key={label} className="flex items-center gap-4 py-1 text-[11px]">
          <span className="text-[#899384] w-24 shrink-0 uppercase tracking-wider text-[10px]">
            {label}
          </span>
          <span className="text-[#e6f0e4] truncate">{cell(value)}</span>
        </div>
      ))}
    </div>
  );
}

export function HarnessTabs() {
  const [harnesses, setHarnesses] = useState<HarnessApi[]>([]);
  const [selected, setSelected] = useState<string>("claude");
  const [scope, setScope] = useState<HarnessScope>("user");
  const [loginMsg, setLoginMsg] = useState<string | null>(null);

  // Repo scope resolves against the first worktree-backed session (mirrors
  // WorkspaceSettings); the server turns the session name into a repo root.
  const { sessions } = useSessions();
  const repoSession = useMemo(
    () => sessions.find((s) => s.worktree?.repoRoot || s.cwd)?.name ?? null,
    [sessions]
  );

  // Apply a fetched harness list (shared by the initial load + Refresh).
  const apply = useCallback((list: HarnessApi[]) => {
    setHarnesses(list);
    setSelected((cur) => (list.some((h) => h.id === cur) ? cur : (list[0]?.id ?? "claude")));
  }, []);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/harnesses");
      if (!res.ok) return;
      const data = await res.json();
      // bash is not a configurable harness tab.
      apply((data.harnesses ?? []).filter((h: HarnessApi) => h.id !== "bash"));
    } catch {
      /* best-effort */
    }
  }, [apply]);

  // Initial load (matches SettingsView's fetch-effect pattern: setState only
  // fires after the request resolves, guarded against unmount).
  useEffect(() => {
    let cancelled = false;
    fetch("/api/harnesses")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("harnesses unavailable"))))
      .then((data) => {
        if (cancelled) return;
        apply((data.harnesses ?? []).filter((h: HarnessApi) => h.id !== "bash"));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [apply]);

  const current = harnesses.find((h) => h.id === selected);

  const runLogin = useCallback(async () => {
    if (!current) return;
    setLoginMsg("starting…");
    try {
      const res = await fetch(`/api/harnesses/${encodeURIComponent(current.id)}/login`, {
        method: "POST",
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setLoginMsg(data?.error ?? "login failed");
        return;
      }
      setLoginMsg(`opened ${data?.name ?? "login session"}`);
    } catch {
      setLoginMsg("login failed");
    }
  }, [current]);

  return (
    <div>
      <ScopeTabs scope={scope} onScope={setScope} />

      {/* Tab strip */}
      <div
        data-testid="harness-tabs"
        className="flex flex-wrap gap-1 mb-4 border-b border-[#1a1d24] pb-2"
      >
        {harnesses.map((h) => (
          <button
            key={h.id}
            data-testid={`harness-tab-${h.id}`}
            onClick={() => setSelected(h.id)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] transition-colors ${
              selected === h.id
                ? "bg-[#1a1d24] text-[#e6f0e4] font-medium"
                : "text-[#899384] hover:text-[#e6f0e4]"
            }`}
          >
            {h.label}
            {h.badge === "NEW" && (
              <span
                data-testid={`harness-badge-${h.id}`}
                className="px-1 py-0.5 text-[8px] uppercase tracking-wider rounded bg-[#ffa657]/20 text-[#ffa657] leading-none"
              >
                NEW
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Selected harness panel */}
      {current && (
        <div data-testid={`harness-panel-${current.id}`}>
          {current.hostsProviders ? (
            <OpenCodePanel
              harness={current}
              scope={scope}
              repoSession={repoSession}
              onRefresh={load}
            />
          ) : (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="text-[10px] uppercase tracking-wider text-[#899384]">
                  Authentication
                </span>
                <StatusPill status={current.status} />
              </div>
              {current.auth === "cli" && <AuthChoice status={current.status} />}
              <AccountTable status={current.status} />
              {current.status?.loginCommand && (
                <div className="flex items-center gap-3">
                  <button
                    data-testid="harness-run-login"
                    onClick={runLogin}
                    className="inline-flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-3 py-1.5 text-[11px] text-[#00ff88] hover:bg-[#00ff88]/10 transition-colors"
                  >
                    <Play size={11} /> Run {current.status.loginCommand}
                  </button>
                  {loginMsg && <span className="text-[10px] text-[#899384]">{loginMsg}</span>}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
