"use client";

// Settings shell (issue #11, §4.1 + fidelity pass). A DEDICATED full-page
// settings view with a LEFT NAV (Conductor parity): General · Account · Models ·
// Harnesses · Providers · Environment · Git · Appearance, then a "More" group:
// Experimental · Advanced — plus a User/Repo scope tab pair at the top.
//
// Selecting a nav item shows that section's page. Each page REUSES the existing
// section components (EngineToggle, ModelsSettingsPage, HarnessTabs,
// OpenCodePanel, GitHubSettings, WorkspaceSettings, MobileSection) so every
// existing data-testid stays reachable — just re-homed behind its nav item.
//
// Pure client component: no Node imports.

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ExternalLink, Shield } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { useSessions } from "@/hooks/useSessions";
import { SettingsScopeTabs } from "@/components/settings/SettingsScopeTabs";
import { SettingsNav, type SettingsNavKey } from "@/components/settings/SettingsNav";
import { ModelsSettingsPage } from "@/components/settings/ModelsSettingsPage";
import { EngineToggle } from "@/components/terminal/EngineToggle";
import { HarnessTabs } from "@/components/settings/HarnessTabs";
import { OpenCodePanel } from "@/components/settings/OpenCodePanel";
import type { HarnessApi } from "@/components/settings/HarnessTabs";
import { GitHubSettings } from "@/components/settings/GitHubSettings";
import { WorkspaceSettings } from "@/components/settings/WorkspaceSettings";
import { MobileSection } from "@/components/settings/MobileSection";
import { TelegramSection } from "@/components/settings/TelegramSection";
import type { SettingsScope } from "@/lib/settings/types";

interface HealthInfo {
  hostname: string;
  version: string;
  uptimeSeconds: number;
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

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-center gap-4 py-1.5 text-[11px]">
      <span className="text-[#899384] w-32 shrink-0 uppercase tracking-wider text-[10px]">
        {label}
      </span>
      <span className={`text-[#e6f0e4] ${mono ? "font-mono" : ""} truncate`}>{value}</span>
    </div>
  );
}

function PageHeader({ title }: { title: string }) {
  return (
    <div className="mb-4">
      <h1 className="text-[20px] font-bold tracking-tight text-[#e6f0e4]">{title}</h1>
    </div>
  );
}

// General: server info (host/version/uptime/auth mode) + terminal engine.
function GeneralPage() {
  const { authMode } = useAuth();
  const [health, setHealth] = useState<HealthInfo | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/health")
      .then((r) => r.json())
      .then((d) => {
        if (!cancelled) setHealth(d);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const uptime = health
    ? (() => {
        const s = health.uptimeSeconds;
        const d = Math.floor(s / 86400);
        const h = Math.floor((s % 86400) / 3600);
        const m = Math.floor((s % 3600) / 60);
        return `${d}d ${h}h ${m}m`;
      })()
    : "…";

  return (
    <div data-testid="settings-page-general">
      <PageHeader title="General" />
      <Section title="server" desc="the box you're reaching over ssh · tmux">
        <Row label="host" value={health?.hostname ?? "…"} mono />
        <Row label="version" value={health?.version ?? "…"} mono />
        <Row label="uptime" value={uptime} mono />
        <Row
          label="auth mode"
          value={
            <span
              className={`px-1.5 py-0.5 text-[9px] rounded uppercase tracking-wider font-medium ${
                authMode === "google"
                  ? "bg-[#00ff88]/20 text-[#00ff88]"
                  : authMode === "none"
                    ? "bg-[#ff5c5c]/20 text-[#ff5c5c]"
                    : "bg-[#5ccfe6]/20 text-[#5ccfe6]"
              }`}
            >
              {authMode}
            </span>
          }
        />
      </Section>

      <Section title="terminal engine" desc="reloads new tabs">
        <EngineToggle />
      </Section>
    </div>
  );
}

// Account: the "you" block (username/role) + admin-panel link.
function AccountPage() {
  const { user } = useAuth();
  return (
    <div data-testid="settings-page-account">
      <PageHeader title="Account" />
      <Section title="you">
        <Row label="username" value={user?.username ?? "anonymous"} mono />
        <Row
          label="role"
          value={
            user ? (
              <span
                className={`px-1.5 py-0.5 text-[9px] rounded uppercase tracking-wider font-medium ${
                  user.role === "admin"
                    ? "bg-[#d58fff]/20 text-[#d58fff]"
                    : "bg-[#5ccfe6]/20 text-[#5ccfe6]"
                }`}
              >
                {user.role}
              </span>
            ) : (
              "—"
            )
          }
        />
        {user?.role === "admin" && (
          <div className="mt-3 pt-3 border-t border-[#1a1d24]">
            <Link
              href="/admin"
              className="inline-flex items-center gap-1.5 text-[11px] text-[#00ff88] hover:underline"
            >
              <Shield size={11} /> admin panel <ExternalLink size={10} />
            </Link>
          </div>
        )}
      </Section>
    </div>
  );
}

// Models: the dedicated ModelsSettingsPage. Wrapped in settings-models-section so
// the historical e2e selector keeps resolving under its nav item.
function ModelsPage({
  scope,
  session,
  readOnly,
}: {
  scope: SettingsScope;
  session?: string;
  readOnly: boolean;
}) {
  return (
    <div data-testid="settings-models-section">
      <ModelsSettingsPage scope={scope} session={session} readOnly={readOnly} />
    </div>
  );
}

// Harnesses: the AI runtime tabs (Claude Code / Codex / Cursor / OpenCode).
function HarnessesPage() {
  return (
    <div data-testid="settings-page-harnesses">
      <PageHeader title="Harnesses" />
      <Section title="harnesses" desc="AI runtimes available to new sessions">
        <HarnessTabs />
      </Section>
    </div>
  );
}

// Providers: the OpenCode providers surface (configured list + picker entry).
// Mirrors the OpenCode harness panel so the providers nav item matches Conductor
// without duplicating the auth tabs.
function ProvidersPage({ scope, session }: { scope: SettingsScope; session?: string }) {
  const { sessions } = useSessions();
  const repoSession = useMemo(
    () => sessions.find((s) => s.worktree?.repoRoot || s.cwd)?.name ?? session ?? null,
    [sessions, session]
  );
  const [opencode, setOpencode] = useState<HarnessApi | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/harnesses")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("harnesses unavailable"))))
      .then((data) => {
        if (cancelled) return;
        const found = (data.harnesses ?? []).find((h: HarnessApi) => h.id === "opencode");
        if (found) setOpencode(found);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div data-testid="settings-page-providers">
      <PageHeader title="Providers" />
      <Section title="providers" desc="OpenCode providers + models">
        {opencode ? (
          <OpenCodePanel
            harness={opencode}
            scope={scope === "repo" ? "repo" : "user"}
            repoSession={repoSession}
            onRefresh={() => {}}
          />
        ) : (
          <p className="text-[11px] text-[#899384]">loading providers…</p>
        )}
      </Section>
    </div>
  );
}

// Environment: the workspace env/config surface.
function EnvironmentPage() {
  return (
    <div data-testid="settings-page-environment">
      <PageHeader title="Environment" />
      <WorkspaceSettings />
    </div>
  );
}

// Git: the GitHub integration surface.
function GitPage() {
  return (
    <div data-testid="settings-page-git">
      <PageHeader title="Git" />
      <GitHubSettings />
    </div>
  );
}

// Appearance: theme note (dark). Minimal per the mandate.
function AppearancePage() {
  return (
    <div data-testid="settings-page-appearance">
      <PageHeader title="Appearance" />
      <Section title="theme" desc="terminalx ships a single dark theme">
        <Row label="theme" value="dark" />
        <p className="mt-2 text-[11px] text-[#899384] leading-relaxed">
          terminalx uses a fixed dark theme tuned for long terminal sessions. A light theme is not
          available yet.
        </p>
      </Section>
    </div>
  );
}

// Experimental: misc surfaces not yet promoted to a primary nav item.
function ExperimentalPage() {
  return (
    <div data-testid="settings-page-experimental">
      <PageHeader title="Experimental" />
      <Section title="mobile" desc="pair the terminalx mobile app">
        <MobileSection />
      </Section>
      <TelegramSection />
    </div>
  );
}

// Advanced: help / reference.
function AdvancedPage() {
  return (
    <div data-testid="settings-page-advanced">
      <PageHeader title="Advanced" />
      <Section title="help">
        <div className="text-[11px] text-[#a8b3a6] leading-relaxed">
          <p>
            terminalx runs tmux sessions on a remote host, exposed over a websocket to your browser.
            sessions survive browser reloads; they live in tmux until you{" "}
            <code className="text-[#00cc6e] bg-transparent border-0 px-0">kill</code> them.
          </p>
          <p className="mt-2 text-[#899384]">
            shortcut hints:{" "}
            <kbd className="px-1 py-0.5 bg-[#0a0b10] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
              ⌘
            </kbd>
            <kbd className="ml-0.5 px-1 py-0.5 bg-[#0a0b10] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
              K
            </kbd>{" "}
            commands ·{" "}
            <kbd className="px-1 py-0.5 bg-[#0a0b10] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
              ⌃
            </kbd>
            <kbd className="ml-0.5 px-1 py-0.5 bg-[#0a0b10] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
              B
            </kbd>{" "}
            tmux prefix
          </p>
        </div>
      </Section>
    </div>
  );
}

export function SettingsShell({ session }: { session?: string }) {
  const { user } = useAuth();
  const [scope, setScope] = useState<SettingsScope>("user");
  const [nav, setNav] = useState<SettingsNavKey>("general");
  const [repoAvailable, setRepoAvailable] = useState(false);

  // Probe repo context: a repo-scope GET 404s when no repo is resolvable.
  useEffect(() => {
    let cancelled = false;
    if (!session) {
      setRepoAvailable(false);
      return;
    }
    fetch(`/api/settings?scope=repo&session=${encodeURIComponent(session)}`)
      .then((r) => {
        if (!cancelled) setRepoAvailable(r.ok);
      })
      .catch(() => {
        if (!cancelled) setRepoAvailable(false);
      });
    return () => {
      cancelled = true;
    };
  }, [session]);

  // Fall back to User scope if Repo becomes unavailable.
  useEffect(() => {
    if (scope === "repo" && !repoAvailable) setScope("user");
  }, [scope, repoAvailable]);

  const isAdmin = user?.role === "admin";
  const repoReadOnly = scope === "repo" && !isAdmin;

  const onEditToml = useCallback(() => {
    // The in-app file editor is owned by the files surface; emit a navigation
    // intent the host app can pick up. No-op fallback keeps the shell standalone.
    window.dispatchEvent(
      new CustomEvent("terminalx:open-file", {
        detail: { path: ".terminalx/settings.toml" },
      })
    );
  }, []);

  return (
    <div className="h-full overflow-y-auto contain-scroll" data-testid="settings-shell">
      <div className="max-w-[920px] mx-auto px-4 sm:px-6 py-6 sm:py-8">
        <div className="mb-5">
          <h1 className="text-[26px] font-bold tracking-tight text-[#e6f0e4]">Settings</h1>
        </div>

        <SettingsScopeTabs
          scope={scope}
          onScope={setScope}
          repoAvailable={repoAvailable}
          onEditToml={onEditToml}
        />

        <div className="flex gap-6">
          <aside className="w-40 shrink-0">
            <SettingsNav active={nav} onSelect={setNav} />
          </aside>

          <div className="min-w-0 flex-1">
            {nav === "general" && <GeneralPage />}
            {nav === "account" && <AccountPage />}
            {nav === "models" && (
              <ModelsPage scope={scope} session={session} readOnly={repoReadOnly} />
            )}
            {nav === "harnesses" && <HarnessesPage />}
            {nav === "providers" && <ProvidersPage scope={scope} session={session} />}
            {nav === "environment" && <EnvironmentPage />}
            {nav === "git" && <GitPage />}
            {nav === "appearance" && <AppearancePage />}
            {nav === "experimental" && <ExperimentalPage />}
            {nav === "advanced" && <AdvancedPage />}
          </div>
        </div>
      </div>
    </div>
  );
}
