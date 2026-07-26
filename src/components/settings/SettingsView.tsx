"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Bot, ExternalLink, Save, Shield } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { EngineToggle } from "@/components/terminal/EngineToggle";
import { MobileSection } from "@/components/settings/MobileSection";
// Issue #4: Harnesses settings surface (AI runtime tabs + OpenCode config).
import { HarnessTabs } from "@/components/settings/HarnessTabs";
// Workspace config (feature #5): User/Repo scope tabs + Edit settings.toml.
import { WorkspaceSettings } from "@/components/settings/WorkspaceSettings";
// GitHub integration (feature #7): connect repos, tokens, webhooks.
import { GitHubSettings } from "@/components/settings/GitHubSettings";
// Models & harness settings (feature #11): default/review model, effort,
// personality, plan/fast/Chrome toggles, with User/Repo scope.
import { SettingsScopeTabs } from "@/components/settings/SettingsScopeTabs";
import { ModelsSettingsPage } from "@/components/settings/ModelsSettingsPage";
import type { SettingsScope } from "@/lib/settings/types";
import type { TelegramViewMode } from "@/hooks/useSessions";

interface HealthInfo {
  hostname: string;
  version: string;
  uptimeSeconds: number;
}

interface TelegramSettings {
  config: {
    enabled: boolean;
    configured: boolean;
    botTokenSet: boolean;
    botTokenPreview: string | null;
    webhookUrl: string;
    webhookSecretSet: boolean;
    allowedUsers: string;
    forumChatId: number | null;
    maxTopics: number;
  };
  topics: Array<{
    topicId: number;
    sessionName: string;
    kind: string;
    viewMode: TelegramViewMode;
    endedAtMs?: number;
  }>;
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

// Feature #11: self-contained Models section embedded in the settings view.
// Carries its own User/Repo scope tabs (the standalone SettingsShell offers the
// fuller left-nav shell from §4.1, but the page is reachable here per the
// mandate). `session` is optional — when absent the Repo tab is disabled.
function ModelsSection({ session, isAdmin }: { session?: string; isAdmin: boolean }) {
  const [scope, setScope] = useState<SettingsScope>("user");
  const [repoAvailable, setRepoAvailable] = useState(false);

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

  useEffect(() => {
    if (scope === "repo" && !repoAvailable) setScope("user");
  }, [scope, repoAvailable]);

  return (
    <div data-testid="settings-models-section" className="mb-3">
      <SettingsScopeTabs scope={scope} onScope={setScope} repoAvailable={repoAvailable} />
      <ModelsSettingsPage scope={scope} session={session} readOnly={scope === "repo" && !isAdmin} />
    </div>
  );
}

export function SettingsView({
  session,
  hideModels = false,
}: { session?: string; hideModels?: boolean } = {}) {
  const { user, authMode } = useAuth();
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [telegram, setTelegram] = useState<TelegramSettings | null>(null);
  const [telegramForm, setTelegramForm] = useState({
    enabled: false,
    botToken: "",
    webhookUrl: "",
    webhookSecret: "",
    allowedUsers: "",
    forumChatId: "",
    maxTopics: "10",
  });
  const [telegramStatus, setTelegramStatus] = useState<string | null>(null);

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

  useEffect(() => {
    let cancelled = false;
    fetch("/api/telegram/settings")
      .then((r) => {
        if (!r.ok) throw new Error("telegram settings unavailable");
        return r.json();
      })
      .then((d: TelegramSettings) => {
        if (cancelled) return;
        setTelegram(d);
        setTelegramForm({
          enabled: d.config.enabled,
          botToken: "",
          webhookUrl: d.config.webhookUrl,
          webhookSecret: "",
          allowedUsers: d.config.allowedUsers,
          forumChatId: d.config.forumChatId ? String(d.config.forumChatId) : "",
          maxTopics: d.config.maxTopics ? String(d.config.maxTopics) : "10",
        });
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const saveTelegram = async () => {
    setTelegramStatus("saving...");
    const payload = {
      enabled: telegramForm.enabled,
      botToken: telegramForm.botToken.trim() || undefined,
      webhookUrl: telegramForm.webhookUrl,
      webhookSecret: telegramForm.webhookSecret.trim() || undefined,
      allowedUsers: telegramForm.allowedUsers,
      forumChatId: telegramForm.forumChatId,
      maxTopics: telegramForm.maxTopics,
    };
    const res = await fetch("/api/telegram/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      setTelegramStatus(body?.error ?? "save failed");
      return;
    }
    const data = (await res.json()) as { config: TelegramSettings["config"] };
    setTelegram((prev) => (prev ? { ...prev, config: data.config } : prev));
    setTelegramForm((prev) => ({ ...prev, botToken: "", webhookSecret: "" }));
    setTelegramStatus("saved");
    setTimeout(() => setTelegramStatus(null), 2000);
  };

  const setTopicMode = async (topicId: number, viewMode: TelegramViewMode) => {
    const res = await fetch(`/api/telegram/topics/${topicId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ viewMode }),
    });
    if (!res.ok) return;
    setTelegram((prev) =>
      prev
        ? {
            ...prev,
            topics: prev.topics.map((topic) =>
              topic.topicId === topicId ? { ...topic, viewMode } : topic
            ),
          }
        : prev
    );
  };

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
    <div className="h-full overflow-y-auto contain-scroll">
      <div className="max-w-[720px] mx-auto px-4 sm:px-6 py-6 sm:py-8">
        <div className="mb-5">
          <h1 className="text-[26px] font-bold tracking-tight text-[#e6f0e4]">settings</h1>
          <p className="text-[11px] text-[#899384] mt-1">
            server + user config. read only for now.
          </p>
        </div>

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

        <GitHubSettings />

        {/* Feature #11: Models & harness settings (default/review model, effort,
            personality, plan/fast/Chrome toggles) with User/Repo scope. */}
        {!hideModels && (
          <Section title="models" desc="default + review model, effort, personality">
            <ModelsSection session={session} isAdmin={user?.role === "admin"} />
          </Section>
        )}

        <Section title="terminal engine" desc="reloads new tabs">
          <EngineToggle />
        </Section>

        {/* Issue #4: Harnesses — AI runtimes available to new sessions. */}
        <Section title="harnesses" desc="AI runtimes available to new sessions">
          <HarnessTabs />
        </Section>

        {/* Workspace config (feature #5) — its own card with User/Repo tabs. */}
        <WorkspaceSettings />

        <Section title="mobile" desc="pair the terminalx mobile app">
          <MobileSection />
        </Section>

        <Section title="telegram" desc={telegram?.config.configured ? "configured" : "not ready"}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <label className="flex items-center gap-2 text-[11px] text-[#a8b3a6] sm:col-span-2">
              <input
                type="checkbox"
                checked={telegramForm.enabled}
                onChange={(e) => setTelegramForm((f) => ({ ...f, enabled: e.target.checked }))}
                className="accent-[#00ff88]"
                disabled={user?.role !== "admin"}
              />
              enabled
              {telegram?.config.botTokenPreview && (
                <span className="text-[#899384]">token {telegram.config.botTokenPreview}</span>
              )}
            </label>
            <input
              type="password"
              value={telegramForm.botToken}
              onChange={(e) => setTelegramForm((f) => ({ ...f, botToken: e.target.value }))}
              placeholder={telegram?.config.botTokenSet ? "bot token unchanged" : "bot token"}
              disabled={user?.role !== "admin"}
              className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88]"
            />
            <input
              value={telegramForm.forumChatId}
              onChange={(e) => setTelegramForm((f) => ({ ...f, forumChatId: e.target.value }))}
              placeholder="forum chat id"
              disabled={user?.role !== "admin"}
              className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88]"
            />
            <input
              value={telegramForm.webhookUrl}
              onChange={(e) => setTelegramForm((f) => ({ ...f, webhookUrl: e.target.value }))}
              placeholder="webhook url"
              disabled={user?.role !== "admin"}
              className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88] sm:col-span-2"
            />
            <input
              type="password"
              value={telegramForm.webhookSecret}
              onChange={(e) => setTelegramForm((f) => ({ ...f, webhookSecret: e.target.value }))}
              placeholder={
                telegram?.config.webhookSecretSet ? "webhook secret unchanged" : "webhook secret"
              }
              disabled={user?.role !== "admin"}
              className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88]"
            />
            <input
              value={telegramForm.maxTopics}
              onChange={(e) => setTelegramForm((f) => ({ ...f, maxTopics: e.target.value }))}
              placeholder="max topics"
              disabled={user?.role !== "admin"}
              className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88]"
            />
            <input
              value={telegramForm.allowedUsers}
              onChange={(e) => setTelegramForm((f) => ({ ...f, allowedUsers: e.target.value }))}
              placeholder="123456789:admin"
              disabled={user?.role !== "admin"}
              className="rounded border border-[#252933] bg-[#07080c] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none focus:border-[#00ff88] sm:col-span-2"
            />
          </div>
          {user?.role === "admin" && (
            <button
              onClick={saveTelegram}
              className="mt-3 inline-flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-3 py-1.5 text-[11px] text-[#00ff88] hover:bg-[#00ff88]/10"
            >
              <Save size={12} /> save telegram
            </button>
          )}
          {telegramStatus && (
            <span className="ml-3 text-[11px] text-[#899384]">{telegramStatus}</span>
          )}

          <div className="mt-4 space-y-1">
            {telegram?.topics.map((topic) => (
              <div
                key={topic.topicId}
                className="flex items-center gap-2 rounded border border-[#1a1d24] bg-[#07080c] px-2 py-1.5 text-[11px]"
              >
                <Bot size={12} className="text-[#5ccfe6]" />
                <span className="min-w-0 flex-1 truncate text-[#e6f0e4]">{topic.sessionName}</span>
                <select
                  value={topic.viewMode}
                  onChange={(e) => setTopicMode(topic.topicId, e.target.value as TelegramViewMode)}
                  className="rounded border border-[#252933] bg-[#0a0b10] px-1 py-0.5 text-[10px] text-[#5ccfe6] outline-none"
                >
                  <option value="chat">chat</option>
                  <option value="screen">screen</option>
                  <option value="off">off</option>
                </select>
              </div>
            ))}
          </div>
        </Section>

        <Section title="help">
          <div className="text-[11px] text-[#a8b3a6] leading-relaxed">
            <p>
              terminalx runs tmux sessions on a remote host, exposed over a websocket to your
              browser. sessions survive browser reloads; they live in tmux until you{" "}
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
    </div>
  );
}
