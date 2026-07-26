"use client";

// Telegram bridge settings, extracted from the legacy SettingsView so it can be
// re-homed under the Experimental nav item in the settings shell. Admin-only
// edits; bot token / webhook secret are write-only (never echoed back). Pure
// client component — talks to the server exclusively over fetch.

import { useEffect, useState } from "react";
import { Bot, Save } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import type { TelegramViewMode } from "@/hooks/useSessions";

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

export function TelegramSection() {
  const { user } = useAuth();
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

  return (
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
      {telegramStatus && <span className="ml-3 text-[11px] text-[#899384]">{telegramStatus}</span>}

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
  );
}
