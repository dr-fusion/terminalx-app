"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ExternalLink, Shield } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { EngineToggle } from "@/components/terminal/EngineToggle";

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
        {desc && <span className="text-[10px] text-[#6b7569]">{desc}</span>}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-center gap-4 py-1.5 text-[11px]">
      <span className="text-[#6b7569] w-32 shrink-0 uppercase tracking-wider text-[10px]">
        {label}
      </span>
      <span className={`text-[#e6f0e4] ${mono ? "font-mono" : ""} truncate`}>{value}</span>
    </div>
  );
}

export function SettingsView() {
  const { user, authMode } = useAuth();
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
    <div className="h-full overflow-y-auto">
      <div className="max-w-[720px] mx-auto px-6 py-8">
        <div className="mb-5">
          <h1 className="text-[26px] font-bold tracking-tight text-[#e6f0e4]">settings</h1>
          <p className="text-[11px] text-[#6b7569] mt-1">
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

        <Section title="terminal engine" desc="reloads new tabs">
          <EngineToggle />
        </Section>

        <Section title="help">
          <div className="text-[11px] text-[#a8b3a6] leading-relaxed">
            <p>
              terminalx runs tmux sessions on a remote host, exposed over a websocket to your
              browser. sessions survive browser reloads; they live in tmux until you{" "}
              <code className="text-[#00cc6e] bg-transparent border-0 px-0">kill</code> them.
            </p>
            <p className="mt-2 text-[#6b7569]">
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
