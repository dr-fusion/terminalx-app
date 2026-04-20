"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import {
  Terminal,
  Plus,
  RefreshCw,
  X,
  FlaskConical,
  Film,
  Sparkles,
  Bot,
  AlertTriangle,
} from "lucide-react";
import { useSessions, type TmuxSession, type SessionKind } from "@/hooks/useSessions";
import { UserSection } from "@/components/auth/UserSection";
import { EngineToggle } from "@/components/terminal/EngineToggle";

interface SessionSidebarProps {
  onOpenSession: (sessionName: string) => void;
}

export function SessionSidebar({ onOpenSession }: SessionSidebarProps) {
  const { sessions, isLoading, createSession, killSession, refresh } = useSessions();
  const [hostname, setHostname] = useState<string>("...");
  const [connectionStatus, setConnectionStatus] = useState<
    "connected" | "reconnecting" | "disconnected"
  >("disconnected");
  const [showNewSessionDialog, setShowNewSessionDialog] = useState(false);
  const [newSessionName, setNewSessionName] = useState("");
  const [newSessionKind, setNewSessionKind] = useState<SessionKind>("bash");
  const [skipPermissions, setSkipPermissions] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const nameInputRef = useRef<HTMLInputElement>(null);

  // Fetch server health/hostname
  useEffect(() => {
    let cancelled = false;

    async function checkHealth() {
      try {
        const res = await fetch("/api/health");
        if (!res.ok) throw new Error("unhealthy");
        const data = await res.json();
        if (!cancelled) {
          setHostname(data.hostname ?? "localhost");
          setConnectionStatus("connected");
        }
      } catch {
        if (!cancelled) {
          setConnectionStatus("disconnected");
        }
      }
    }

    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const statusColors = {
    connected: "#22C55E",
    reconnecting: "#EAB308",
    disconnected: "#EF4444",
  };

  const handleOpenDialog = () => {
    setNewSessionName("");
    setNewSessionKind("bash");
    setSkipPermissions(false);
    setCreateError(null);
    setShowNewSessionDialog(true);
    setTimeout(() => nameInputRef.current?.focus(), 50);
  };

  const slugify = (raw: string) =>
    raw
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9 ]/g, "")
      .replace(/\s+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-+|-+$/g, "");

  const previewSlug = slugify(newSessionName);

  const handleCreate = async () => {
    const name = previewSlug;
    if (!name) {
      setCreateError("Session name is required");
      return;
    }
    if (!/^[a-zA-Z0-9_.\-]+$/.test(name)) {
      setCreateError("Only letters, numbers, _ - . allowed");
      return;
    }
    if (sessions.some((s) => s.name === name)) {
      setCreateError("Session name already exists");
      return;
    }
    setCreateError(null);
    const session = await createSession(name, newSessionKind, {
      dangerouslySkipPermissions: newSessionKind === "claude" ? skipPermissions : undefined,
    });
    if (session) {
      setShowNewSessionDialog(false);
      setNewSessionName("");
      onOpenSession(session.name);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#151820] text-[13px] font-sans">
      {/* Server info header */}
      <div className="px-3 py-3 border-b border-[#2A2D3A]">
        <div className="flex items-center gap-2 mb-1">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ backgroundColor: statusColors[connectionStatus] }}
          />
          <span className="text-[#E4E4E7] font-medium truncate">{hostname}</span>
        </div>
        <span className="text-[11px] text-[#6B7280] capitalize">{connectionStatus}</span>
      </div>

      {/* Sessions header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#2A2D3A]">
        <span className="text-[11px] text-[#6B7280] uppercase tracking-wider font-medium">
          Sessions
        </span>
        <button
          onClick={() => refresh()}
          className="p-1 text-[#6B7280] hover:text-[#E4E4E7] transition-colors"
          title="Refresh sessions"
          aria-label="Refresh sessions"
        >
          <RefreshCw size={12} />
        </button>
      </div>

      {/* Session list */}
      <div className="flex-1 overflow-y-auto py-1">
        {isLoading && sessions.length === 0 ? (
          <div className="px-3 py-4 text-[#6B7280] text-center">Loading...</div>
        ) : sessions.length === 0 ? (
          <div className="px-3 py-4 text-[#6B7280] text-center">No sessions</div>
        ) : (
          sessions.map((session: TmuxSession) => (
            <button
              key={session.name}
              onClick={() => onOpenSession(session.name)}
              className="w-full flex items-center gap-2 px-3 py-2
                text-left hover:bg-[#1C1F2B] transition-colors group"
            >
              {session.kind === "claude" ? (
                <Sparkles size={14} className="text-[#A855F7] shrink-0" />
              ) : session.kind === "codex" ? (
                <Bot size={14} className="text-[#06B6D4] shrink-0" />
              ) : (
                <Terminal size={14} className="text-[#6B7280] shrink-0" />
              )}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[#E4E4E7] truncate">{session.name}</span>
                  {session.kind && session.kind !== "bash" && (
                    <span
                      className={`px-1 py-0.5 text-[9px] rounded leading-none uppercase ${
                        session.kind === "claude"
                          ? "bg-[#A855F7]/20 text-[#A855F7]"
                          : "bg-[#06B6D4]/20 text-[#06B6D4]"
                      }`}
                    >
                      {session.kind}
                    </span>
                  )}
                  {session.attached && (
                    <span className="px-1 py-0.5 text-[9px] rounded bg-[#22C55E]/20 text-[#22C55E] leading-none">
                      attached
                    </span>
                  )}
                </div>
                <span className="text-[11px] text-[#6B7280]">
                  {session.windows} window{session.windows !== 1 ? "s" : ""}
                </span>
              </div>
              <span
                role="button"
                tabIndex={0}
                onClick={(e) => {
                  e.stopPropagation();
                  killSession(session.name);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    e.stopPropagation();
                    killSession(session.name);
                  }
                }}
                className="p-1 text-[#6B7280] hover:text-[#EF4444]
                  opacity-0 group-hover:opacity-100 transition-opacity"
                title="Kill session"
                aria-label={`Kill session ${session.name}`}
              >
                &times;
              </span>
            </button>
          ))
        )}
      </div>

      {/* Engine toggle */}
      <EngineToggle />

      {/* Playground link */}
      <Link
        href="/playground"
        className="flex items-center gap-2 px-3 py-2 border-t border-[#2A2D3A]
          text-[#6B7280] hover:text-[#E4E4E7] hover:bg-[#1C1F2B] transition-colors"
      >
        <FlaskConical size={14} />
        <span className="text-[13px]">Playground</span>
        <span className="ml-auto text-[10px] text-[#3B82F6] px-1.5 py-0.5 rounded bg-[#3B82F6]/10">
          wasm
        </span>
      </Link>

      {/* Recordings link */}
      <Link
        href="/replay"
        className="flex items-center gap-2 px-3 py-2
          text-[#6B7280] hover:text-[#E4E4E7] hover:bg-[#1C1F2B] transition-colors"
      >
        <Film size={14} />
        <span className="text-[13px]">Recordings</span>
      </Link>

      {/* User section */}
      <UserSection />

      {/* New session dialog */}
      {showNewSessionDialog && (
        <div className="px-3 py-3 border-t border-[#2A2D3A] bg-[#1C1F2B]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] text-[#6B7280] uppercase tracking-wider font-medium">
              New Session
            </span>
            <button
              onClick={() => setShowNewSessionDialog(false)}
              className="p-0.5 text-[#6B7280] hover:text-[#E4E4E7] transition-colors"
            >
              <X size={12} />
            </button>
          </div>
          <input
            ref={nameInputRef}
            type="text"
            value={newSessionName}
            onChange={(e) => {
              const filtered = e.target.value.replace(/[^A-Za-z0-9 ]/g, "");
              setNewSessionName(filtered);
              setCreateError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleCreate();
              if (e.key === "Escape") setShowNewSessionDialog(false);
            }}
            placeholder="e.g. My Project"
            className="w-full px-2 py-1.5 rounded bg-[#0D0F12] border border-[#2A2D3A]
              text-[#E4E4E7] text-[13px] placeholder:text-[#6B7280]/50
              focus:outline-none focus:border-[#3B82F6] transition-colors"
          />
          {newSessionName.trim() && (
            <p className="text-[10px] text-[#6B7280] mt-1">
              Will be created as <code className="text-[#E4E4E7]">{previewSlug || "—"}</code>
            </p>
          )}

          <div className="mt-2">
            <span className="block text-[10px] text-[#6B7280] uppercase tracking-wider mb-1">
              Session kind
            </span>
            <div className="flex rounded bg-[#0D0F12] border border-[#2A2D3A] p-0.5">
              {(
                [
                  { value: "bash" as const, label: "bash", color: "#3B82F6" },
                  { value: "claude" as const, label: "claude", color: "#A855F7" },
                  { value: "codex" as const, label: "codex", color: "#06B6D4" },
                ] as const
              ).map((k) => (
                <button
                  key={k.value}
                  onClick={() => setNewSessionKind(k.value)}
                  className={`flex-1 px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                    newSessionKind === k.value
                      ? "text-white"
                      : "text-[#6B7280] hover:text-[#E4E4E7]"
                  }`}
                  style={{
                    backgroundColor: newSessionKind === k.value ? k.color : "transparent",
                  }}
                >
                  {k.label}
                </button>
              ))}
            </div>
            {newSessionKind !== "bash" && (
              <p className="text-[10px] text-[#6B7280] mt-1">
                Runs <code className="text-[#E4E4E7]">{newSessionKind}</code> CLI inside tmux — must
                be installed & logged in on the server.
              </p>
            )}
          </div>

          {newSessionKind === "claude" && (
            <label
              className={`mt-2 flex items-start gap-2 px-2 py-1.5 rounded border cursor-pointer transition-colors ${
                skipPermissions
                  ? "bg-[#EF4444]/10 border-[#EF4444]/50"
                  : "bg-[#0D0F12] border-[#2A2D3A] hover:border-[#EF4444]/40"
              }`}
            >
              <input
                type="checkbox"
                checked={skipPermissions}
                onChange={(e) => setSkipPermissions(e.target.checked)}
                className="mt-0.5 accent-[#EF4444] cursor-pointer"
              />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1 text-[11px] font-medium text-[#EF4444]">
                  <AlertTriangle size={11} />
                  <span>Dangerously skip permissions</span>
                </div>
                <p className="text-[10px] text-[#6B7280] mt-0.5 leading-tight">
                  Passes <code className="text-[#E4E4E7]">--dangerously-skip-permissions</code>.
                  Claude won&apos;t ask for approval before running tools — use only in trusted
                  sandboxes.
                </p>
              </div>
            </label>
          )}

          {createError && <p className="text-[11px] text-[#EF4444] mt-1">{createError}</p>}
          <button
            onClick={handleCreate}
            className="w-full mt-2 flex items-center justify-center gap-1.5 px-3 py-1.5
              rounded bg-[#3B82F6] text-white text-[13px] font-medium
              hover:bg-[#2563EB] transition-colors"
          >
            Create
          </button>
        </div>
      )}

      {/* New session button */}
      {!showNewSessionDialog && (
        <div className="p-2 border-t border-[#2A2D3A]">
          <button
            onClick={handleOpenDialog}
            className="w-full flex items-center justify-center gap-1.5 px-3 py-2
              rounded bg-[#1C1F2B] text-[#E4E4E7] hover:bg-[#252838] transition-colors"
          >
            <Plus size={14} />
            New Session
          </button>
        </div>
      )}
    </div>
  );
}
