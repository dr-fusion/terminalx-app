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
    connected: "#00ff88",
    reconnecting: "#ffb454",
    disconnected: "#ff5c5c",
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
    <div className="flex flex-col h-full bg-[#0f1117] text-[13px]">
      {/* Brand + server info header */}
      <div className="px-3 py-3 border-b border-[#1a1d24]">
        <div className="flex items-baseline gap-0 mb-2 font-mono font-bold text-[16px] tracking-tight text-[#e6f0e4]">
          <span
            className="text-[#00ff88]"
            style={{ textShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
          >
            [
          </span>
          <span>terminalx</span>
          <span className="stx-cursor" style={{ height: "0.9em" }} />
        </div>
        <div className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{
              backgroundColor: statusColors[connectionStatus],
              boxShadow:
                connectionStatus === "connected" ? "0 0 6px rgba(0, 255, 136, 0.6)" : "none",
            }}
          />
          <span className="text-[11px] text-[#a8b3a6] truncate">{hostname}</span>
          <span className="text-[10px] text-[#6b7569] uppercase tracking-wider ml-auto">
            {connectionStatus === "connected" ? "live" : connectionStatus}
          </span>
        </div>
      </div>

      {/* Sessions header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#1a1d24]">
        <span className="text-[10px] text-[#6b7569] uppercase tracking-wider font-medium">
          sessions
        </span>
        <button
          onClick={() => refresh()}
          className="p-1 text-[#6b7569] hover:text-[#00ff88] transition-colors"
          title="refresh"
          aria-label="refresh sessions"
        >
          <RefreshCw size={12} />
        </button>
      </div>

      {/* Session list */}
      <div className="flex-1 overflow-y-auto py-1">
        {isLoading && sessions.length === 0 ? (
          <div className="px-3 py-4 text-[#6b7569] text-center text-[11px]">resurrecting tmux…</div>
        ) : sessions.length === 0 ? (
          <div className="px-3 py-4 text-[#6b7569] text-center text-[11px]">
            no sessions. the box is lonely.
          </div>
        ) : (
          sessions.map((session: TmuxSession) => (
            <button
              key={session.name}
              onClick={() => onOpenSession(session.name)}
              className="w-full flex items-center gap-2 px-3 py-2
                text-left hover:bg-[#14161e] transition-colors group"
            >
              {session.kind === "claude" ? (
                <Sparkles size={14} className="text-[#d58fff] shrink-0" />
              ) : session.kind === "codex" ? (
                <Bot size={14} className="text-[#5ccfe6] shrink-0" />
              ) : (
                <Terminal size={14} className="text-[#6b7569] shrink-0" />
              )}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[#e6f0e4] truncate">{session.name}</span>
                  {session.kind && session.kind !== "bash" && (
                    <span
                      className={`px-1 py-0.5 text-[9px] rounded leading-none uppercase ${
                        session.kind === "claude"
                          ? "bg-[#d58fff]/20 text-[#d58fff]"
                          : "bg-[#5ccfe6]/20 text-[#5ccfe6]"
                      }`}
                    >
                      {session.kind}
                    </span>
                  )}
                  {session.attached && (
                    <span className="px-1 py-0.5 text-[9px] rounded bg-[#00ff88]/20 text-[#00ff88] leading-none">
                      attached
                    </span>
                  )}
                </div>
                <span className="text-[11px] text-[#6b7569]">
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
                className="p-1 text-[#6b7569] hover:text-[#ff5c5c]
                  opacity-0 group-hover:opacity-100 transition-opacity"
                title="kill session"
                aria-label={`kill session ${session.name}`}
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
        className="flex items-center gap-2 px-3 py-2 border-t border-[#1a1d24]
          text-[#6b7569] hover:text-[#e6f0e4] hover:bg-[#14161e] transition-colors"
      >
        <FlaskConical size={14} />
        <span className="text-[13px]">playground</span>
        <span className="ml-auto text-[9px] text-[#00ff88] px-1.5 py-0.5 rounded bg-[#00ff88]/10 uppercase tracking-wider">
          wasm
        </span>
      </Link>

      {/* Recordings link */}
      <Link
        href="/replay"
        className="flex items-center gap-2 px-3 py-2
          text-[#6b7569] hover:text-[#e6f0e4] hover:bg-[#14161e] transition-colors"
      >
        <Film size={14} />
        <span className="text-[13px]">recordings</span>
      </Link>

      {/* User section */}
      <UserSection />

      {/* New session dialog */}
      {showNewSessionDialog && (
        <div className="px-3 py-3 border-t border-[#1a1d24] bg-[#14161e]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-[#6b7569] uppercase tracking-wider font-medium">
              new session
            </span>
            <button
              onClick={() => setShowNewSessionDialog(false)}
              className="p-0.5 text-[#6b7569] hover:text-[#e6f0e4] transition-colors"
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
            placeholder="my-project"
            className="w-full px-2 py-1.5 rounded bg-[#07080c] border border-[#252933]
              text-[#e6f0e4] text-[13px] placeholder:text-[#6b7569]/50
              focus:outline-none focus:border-[#00ff88] focus:shadow-[0_0_6px_rgba(0,255,136,0.35)] transition-colors"
          />
          {newSessionName.trim() && (
            <p className="text-[10px] text-[#6b7569] mt-1">
              →{" "}
              <code className="text-[#00cc6e] bg-transparent border-0 px-0">
                {previewSlug || "—"}
              </code>
            </p>
          )}

          <div className="mt-2">
            <span className="block text-[10px] text-[#6b7569] uppercase tracking-wider mb-1">
              session kind
            </span>
            <div className="flex rounded bg-[#0a0b10] border border-[#1a1d24] p-0.5">
              {(
                [
                  { value: "bash" as const, label: "bash", color: "#00cc6e" },
                  { value: "claude" as const, label: "claude", color: "#d58fff" },
                  { value: "codex" as const, label: "codex", color: "#5ccfe6" },
                ] as const
              ).map((k) => (
                <button
                  key={k.value}
                  onClick={() => setNewSessionKind(k.value)}
                  className={`flex-1 px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                    newSessionKind === k.value
                      ? "text-white"
                      : "text-[#6b7569] hover:text-[#e6f0e4]"
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
              <p className="text-[10px] text-[#6b7569] mt-1">
                Runs <code className="text-[#e6f0e4]">{newSessionKind}</code> CLI inside tmux — must
                be installed & logged in on the server.
              </p>
            )}
          </div>

          {newSessionKind === "claude" && (
            <label
              className={`mt-2 flex items-start gap-2 px-2 py-1.5 rounded border cursor-pointer transition-colors ${
                skipPermissions
                  ? "bg-[#ff5c5c]/10 border-[#ff5c5c]/50"
                  : "bg-[#0a0b10] border-[#1a1d24] hover:border-[#ff5c5c]/40"
              }`}
            >
              <input
                type="checkbox"
                checked={skipPermissions}
                onChange={(e) => setSkipPermissions(e.target.checked)}
                className="mt-0.5 accent-[#ff5c5c] cursor-pointer"
              />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1 text-[11px] font-medium text-[#ff5c5c]">
                  <AlertTriangle size={11} />
                  <span>Dangerously skip permissions</span>
                </div>
                <p className="text-[10px] text-[#6b7569] mt-0.5 leading-tight">
                  Passes <code className="text-[#e6f0e4]">--dangerously-skip-permissions</code>.
                  Claude won&apos;t ask for approval before running tools — use only in trusted
                  sandboxes.
                </p>
              </div>
            </label>
          )}

          {createError && <p className="text-[11px] text-[#ff5c5c] mt-1">{createError}</p>}
          <button
            onClick={handleCreate}
            className="w-full mt-2 flex items-center justify-center gap-1.5 px-3 py-1.5
              rounded bg-[#002a17] text-[#00ff88] text-[13px] font-medium
              border border-[#00cc6e] hover:bg-[#00ff88]/10 transition-colors"
            style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
          >
            create →
          </button>
        </div>
      )}

      {/* New session button */}
      {!showNewSessionDialog && (
        <div className="p-2 border-t border-[#1a1d24]">
          <button
            onClick={handleOpenDialog}
            className="w-full flex items-center justify-center gap-1.5 px-3 py-2
              rounded bg-[#14161e] border border-[#252933] text-[#e6f0e4]
              hover:border-[#00cc6e] hover:text-[#00ff88] transition-colors"
          >
            <Plus size={14} />
            new session
          </button>
        </div>
      )}
    </div>
  );
}
