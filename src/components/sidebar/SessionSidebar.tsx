"use client";

import { useEffect, useState } from "react";
import { Terminal, Plus, RefreshCw } from "lucide-react";
import { useSessions, type TmuxSession } from "@/hooks/useSessions";

interface SessionSidebarProps {
  onOpenSession: (sessionName: string) => void;
}

export function SessionSidebar({ onOpenSession }: SessionSidebarProps) {
  const { sessions, isLoading, createSession, killSession, refresh } =
    useSessions();
  const [hostname, setHostname] = useState<string>("...");
  const [connectionStatus, setConnectionStatus] = useState<
    "connected" | "reconnecting" | "disconnected"
  >("disconnected");

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

  const handleCreate = async () => {
    const session = await createSession();
    if (session) {
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
          <span className="text-[#E4E4E7] font-medium truncate">
            {hostname}
          </span>
        </div>
        <span className="text-[11px] text-[#6B7280] capitalize">
          {connectionStatus}
        </span>
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
        >
          <RefreshCw size={12} />
        </button>
      </div>

      {/* Session list */}
      <div className="flex-1 overflow-y-auto py-1">
        {isLoading && sessions.length === 0 ? (
          <div className="px-3 py-4 text-[#6B7280] text-center">
            Loading...
          </div>
        ) : sessions.length === 0 ? (
          <div className="px-3 py-4 text-[#6B7280] text-center">
            No sessions
          </div>
        ) : (
          sessions.map((session: TmuxSession) => (
            <button
              key={session.name}
              onClick={() => onOpenSession(session.name)}
              className="w-full flex items-center gap-2 px-3 py-2
                text-left hover:bg-[#1C1F2B] transition-colors group"
            >
              <Terminal size={14} className="text-[#6B7280] shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[#E4E4E7] truncate">
                    {session.name}
                  </span>
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
                onClick={(e) => {
                  e.stopPropagation();
                  killSession(session.name);
                }}
                className="p-1 text-[#6B7280] hover:text-[#EF4444]
                  opacity-0 group-hover:opacity-100 transition-opacity"
                title="Kill session"
              >
                &times;
              </span>
            </button>
          ))
        )}
      </div>

      {/* New session button */}
      <div className="p-2 border-t border-[#2A2D3A]">
        <button
          onClick={handleCreate}
          className="w-full flex items-center justify-center gap-1.5 px-3 py-2
            rounded bg-[#1C1F2B] text-[#E4E4E7] hover:bg-[#252838] transition-colors"
        >
          <Plus size={14} />
          New Session
        </button>
      </div>
    </div>
  );
}
