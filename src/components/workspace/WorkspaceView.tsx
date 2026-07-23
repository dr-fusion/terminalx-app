"use client";

import { useCallback, useEffect, useMemo } from "react";
import { useRouter } from "next/navigation";
import { Plus, X } from "lucide-react";
import dynamic from "next/dynamic";
import { useOpenTabs } from "@/hooks/useOpenTabs";
import { useSessions } from "@/hooks/useSessions";

const TerminalView = dynamic(
  () => import("@/components/terminal/TerminalView").then((m) => m.TerminalView),
  { ssr: false }
);

interface WorkspaceViewProps {
  activeSession: string | null;
}

function firstLiveTab(
  candidates: string[],
  liveSessionIds: ReadonlySet<string>,
  excluded?: string
): string | undefined {
  return candidates.find((tab) => tab !== excluded && liveSessionIds.has(tab));
}

export function WorkspaceView({ activeSession }: WorkspaceViewProps) {
  const router = useRouter();
  const { tabs, openTab, closeTab, reconcileTabs } = useOpenTabs();
  const { sessionNames, hasLoadedSuccessfully } = useSessions();
  const liveSessionIds = useMemo(() => new Set(sessionNames), [sessionNames]);

  useEffect(() => {
    if (!activeSession) return;
    if (liveSessionIds.has(activeSession)) {
      openTab(activeSession);
      return;
    }
    if (!hasLoadedSuccessfully) return;

    // A stale deep link or browser-history entry must not recreate a ghost
    // tab. Replace it so Back does not immediately revive the dead URL.
    const remaining = reconcileTabs(liveSessionIds);
    const fallback = firstLiveTab(remaining, liveSessionIds);
    router.replace(fallback ? `/workspace/${encodeURIComponent(fallback)}` : "/dashboard");
  }, [activeSession, hasLoadedSuccessfully, liveSessionIds, openTab, reconcileTabs, router]);

  const handleSessionEnded = useCallback(
    (sessionId: string) => {
      window.dispatchEvent(new CustomEvent("terminalx:session-ended", { detail: { sessionId } }));
      const remainingTabs = closeTab(sessionId);
      if (sessionId === activeSession) {
        const fallback = firstLiveTab(remainingTabs, liveSessionIds, sessionId);
        if (fallback) {
          router.push(`/workspace/${encodeURIComponent(fallback)}`);
        } else {
          router.push("/dashboard");
        }
      }
    },
    [activeSession, closeTab, liveSessionIds, router]
  );

  const selectTab = useCallback(
    (t: string) => router.push(`/workspace/${encodeURIComponent(t)}`),
    [router]
  );

  const handleCloseTab = useCallback(
    (t: string) => {
      const remainingTabs = closeTab(t);
      if (t === activeSession) {
        const fallback = firstLiveTab(remainingTabs, liveSessionIds);
        if (fallback) {
          router.push(`/workspace/${encodeURIComponent(fallback)}`);
        } else {
          router.push("/dashboard");
        }
      }
    },
    [activeSession, closeTab, liveSessionIds, router]
  );

  const activeSessionExists = activeSession ? liveSessionIds.has(activeSession) : false;

  if (activeSession && hasLoadedSuccessfully && !activeSessionExists) {
    return (
      <div className="flex h-full items-center justify-center text-[13px] text-[#6b7569]">
        session no longer exists; returning to a live workspace…
      </div>
    );
  }

  if (!activeSession) {
    return (
      <div className="h-full flex items-center justify-center text-[13px] text-[#6b7569]">
        <div className="text-center">
          <p className="mb-3">no session attached.</p>
          <button
            onClick={() => router.push("/dashboard")}
            className="px-3 py-1.5 rounded bg-[#002a17] border border-[#00cc6e]
              text-[#00ff88] hover:bg-[#00ff88]/10 transition-colors text-[13px]"
            style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
          >
            pick one →
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-[#0a0b10]">
      <div className="flex items-center h-8 bg-[#0f1117] border-b border-[#1a1d24] overflow-x-auto no-scrollbar shrink-0">
        <div className="flex items-center min-w-0 flex-1">
          {tabs.map((t) => {
            const active = t === activeSession;
            return (
              <button
                key={t}
                data-testid="workspace-tab"
                data-session={t}
                onClick={() => selectTab(t)}
                className={`group relative flex items-center gap-1.5 px-3 h-8 text-[11px]
                  border-r border-[#1a1d24] transition-colors whitespace-nowrap ${
                    active
                      ? "bg-[#0a0b10] text-[#e6f0e4]"
                      : "bg-[#0f1117] text-[#6b7569] hover:text-[#e6f0e4] hover:bg-[#14161e]"
                  }`}
              >
                {active && (
                  <span
                    className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#00ff88]"
                    style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
                  />
                )}
                <span className="truncate max-w-[160px]">{t}</span>
                <span
                  onClick={(e) => {
                    e.stopPropagation();
                    handleCloseTab(t);
                  }}
                  className="flex items-center justify-center w-4 h-4 rounded-sm
                    opacity-0 group-hover:opacity-100 hover:bg-[#1a1d24] transition-opacity"
                >
                  <X size={11} />
                </span>
              </button>
            );
          })}
        </div>
        <button
          onClick={() => router.push("/dashboard")}
          className="flex items-center justify-center w-8 h-8 text-[#6b7569]
            hover:text-[#e6f0e4] hover:bg-[#14161e] transition-colors shrink-0"
          title="new session (dashboard)"
          aria-label="new session"
        >
          <Plus size={14} />
        </button>
      </div>
      <div className="flex-1 min-h-0 relative">
        <div key={activeSession} className="absolute inset-0">
          <TerminalView sessionId={activeSession} onSessionEnded={handleSessionEnded} />
        </div>
      </div>
    </div>
  );
}
