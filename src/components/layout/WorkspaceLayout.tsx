"use client";

import { useCallback, useState, useEffect } from "react";
import { Group, Panel, Separator } from "react-resizable-panels";
import { SessionSidebar } from "@/components/sidebar/SessionSidebar";
import { TerminalTabs, type TerminalTab } from "@/components/terminal/TerminalTabs";
import { TerminalView } from "@/components/terminal/TerminalView";
import { RightPanel } from "@/components/layout/RightPanel";
import { StatusBar } from "@/components/layout/StatusBar";
import { Terminal, LayoutList, FolderTree, ScrollText, Menu, X } from "lucide-react";

let tabCounter = 0;

function useIsMobile() {
  const [isMobile, setIsMobile] = useState(false);
  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 768);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);
  return isMobile;
}

type MobileView = "terminal" | "sessions" | "files" | "logs";

export default function WorkspaceLayout() {
  const [tabs, setTabs] = useState<TerminalTab[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [mobileView, setMobileView] = useState<MobileView>("terminal");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const isMobile = useIsMobile();

  const createTab = useCallback((sessionName?: string) => {
    const id = `tab-${++tabCounter}`;
    const name = sessionName ?? `Terminal ${tabCounter}`;
    const sessionId = sessionName ?? `session-${tabCounter}`;

    const newTab: TerminalTab = { id, name, sessionId };
    setTabs((prev) => [...prev, newTab]);
    setActiveTab(id);
    return newTab;
  }, []);

  const handleOpenSession = useCallback(
    (sessionName: string) => {
      const existing = tabs.find((t) => t.sessionId === sessionName);
      if (existing) {
        setActiveTab(existing.id);
      } else {
        createTab(sessionName);
      }
      if (isMobile) {
        setMobileView("terminal");
        setSidebarOpen(false);
      }
    },
    [tabs, createTab, isMobile]
  );

  const closeTab = useCallback(
    (id: string) => {
      setTabs((prev) => {
        const filtered = prev.filter((t) => t.id !== id);
        if (activeTab === id) {
          const idx = prev.findIndex((t) => t.id === id);
          const nextTab = filtered[Math.min(idx, filtered.length - 1)] ?? null;
          setActiveTab(nextTab?.id ?? null);
        }
        return filtered;
      });
    },
    [activeTab]
  );

  const handleSessionEnded = useCallback(
    (sessionId: string) => {
      // Close any tabs bound to this session, then tell the sidebar to
      // refresh so the now-dead tmux session disappears from the list.
      setTabs((prev) => {
        const dead = prev.filter((t) => t.sessionId === sessionId);
        if (dead.length === 0) return prev;
        const filtered = prev.filter((t) => t.sessionId !== sessionId);
        if (dead.some((t) => t.id === activeTab)) {
          setActiveTab(filtered[0]?.id ?? null);
        }
        return filtered;
      });
      window.dispatchEvent(new CustomEvent("terminalx:session-ended", { detail: { sessionId } }));
    },
    [activeTab]
  );

  const handleNew = useCallback(() => {
    createTab();
  }, [createTab]);

  const activeTerminal = tabs.find((t) => t.id === activeTab);

  const [hostname, setHostname] = useState<string>("…");
  useEffect(() => {
    let cancelled = false;
    fetch("/api/health")
      .then((r) => r.json())
      .then((d) => {
        if (!cancelled) setHostname(d.hostname ?? "localhost");
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  // ── Mobile Layout ──────────────────────────────────────────────────────────
  if (isMobile) {
    return (
      <div className="h-dvh w-screen bg-[#0a0b10] flex flex-col overflow-hidden">
        {/* Mobile Header */}
        <div className="flex items-center justify-between px-3 h-11 bg-[#0f1117] border-b border-[#1a1d24] shrink-0">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-1.5 text-[#6b7569] hover:text-[#e6f0e4] transition-colors"
          >
            {sidebarOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
          <span
            className="flex items-baseline gap-0 text-[14px] font-bold tracking-tight text-[#e6f0e4]"
            style={{ fontFamily: "var(--font-jetbrains-mono), monospace" }}
          >
            <span
              className="text-[#00ff88]"
              style={{ textShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
            >
              [
            </span>
            <span>terminalx</span>
            <span className="stx-cursor" style={{ height: "0.9em" }} />
          </span>
          <div className="w-8" /> {/* Spacer for centering */}
        </div>

        {/* Mobile Sidebar Overlay */}
        {sidebarOpen && (
          <div className="absolute inset-0 z-50 flex" style={{ top: 44 }}>
            <div className="w-72 h-full bg-[#0f1117] border-r border-[#1a1d24] shadow-2xl">
              <SessionSidebar onOpenSession={handleOpenSession} />
            </div>
            <div className="flex-1 bg-black/50" onClick={() => setSidebarOpen(false)} />
          </div>
        )}

        {/* Mobile Content */}
        <div className="flex-1 overflow-hidden">
          {mobileView === "terminal" && (
            <div className="flex flex-col h-full">
              <TerminalTabs
                tabs={tabs}
                activeTab={activeTab}
                onSelect={setActiveTab}
                onClose={closeTab}
                onNew={handleNew}
              />
              <div className="flex-1 relative overflow-hidden">
                {activeTerminal ? (
                  <div key={activeTerminal.id} className="absolute inset-0">
                    <TerminalView
                      sessionId={activeTerminal.sessionId}
                      onSessionEnded={handleSessionEnded}
                    />
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-full text-[#6b7569] text-[13px]">
                    <div className="text-center">
                      <p className="mb-3">no session attached.</p>
                      <button
                        onClick={() => setSidebarOpen(true)}
                        className="px-4 py-2 rounded bg-[#002a17] border border-[#00cc6e]
                          text-[#00ff88] hover:bg-[#00ff88]/10 transition-colors text-[13px]"
                        style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
                      >
                        open sessions →
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {mobileView === "sessions" && <SessionSidebar onOpenSession={handleOpenSession} />}

          {mobileView === "files" && <RightPanel defaultTab="files" />}

          {mobileView === "logs" && <RightPanel defaultTab="logs" />}
        </div>

        {/* Mobile Bottom Nav */}
        <div className="flex items-center h-14 bg-[#0f1117] border-t border-[#1a1d24] shrink-0">
          {(
            [
              { id: "terminal" as MobileView, icon: Terminal, label: "Terminal" },
              { id: "sessions" as MobileView, icon: LayoutList, label: "Sessions" },
              { id: "files" as MobileView, icon: FolderTree, label: "Files" },
              { id: "logs" as MobileView, icon: ScrollText, label: "Logs" },
            ] as const
          ).map(({ id, icon: Icon, label }) => (
            <button
              key={id}
              onClick={() => {
                setMobileView(id);
                setSidebarOpen(false);
              }}
              className={`flex-1 flex flex-col items-center justify-center gap-0.5 transition-colors ${
                mobileView === id ? "text-[#00cc6e]" : "text-[#6b7569]"
              }`}
            >
              <Icon size={20} />
              <span className="text-[10px] font-medium">{label}</span>
            </button>
          ))}
        </div>
      </div>
    );
  }

  // ── Desktop Layout ─────────────────────────────────────────────────────────
  return (
    <div className="h-screen w-screen bg-[#0a0b10] overflow-hidden flex flex-col">
      <Group orientation="horizontal" className="flex-1 min-h-0">
        {/* Left Sidebar */}
        <Panel id="sidebar" defaultSize="220px" minSize="180px" collapsible>
          <SessionSidebar onOpenSession={handleOpenSession} />
        </Panel>

        <Separator className="w-px bg-[#1a1d24] hover:bg-[#00cc6e] active:bg-[#00cc6e] transition-colors" />

        {/* Center Terminal */}
        <Panel id="terminal" minSize="200px">
          <div className="flex flex-col h-full bg-[#0a0b10]">
            <TerminalTabs
              tabs={tabs}
              activeTab={activeTab}
              onSelect={setActiveTab}
              onClose={closeTab}
              onNew={handleNew}
            />
            <div className="flex-1 relative overflow-hidden">
              {activeTerminal ? (
                <div key={activeTerminal.id} className="absolute inset-0">
                  <TerminalView
                    sessionId={activeTerminal.sessionId}
                    onSessionEnded={handleSessionEnded}
                  />
                </div>
              ) : (
                <div className="flex items-center justify-center h-full text-[#6b7569] text-[13px]">
                  <div className="text-center">
                    <p className="mb-3">no session attached.</p>
                    <button
                      onClick={handleNew}
                      className="px-3 py-1.5 rounded bg-[#002a17] border border-[#00cc6e]
                        text-[#00ff88] hover:bg-[#00ff88]/10 transition-colors text-[13px]"
                      style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
                    >
                      spawn one →
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </Panel>

        <Separator className="w-px bg-[#1a1d24] hover:bg-[#00cc6e] active:bg-[#00cc6e] transition-colors" />

        {/* Right Panel */}
        <Panel id="right-panel" defaultSize="320px" minSize="200px" collapsible>
          <RightPanel />
        </Panel>
      </Group>

      <StatusBar
        hostname={hostname}
        session={activeTerminal?.sessionId ?? null}
        tabCount={tabs.length}
      />
    </div>
  );
}
