"use client";

import { useState, useCallback } from "react";
import { TerminalTabs, type TerminalTab } from "./TerminalTabs";
import { TerminalView } from "./TerminalView";

let tabCounter = 0;

export function TerminalPanel() {
  const [tabs, setTabs] = useState<TerminalTab[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);

  const createTab = useCallback((sessionName?: string) => {
    const id = `tab-${++tabCounter}`;
    const name = sessionName ?? `Terminal ${tabCounter}`;
    const sessionId = sessionName ?? `session-${tabCounter}`;

    const newTab: TerminalTab = { id, name, sessionId };
    setTabs((prev) => [...prev, newTab]);
    setActiveTab(id);
    return newTab;
  }, []);

  const closeTab = useCallback(
    (id: string) => {
      setTabs((prev) => {
        const filtered = prev.filter((t) => t.id !== id);
        if (activeTab === id) {
          const idx = prev.findIndex((t) => t.id === id);
          const nextTab =
            filtered[Math.min(idx, filtered.length - 1)] ?? null;
          setActiveTab(nextTab?.id ?? null);
        }
        return filtered;
      });
    },
    [activeTab]
  );

  const handleNew = useCallback(() => {
    createTab();
  }, [createTab]);

  const activeTerminal = tabs.find((t) => t.id === activeTab);

  return (
    <div className="flex flex-col h-full bg-[#0D0F12]">
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
            <TerminalView sessionId={activeTerminal.sessionId} />
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-[#6B7280] text-[13px] font-sans">
            <div className="text-center">
              <p className="mb-2">No terminal open</p>
              <button
                onClick={handleNew}
                className="px-3 py-1.5 rounded bg-[#1C1F2B] text-[#E4E4E7]
                  hover:bg-[#252838] transition-colors text-[13px]"
              >
                New Terminal
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export { type TerminalTab };
