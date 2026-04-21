"use client";

import { useState } from "react";
import { FileBrowser } from "@/components/files/FileBrowser";
import { LogViewer } from "@/components/logs/LogViewer";
import { SnippetsPanel } from "@/components/snippets/SnippetsPanel";

type RightPanelTab = "files" | "logs" | "snippets";

interface RightPanelProps {
  defaultTab?: RightPanelTab;
}

export function RightPanel({ defaultTab = "files" }: RightPanelProps) {
  const [activeTab, setActiveTab] = useState<RightPanelTab>(defaultTab);

  return (
    <div className="flex flex-col h-full bg-[#0f1117]">
      {/* Tab switcher */}
      <div className="flex items-center h-9 border-b border-[#1a1d24]">
        {(["files", "logs", "snippets"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`relative flex-1 h-full text-[13px] font-sans capitalize transition-colors
              ${activeTab === tab ? "text-[#e6f0e4]" : "text-[#6b7569] hover:text-[#e6f0e4]"}
            `}
          >
            {tab}
            {activeTab === tab && (
              <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#00cc6e]" />
            )}
          </button>
        ))}
      </div>

      {/* Panel content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "files" ? (
          <FileBrowser />
        ) : activeTab === "logs" ? (
          <LogViewer />
        ) : (
          <SnippetsPanel />
        )}
      </div>
    </div>
  );
}
