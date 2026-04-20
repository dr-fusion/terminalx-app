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
    <div className="flex flex-col h-full bg-[#151820]">
      {/* Tab switcher */}
      <div className="flex items-center h-9 border-b border-[#2A2D3A]">
        {(["files", "logs", "snippets"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`relative flex-1 h-full text-[13px] font-sans capitalize transition-colors
              ${
                activeTab === tab
                  ? "text-[#E4E4E7]"
                  : "text-[#6B7280] hover:text-[#E4E4E7]"
              }
            `}
          >
            {tab}
            {activeTab === tab && (
              <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#3B82F6]" />
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
