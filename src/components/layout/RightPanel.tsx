"use client";

import { useState } from "react";
import { CheckCircle2, Files, GitBranch } from "lucide-react";
import { FileBrowser } from "@/components/files/FileBrowser";
import { LogViewer } from "@/components/logs/LogViewer";
import { SnippetsPanel } from "@/components/snippets/SnippetsPanel";

type RightPanelTab = "files" | "logs" | "snippets";

interface RightPanelProps {
  defaultTab?: RightPanelTab;
}

export function RightPanel({ defaultTab = "files" }: RightPanelProps) {
  const [activeTab, setActiveTab] = useState<RightPanelTab>(defaultTab);
  const tabs = [
    { id: "files", label: "All files", icon: Files },
    { id: "logs", label: "Logs", icon: GitBranch },
    { id: "snippets", label: "Snippets", icon: CheckCircle2 },
  ] as const;

  return (
    <div className="flex h-full flex-col bg-[#0a0b10]">
      <div className="flex h-12 shrink-0 items-center gap-2 border-b border-[#1a1d24] bg-[#0f1117] px-3">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`relative flex h-8 items-center gap-1.5 rounded px-2 text-[12px] transition-colors ${
              activeTab === tab.id
                ? "bg-[#14161e] text-[#e6f0e4]"
                : "text-[#899384] hover:bg-[#14161e] hover:text-[#e6f0e4]"
            }`}
          >
            <tab.icon size={13} />
            <span>{tab.label}</span>
          </button>
        ))}
        <span className="flex-1" />
      </div>

      <div className="min-h-0 flex-1 overflow-hidden">
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
