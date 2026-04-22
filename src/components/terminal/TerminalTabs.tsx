"use client";

import { Plus, X } from "lucide-react";

export interface TerminalTab {
  id: string;
  name: string;
  sessionId: string;
}

interface TerminalTabsProps {
  tabs: TerminalTab[];
  activeTab: string | null;
  onSelect: (id: string) => void;
  onClose: (id: string) => void;
  onNew: () => void;
}

export function TerminalTabs({ tabs, activeTab, onSelect, onClose, onNew }: TerminalTabsProps) {
  return (
    <div className="flex items-center h-9 bg-[#0f1117] border-b border-[#1a1d24] overflow-x-auto">
      <div className="flex items-center min-w-0 flex-1">
        {tabs.map((tab) => {
          const isActive = tab.id === activeTab;
          return (
            <button
              key={tab.id}
              onClick={() => onSelect(tab.id)}
              className={`group relative flex items-center gap-1.5 px-3 h-9 text-[13px] font-sans
                border-r border-[#1a1d24] transition-colors whitespace-nowrap min-w-0
                ${
                  isActive
                    ? "bg-[#0a0b10] text-[#e6f0e4]"
                    : "bg-[#0f1117] text-[#6b7569] hover:text-[#e6f0e4] hover:bg-[#14161e]"
                }
              `}
            >
              {isActive && (
                <span
                  className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#00ff88]"
                  style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
                />
              )}
              <span className="truncate max-w-[120px]">{tab.name}</span>
              <span
                onClick={(e) => {
                  e.stopPropagation();
                  onClose(tab.id);
                }}
                className="flex items-center justify-center w-4 h-4 rounded-sm
                  opacity-0 group-hover:opacity-100 hover:bg-[#1a1d24] transition-opacity"
              >
                <X size={12} />
              </span>
            </button>
          );
        })}
      </div>
      <button
        onClick={onNew}
        className="flex items-center justify-center w-9 h-9 text-[#6b7569]
          hover:text-[#e6f0e4] hover:bg-[#14161e] transition-colors shrink-0"
        title="New terminal"
        aria-label="New terminal"
      >
        <Plus size={16} />
      </button>
    </div>
  );
}
