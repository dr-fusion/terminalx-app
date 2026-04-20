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
    <div className="flex items-center h-9 bg-[#151820] border-b border-[#2A2D3A] overflow-x-auto">
      <div className="flex items-center min-w-0 flex-1">
        {tabs.map((tab) => {
          const isActive = tab.id === activeTab;
          return (
            <button
              key={tab.id}
              onClick={() => onSelect(tab.id)}
              className={`group relative flex items-center gap-1.5 px-3 h-9 text-[13px] font-sans
                border-r border-[#2A2D3A] transition-colors whitespace-nowrap min-w-0
                ${
                  isActive
                    ? "bg-[#0D0F12] text-[#E4E4E7]"
                    : "bg-[#151820] text-[#6B7280] hover:text-[#E4E4E7] hover:bg-[#1C1F2B]"
                }
              `}
            >
              {isActive && (
                <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#3B82F6]" />
              )}
              <span className="truncate max-w-[120px]">{tab.name}</span>
              <span
                onClick={(e) => {
                  e.stopPropagation();
                  onClose(tab.id);
                }}
                className="flex items-center justify-center w-4 h-4 rounded-sm
                  opacity-0 group-hover:opacity-100 hover:bg-[#2A2D3A] transition-opacity"
              >
                <X size={12} />
              </span>
            </button>
          );
        })}
      </div>
      <button
        onClick={onNew}
        className="flex items-center justify-center w-9 h-9 text-[#6B7280]
          hover:text-[#E4E4E7] hover:bg-[#1C1F2B] transition-colors shrink-0"
        title="New terminal"
        aria-label="New terminal"
      >
        <Plus size={16} />
      </button>
    </div>
  );
}
