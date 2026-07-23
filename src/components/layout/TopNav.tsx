"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Command, LogOut, PanelRight, Terminal } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

interface TopNavProps {
  hostname: string;
  activeSession: string | null;
  onOpenPalette?: () => void;
}

function initials(name: string): string {
  return name.slice(0, 2).toLowerCase();
}

function sectionForPath(path: string): string {
  if (path.startsWith("/team-sessions")) return "team sessions";
  if (path.startsWith("/workspace")) return "workspace";
  if (path.startsWith("/settings")) return "settings";
  if (path.startsWith("/admin")) return "admin";
  return "sessions";
}

export function TopNav({ hostname, activeSession, onOpenPalette }: TopNavProps) {
  const path = usePathname();
  const { user, logout } = useAuth();
  const section = sectionForPath(path);

  return (
    <div
      className="flex h-12 shrink-0 items-center gap-3 border-b border-[#1a1d24] bg-[#0f1117] px-3"
      style={{ position: "sticky", top: 0, zIndex: 50 }}
    >
      <Link
        href="/dashboard"
        className="hidden items-center gap-2 text-[13px] font-medium text-[#a8b3a6] transition-colors hover:text-[#e6f0e4] sm:flex"
      >
        <span className="flex h-5 w-5 items-center justify-center rounded bg-[#002a17] text-[9px] text-[#00ff88]">
          tx
        </span>
        <span>terminalx</span>
      </Link>

      <ChevronRight size={13} className="hidden text-[#3f4742] sm:block" />

      <div className="flex min-w-0 items-center gap-2 text-[13px]">
        <span className="truncate text-[#e6f0e4]">{section}</span>
        {activeSession && (
          <>
            <ChevronRight size={13} className="text-[#3f4742]" />
            <span className="truncate text-[#a8b3a6]">{activeSession}</span>
          </>
        )}
      </div>

      <div className="flex-1" />

      <span className="hidden text-[11px] text-[#6b7569] lg:inline">{hostname}</span>

      <div className="hidden items-center gap-1 rounded border border-[#252933] bg-[#0a0b10] px-2 py-1 text-[11px] text-[#a8b3a6] md:flex">
        <Terminal size={12} className="text-[#5ccfe6]" />
        <span className="max-w-[150px] truncate">{activeSession ?? `/${section}`}</span>
      </div>

      <button
        onClick={onOpenPalette}
        className="flex shrink-0 items-center gap-2 rounded border border-[#252933] bg-[#14161e] px-2 py-1.5 text-[10px]
          text-[#6b7569] transition-colors hover:border-[#363b47] hover:text-[#e6f0e4] sm:px-2.5"
        title="command palette (⌘K)"
        aria-label="command palette"
      >
        <Command size={11} />
        <span className="hidden sm:inline">commands</span>
        <span className="hidden sm:flex ml-4 items-center gap-0.5">
          <kbd className="px-1 py-0.5 bg-[#0a0b10] border border-[#1a1d24] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
            ⌘
          </kbd>
          <kbd className="px-1 py-0.5 bg-[#0a0b10] border border-[#1a1d24] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
            K
          </kbd>
        </span>
      </button>

      {user && (
        <div className="flex shrink-0 items-center gap-2 border-l border-[#1a1d24] pl-3">
          <span
            className="flex h-6 w-6 items-center justify-center rounded-full border border-[#a76fd0] bg-[#1f1328]
              text-[10px] font-bold text-[#d58fff]"
          >
            {initials(user.username)}
          </span>
          <button
            onClick={logout}
            className="text-[10px] text-[#6b7569] hover:text-[#ff5c5c] transition-colors hidden sm:inline"
          >
            sign out
          </button>
          <button
            onClick={logout}
            className="p-1 text-[#6b7569] hover:text-[#ff5c5c] transition-colors sm:hidden"
            aria-label="sign out"
          >
            <LogOut size={12} />
          </button>
        </div>
      )}

      <PanelRight size={14} className="hidden text-[#6b7569] xl:block" />
    </div>
  );
}
