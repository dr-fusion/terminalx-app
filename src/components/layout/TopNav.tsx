"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Command, LogOut } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

interface TopNavProps {
  onOpenPalette?: () => void;
}

const tabs = [
  { href: "/dashboard", label: "sessions", match: /^\/dashboard/ },
  { href: "/workspace", label: "workspace", match: /^\/workspace/ },
  { href: "/settings", label: "settings", match: /^\/settings/ },
];

function initials(name: string): string {
  return name.slice(0, 2).toLowerCase();
}

export function TopNav({ onOpenPalette }: TopNavProps) {
  const path = usePathname();
  const { user, logout } = useAuth();

  return (
    <div
      className="h-12 flex items-center gap-3 sm:gap-5 px-3 sm:px-4 border-b border-[#1a1d24] bg-[#0a0b10] shrink-0"
      style={{ position: "sticky", top: 0, zIndex: 50 }}
    >
      <Link
        href="/dashboard"
        className="flex items-baseline gap-0 text-[15px] sm:text-[16px] font-bold tracking-tight text-[#e6f0e4] shrink-0"
      >
        <span className="text-[#00ff88]" style={{ textShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}>
          [
        </span>
        <span>terminalx</span>
        <span className="stx-cursor" style={{ height: "0.9em" }} />
      </Link>

      <div className="flex h-12 min-w-0 overflow-x-auto no-scrollbar">
        {tabs.map((t) => {
          const active = t.match.test(path);
          return (
            <Link
              key={t.href}
              href={t.href}
              className={`px-2.5 sm:px-3 flex items-center text-[11px] relative shrink-0 ${
                active ? "text-[#e6f0e4]" : "text-[#6b7569] hover:text-[#e6f0e4]"
              } transition-colors`}
              style={{
                borderBottom: active ? "2px solid #00ff88" : "2px solid transparent",
                marginBottom: -1,
                boxShadow: active ? "inset 0 -2px 0 0 rgba(0, 255, 136, 0.35)" : undefined,
              }}
            >
              {t.label}
            </Link>
          );
        })}
      </div>

      <div className="flex-1" />

      <button
        onClick={onOpenPalette}
        className="flex items-center gap-2 bg-[#14161e] border border-[#252933] hover:border-[#363b47]
          rounded px-2 sm:px-2.5 py-1.5 text-[10px] text-[#6b7569] transition-colors shrink-0"
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
        <div className="flex items-center gap-2 pl-3 border-l border-[#1a1d24] shrink-0">
          <span
            className="w-6 h-6 rounded-full bg-[#1f1328] border border-[#a76fd0]
              text-[#d58fff] text-[10px] font-bold flex items-center justify-center"
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
    </div>
  );
}
