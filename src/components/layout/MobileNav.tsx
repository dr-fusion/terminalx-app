"use client";

import { useEffect, useRef } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  History,
  Inbox,
  RotateCcw,
  Settings,
  Terminal,
  UsersRound,
  X,
  type LucideIcon,
} from "lucide-react";
import { InboxBadge } from "@/components/attention/InboxBadge";

export interface MobileNavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

export const MOBILE_NAV_ITEMS: MobileNavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: History },
  { href: "/team-sessions", label: "Team sessions", icon: UsersRound },
  { href: "/inbox", label: "Inbox", icon: Inbox },
  { href: "/playground", label: "Playground", icon: Terminal },
  { href: "/replay", label: "Replays", icon: RotateCcw },
  { href: "/settings", label: "Settings", icon: Settings },
];

/** Whether a nav item is the active route. Exported for unit testing. */
export function isMobileNavItemActive(itemHref: string, pathname: string): boolean {
  return pathname === itemHref || pathname.startsWith(`${itemHref}/`);
}

interface MobileNavProps {
  open: boolean;
  onClose: () => void;
}

/**
 * Off-canvas primary navigation for viewports below `lg`, where the desktop
 * left rail is hidden. It is a modal dialog: focus moves to the close control on
 * open, Escape and backdrop dismiss it, and body scroll is locked while open.
 */
export function MobileNav({ open, onClose }: MobileNavProps) {
  const pathname = usePathname();
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[80] lg:hidden">
      <button
        type="button"
        aria-label="Close navigation"
        tabIndex={-1}
        className="absolute inset-0 bg-black/60"
        onClick={onClose}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Primary navigation"
        className="absolute inset-y-0 left-0 flex w-[280px] max-w-[85vw] flex-col border-r border-[#1a1d24] bg-[#0f1117] shadow-xl"
      >
        <div className="flex h-12 items-center gap-3 border-b border-[#1a1d24] px-3">
          <span className="flex h-6 w-6 items-center justify-center rounded border border-[#252933] bg-[#002a17] text-[10px] font-medium text-[#00ff88]">
            tx
          </span>
          <span className="text-[13px] font-medium text-[#e6f0e4]">terminalx</span>
          <span className="flex-1" />
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label="Close navigation"
            className="flex size-9 items-center justify-center rounded text-[#899384] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4] focus-visible:ring-2 focus-visible:ring-[#00cc6e]"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <nav
          aria-label="Primary"
          className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto p-2"
        >
          {MOBILE_NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = isMobileNavItemActive(href, pathname);
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                onClick={onClose}
                className={`flex min-h-11 items-center gap-3 rounded px-3 text-sm transition-colors focus-visible:ring-2 focus-visible:ring-[#00cc6e] ${
                  active
                    ? "bg-[#14161e] text-[#e6f0e4]"
                    : "text-[#a8b3a6] hover:bg-[#14161e] hover:text-[#e6f0e4]"
                }`}
              >
                <Icon
                  size={16}
                  className={active ? "text-[#00ff88]" : "text-[#899384]"}
                  aria-hidden="true"
                />
                <span className="flex-1">{label}</span>
                {href === "/inbox" ? <InboxBadge /> : null}
              </Link>
            );
          })}
        </nav>
      </div>
    </div>
  );
}
