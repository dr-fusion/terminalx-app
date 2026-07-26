"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { useSessions } from "@/hooks/useSessions";
import { useAuth } from "@/hooks/useAuth";
// Workspace config (feature #5): surface run scripts + "run setup" for the
// active workspace in the command palette.
import {
  useWorkspaceConfig,
  executeRunScript,
  runWorkspaceSetup,
} from "@/hooks/useWorkspaceConfig";

interface Item {
  id: string;
  label: string;
  hint?: string;
  action: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const router = useRouter();
  const pathname = usePathname();
  const { sessions } = useSessions();
  const { logout } = useAuth();
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Derive the active workspace session from the route (/workspace/<name>).
  const activeSession = useMemo(() => {
    const m = pathname?.match(/^\/workspace\/([^/]+)/);
    return m ? decodeURIComponent(m[1]!) : null;
  }, [pathname]);
  const { config: workspaceConfig } = useWorkspaceConfig(activeSession);

  useEffect(() => {
    if (open) {
      setQ("");
      setCursor(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  const items = useMemo<Item[]>(() => {
    const go = (href: string) => () => {
      onClose();
      router.push(href);
    };
    const base: Item[] = [
      { id: "dashboard", label: "sessions · dashboard", hint: "g d", action: go("/dashboard") },
      { id: "workspace", label: "workspace", hint: "g w", action: go("/workspace") },
      { id: "settings", label: "settings", hint: "g s", action: go("/settings") },
      {
        id: "signout",
        label: "sign out",
        action: () => {
          onClose();
          logout();
        },
      },
    ];
    const attachItems: Item[] = sessions.map((s) => ({
      id: `attach-${s.name}`,
      label: `attach → ${s.name}`,
      hint: s.kind ? s.kind : undefined,
      action: go(`/workspace/${encodeURIComponent(s.name)}`),
    }));

    // Run scripts for the active workspace surface as `run · <name>` entries.
    const runItems: Item[] =
      activeSession && workspaceConfig
        ? workspaceConfig.scripts.map((s) => ({
            id: `run-${s.name}`,
            label: `run · ${s.name}`,
            hint: s.description ?? "script",
            action: () => {
              onClose();
              void executeRunScript(activeSession, s.name);
            },
          }))
        : [];
    if (activeSession && workspaceConfig?.setup) {
      runItems.push({
        id: "workspace-run-setup",
        label: "workspace · run setup",
        hint: "setup",
        action: () => {
          onClose();
          void runWorkspaceSetup(activeSession);
        },
      });
    }

    return [...attachItems, ...runItems, ...base];
  }, [sessions, router, onClose, logout, activeSession, workspaceConfig]);

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    if (!query) return items;
    return items.filter((i) => i.label.toLowerCase().includes(query));
  }, [items, q]);

  useEffect(() => {
    if (cursor >= filtered.length) setCursor(0);
  }, [filtered.length, cursor]);

  if (!open) return null;

  return (
    <div
      onClick={onClose}
      className="fixed inset-0 z-[200] flex items-start justify-center pt-[12vh]"
      style={{ background: "rgba(5, 6, 10, 0.7)", backdropFilter: "blur(6px)" }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[600px] max-w-[90vw] rounded bg-[#14161e] border border-[#363b47] overflow-hidden"
        style={{ boxShadow: "0 8px 24px rgba(0, 0, 0, 0.6)" }}
      >
        <div className="flex items-center gap-2 px-3 py-3 border-b border-[#1a1d24]">
          <span className="text-[#00ff88]">&gt;</span>
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setCursor((c) => Math.min(c + 1, filtered.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setCursor((c) => Math.max(c - 1, 0));
              } else if (e.key === "Enter") {
                e.preventDefault();
                filtered[cursor]?.action();
              }
            }}
            placeholder="search commands…"
            className="flex-1 bg-transparent outline-none text-[13px] text-[#e6f0e4] placeholder:text-[#899384]"
          />
          <kbd className="px-1.5 py-0.5 bg-[#0a0b10] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
            ESC
          </kbd>
        </div>
        <div className="max-h-[360px] overflow-y-auto p-1">
          {filtered.length === 0 ? (
            <div className="px-3 py-4 text-center text-[11px] text-[#899384]">
              no matches. the void is quiet.
            </div>
          ) : (
            filtered.map((it, idx) => {
              const active = idx === cursor;
              return (
                <div
                  key={it.id}
                  onMouseEnter={() => setCursor(idx)}
                  onClick={() => it.action()}
                  className={`flex items-center px-3 py-2 rounded cursor-pointer text-[11px] ${
                    active ? "bg-[#002a17] text-[#00ff88]" : "text-[#e6f0e4]"
                  }`}
                >
                  <span className={`mr-2.5 ${active ? "text-[#00ff88]" : "text-[#899384]"}`}>
                    →
                  </span>
                  <span className="flex-1 truncate">{it.label}</span>
                  {it.hint && (
                    <span className="ml-auto text-[9px] uppercase tracking-wider text-[#899384]">
                      {it.hint}
                    </span>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
