"use client";

import { useEffect, useState } from "react";

interface StatusBarProps {
  hostname: string;
  session: string | null;
  tabCount: number;
}

function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

const SEP = <span className="text-[#363b47]">│</span>;

export function StatusBar({ hostname, session, tabCount }: StatusBarProps) {
  const time = useClock();

  return (
    <div
      className="flex items-center h-7 px-3 gap-3 bg-[#14161e] border-t border-[#252933]
        text-[11px] text-[#a8b3a6] shrink-0 select-none"
      style={{ fontVariantNumeric: "tabular-nums" }}
    >
      <span className="flex items-center gap-1.5 shrink-0">
        <span
          className="w-2 h-2 rounded-full bg-[#00ff88] shrink-0"
          style={{ boxShadow: "0 0 6px #00ff88" }}
        />
        <span className="text-[#00ff88]" style={{ textShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}>
          {hostname}
        </span>
      </span>
      <span className="hidden sm:inline">{SEP}</span>
      <span className="text-[#e6f0e4] truncate min-w-0 flex-shrink">{session ?? "no session"}</span>
      <span className="hidden sm:inline">{SEP}</span>
      <span className="text-[#6b7569] whitespace-nowrap shrink-0 hidden sm:inline">
        {tabCount} {tabCount === 1 ? "pane" : "panes"}
      </span>
      <span className="flex-1" />
      <span className="text-[#6b7569] hidden md:inline shrink-0">
        <kbd className="px-1 py-0.5 bg-[#0f1117] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
          ⌃
        </kbd>
        <kbd className="ml-1 px-1 py-0.5 bg-[#0f1117] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
          B
        </kbd>
        <span className="ml-1.5">prefix</span>
      </span>
      <span className="hidden md:inline">{SEP}</span>
      <span className="shrink-0">{time}</span>
    </div>
  );
}
