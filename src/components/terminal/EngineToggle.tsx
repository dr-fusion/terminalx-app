"use client";

import { useTerminalEngine } from "@/hooks/useTerminalEngine";
import type { TerminalEngine } from "./types";

const ENGINES: { value: TerminalEngine; label: string; hint: string }[] = [
  { value: "xterm", label: "xterm.js", hint: "canvas · addons · default" },
  { value: "wterm", label: "wterm", hint: "DOM · native find · wasm" },
];

export function EngineToggle() {
  const { engine, setEngine } = useTerminalEngine();

  return (
    <div className="px-3 py-2 border-t border-[#2A2D3A]">
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[10px] text-[#6B7280] uppercase tracking-wider font-medium">
          Terminal Engine
        </span>
        <span className="text-[10px] text-[#6B7280]" title={ENGINES.find((e) => e.value === engine)?.hint}>
          reloads new tabs
        </span>
      </div>
      <div className="flex rounded bg-[#0D0F12] border border-[#2A2D3A] p-0.5">
        {ENGINES.map((e) => (
          <button
            key={e.value}
            onClick={() => setEngine(e.value)}
            className={`flex-1 px-2 py-1 rounded text-[11px] font-mono transition-colors ${
              engine === e.value
                ? "bg-[#3B82F6] text-white"
                : "text-[#6B7280] hover:text-[#E4E4E7]"
            }`}
            title={e.hint}
          >
            {e.label}
          </button>
        ))}
      </div>
    </div>
  );
}
