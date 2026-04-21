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
    <div className="px-3 py-2 border-t border-[#1a1d24]">
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[10px] text-[#6b7569] uppercase tracking-wider font-medium">
          Terminal Engine
        </span>
        <span
          className="text-[10px] text-[#6b7569]"
          title={ENGINES.find((e) => e.value === engine)?.hint}
        >
          reloads new tabs
        </span>
      </div>
      <div className="flex rounded bg-[#0a0b10] border border-[#1a1d24] p-0.5">
        {ENGINES.map((e) => (
          <button
            key={e.value}
            onClick={() => setEngine(e.value)}
            className={`flex-1 px-2 py-1 rounded text-[11px] font-mono transition-colors ${
              engine === e.value ? "bg-[#00cc6e] text-white" : "text-[#6b7569] hover:text-[#e6f0e4]"
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
