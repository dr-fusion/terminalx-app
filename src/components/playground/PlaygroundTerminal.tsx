"use client";

import { useCallback, useRef, useState } from "react";
import { Terminal, useTerminal } from "@wterm/react";
import { BashShell } from "@wterm/just-bash";
import "@wterm/react/css";

const THEMES = [
  { label: "Default", value: undefined },
  { label: "Solarized Dark", value: "solarized-dark" },
  { label: "Monokai", value: "monokai" },
  { label: "Light", value: "light" },
] as const;

const INITIAL_FILES: Record<string, string> = {
  "/home/user/README.md":
    "# TerminalX Playground\n\nIn-browser bash running on WebAssembly.\nNo server, no PTY — everything executes locally.\n\nTry: ls, cat README.md, help\n",
  "/home/user/examples/hello.sh":
    '#!/bin/bash\necho "Hello from the playground!"\necho "Date: $(date)"\n',
};

export function PlaygroundTerminal() {
  const { ref, write } = useTerminal();
  const [themeLabel, setThemeLabel] = useState<string>("Default");
  const theme = THEMES.find((t) => t.label === themeLabel)?.value;
  const shellRef = useRef<BashShell | null>(null);

  const handleReady = useCallback(() => {
    if (shellRef.current) return;
    const shell = new BashShell({
      files: INITIAL_FILES,
      greeting: [
        "TerminalX Playground — bash in your browser",
        "Powered by just-bash · no backend required",
        "",
        "Try: ls, cat README.md, bash examples/hello.sh",
        "",
      ],
    });
    shellRef.current = shell;
    shell.attach(write);
  }, [write]);

  const handleData = useCallback((data: string) => {
    shellRef.current?.handleInput(data);
  }, []);

  return (
    <div className="flex flex-col h-full bg-[#0D0F12]">
      <div className="flex items-center justify-between px-3 h-9 bg-[#151820] border-b border-[#2A2D3A] shrink-0">
        <span
          className="text-[12px] text-[#E4E4E7]"
          style={{ fontFamily: "var(--font-jetbrains-mono), monospace" }}
        >
          Playground · in-browser bash
        </span>
        <div className="flex items-center gap-2">
          <label className="text-[11px] text-[#6B7280]">Theme</label>
          <select
            value={themeLabel}
            onChange={(e) => setThemeLabel(e.target.value)}
            className="h-6 px-1.5 rounded bg-[#1C1F2B] border border-[#2A2D3A] text-[11px] text-[#E4E4E7]"
          >
            {THEMES.map((t) => (
              <option key={t.label} value={t.label}>
                {t.label}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="flex-1 overflow-hidden p-2">
        <Terminal
          ref={ref}
          autoResize
          wasmUrl="/wterm.wasm"
          theme={theme}
          onData={handleData}
          onReady={handleReady}
          className="h-full w-full"
        />
      </div>
    </div>
  );
}
