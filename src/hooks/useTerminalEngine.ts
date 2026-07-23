"use client";

import { useCallback, useEffect, useState } from "react";
import type { TerminalEngine } from "@/components/terminal/types";

const KEY = "terminalx.engine";
const DEFAULT: TerminalEngine = "xterm";

function read(): TerminalEngine {
  if (typeof window === "undefined") return DEFAULT;
  const v = window.localStorage.getItem(KEY);
  return v === "wterm" || v === "xterm" ? v : DEFAULT;
}

export function useTerminalEngine() {
  // TerminalView is client-only, so read the persisted engine on its first
  // render. Starting with xterm and switching in an effect briefly attaches
  // the wrong renderer (and therefore an extra tmux client) for wterm users.
  const [engine, setEngineState] = useState<TerminalEngine>(read);

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === KEY) setEngineState(read());
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const setEngine = useCallback((next: TerminalEngine) => {
    window.localStorage.setItem(KEY, next);
    setEngineState(next);
  }, []);

  return { engine, setEngine };
}
