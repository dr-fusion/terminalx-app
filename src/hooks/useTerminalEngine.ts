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
  const [engine, setEngineState] = useState<TerminalEngine>(DEFAULT);

  useEffect(() => {
    setEngineState(read());
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
