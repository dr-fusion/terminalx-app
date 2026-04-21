"use client";

import { useCallback, useEffect, useState } from "react";

const STORAGE_KEY = "terminalx:open-tabs";

function read(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

function write(tabs: string[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(tabs));
    window.dispatchEvent(new CustomEvent("terminalx:tabs-changed"));
  } catch {
    // ignore
  }
}

export function useOpenTabs() {
  const [tabs, setTabs] = useState<string[]>([]);

  useEffect(() => {
    setTabs(read());
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) setTabs(read());
    };
    const onEnd = (e: Event) => {
      const detail = (e as CustomEvent<{ sessionId: string }>).detail;
      if (detail?.sessionId) {
        setTabs((prev) => {
          const next = prev.filter((s) => s !== detail.sessionId);
          write(next);
          return next;
        });
      }
    };
    const onTabsChanged = () => setTabs(read());
    window.addEventListener("storage", onStorage);
    window.addEventListener("terminalx:session-ended", onEnd);
    window.addEventListener("terminalx:tabs-changed", onTabsChanged);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("terminalx:session-ended", onEnd);
      window.removeEventListener("terminalx:tabs-changed", onTabsChanged);
    };
  }, []);

  const openTab = useCallback((sessionId: string) => {
    setTabs((prev) => {
      if (prev.includes(sessionId)) return prev;
      const next = [...prev, sessionId];
      write(next);
      return next;
    });
  }, []);

  const closeTab = useCallback((sessionId: string) => {
    setTabs((prev) => {
      const next = prev.filter((s) => s !== sessionId);
      write(next);
      return next;
    });
  }, []);

  return { tabs, openTab, closeTab };
}
