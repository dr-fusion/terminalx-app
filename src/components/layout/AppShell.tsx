"use client";

import { useEffect, useState } from "react";
import { useParams, usePathname } from "next/navigation";
import { TopNav } from "./TopNav";
import { StatusBar } from "./StatusBar";
import { CommandPalette } from "./CommandPalette";
import { useOpenTabs } from "@/hooks/useOpenTabs";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [hostname, setHostname] = useState("…");
  const params = useParams();
  const path = usePathname();
  const { tabs } = useOpenTabs();

  useEffect(() => {
    let cancelled = false;
    fetch("/api/health")
      .then((r) => r.json())
      .then((d) => {
        if (!cancelled) setHostname(d.hostname ?? "localhost");
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
      if (e.key === "Escape") setPaletteOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const activeSession =
    typeof params?.session === "string"
      ? params.session
      : path.startsWith("/workspace/")
        ? decodeURIComponent(path.split("/")[2] ?? "")
        : null;

  return (
    <div className="h-dvh w-screen flex flex-col bg-[#0a0b10] overflow-hidden">
      <TopNav onOpenPalette={() => setPaletteOpen(true)} />
      <main className="flex-1 min-h-0 overflow-hidden">{children}</main>
      <StatusBar hostname={hostname} session={activeSession} tabCount={tabs.length} />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
