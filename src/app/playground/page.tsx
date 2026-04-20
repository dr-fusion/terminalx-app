"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

const PlaygroundTerminal = dynamic(
  () =>
    import("@/components/playground/PlaygroundTerminal").then(
      (m) => m.PlaygroundTerminal
    ),
  { ssr: false }
);

export default function PlaygroundPage() {
  return (
    <div className="h-dvh w-screen flex flex-col bg-[#0D0F12] overflow-hidden">
      <div className="flex items-center h-11 px-3 bg-[#151820] border-b border-[#2A2D3A] shrink-0 gap-3">
        <Link
          href="/"
          className="flex items-center gap-1.5 text-[#6B7280] hover:text-[#E4E4E7] transition-colors text-[13px]"
        >
          <ArrowLeft size={14} />
          Back
        </Link>
        <span
          className="text-[13px] font-bold text-[#3B82F6]"
          style={{ fontFamily: "var(--font-jetbrains-mono), monospace" }}
        >
          TerminalX / Playground
        </span>
      </div>
      <div className="flex-1 overflow-hidden">
        <PlaygroundTerminal />
      </div>
    </div>
  );
}
