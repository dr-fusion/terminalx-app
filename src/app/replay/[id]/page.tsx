"use client";

import { use } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

const ReplayView = dynamic(
  () => import("@/components/replay/ReplayView").then((m) => m.ReplayView),
  { ssr: false }
);

export default function ReplayPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);

  return (
    <div className="h-dvh w-screen flex flex-col bg-[#0a0b10] overflow-hidden">
      <div className="flex items-center h-11 px-3 bg-[#0f1117] border-b border-[#1a1d24] shrink-0 gap-3">
        <Link
          href="/replay"
          className="flex items-center gap-1.5 text-[#6b7569] hover:text-[#e6f0e4] transition-colors text-[13px]"
        >
          <ArrowLeft size={14} />
          Back
        </Link>
        <span
          className="text-[13px] font-bold text-[#00cc6e]"
          style={{ fontFamily: "var(--font-jetbrains-mono), monospace" }}
        >
          TerminalX / Replay / {id}
        </span>
      </div>
      <div className="flex-1 overflow-hidden">
        <ReplayView id={id} />
      </div>
    </div>
  );
}
