"use client";

import { ExternalLink } from "lucide-react";
import type { ChecksItem } from "@/types/checks";
import { formatDuration, STATE_PRESENTATION } from "./presentation";

interface ChecksRowProps {
  item: ChecksItem;
}

/** One normalized check row: glyph, name, source, duration, ↗ link (§5.1). */
export function ChecksRow({ item }: ChecksRowProps) {
  const pres = STATE_PRESENTATION[item.state];
  const duration =
    item.state === "pending" ? "running…" : (formatDuration(item.durationMs) ?? pres.label);

  return (
    <div
      data-testid={`checks-row-${item.id}`}
      data-state={item.state}
      title={item.summary ?? undefined}
      className="flex h-9 items-center gap-3 border-b border-[#14161e] px-3 text-[12px] hover:bg-[#14161e]"
    >
      <span
        aria-hidden
        className="w-4 shrink-0 text-center"
        style={{ color: pres.color }}
        data-testid="checks-row-glyph"
      >
        {pres.glyph}
      </span>
      <span className="min-w-0 flex-1 truncate text-[#e6f0e4]">{item.name}</span>
      <span className="hidden shrink-0 text-[#899384] sm:inline">{item.source}</span>
      <span className="w-20 shrink-0 text-right text-[#a8b3a6]">{duration}</span>
      {item.detailsUrl ? (
        <a
          data-testid="checks-row-link"
          href={item.detailsUrl}
          target="_blank"
          rel="noreferrer"
          className="shrink-0 text-[#5ccfe6] hover:text-[#8fe0f0]"
          aria-label={`Open ${item.name} details`}
        >
          <ExternalLink size={12} />
        </a>
      ) : (
        <span className="w-3 shrink-0" />
      )}
    </div>
  );
}
