"use client";

import type { ChecksItem } from "@/types/checks";
import { ChecksRow } from "./ChecksRow";

interface ChecksListProps {
  items: ChecksItem[];
}

// Past this row count we cap the visible window for performance, matching the
// diff-viewer's > 80 threshold (§7). counts in the summary still reflect the full
// set. A lightweight cap (not full windowing) keeps the DOM bounded without a new dep.
const MAX_VISIBLE_ROWS = 80;

/** The scrollable list of normalized check rows (§5.1). */
export function ChecksList({ items }: ChecksListProps) {
  const visible = items.slice(0, MAX_VISIBLE_ROWS);
  const hidden = items.length - visible.length;

  return (
    <div data-testid="checks-list" className="min-h-0 flex-1 overflow-y-auto">
      {visible.map((item) => (
        <ChecksRow key={item.id} item={item} />
      ))}
      {hidden > 0 && (
        <div
          data-testid="checks-list-overflow"
          className="px-3 py-2 text-center text-[11px] text-[#899384]"
        >
          + {hidden} more check{hidden === 1 ? "" : "s"} not shown
        </div>
      )}
    </div>
  );
}
