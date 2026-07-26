"use client";

import { RefreshCw } from "lucide-react";
import { shortSha } from "./presentation";

interface ChecksHeaderProps {
  branch: string | null;
  headSha: string | null;
  isRefreshing: boolean;
  stale: boolean;
  onRefresh: () => void;
}

/** Header row: "Checks for <branch> @ <sha>" + the per-tab refresh ↻ (§5.1). */
export function ChecksHeader({
  branch,
  headSha,
  isRefreshing,
  stale,
  onRefresh,
}: ChecksHeaderProps) {
  const sha = shortSha(headSha);
  return (
    <div
      data-testid="checks-header"
      className="flex items-center gap-2 px-3 pt-3 text-[12px] text-[#e6f0e4]"
    >
      <span className="min-w-0 flex-1 truncate">
        {branch ? (
          <>
            Checks for <span className="text-[#a8b3a6]">{branch}</span>
            {sha ? (
              <>
                {" "}
                @ <span className="font-mono text-[#899384]">{sha}</span>
              </>
            ) : null}
          </>
        ) : (
          "Checks"
        )}
        {stale ? (
          <span data-testid="checks-stale-badge" className="ml-2 text-[10px] text-[#d5a04f]">
            stale
          </span>
        ) : null}
      </span>
      <button
        data-testid="checks-refresh"
        onClick={onRefresh}
        disabled={isRefreshing}
        aria-label="Refresh checks"
        className="flex h-6 w-6 items-center justify-center rounded text-[#899384] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4] disabled:opacity-50"
      >
        <RefreshCw size={13} className={isRefreshing ? "animate-spin" : undefined} />
      </button>
    </div>
  );
}
