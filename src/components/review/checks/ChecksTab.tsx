"use client";

import type { ChecksView } from "@/types/checks";
import { ChecksHeader } from "./ChecksHeader";
import { ChecksRollupSummary } from "./ChecksRollupSummary";
import { ChecksList } from "./ChecksList";
import { ChecksEmptyState } from "./ChecksEmptyState";

interface ChecksTabProps {
  sessionName: string | null;
  /** Provided by the panel shell so the tab and badge share one fetch (§5.4). */
  view: ChecksView | null;
  isLoading: boolean;
  error: string | null;
  onRefresh: () => void; // forces force=true refetch
}

const EMPTY_ROLLUPS = new Set(["no-repo", "no-pr", "none", "error"]);

/** The Checks tab content (checks-dashboard.spec.md §5). */
export function ChecksTab({ sessionName, view, isLoading, error, onRefresh }: ChecksTabProps) {
  // Initial load (no view yet).
  if (!view && isLoading) {
    return (
      <div
        data-testid="checks-tab"
        data-state="loading"
        className="flex h-full items-center justify-center text-[12px] text-[#899384]"
      >
        Loading checks…
      </div>
    );
  }

  // No session selected, or no view and an error before any data arrived.
  if (!view) {
    return (
      <div
        data-testid="checks-tab"
        data-state={error ? "error" : "empty"}
        className="flex h-full flex-col"
      >
        <ChecksHeader
          branch={null}
          headSha={null}
          isRefreshing={isLoading}
          stale={false}
          onRefresh={onRefresh}
        />
        <ChecksEmptyState
          rollup="error"
          reason={sessionName ? (error ?? "upstream") : undefined}
          onRetry={onRefresh}
        />
      </div>
    );
  }

  const isEmptyRollup = EMPTY_ROLLUPS.has(view.rollup);

  return (
    <div data-testid="checks-tab" data-rollup={view.rollup} className="flex h-full flex-col">
      <ChecksHeader
        branch={view.branch}
        headSha={view.headSha}
        isRefreshing={isLoading}
        stale={view.stale}
        onRefresh={onRefresh}
      />
      {isEmptyRollup ? (
        <ChecksEmptyState
          rollup={view.rollup as "no-repo" | "no-pr" | "none" | "error"}
          reason={view.reason}
          onRetry={onRefresh}
        />
      ) : (
        <>
          <ChecksRollupSummary counts={view.counts} />
          <ChecksList items={view.items} />
        </>
      )}
    </div>
  );
}
