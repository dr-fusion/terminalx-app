"use client";

import type { ChecksRollup } from "@/types/checks";

interface ChecksEmptyStateProps {
  rollup: Extract<ChecksRollup, "no-repo" | "no-pr" | "none" | "error">;
  reason?: string;
  onRetry?: () => void;
}

interface EmptyCopy {
  title: string;
  body: string;
  retryable: boolean;
}

/** Distinct, actionable copy per empty/error rollup (§6 acceptance, §5.3). */
function copyFor(rollup: ChecksEmptyStateProps["rollup"], reason?: string): EmptyCopy {
  if (rollup === "no-repo") {
    return {
      title: "Not a GitHub repository",
      body: reason ?? "This session's directory isn't a GitHub-backed git repository.",
      retryable: false,
    };
  }
  if (rollup === "no-pr") {
    return {
      title: "No pull request yet",
      body: "Open a PR for this branch to see its checks here.",
      retryable: false,
    };
  }
  if (rollup === "none") {
    return {
      title: "No checks reported",
      body: "No CI runs or status checks were found for this commit.",
      retryable: true,
    };
  }
  // error
  if (reason === "no-auth") {
    return {
      title: "GitHub not connected",
      body: "Connect GitHub in Settings → Git to load checks for this repository.",
      retryable: true,
    };
  }
  if (reason === "rate-limited") {
    return {
      title: "GitHub rate limited",
      body: "GitHub temporarily rate-limited us. Showing the last known result.",
      retryable: true,
    };
  }
  return {
    title: "Couldn't load checks",
    body: reason ?? "We couldn't reach GitHub to load checks. Try again.",
    retryable: true,
  };
}

export function ChecksEmptyState({ rollup, reason, onRetry }: ChecksEmptyStateProps) {
  const copy = copyFor(rollup, reason);
  return (
    <div
      data-testid="checks-empty-state"
      data-rollup={rollup}
      data-reason={reason ?? undefined}
      className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center"
    >
      <div className="text-[13px] text-[#e6f0e4]">{copy.title}</div>
      <div className="max-w-xs text-[12px] text-[#899384]">{copy.body}</div>
      {copy.retryable && onRetry ? (
        <button
          data-testid="checks-empty-retry"
          onClick={onRetry}
          className="mt-1 rounded border border-[#1a1d24] px-3 py-1 text-[11px] text-[#a8b3a6] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4]"
        >
          Retry
        </button>
      ) : null}
    </div>
  );
}
