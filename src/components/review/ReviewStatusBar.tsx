"use client";

import { Archive, ExternalLink, GitPullRequest, Play } from "lucide-react";

/**
 * Shared shell type. In the full system this is
 * Pick<PullRequestView, "number" | "htmlUrl" | "status"> exported by
 * github-integration.spec.md §2.3a; defined inline here so the Changes tab
 * compiles ahead of that track, using its field names verbatim.
 */
export interface ReviewStatusBarPr {
  number: number;
  htmlUrl: string;
  status: "open" | "draft" | "merged" | "closed";
}

const PILL_CLASSES: Record<ReviewStatusBarPr["status"], string> = {
  open: "bg-[#002a17] text-[#00ff88] border-[#00cc6e]",
  draft: "bg-[#14161e] text-[#899384] border-[#1a1d24]",
  merged: "bg-[#1e1430] text-[#d58fff] border-[#7a4fb8]",
  closed: "bg-[#2a0a0a] text-[#ff5050] border-[#a13d3d]",
};

interface ReviewStatusBarProps {
  pr?: ReviewStatusBarPr;
  onContinue: () => void;
  onArchive: () => void;
  /**
   * Create-PR affordance for the #n slot (PR-review spec §5). When provided and
   * there is no PR yet, the bar shows a "Create PR" button instead of the link.
   */
  onCreatePr?: () => void;
}

/** The screenshot's top bar: #n ↗, status pill, Continue, Archive. spec §4.1. */
export function ReviewStatusBar({ pr, onContinue, onArchive, onCreatePr }: ReviewStatusBarProps) {
  return (
    <div
      data-testid="review-status-bar"
      className="flex h-9 shrink-0 items-center gap-2 border-b border-[#1a1d24] bg-[#0f1117] px-3 text-[11px]"
    >
      {pr ? (
        <>
          <a
            data-testid="review-pr-link"
            href={pr.htmlUrl}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1 text-[#5ccfe6] hover:underline"
          >
            #{pr.number}
            <ExternalLink size={11} />
          </a>
          <span
            data-testid="review-status-pill"
            className={`rounded border px-1.5 py-0.5 text-[10px] capitalize ${PILL_CLASSES[pr.status]}`}
          >
            {pr.status}
          </span>
        </>
      ) : onCreatePr ? (
        // No PR for this branch yet — the #n slot becomes a Create-PR affordance (§5).
        <button
          data-testid="review-status-create-pr"
          onClick={onCreatePr}
          className="flex items-center gap-1 rounded border border-[#00cc6e] bg-[#002a17] px-1.5 py-0.5 text-[10px] text-[#00ff88] hover:bg-[#003d22]"
        >
          <GitPullRequest size={11} />
          Create PR
        </button>
      ) : null}
      <span className="flex-1" />
      <button
        data-testid="review-continue"
        onClick={onContinue}
        className="flex items-center gap-1 rounded px-2 py-0.5 text-[#a8b3a6] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4]"
      >
        <Play size={11} />
        Continue
      </button>
      <button
        data-testid="review-archive"
        onClick={onArchive}
        className="flex items-center gap-1 rounded border border-[#1a1d24] px-2 py-0.5 text-[#a8b3a6] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4]"
      >
        <Archive size={11} />
        Archive
      </button>
    </div>
  );
}
