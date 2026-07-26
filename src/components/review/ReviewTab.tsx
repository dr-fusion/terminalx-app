"use client";

// The Review tab (spec §4) — line-anchored inline comment threads, the per-
// reviewer decision rollup, and the Create-PR entry point. Renders INLINE inside
// ReviewPanel's narrow column (no modal, no second sidebar). All GitHub data is
// fetched via the session-scoped API routes; drafts persist server-side. Dark-
// themed to match ReviewStatusBar / ReviewPanel. NO Node imports.
import { useMemo, useState } from "react";
import {
  AlertCircle,
  ChevronDown,
  ChevronRight,
  Eye,
  GitPullRequest,
  MessageSquarePlus,
  RefreshCw,
} from "lucide-react";
import { usePrReview, type UsePrReview } from "@/hooks/usePrReview";
import { usePrReviewDrafts } from "@/hooks/usePrReviewDrafts";
import { overlayLiveDrafts } from "@/lib/pr-review/merge";
import type {
  MergedThread,
  ReviewDecision,
  ReviewFileGroup,
  ReviewTabModel,
} from "@/types/pr-review";
import { CreatePrDialog } from "./CreatePrDialog";

const DECISION_PILL: Record<ReviewDecision, { label: string; cls: string }> = {
  approved: { label: "Approved", cls: "border-[#00cc6e] bg-[#002a17] text-[#00ff88]" },
  changes_requested: {
    label: "Changes requested",
    cls: "border-[#a13d3d] bg-[#2a0a0a] text-[#ff5050]",
  },
  review_required: {
    label: "Review required",
    cls: "border-[#1a1d24] bg-[#14161e] text-[#899384]",
  },
  pending: { label: "Pending", cls: "border-[#2f6f80] bg-[#06212a] text-[#5ccfe6]" },
};

interface ReviewTabProps {
  session: string | null;
  /** Session worktree branch — head for Create-PR. */
  headBranch?: string;
  /**
   * Shared review controller. When the parent panel already owns a usePrReview
   * instance (to drive the status bar), it passes it down so the tab and the bar
   * stay in sync without a second fetch. When absent, the tab self-fetches.
   */
  controller?: UsePrReview;
  /** Externally controlled Create-PR dialog (shared with the status-bar button). */
  dialogOpen?: boolean;
  onDialogOpenChange?: (open: boolean) => void;
}

export function ReviewTab({
  session,
  headBranch = "",
  controller,
  dialogOpen: extDialogOpen,
  onDialogOpenChange,
}: ReviewTabProps) {
  const own = usePrReview(controller ? null : session);
  const { model, loading, error, refetch, createPr, submitReview, setResolved } = controller ?? own;
  const drafts = usePrReviewDrafts(session);
  const [internalOpen, setInternalOpen] = useState(false);
  const dialogOpen = extDialogOpen ?? internalOpen;
  const setDialogOpen = onDialogOpenChange ?? setInternalOpen;

  // Overlay the LIVE local drafts onto the snapshot model so a NEW top-level line
  // comment (authored from the Changes tab) surfaces here as a draft thread
  // immediately — even before a PR exists (#3).
  const liveByFile = useMemo(
    () => overlayLiveDrafts(model?.byFile ?? [], drafts.drafts),
    [model?.byFile, drafts.drafts]
  );

  if (!session) {
    return (
      <Empty testid="review-no-session" title="No session selected">
        Open a session to review its pull request.
      </Empty>
    );
  }

  if (loading && !model) {
    return <SkeletonRows />;
  }

  if (error) {
    return (
      <div
        data-testid="review-error"
        className="flex flex-col items-start gap-3 px-4 py-6 text-[12px]"
      >
        <div className="flex items-center gap-2 text-[#ff5050]">
          <AlertCircle size={14} />
          {error}
        </div>
        <button
          data-testid="review-retry"
          onClick={() => void refetch()}
          className="flex items-center gap-1.5 rounded border border-[#1a1d24] px-2 py-1 text-[#a8b3a6] hover:bg-[#14161e] hover:text-[#e6f0e4]"
        >
          <RefreshCw size={12} />
          Retry
        </button>
      </div>
    );
  }

  if (!model) {
    return <SkeletonRows />;
  }

  // No PR yet → Create-PR empty state (mirrors the status-bar affordance, §2.2/§5).
  // Local drafts (e.g. a NEW inline comment authored on a diff line) still surface
  // here as pending draft threads even before a PR exists (#3).
  if (!model.pr) {
    const draftGroups = liveByFile.filter((g) => g.threads.length > 0);
    return (
      <div data-testid="review-tab" className="flex h-full flex-col overflow-y-auto">
        {draftGroups.length > 0 && (
          <div
            data-testid="review-pending-drafts"
            className="flex flex-col border-b border-[#1a1d24]"
          >
            <DraftBanner
              count={drafts.count}
              onSubmit={(event, body) => submitReview(event, body)}
            />
            {draftGroups.map((group) => (
              <FileThreadGroup
                key={group.path}
                group={group}
                onReply={(thread, body) =>
                  drafts.upsert({
                    path: thread.path,
                    line: thread.line,
                    side: thread.side,
                    inReplyToId: thread.comments[0]?.id,
                    body,
                  })
                }
                onResolve={(thread, resolved) => void setResolved(thread.key, resolved)}
                onDiscardDraft={(id) => void drafts.discard(id)}
              />
            ))}
          </div>
        )}
        <div
          data-testid="review-no-pr"
          className="flex flex-1 flex-col items-center justify-center gap-3 px-6 text-center"
        >
          <Eye size={20} className="text-[#3f4a3d]" />
          {model.unbound ? (
            <>
              <p className="text-[12px] text-[#a8b3a6]">
                This repo isn&apos;t connected to GitHub.
              </p>
              <a
                href="/settings"
                data-testid="review-connect-repo"
                className="rounded border border-[#1a1d24] px-3 py-1.5 text-[12px] text-[#5ccfe6] hover:bg-[#14161e]"
              >
                Connect this repo
              </a>
            </>
          ) : (
            <>
              <p className="text-[12px] text-[#a8b3a6]">No pull request for this branch.</p>
              <button
                data-testid="review-create-pr"
                onClick={() => setDialogOpen(true)}
                className="flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-3 py-1.5 text-[12px] text-[#00ff88] hover:bg-[#003d22]"
              >
                <GitPullRequest size={13} />
                Create PR
              </button>
            </>
          )}
        </div>
        <CreatePrDialog
          open={dialogOpen}
          onOpenChange={setDialogOpen}
          headBranch={model.headBranch || headBranch}
          defaultBase={model.defaultBase || "main"}
          onCreate={createPr}
        />
      </div>
    );
  }

  const hasActivity = liveByFile.length > 0 || model.reviews.length > 0;
  const mergedMerged = mergeDraftCount(model, drafts.count);

  return (
    <div data-testid="review-tab" className="flex h-full flex-col overflow-y-auto">
      <ReviewHeader decision={model.decision} model={model} />

      {mergedMerged > 0 && (
        <DraftBanner count={mergedMerged} onSubmit={(event, body) => submitReview(event, body)} />
      )}

      {!hasActivity ? (
        <div
          data-testid="review-no-activity"
          className="flex flex-col items-start gap-2 px-4 py-6 text-[12px] text-[#899384]"
        >
          No review activity yet.
        </div>
      ) : (
        <div className="flex flex-col">
          {liveByFile.map((group) => (
            <FileThreadGroup
              key={group.path}
              group={group}
              onReply={(thread, body) =>
                drafts.upsert({
                  path: thread.path,
                  line: thread.line,
                  side: thread.side,
                  inReplyToId: thread.comments[0]?.id,
                  body,
                })
              }
              onResolve={(thread, resolved) => void setResolved(thread.key, resolved)}
              onDiscardDraft={(id) => void drafts.discard(id)}
            />
          ))}
        </div>
      )}

      <ReviewComposer
        merged={model.pr.status === "merged"}
        onSubmit={(event, body) => submitReview(event, body)}
      />
    </div>
  );
}

// ── Header / decision rollup (§4.1) ───────────────────────────────────────────

function ReviewHeader({ decision, model }: { decision: ReviewDecision; model: ReviewTabModel }) {
  const pill = DECISION_PILL[decision];
  return (
    <div
      data-testid="review-header"
      className="flex items-center gap-2 border-b border-[#1a1d24] bg-[#0f1117] px-4 py-2.5"
    >
      <span
        data-testid="review-decision-pill"
        data-decision={decision}
        className={`rounded border px-1.5 py-0.5 text-[10px] ${pill.cls}`}
      >
        {pill.label}
      </span>
      <div data-testid="review-reviewers" className="flex items-center gap-1">
        {model.reviews.map((r) => (
          <span
            key={r.id}
            title={`${r.user.login}: ${r.state}`}
            className="flex h-5 items-center gap-1 rounded-full bg-[#14161e] px-1.5 text-[10px] text-[#a8b3a6]"
          >
            {r.user.avatar_url ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={r.user.avatar_url}
                alt={r.user.login}
                className="h-3.5 w-3.5 rounded-full"
              />
            ) : (
              <span className="text-[#d58fff]">@</span>
            )}
            {r.user.login}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Draft banner (§4 component tree) ──────────────────────────────────────────

function DraftBanner({
  count,
  onSubmit,
}: {
  count: number;
  onSubmit: (event: "COMMENT" | "APPROVE" | "REQUEST_CHANGES", body: string) => void;
}) {
  return (
    <div
      data-testid="review-draft-banner"
      className="flex items-center justify-between gap-2 border-b border-[#3a2e10] bg-[#1a1405] px-4 py-2 text-[11px] text-[#ffb454]"
    >
      <span>
        {count} pending comment{count === 1 ? "" : "s"}
      </span>
      <button
        data-testid="review-submit-shortcut"
        onClick={() => onSubmit("COMMENT", "")}
        className="rounded border border-[#3a2e10] px-2 py-0.5 text-[#ffb454] hover:bg-[#2a2208]"
      >
        Submit review
      </button>
    </div>
  );
}

// ── File thread group (§4) ────────────────────────────────────────────────────

function FileThreadGroup({
  group,
  onReply,
  onResolve,
  onDiscardDraft,
}: {
  group: ReviewFileGroup;
  onReply: (thread: MergedThread, body: string) => void;
  onResolve: (thread: MergedThread, resolved: boolean) => void;
  onDiscardDraft: (id: string) => void;
}) {
  const [open, setOpen] = useState(true);
  return (
    <div
      data-testid="review-file-group"
      data-path={group.path}
      className="border-b border-[#14161e]"
    >
      <button
        data-testid="review-file-header"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-1.5 px-4 py-2 text-left text-[12px] hover:bg-[#0f1117]"
      >
        {open ? (
          <ChevronDown size={12} className="text-[#899384]" />
        ) : (
          <ChevronRight size={12} className="text-[#899384]" />
        )}
        <span className="text-[#899384]">{group.dir}</span>
        <span className="font-medium text-[#e6f0e4]">{group.filename}</span>
        <span className="ml-auto rounded-full bg-[#14161e] px-1.5 text-[10px] text-[#a8b3a6]">
          {group.threads.length}
        </span>
      </button>
      {open && (
        <div className="flex flex-col gap-2 px-4 pb-3">
          {group.threads.map((thread) => (
            <ThreadCard
              key={thread.key}
              thread={thread}
              onReply={(body) => onReply(thread, body)}
              onResolve={(resolved) => onResolve(thread, resolved)}
              onDiscardDraft={onDiscardDraft}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Thread card (§4) ──────────────────────────────────────────────────────────

function ThreadCard({
  thread,
  onReply,
  onResolve,
  onDiscardDraft,
}: {
  thread: MergedThread;
  onReply: (body: string) => void;
  onResolve: (resolved: boolean) => void;
  onDiscardDraft: (id: string) => void;
}) {
  const [replyOpen, setReplyOpen] = useState(false);
  const [replyText, setReplyText] = useState("");
  const root = thread.comments[0];
  const outdated = root != null && root.line == null;

  return (
    <div
      data-testid="review-thread"
      data-thread-key={thread.key}
      data-resolved={thread.resolved}
      className={`rounded border border-[#1a1d24] bg-[#0f1117] ${
        thread.resolved ? "opacity-60" : ""
      }`}
    >
      <div className="flex items-center justify-between gap-2 border-b border-[#14161e] px-2.5 py-1.5 text-[10px] text-[#899384]">
        <span>
          line {thread.line}
          {outdated && (
            <span data-testid="review-thread-outdated" className="ml-1.5 text-[#ffb454]">
              Outdated
            </span>
          )}
        </span>
        <button
          data-testid="review-resolve-toggle"
          onClick={() => onResolve(!thread.resolved)}
          className={`rounded px-1.5 py-0.5 ${
            thread.resolved
              ? "text-[#00ff88] hover:bg-[#14161e]"
              : "text-[#a8b3a6] hover:bg-[#14161e]"
          }`}
        >
          {thread.resolved ? "Unresolve" : "Resolve"}
        </button>
      </div>

      {root?.diff_hunk && (
        <pre
          data-testid="review-diff-hunk"
          className="overflow-x-auto border-b border-[#14161e] bg-[#0a0b10] px-2.5 py-1.5 font-mono text-[10px] leading-4 text-[#899384]"
        >
          {root.diff_hunk}
        </pre>
      )}

      <div className="flex flex-col gap-2 px-2.5 py-2">
        {thread.comments.map((c) => (
          <div key={c.id} data-testid="review-comment" className="text-[11px]">
            <div className="mb-0.5 flex items-center gap-1.5">
              <span className="text-[#d58fff]">@{c.user.login}</span>
              <span className="text-[#899384]">{relativeTime(c.created_at)}</span>
            </div>
            <p className="whitespace-pre-wrap text-[#a8b3a6]">{c.body}</p>
          </div>
        ))}

        {thread.draftReplies.map((d) => (
          <div key={d.id} data-testid="review-draft-reply" className="text-[11px]">
            <div className="mb-0.5 flex items-center gap-1.5">
              <span
                data-testid="review-pending-tag"
                className="rounded bg-[#1a1405] px-1 text-[9px] text-[#ffb454]"
              >
                Pending
              </span>
              <button
                data-testid="review-discard-draft"
                onClick={() => onDiscardDraft(d.id)}
                className="text-[#899384] hover:text-[#ff5050]"
              >
                Discard
              </button>
            </div>
            <p className="whitespace-pre-wrap text-[#a8b3a6]">{d.body}</p>
          </div>
        ))}
      </div>

      <div className="border-t border-[#14161e] px-2.5 py-1.5">
        {replyOpen ? (
          <div className="flex flex-col gap-1.5">
            <textarea
              data-testid="review-reply-input"
              value={replyText}
              onChange={(e) => setReplyText(e.target.value)}
              rows={2}
              placeholder="Reply…"
              className="w-full resize-none rounded border border-[#1a1d24] bg-[#0a0b10] px-2 py-1 text-[11px] text-[#e6f0e4] outline-none placeholder:text-[#899384] focus:border-[#5ccfe6]"
            />
            <div className="flex justify-end gap-1.5">
              <button
                onClick={() => {
                  setReplyOpen(false);
                  setReplyText("");
                }}
                className="rounded px-2 py-0.5 text-[10px] text-[#899384] hover:text-[#e6f0e4]"
              >
                Cancel
              </button>
              <button
                data-testid="review-reply-save"
                disabled={!replyText.trim()}
                onClick={() => {
                  onReply(replyText.trim());
                  setReplyOpen(false);
                  setReplyText("");
                }}
                className="rounded border border-[#1a1d24] px-2 py-0.5 text-[10px] text-[#ffb454] hover:bg-[#14161e] disabled:opacity-40"
              >
                Save draft
              </button>
            </div>
          </div>
        ) : (
          <button
            data-testid="review-reply-open"
            onClick={() => setReplyOpen(true)}
            className="flex items-center gap-1 text-[10px] text-[#899384] hover:text-[#5ccfe6]"
          >
            <MessageSquarePlus size={11} />
            Reply
          </button>
        )}
      </div>
    </div>
  );
}

// ── Review composer (§4.4) ────────────────────────────────────────────────────

function ReviewComposer({
  merged,
  onSubmit,
}: {
  merged: boolean;
  onSubmit: (
    event: "COMMENT" | "APPROVE" | "REQUEST_CHANGES",
    body: string
  ) => Promise<{ ok: boolean; error?: string }>;
}) {
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async (event: "COMMENT" | "APPROVE" | "REQUEST_CHANGES") => {
    setBusy(true);
    setErr(null);
    const res = await onSubmit(event, body);
    setBusy(false);
    if (res.ok) setBody("");
    else setErr(res.error ?? "Submit failed");
  };

  return (
    <div
      data-testid="review-composer"
      className="mt-auto flex flex-col gap-2 border-t border-[#1a1d24] bg-[#0f1117] px-4 py-3"
    >
      <textarea
        data-testid="review-composer-body"
        value={body}
        onChange={(e) => setBody(e.target.value)}
        rows={2}
        placeholder="Leave an overall review comment…"
        className="w-full resize-none rounded border border-[#1a1d24] bg-[#0a0b10] px-2 py-1.5 text-[11px] text-[#e6f0e4] outline-none placeholder:text-[#899384] focus:border-[#5ccfe6]"
      />
      {err && (
        <p data-testid="review-composer-error" className="text-[11px] text-[#ff5050]">
          {err}
        </p>
      )}
      <div className="flex items-center gap-2">
        <button
          data-testid="review-submit-comment"
          disabled={busy}
          onClick={() => submit("COMMENT")}
          className="rounded border border-[#1a1d24] px-2.5 py-1 text-[11px] text-[#a8b3a6] hover:bg-[#14161e] hover:text-[#e6f0e4] disabled:opacity-50"
        >
          Comment
        </button>
        <button
          data-testid="review-submit-approve"
          disabled={busy || merged}
          title={merged ? "Cannot approve a merged PR" : undefined}
          onClick={() => submit("APPROVE")}
          className="rounded border border-[#00cc6e] bg-[#002a17] px-2.5 py-1 text-[11px] text-[#00ff88] hover:bg-[#003d22] disabled:opacity-40"
        >
          Approve
        </button>
        <button
          data-testid="review-submit-request-changes"
          disabled={busy || merged}
          title={merged ? "Cannot request changes on a merged PR" : undefined}
          onClick={() => submit("REQUEST_CHANGES")}
          className="rounded border border-[#a13d3d] bg-[#2a0a0a] px-2.5 py-1 text-[11px] text-[#ff5050] hover:bg-[#3d0f0f] disabled:opacity-40"
        >
          Request changes
        </button>
      </div>
    </div>
  );
}

// ── Bits ──────────────────────────────────────────────────────────────────────

function Empty({
  testid,
  title,
  children,
}: {
  testid: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div
      data-testid={testid}
      className="flex h-full flex-col items-center justify-center gap-1 px-6 text-center"
    >
      <p className="text-[12px] text-[#a8b3a6]">{title}</p>
      <p className="text-[11px] text-[#899384]">{children}</p>
    </div>
  );
}

function SkeletonRows() {
  return (
    <div data-testid="review-loading" className="flex flex-col gap-2 px-4 py-4">
      {[0, 1, 2].map((i) => (
        <div key={i} className="h-10 animate-pulse rounded bg-[#14161e]" />
      ))}
    </div>
  );
}

/** Total pending count — drafts hook is the live source; model is the snapshot. */
function mergeDraftCount(model: ReviewTabModel, liveCount: number): number {
  return Math.max(model.draftCount, liveCount);
}

function relativeTime(iso: string): string {
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return "";
  const secs = Math.round((Date.now() - then) / 1000);
  if (secs < 60) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  return `${days}d ago`;
}
