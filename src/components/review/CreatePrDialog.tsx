"use client";

// Create-PR flow (spec §5). The ONE legitimate modal in the feature — the create
// form only, not the review surface. head is the session's worktree branch
// (read-only); base defaults to the repo default branch. Validates head !== base
// and non-empty branch names inline BEFORE the network call. Dark-themed to match
// ReviewStatusBar / ReviewPanel (raw Tailwind hex, no Node imports).
import { useState } from "react";
import { GitPullRequest, Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import type { CreatePrForm } from "@/types/pr-review";

interface CreatePrDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The session's worktree branch — head is fixed to this. */
  headBranch: string;
  /** Repo default branch (settings.toml / getGitDirectoryInfo). */
  defaultBase: string;
  onCreate: (form: CreatePrForm) => Promise<{ ok: boolean; error?: string }>;
}

const TITLE_SOFT_LIMIT = 72;
const TITLE_HARD_LIMIT = 256;

const inputClass =
  "w-full rounded border border-[#1a1d24] bg-[#0a0b10] px-2.5 py-1.5 text-[12px] text-[#e6f0e4] outline-none placeholder:text-[#899384] focus:border-[#5ccfe6]";

function deriveTitle(branch: string): string {
  const tail = branch.split("/").pop() ?? branch;
  const words = tail.replace(/[-_]+/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "";
}

export function CreatePrDialog({
  open,
  onOpenChange,
  headBranch,
  defaultBase,
  onCreate,
}: CreatePrDialogProps) {
  const [base, setBase] = useState(defaultBase);
  const [title, setTitle] = useState(() => deriveTitle(headBranch));
  const [body, setBody] = useState("");
  const [reviewers, setReviewers] = useState("");
  const [draft, setDraft] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errors, setErrors] = useState<Partial<Record<"base" | "head" | "title" | "form", string>>>(
    {}
  );

  const validate = (): boolean => {
    const next: typeof errors = {};
    if (!title.trim()) next.title = "A title is required";
    else if (title.length > TITLE_HARD_LIMIT) next.title = "Title is too long (256 max)";
    if (!base.trim()) next.base = "A base branch is required";
    if (!headBranch.trim()) next.head = "This session has no branch";
    if (base.trim() === headBranch.trim()) next.base = "Base must differ from head";
    setErrors(next);
    return Object.keys(next).length === 0;
  };

  const handleCreate = async () => {
    if (!validate()) return;
    setSubmitting(true);
    setErrors((e) => ({ ...e, form: undefined }));
    const result = await onCreate({
      base: base.trim(),
      head: headBranch,
      title: title.trim(),
      body,
      draft,
      reviewers: reviewers
        .split(/[\s,]+/)
        .map((r) => r.trim())
        .filter(Boolean),
    });
    setSubmitting(false);
    if (result.ok) {
      onOpenChange(false);
    } else {
      setErrors((e) => ({ ...e, form: result.error ?? "Could not create pull request" }));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        data-testid="create-pr-dialog"
        className="border border-[#1a1d24] bg-[#0a0b10] text-[#e6f0e4] sm:max-w-md"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-[14px] text-[#e6f0e4]">
            <GitPullRequest size={14} className="text-[#00ff88]" />
            Create pull request
          </DialogTitle>
          <DialogDescription className="text-[11px] text-[#899384]">
            Open a PR for this session&apos;s branch.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3">
          {/* base ⇽ head */}
          <div
            data-testid="create-pr-branch-row"
            className="flex items-center gap-2 text-[12px] text-[#a8b3a6]"
          >
            <div className="flex-1">
              <label className="mb-1 block text-[10px] uppercase tracking-wide text-[#899384]">
                base
              </label>
              <input
                data-testid="create-pr-base"
                value={base}
                onChange={(e) => setBase(e.target.value)}
                className={inputClass}
                placeholder="main"
              />
            </div>
            <span className="mt-4 text-[#899384]">⇽</span>
            <div className="flex-1">
              <label className="mb-1 block text-[10px] uppercase tracking-wide text-[#899384]">
                head
              </label>
              <input
                data-testid="create-pr-head"
                value={headBranch}
                readOnly
                className={`${inputClass} cursor-not-allowed text-[#899384]`}
              />
            </div>
          </div>
          {errors.base && (
            <p data-testid="create-pr-base-error" className="text-[11px] text-[#ff5050]">
              {errors.base}
            </p>
          )}
          {errors.head && (
            <p data-testid="create-pr-head-error" className="text-[11px] text-[#ff5050]">
              {errors.head}
            </p>
          )}

          {/* title with soft counter */}
          <div>
            <div className="mb-1 flex items-center justify-between">
              <label className="text-[10px] uppercase tracking-wide text-[#899384]">title</label>
              <span
                data-testid="create-pr-title-counter"
                className={`text-[10px] ${
                  title.length > TITLE_SOFT_LIMIT ? "text-[#ffb454]" : "text-[#899384]"
                }`}
              >
                {title.length}/{TITLE_SOFT_LIMIT}
              </span>
            </div>
            <input
              data-testid="create-pr-title"
              value={title}
              maxLength={TITLE_HARD_LIMIT}
              onChange={(e) => setTitle(e.target.value)}
              className={inputClass}
              placeholder="Add settings"
            />
            {errors.title && (
              <p data-testid="create-pr-title-error" className="mt-1 text-[11px] text-[#ff5050]">
                {errors.title}
              </p>
            )}
          </div>

          {/* body */}
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-[#899384]">
              description <span className="text-[#3f4a3d]">(markdown)</span>
            </label>
            <textarea
              data-testid="create-pr-body"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={4}
              className={`${inputClass} resize-none`}
              placeholder="What does this change?"
            />
          </div>

          {/* reviewers */}
          <div>
            <label className="mb-1 block text-[10px] uppercase tracking-wide text-[#899384]">
              reviewers <span className="text-[#3f4a3d]">(optional, comma-separated)</span>
            </label>
            <input
              data-testid="create-pr-reviewers"
              value={reviewers}
              onChange={(e) => setReviewers(e.target.value)}
              className={inputClass}
              placeholder="octocat, monalisa"
            />
          </div>

          {/* draft */}
          <label className="flex cursor-pointer items-center gap-2 text-[12px] text-[#a8b3a6]">
            <input
              data-testid="create-pr-draft"
              type="checkbox"
              checked={draft}
              onChange={(e) => setDraft(e.target.checked)}
              className="h-3.5 w-3.5 accent-[#5ccfe6]"
            />
            Create as draft
          </label>

          {errors.form && (
            <p data-testid="create-pr-form-error" className="text-[11px] text-[#ff5050]">
              {errors.form}
            </p>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 pt-1">
          <button
            data-testid="create-pr-cancel"
            onClick={() => onOpenChange(false)}
            disabled={submitting}
            className="rounded border border-[#1a1d24] px-3 py-1.5 text-[12px] text-[#a8b3a6] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4] disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            data-testid="create-pr-submit"
            onClick={handleCreate}
            disabled={submitting}
            className="flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-3 py-1.5 text-[12px] text-[#00ff88] transition-colors hover:bg-[#003d22] disabled:opacity-50"
          >
            {submitting && <Loader2 size={12} className="animate-spin" />}
            Create pull request
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
