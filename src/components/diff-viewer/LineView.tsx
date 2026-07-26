"use client";

import { useState } from "react";
import { MessageSquarePlus } from "lucide-react";
import type { DiffLine } from "@/types/diff";
import type { CommentSide } from "@/types/pr-review";

const TYPE_CLASSES: Record<DiffLine["type"], { row: string; txt: string; marker: string }> = {
  addition: {
    row: "bg-[rgba(0,255,136,0.08)]",
    txt: "text-[#00ff88]",
    marker: "+",
  },
  deletion: {
    row: "bg-[rgba(255,80,80,0.08)]",
    txt: "text-[#ff5050]",
    marker: "-",
  },
  context: {
    row: "",
    txt: "text-[#e6f0e4]",
    marker: " ",
  },
};

function gutterNum(n: number | null): string {
  return n === null ? "" : String(n);
}

/**
 * Per-line inline-comment plumbing (#3). The diff viewer threads these down so a
 * reviewer can open a composer on a line and create a NEW top-level draft comment
 * (NOT a reply). All persistence lives in the parent (usePrReviewDrafts); LineView
 * only surfaces the affordance + composer. Optional so the diff viewer still
 * renders when no session/draft store is wired (e.g. read-only previews).
 */
export interface LineCommentApi {
  /** Repo-relative file path this line belongs to. */
  filePath: string;
  /** True when the composer for THIS line is open (controlled by the parent). */
  isOpen: (line: number, side: CommentSide) => boolean;
  /** Open/close the composer for this line. */
  onOpen: (line: number, side: CommentSide) => void;
  onClose: () => void;
  /** Persist a NEW top-level draft comment for {filePath,line,side,body}. */
  onSubmit: (line: number, side: CommentSide, body: string) => void;
}

/** The new-file line number + side a comment anchors to, or null if not commentable. */
function commentAnchor(line: DiffLine): { line: number; side: CommentSide } | null {
  // Annotate the new-file side for additions/context; the old side for deletions.
  if (line.type === "deletion") {
    return line.oldLineNum != null ? { line: line.oldLineNum, side: "LEFT" } : null;
  }
  return line.newLineNum != null ? { line: line.newLineNum, side: "RIGHT" } : null;
}

/**
 * A single unified diff line: old gutter, new gutter, marker, content.
 * Mono, dark theme (spec §8). data-testid="diff-line" on every rendered line.
 * When a `comments` API is provided, a hover-revealed "+" opens an inline
 * composer to add a NEW top-level inline comment on the line (#3).
 */
export function LineView({
  line,
  wordWrap,
  comments,
}: {
  line: DiffLine;
  wordWrap?: boolean;
  comments?: LineCommentApi;
}) {
  const cls = TYPE_CLASSES[line.type];
  const anchor = comments ? commentAnchor(line) : null;
  const open = comments && anchor ? comments.isOpen(anchor.line, anchor.side) : false;

  return (
    <div data-line-anchor={anchor ? `${anchor.line}:${anchor.side}` : undefined}>
      <div
        data-testid="diff-line"
        data-line-type={line.type}
        className={`group/line flex font-mono text-[12px] leading-5 ${cls.row}`}
      >
        <span className="w-10 shrink-0 select-none px-1 text-right text-[#899384]" aria-hidden>
          {gutterNum(line.oldLineNum)}
        </span>
        <span className="relative w-10 shrink-0 select-none px-1 text-right text-[#899384]">
          {comments && anchor && !open && (
            <button
              type="button"
              data-testid="line-comment-add"
              data-line={anchor.line}
              data-side={anchor.side}
              title="Add a comment on this line"
              aria-label="Add a comment on this line"
              onClick={() => comments.onOpen(anchor.line, anchor.side)}
              className="absolute -left-1 top-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-[3px] bg-[#5ccfe6] text-[#0a0b10] opacity-0 transition-opacity group-hover/line:opacity-100 focus:opacity-100"
            >
              <MessageSquarePlus size={10} strokeWidth={2.5} />
            </button>
          )}
          <span aria-hidden>{gutterNum(line.newLineNum)}</span>
        </span>
        <span className={`w-4 shrink-0 select-none text-center ${cls.txt}`} aria-hidden>
          {cls.marker}
        </span>
        <span
          className={`flex-1 ${cls.txt} ${wordWrap ? "whitespace-pre-wrap break-all" : "whitespace-pre overflow-x-auto"}`}
        >
          {line.content || " "}
        </span>
      </div>
      {comments && anchor && open && (
        <LineCommentComposer
          line={anchor.line}
          side={anchor.side}
          onCancel={comments.onClose}
          onSubmit={(body) => comments.onSubmit(anchor.line, anchor.side, body)}
        />
      )}
    </div>
  );
}

/** Inline composer to author a NEW top-level line comment (#3). Dark theme. */
function LineCommentComposer({
  line,
  side,
  onCancel,
  onSubmit,
}: {
  line: number;
  side: CommentSide;
  onCancel: () => void;
  onSubmit: (body: string) => void;
}) {
  const [body, setBody] = useState("");
  const save = () => {
    const trimmed = body.trim();
    if (!trimmed) return;
    onSubmit(trimmed);
    setBody("");
  };
  return (
    <div
      data-testid="line-comment-composer"
      data-line={line}
      data-side={side}
      className="flex flex-col gap-1.5 border-y border-[#1a1d24] bg-[#0f1117] px-3 py-2"
    >
      <textarea
        data-testid="line-comment-input"
        value={body}
        autoFocus
        rows={2}
        placeholder={`Comment on line ${line}…`}
        onChange={(e) => setBody(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onCancel();
          } else if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
            e.preventDefault();
            save();
          }
        }}
        className="w-full resize-none rounded border border-[#1a1d24] bg-[#0a0b10] px-2 py-1 font-sans text-[11px] text-[#e6f0e4] outline-none placeholder:text-[#899384] focus:border-[#5ccfe6]"
      />
      <div className="flex justify-end gap-1.5">
        <button
          type="button"
          data-testid="line-comment-cancel"
          onClick={onCancel}
          className="rounded px-2 py-0.5 text-[10px] text-[#899384] hover:text-[#e6f0e4]"
        >
          Cancel
        </button>
        <button
          type="button"
          data-testid="line-comment-submit"
          disabled={!body.trim()}
          onClick={save}
          className="rounded border border-[#1a1d24] px-2 py-0.5 text-[10px] text-[#ffb454] hover:bg-[#14161e] disabled:opacity-40"
        >
          Add comment
        </button>
      </div>
    </div>
  );
}

/** One side of a split (side-by-side) line cell; null renders an empty filler. */
export function SplitCell({
  line,
  side,
  wordWrap,
  comments,
}: {
  line: DiffLine | null;
  side: "old" | "new";
  wordWrap?: boolean;
  comments?: LineCommentApi;
}) {
  if (!line) {
    return <div data-testid="diff-split-cell" className="flex-1 bg-[#0d0e13]" aria-hidden />;
  }
  const cls = TYPE_CLASSES[line.type];
  const num = side === "old" ? line.oldLineNum : line.newLineNum;
  // Only the new (RIGHT) side of a split carries the comment affordance, to avoid
  // double-rendering a composer for the same paired line.
  const anchor =
    comments && side === "new" && line.newLineNum != null
      ? { line: line.newLineNum, side: "RIGHT" as CommentSide }
      : null;
  const open = comments && anchor ? comments.isOpen(anchor.line, anchor.side) : false;

  return (
    <div className="min-w-0 flex-1">
      <div
        data-testid="diff-split-cell"
        data-line-type={line.type}
        className={`group/line flex min-w-0 font-mono text-[12px] leading-5 ${cls.row}`}
      >
        <span className="relative w-10 shrink-0 select-none px-1 text-right text-[#899384]">
          {comments && anchor && !open && (
            <button
              type="button"
              data-testid="line-comment-add"
              data-line={anchor.line}
              data-side={anchor.side}
              title="Add a comment on this line"
              aria-label="Add a comment on this line"
              onClick={() => comments.onOpen(anchor.line, anchor.side)}
              className="absolute -left-1 top-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-[3px] bg-[#5ccfe6] text-[#0a0b10] opacity-0 transition-opacity group-hover/line:opacity-100 focus:opacity-100"
            >
              <MessageSquarePlus size={10} strokeWidth={2.5} />
            </button>
          )}
          <span aria-hidden>{gutterNum(num)}</span>
        </span>
        <span
          className={`flex-1 px-1 ${cls.txt} ${wordWrap ? "whitespace-pre-wrap break-all" : "whitespace-pre overflow-x-auto"}`}
        >
          {line.content || " "}
        </span>
      </div>
      {comments && anchor && open && (
        <LineCommentComposer
          line={anchor.line}
          side={anchor.side}
          onCancel={comments.onClose}
          onSubmit={(body) => comments.onSubmit(anchor.line, anchor.side, body)}
        />
      )}
    </div>
  );
}
