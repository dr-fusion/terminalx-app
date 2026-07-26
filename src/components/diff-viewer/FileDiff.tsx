"use client";

import { useEffect, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  FileMinus,
  FilePen,
  FilePlus,
  FileSymlink,
  FileText,
} from "lucide-react";
import type { FileDiff as FileDiffModel, FileStatus } from "@/types/diff";
import { HunkView } from "./HunkView";
import type { LineCommentApi } from "./LineView";

/** lucide status icon + accent color per FileStatus (spec §4.3). */
function StatusIcon({ status }: { status: FileStatus }) {
  switch (status) {
    case "added":
      return <FilePlus size={13} className="shrink-0 text-[#00ff88]" aria-label="added" />;
    case "deleted":
      return <FileMinus size={13} className="shrink-0 text-[#ff5050]" aria-label="deleted" />;
    case "renamed":
    case "copied":
      return <FileSymlink size={13} className="shrink-0 text-[#d58fff]" aria-label="renamed" />;
    case "mode-change":
      return <FileText size={13} className="shrink-0 text-[#899384]" aria-label="mode change" />;
    case "modified":
    default:
      return <FilePen size={13} className="shrink-0 text-[#5ccfe6]" aria-label="modified" />;
  }
}

interface FileDiffProps {
  file: FileDiffModel;
  collapsed: boolean;
  onToggle: () => void;
  layout: "unified" | "split";
  wordWrap?: boolean;
  /** Lazily fetch hunks for this file when expanded (spec §3.3). */
  loadFile?: (path: string) => Promise<FileDiffModel | null>;
  /** Per-file inline-comment API factory (#3); absent => read-only diff. */
  lineComments?: (filePath: string) => LineCommentApi;
}

/**
 * The screenshot's file row: muted dir + emphasized filename, +N/-N delta badge,
 * status icon; expands to a lazily-loaded body of HunkViews. spec §4.3.
 */
export function FileDiff({
  file,
  collapsed,
  onToggle,
  layout,
  wordWrap,
  loadFile,
  lineComments,
}: FileDiffProps) {
  const [hunks, setHunks] = useState(file.hunks);
  const [loading, setLoading] = useState(false);
  const fileComments = lineComments?.(file.path);

  useEffect(() => {
    setHunks(file.hunks);
  }, [file.hunks]);

  // Lazy-load hunks the first time the row is expanded (spec §3.3).
  useEffect(() => {
    if (collapsed || hunks || file.isBinary || file.truncated || !loadFile) return;
    let cancelled = false;
    setLoading(true);
    loadFile(file.path)
      .then((full) => {
        if (!cancelled && full?.hunks) setHunks(full.hunks);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [collapsed, hunks, file.isBinary, file.truncated, file.path, loadFile]);

  return (
    <div className="border-b border-[#1a1d24]" data-testid="diff-file">
      <button
        data-testid="diff-file-row"
        data-file-path={file.path}
        data-file-status={file.status}
        onClick={onToggle}
        className="flex h-9 w-full items-center gap-2 px-3 text-left text-[12px] hover:bg-[#14161e]"
      >
        {collapsed ? (
          <ChevronRight size={13} className="shrink-0 text-[#899384]" />
        ) : (
          <ChevronDown size={13} className="shrink-0 text-[#899384]" />
        )}
        <StatusIcon status={file.status} />
        <span className="min-w-0 truncate" data-testid="diff-file-path">
          {file.oldPath && (file.status === "renamed" || file.status === "copied") ? (
            <>
              <span className="text-[#899384]">{file.oldPath}</span>
              <span className="px-1 text-[#899384]">→</span>
            </>
          ) : null}
          <span className="text-[#899384]">{file.dir}</span>
          <span className="font-medium text-[#e6f0e4]">{file.filename}</span>
        </span>
        <span className="flex-1" />
        {!file.isBinary && file.additions > 0 && (
          <span data-testid="diff-file-additions" className="font-mono text-[#00ff88]">
            +{file.additions}
          </span>
        )}
        {!file.isBinary && file.deletions > 0 && (
          <span data-testid="diff-file-deletions" className="font-mono text-[#ff5050]">
            -{file.deletions}
          </span>
        )}
      </button>

      {!collapsed && (
        <div data-testid="diff-file-body" className="bg-[#0a0b10]">
          {file.isBinary ? (
            <div className="px-4 py-2 text-[12px] text-[#899384]">Binary file changed</div>
          ) : file.truncated ? (
            <div className="px-4 py-2 text-[12px] text-[#899384]">
              File too large to display — open externally
            </div>
          ) : file.status === "mode-change" ? (
            <div className="px-4 py-2 font-mono text-[12px] text-[#899384]">
              Mode change {file.oldMode ?? ""} → {file.newMode ?? ""}
            </div>
          ) : loading ? (
            <div className="px-4 py-2 text-[12px] text-[#899384]">Loading diff…</div>
          ) : hunks && hunks.length > 0 ? (
            hunks.map((hunk) => (
              <HunkView
                key={hunk.index}
                hunk={hunk}
                layout={layout}
                wordWrap={wordWrap}
                comments={fileComments}
              />
            ))
          ) : (
            <div className="px-4 py-2 text-[12px] text-[#899384]">No textual changes</div>
          )}
        </div>
      )}
    </div>
  );
}
