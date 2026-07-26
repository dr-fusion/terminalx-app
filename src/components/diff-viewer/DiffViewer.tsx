"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Columns2, RefreshCw, Rows3, WrapText } from "lucide-react";
import { useSessionDiff } from "@/hooks/useSessionDiff";
import { useDiffPrefs } from "@/hooks/useDiffPrefs";
import { usePrReviewDrafts } from "@/hooks/usePrReviewDrafts";
import { buildLineDraftInput } from "@/lib/pr-review/merge";
import { FileDiffList } from "./FileDiffList";
import type { LineCommentApi } from "./LineView";

const SPLIT_MIN_WIDTH = 900; // spec §5: split needs width, else fall back to unified.
const LARGE_FILE_LINES = 600; // spec §4.4: collapse big files by default.

/**
 * The "Changes" tab body (DiffViewer). Owns prefs, fetches the file list, and
 * renders the toolbar + FileDiffList. spec §4.4.
 */
export function DiffViewer({ session }: { session: string | null }) {
  const { data, loading, error, refresh, loadFile } = useSessionDiff(session);
  const [prefs, setPrefs] = useDiffPrefs();
  // Inline line comments (#3): the diff viewer owns the (server-persisted) draft
  // store so a NEW top-level comment authored on a diff line lands in the SAME
  // store the Review tab reads — it then surfaces there as a draft-only thread.
  const drafts = usePrReviewDrafts(session);
  // The single open line composer, addressed by `${path}:${line}:${side}`.
  const [activeComposer, setActiveComposer] = useState<string | null>(null);

  const lineComments = useCallback(
    (filePath: string): LineCommentApi => ({
      filePath,
      isOpen: (line, side) => activeComposer === `${filePath}:${line}:${side}`,
      onOpen: (line, side) => setActiveComposer(`${filePath}:${line}:${side}`),
      onClose: () => setActiveComposer(null),
      onSubmit: (line, side, body) => {
        // NEW top-level draft (inReplyToId UNDEFINED) keyed by {file,line,side}.
        void drafts.upsert(buildLineDraftInput({ path: filePath, line, side, body }));
        setActiveComposer(null);
      },
    }),
    [activeComposer, drafts]
  );

  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState<number>(360);
  // File ids the user has explicitly toggled this session — once toggled, we no
  // longer auto-collapse them on the large-file heuristic.
  const [touched, setTouched] = useState<Set<string>>(() => new Set());

  // Observe panel width so split can degrade to unified below ~900px (spec §5).
  useEffect(() => {
    const el = containerRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w) setWidth(w);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const splitAvailable = width >= SPLIT_MIN_WIDTH;
  const effectiveLayout = prefs.layout === "split" && splitAvailable ? "split" : "unified";

  // The user's persisted collapsed set, plus any very large file auto-collapsed
  // by default to keep the panel responsive (spec §4.4) — unless the user has
  // already recorded a preference for it (its presence/absence in prefs.collapsed).
  const collapsed = useMemo(() => {
    const explicit = new Set(prefs.collapsed);
    if (!data) return explicit;
    const set = new Set(explicit);
    for (const f of data.files) {
      const big = f.additions + f.deletions > LARGE_FILE_LINES;
      // toggleFile records EVERY interaction, so a big file the user has touched
      // appears in prefs.collapsed (collapsed) or was removed (expanded). We only
      // auto-collapse big files the user has never toggled. We approximate "never
      // toggled" as: not already collapsed AND big — auto-collapse on first paint.
      if (big && !explicit.has(f.id) && !touched.has(f.id)) set.add(f.id);
    }
    return set;
  }, [prefs.collapsed, data, touched]);

  const toggleFile = (id: string) => {
    setTouched((prev) => (prev.has(id) ? prev : new Set(prev).add(id)));
    // Toggle against the EFFECTIVE collapsed state (includes auto-collapsed big
    // files) so the first click on an auto-collapsed file expands it.
    const next = new Set(collapsed);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setPrefs({ collapsed: [...next] });
  };

  return (
    <div ref={containerRef} data-testid="diff-viewer" className="flex h-full flex-col bg-[#0a0b10]">
      {/* Toolbar (spec §4.4): summary stat + layout/word-wrap toggles + refresh. */}
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-[#1a1d24] bg-[#0f1117] px-3 text-[11px]">
        {data ? (
          <span data-testid="diff-summary" className="text-[#a8b3a6]">
            {data.summary.filesChanged} {data.summary.filesChanged === 1 ? "file" : "files"}{" "}
            <span className="text-[#00ff88]">+{data.summary.additions}</span>{" "}
            <span className="text-[#ff5050]">-{data.summary.deletions}</span>
          </span>
        ) : (
          <span className="text-[#899384]">—</span>
        )}
        <span className="flex-1" />
        <button
          data-testid="diff-wordwrap-toggle"
          onClick={() => setPrefs({ wordWrap: !prefs.wordWrap })}
          aria-pressed={prefs.wordWrap}
          title="Toggle word wrap"
          className={`flex h-6 w-6 items-center justify-center rounded transition-colors ${
            prefs.wordWrap
              ? "bg-[#14161e] text-[#e6f0e4]"
              : "text-[#899384] hover:bg-[#14161e] hover:text-[#e6f0e4]"
          }`}
        >
          <WrapText size={13} />
        </button>
        <button
          data-testid="diff-layout-toggle"
          onClick={() => setPrefs({ layout: prefs.layout === "split" ? "unified" : "split" })}
          disabled={!splitAvailable}
          aria-pressed={effectiveLayout === "split"}
          title={
            splitAvailable ? "Toggle unified / side-by-side" : "Side-by-side needs a wider panel"
          }
          className={`flex h-6 w-6 items-center justify-center rounded transition-colors disabled:opacity-40 ${
            effectiveLayout === "split"
              ? "bg-[#14161e] text-[#e6f0e4]"
              : "text-[#899384] hover:bg-[#14161e] hover:text-[#e6f0e4]"
          }`}
        >
          {effectiveLayout === "split" ? <Columns2 size={13} /> : <Rows3 size={13} />}
        </button>
        <button
          data-testid="diff-refresh"
          onClick={refresh}
          title="Refresh diff"
          className="flex h-6 w-6 items-center justify-center rounded text-[#899384] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4]"
        >
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading && !data ? (
          <div className="px-4 py-6 text-[12px] text-[#899384]">Loading changes…</div>
        ) : error ? (
          <div data-testid="diff-error" className="px-4 py-6 text-[12px] text-[#ff5050]">
            {error}
          </div>
        ) : !data || data.files.length === 0 ? (
          <div data-testid="diff-empty" className="px-4 py-6 text-[12px] text-[#899384]">
            No changes in this workspace.
          </div>
        ) : (
          <FileDiffList
            files={data.files}
            collapsed={collapsed}
            onToggle={toggleFile}
            layout={effectiveLayout}
            wordWrap={prefs.wordWrap}
            loadFile={loadFile}
            lineComments={session ? lineComments : undefined}
          />
        )}
      </div>
    </div>
  );
}
