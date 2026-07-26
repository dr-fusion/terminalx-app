// Pure, browser-safe presentation helpers for the Checks tab (no Node imports, no
// React). Shared by ChecksRow / ChecksRollupSummary / the tab badge. Unit-tested.
import type { ChecksCounts, ChecksItemState, ChecksRollup } from "@/types/checks";

/** Glyph + dark-palette color per row state (§5.2). */
export const STATE_PRESENTATION: Record<
  ChecksItemState,
  { glyph: string; color: string; label: string }
> = {
  success: { glyph: "✓", color: "#00ff88", label: "passed" },
  failure: { glyph: "✗", color: "#ff5050", label: "failed" },
  pending: { glyph: "⏳", color: "#5ccfe6", label: "running" },
  neutral: { glyph: "◷", color: "#899384", label: "neutral" },
  skipped: { glyph: "⊘", color: "#899384", label: "skipped" },
};

/** Tab-strip badge glyph for an aggregate rollup (§5.1). null => no badge. */
export function rollupBadgeGlyph(rollup: ChecksRollup): { glyph: string; color: string } | null {
  switch (rollup) {
    case "success":
      return { glyph: "✓", color: "#00ff88" };
    case "failure":
      return { glyph: "✗", color: "#ff5050" };
    case "pending":
      return { glyph: "⏳", color: "#5ccfe6" };
    default:
      return null; // none / no-pr / no-repo / error: no badge
  }
}

/** Humanized duration, e.g. "3m 10s", "42s". null while pending. */
export function formatDuration(durationMs: number | null): string | null {
  if (durationMs == null || durationMs < 0) return null;
  const totalSec = Math.round(durationMs / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  if (m === 0) return `${s}s`;
  return `${m}m ${String(s).padStart(2, "0")}s`;
}

/** Humanized counts line, e.g. "3 passed · 1 running · 1 skipped". */
export function summarizeCounts(counts: ChecksCounts): string {
  const parts: string[] = [];
  if (counts.success) parts.push(`${counts.success} passed`);
  if (counts.failure) parts.push(`${counts.failure} failed`);
  if (counts.pending) parts.push(`${counts.pending} running`);
  if (counts.neutral) parts.push(`${counts.neutral} neutral`);
  if (counts.skipped) parts.push(`${counts.skipped} skipped`);
  return parts.length ? parts.join(" · ") : "No checks";
}

/** Short 7-char SHA for the header row. */
export function shortSha(sha: string | null): string | null {
  if (!sha) return null;
  return sha.slice(0, 7);
}
