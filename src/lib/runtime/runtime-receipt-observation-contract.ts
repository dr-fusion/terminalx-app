/**
 * Durable signed-follow cursor bound, measured in Unicode code points.
 * SQLite `length(TEXT)` uses the same unit for non-NUL text.
 */
export const RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS = 1_000;

export function runtimeReceiptObservationCursorCodePoints(cursor: string): number {
  return Array.from(cursor).length;
}
