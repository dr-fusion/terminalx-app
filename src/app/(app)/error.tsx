"use client";

import { useEffect } from "react";
import { classifyOperatorError } from "@/lib/operator-error";
import { OperatorErrorScreen } from "@/components/errors/OperatorErrorScreen";

/**
 * Segment error boundary for the authenticated app. It catches uncaught render
 * errors below the `(app)` layout and renders the non-leaking operator surface.
 * The raw error is never shown; only a static log line and the safe digest are
 * surfaced.
 */
export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Intentionally static: raw error text may carry paths/output/secrets.
    console.error("[operator-error] app segment error");
  }, [error]);

  const offline = typeof navigator !== "undefined" && navigator.onLine === false;
  const info = classifyOperatorError(error, { offline });
  return <OperatorErrorScreen info={info} onRetry={reset} />;
}
