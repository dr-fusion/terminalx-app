"use client";

import { useEffect } from "react";
import { classifyOperatorError } from "@/lib/operator-error";
import { OperatorErrorScreen } from "@/components/errors/OperatorErrorScreen";

/**
 * Root error boundary. It replaces the root layout when active, so it must
 * render its own <html>/<body>. Used only for errors thrown in the root layout
 * itself; ordinary app errors are caught by the (app) segment boundary.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[operator-error] root error");
  }, [error]);

  const offline = typeof navigator !== "undefined" && navigator.onLine === false;
  const info = classifyOperatorError(error, { offline });

  return (
    <html lang="en" className="dark h-full antialiased">
      <body className="h-dvh overflow-hidden font-mono">
        <title>Something went wrong · TerminalX</title>
        <OperatorErrorScreen info={info} onRetry={reset} bare />
      </body>
    </html>
  );
}
