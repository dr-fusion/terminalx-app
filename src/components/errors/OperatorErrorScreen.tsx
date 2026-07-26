"use client";

import Link from "next/link";
import { AlertTriangle, LogIn, RefreshCw, Home } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { OperatorErrorInfo } from "@/lib/operator-error";

interface OperatorErrorScreenProps {
  info: OperatorErrorInfo;
  /** Retry the current view (error-boundary reset). */
  onRetry?: () => void;
  /** Render without app chrome assumptions (used by global-error). */
  bare?: boolean;
}

/**
 * The single, non-leaking operator error surface. It renders only the
 * pre-approved copy from {@link OperatorErrorInfo} and an opaque reference — it
 * never receives or displays a raw error object.
 */
export function OperatorErrorScreen({ info, onRetry, bare = false }: OperatorErrorScreenProps) {
  const showRetry = info.action === "retry" && onRetry;
  return (
    <div
      className={
        bare
          ? "flex min-h-dvh items-center justify-center bg-[#0a0b10] p-6 text-[#e6f0e4]"
          : "flex h-full min-h-0 items-center justify-center p-6"
      }
    >
      <div
        role="alert"
        aria-live="assertive"
        className="w-full max-w-md rounded-lg border border-border bg-card p-6 text-center"
      >
        <div className="mx-auto flex size-11 items-center justify-center rounded-full border border-[color:var(--amber-dim)] bg-[var(--amber-ghost)]">
          <AlertTriangle className="size-5 text-[var(--amber)]" aria-hidden="true" />
        </div>
        <h1 className="mt-4 text-base font-semibold">{info.title}</h1>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">{info.description}</p>

        <div className="mt-5 flex flex-wrap justify-center gap-2">
          {showRetry ? (
            <Button type="button" size="lg" className="min-h-10" onClick={onRetry}>
              <RefreshCw aria-hidden="true" />
              Try again
            </Button>
          ) : null}
          {info.action === "sign-in" ? (
            <Button
              render={<Link href="/login" />}
              nativeButton={false}
              size="lg"
              className="min-h-10"
            >
              <LogIn aria-hidden="true" />
              Sign in
            </Button>
          ) : null}
          {info.action === "home" || (!showRetry && info.action !== "sign-in") ? (
            <Button
              render={<Link href="/dashboard" />}
              nativeButton={false}
              size="lg"
              variant="outline"
              className="min-h-10"
            >
              <Home aria-hidden="true" />
              Back to dashboard
            </Button>
          ) : null}
          {onRetry && info.action !== "retry" ? (
            <Button
              type="button"
              size="lg"
              variant="outline"
              className="min-h-10"
              onClick={onRetry}
            >
              <RefreshCw aria-hidden="true" />
              Try again
            </Button>
          ) : null}
        </div>

        {info.reference ? (
          <p className="mt-4 text-xs text-muted-foreground">
            Reference: <span className="font-mono">{info.reference}</span>
          </p>
        ) : null}
      </div>
    </div>
  );
}
