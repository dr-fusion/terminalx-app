/**
 * Operator-facing error classification.
 *
 * The single rule here is non-leakage: raw error messages, stack traces,
 * provider payloads, paths, and secrets must never reach the UI. This module
 * maps an arbitrary thrown value onto a small, closed set of safe operator
 * error classes with fixed, human-written copy. The only value ever carried
 * through from the original error is the server-generated `digest`, which is an
 * opaque correlation hash (see Next.js `error.digest`).
 */

export type OperatorErrorKind =
  | "auth-expired"
  | "permission-denied"
  | "not-found"
  | "conflict"
  | "runtime-unavailable"
  | "offline"
  | "rate-limited"
  | "server"
  | "unknown";

export type OperatorErrorAction = "retry" | "sign-in" | "home" | "none";

export interface OperatorErrorInfo {
  kind: OperatorErrorKind;
  title: string;
  description: string;
  action: OperatorErrorAction;
  /** Opaque, safe correlation id (the server error digest) when available. */
  reference?: string;
}

interface NormalizedError {
  status?: number;
  code?: string;
  name?: string;
  digest?: string;
}

const COPY: Record<
  OperatorErrorKind,
  { title: string; description: string; action: OperatorErrorAction }
> = {
  "auth-expired": {
    title: "Your session expired",
    description: "Sign in again to continue. Your work stays safely on the server.",
    action: "sign-in",
  },
  "permission-denied": {
    title: "You don't have access",
    description:
      "This resource isn't available to your account. Access is re-checked on every request, so ask a session manager if you think this is wrong.",
    action: "home",
  },
  "not-found": {
    title: "This is no longer available",
    description: "It may have been ended, revoked, or removed. Head back and pick another session.",
    action: "home",
  },
  conflict: {
    title: "The state changed",
    description: "Someone else changed this while you were working. Refresh to see the latest.",
    action: "retry",
  },
  "runtime-unavailable": {
    title: "The runtime is unavailable",
    description:
      "The execution environment isn't reachable right now. Live terminal and run controls are paused; the canonical history is safe.",
    action: "retry",
  },
  offline: {
    title: "You appear to be offline",
    description: "Check your connection. This view will recover once the network is back.",
    action: "retry",
  },
  "rate-limited": {
    title: "Too many requests",
    description: "Slow down for a moment, then try again.",
    action: "retry",
  },
  server: {
    title: "Something went wrong on our side",
    description:
      "This is a temporary problem, not something you did. Try again in a moment. If it persists, share the reference below.",
    action: "retry",
  },
  unknown: {
    title: "Something went wrong",
    description:
      "An unexpected error interrupted this view. Try again. If it keeps happening, share the reference below.",
    action: "retry",
  },
};

function normalize(error: unknown): NormalizedError {
  const result: NormalizedError = {};
  if (error && typeof error === "object") {
    const record = error as Record<string, unknown>;
    if (typeof record.status === "number" && Number.isFinite(record.status)) {
      result.status = record.status;
    }
    if (typeof record.code === "string") result.code = record.code;
    if (typeof record.name === "string") result.name = record.name;
    if (typeof record.digest === "string") result.digest = record.digest;
  }
  return result;
}

/** Whether a normalized code/name indicates a fail-closed runtime/authority state. */
function isRuntimeUnavailable(code: string | undefined): boolean {
  if (!code) return false;
  const normalized = code.toLowerCase().replace(/_/g, "-");
  return (
    normalized === "runtime-unavailable" ||
    normalized === "runtime-timeout" ||
    normalized === "runtime-invalid-state" ||
    normalized === "runtime-not-ready" ||
    normalized === "authority-unavailable"
  );
}

function isNetworkError(name: string | undefined, code: string | undefined): boolean {
  if (code === "network-error") return true;
  // A fetch() network failure surfaces as a TypeError in browsers.
  return name === "TypeError";
}

export function classifyOperatorError(
  error: unknown,
  hints: { offline?: boolean } = {}
): OperatorErrorInfo {
  const { status, code, name, digest } = normalize(error);

  let kind: OperatorErrorKind = "unknown";
  if (hints.offline === true) {
    kind = "offline";
  } else if (isRuntimeUnavailable(code)) {
    kind = "runtime-unavailable";
  } else if (status !== undefined) {
    if (status === 401) kind = "auth-expired";
    else if (status === 403) kind = "permission-denied";
    else if (status === 404 || status === 410) kind = "not-found";
    else if (status === 409) kind = "conflict";
    else if (status === 429) kind = "rate-limited";
    else if (status === 408) kind = "offline";
    else if (status >= 500) kind = "server";
    else kind = "unknown";
  } else if (isNetworkError(name, code)) {
    kind = "offline";
  }

  const copy = COPY[kind];
  return {
    kind,
    title: copy.title,
    description: copy.description,
    action: copy.action,
    ...(digest ? { reference: digest } : {}),
  };
}
