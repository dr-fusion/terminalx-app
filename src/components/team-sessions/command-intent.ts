import { HttpError } from "@/lib/team-sessions/browser-client";
import type { TeamSessionCommandBody } from "@/types/team-session";

/**
 * Revision fences protect execution, but they are not part of the human's
 * logical intent. Keeping this fingerprint stable lets an uncertain request
 * replay the exact original command and idempotency key after detail refreshes.
 */
export function teamSessionCommandIntentFingerprint(command: TeamSessionCommandBody): string {
  return JSON.stringify(
    Object.fromEntries(
      Object.entries(command).filter(
        ([key]) => !key.startsWith("expected") && key !== "occurredAtMs"
      )
    )
  );
}

/** A definite 4xx rejection may be rebuilt against fresh canonical revisions. */
export function shouldPreserveTeamSessionCommandIntent(cause: unknown): boolean {
  return !(cause instanceof HttpError) || cause.retryable;
}
