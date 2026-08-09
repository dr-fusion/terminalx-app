"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  CheckCircle2,
  KeyRound,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  createTeamSessionIdempotencyKey,
  fetchTeamSessionDetail,
  HttpError,
  submitTeamSessionCommand,
} from "@/lib/team-sessions/browser-client";
import {
  isPendingTeamSessionAdmission,
  parseRedeemedTeamSessionInvitation,
  teamSessionJoinPath,
  type RedeemedTeamSessionInvitation,
} from "./invitation-join";

type JoinPhase = "ready" | "redeeming" | "joining" | "waiting" | "error";

function queryInvitation(
  sessionId: string | null,
  invitationId: string | null
): RedeemedTeamSessionInvitation | null {
  if (!sessionId || !invitationId) return null;
  return { sessionId, invitationId, membershipRole: "guest" };
}

function message(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback;
}

export function JoinTeamSession() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialInvitation = queryInvitation(
    searchParams.get("sessionId"),
    searchParams.get("invitationId")
  );
  const [token, setToken] = useState("");
  const [invitation, setInvitation] = useState<RedeemedTeamSessionInvitation | null>(
    initialInvitation
  );
  const [phase, setPhase] = useState<JoinPhase>(initialInvitation ? "joining" : "ready");
  const [error, setError] = useState<string | null>(null);
  const redeemIntentRef = useRef<{
    token: string;
    idempotencyKey: string;
  } | null>(null);
  const joinIntentRef = useRef<{
    fingerprint: string;
    idempotencyKey: string;
  } | null>(null);
  const operationInFlightRef = useRef(false);
  const attemptedInitialJoinRef = useRef(false);

  const enterSession = useCallback(
    async (redeemed: RedeemedTeamSessionInvitation) => {
      if (operationInFlightRef.current) return;
      operationInFlightRef.current = true;
      setPhase("joining");
      setError(null);
      const fingerprint = `${redeemed.sessionId}:${redeemed.invitationId}`;
      const previous = joinIntentRef.current;
      const intent =
        previous?.fingerprint === fingerprint
          ? previous
          : { fingerprint, idempotencyKey: createTeamSessionIdempotencyKey() };
      joinIntentRef.current = intent;

      try {
        await submitTeamSessionCommand(
          {
            type: "session.join",
            sessionId: redeemed.sessionId,
            invitationId: redeemed.invitationId,
          },
          { idempotencyKey: intent.idempotencyKey }
        );
        joinIntentRef.current = null;
        router.replace(`/team-sessions/${encodeURIComponent(redeemed.sessionId)}`);
      } catch (cause) {
        // If the join committed but its response was lost, canonical detail is
        // the safe recovery check; a second non-idempotent admission is avoided.
        try {
          await fetchTeamSessionDetail(redeemed.sessionId);
          joinIntentRef.current = null;
          router.replace(`/team-sessions/${encodeURIComponent(redeemed.sessionId)}`);
          return;
        } catch {
          // Not admitted yet. Keep the explicit retry path below.
        }

        if (cause instanceof HttpError && !cause.retryable) {
          joinIntentRef.current = null;
        }
        if (isPendingTeamSessionAdmission(cause)) {
          setPhase("waiting");
          setError(null);
        } else {
          setPhase("error");
          setError(message(cause, "Could not check Session access"));
        }
      } finally {
        operationInFlightRef.current = false;
      }
    },
    [router]
  );

  useEffect(() => {
    if (!initialInvitation || attemptedInitialJoinRef.current) return;
    attemptedInitialJoinRef.current = true;
    void enterSession(initialInvitation);
  }, [enterSession, initialInvitation]);

  const redeem = async () => {
    const normalizedToken = token.trim();
    if (!normalizedToken || operationInFlightRef.current) return;
    operationInFlightRef.current = true;
    setPhase("redeeming");
    setError(null);
    const previous = redeemIntentRef.current;
    const intent =
      previous?.token === normalizedToken
        ? previous
        : { token: normalizedToken, idempotencyKey: createTeamSessionIdempotencyKey() };
    redeemIntentRef.current = intent;

    try {
      const result = await submitTeamSessionCommand(
        { type: "session.invitation.redeem", token: intent.token },
        { idempotencyKey: intent.idempotencyKey }
      );
      const redeemed = parseRedeemedTeamSessionInvitation(result);
      redeemIntentRef.current = null;
      setToken("");
      setInvitation(redeemed);
      router.replace(teamSessionJoinPath(redeemed), { scroll: false });
      operationInFlightRef.current = false;
      await enterSession(redeemed);
    } catch (cause) {
      if (cause instanceof HttpError && !cause.retryable) {
        redeemIntentRef.current = null;
      }
      setPhase("error");
      setError(message(cause, "Could not redeem this invitation"));
    } finally {
      operationInFlightRef.current = false;
    }
  };

  const busy = phase === "redeeming" || phase === "joining";
  const waiting = phase === "waiting" || (phase === "error" && invitation !== null);

  return (
    <main className="h-full overflow-y-auto bg-background px-4 py-8 md:px-8">
      <div className="mx-auto max-w-xl">
        <Button
          render={<Link href="/team-sessions" />}
          nativeButton={false}
          size="lg"
          variant="ghost"
          className="min-h-10"
        >
          <ArrowLeft aria-hidden="true" />
          Back to sessions
        </Button>

        <section className="mt-6 rounded-xl border border-border bg-card p-5 md:p-7">
          <div className="flex size-11 items-center justify-center rounded-full border border-border bg-background">
            {waiting ? (
              <ShieldCheck className="size-5 text-[var(--amber)]" aria-hidden="true" />
            ) : (
              <KeyRound className="size-5 text-primary" aria-hidden="true" />
            )}
          </div>
          <h1 className="mt-5 text-lg font-semibold">
            {waiting ? "Membership verified — access is pending" : "Join a team session"}
          </h1>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">
            {waiting
              ? "A manager must now grant the required Project Access or revocable Guest Session Share. The invitation token has already been consumed and is no longer needed."
              : "Sign in, then paste the one-time token you received through a secure channel. Tokens are never saved in the URL or browser storage."}
          </p>

          {invitation ? (
            <div className="mt-5 space-y-4">
              <div className="rounded-lg border border-[color:var(--amber-dim)] bg-[var(--amber-ghost)] p-4 text-sm">
                <div className="flex items-start gap-2">
                  <CheckCircle2
                    className="mt-0.5 size-4 shrink-0 text-[var(--amber)]"
                    aria-hidden="true"
                  />
                  <p className="leading-6 text-muted-foreground">
                    Redemption proves Team Membership, not Session authorization. Joining always
                    rechecks current access and creates an Observer first.
                  </p>
                </div>
              </div>
              {error ? (
                <p
                  className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"
                  role="alert"
                >
                  {error}
                </p>
              ) : null}
              <Button
                type="button"
                size="lg"
                className="min-h-10"
                disabled={busy}
                aria-busy={busy}
                onClick={() => void enterSession(invitation)}
              >
                {busy ? (
                  <LoaderCircle
                    className="animate-spin motion-reduce:animate-none"
                    aria-hidden="true"
                  />
                ) : (
                  <RefreshCw aria-hidden="true" />
                )}
                {busy ? "Checking access" : "Check access and join"}
              </Button>
            </div>
          ) : (
            <form
              className="mt-5 space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                void redeem();
              }}
            >
              <div className="space-y-1.5">
                <label htmlFor="team-session-invitation-token" className="text-xs font-medium">
                  One-time invitation token
                </label>
                <input
                  id="team-session-invitation-token"
                  type="password"
                  value={token}
                  required
                  maxLength={1_000}
                  disabled={busy}
                  autoComplete="off"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-xs text-foreground focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                  placeholder="Paste the token here"
                  onChange={(event) => {
                    redeemIntentRef.current = null;
                    setToken(event.target.value);
                    setError(null);
                    setPhase("ready");
                  }}
                />
              </div>
              {error ? (
                <p
                  className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"
                  role="alert"
                >
                  {error}
                </p>
              ) : null}
              <Button
                type="submit"
                size="lg"
                className="min-h-10"
                disabled={busy || token.trim().length === 0}
                aria-busy={busy}
              >
                {busy ? (
                  <LoaderCircle
                    className="animate-spin motion-reduce:animate-none"
                    aria-hidden="true"
                  />
                ) : (
                  <KeyRound aria-hidden="true" />
                )}
                {busy ? "Redeeming invitation" : "Verify invitation"}
              </Button>
            </form>
          )}
        </section>
      </div>
    </main>
  );
}
