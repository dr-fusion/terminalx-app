"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import {
  AlertCircle,
  MessageSquareText,
  RefreshCw,
  TerminalSquare,
  UsersRound,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConversationComposer, type ConversationIntent } from "./ConversationComposer";
import { ConversationTimeline } from "./ConversationTimeline";
import { InviteGuestDialog } from "./InviteGuestDialog";
import { ParticipantsPanel, type GovernanceAction } from "./ParticipantsPanel";
import { SessionHeader } from "./SessionHeader";
import { shouldRefreshTeamSessionAdmission } from "./admission-refresh";
import {
  shouldPreserveTeamSessionCommandIntent,
  teamSessionCommandIntentFingerprint,
} from "./command-intent";
import { useTeamSession } from "@/hooks/team-sessions/useTeamSession";
import { useTeamSessionAdmission } from "@/hooks/team-sessions/useTeamSessionAdmission";
import { useTeamSessionEvents } from "@/hooks/team-sessions/useTeamSessionEvents";
import {
  createTeamSessionIdempotencyKey,
  submitTeamSessionCommand,
} from "@/lib/team-sessions/browser-client";
import type { TeamSessionCommandBody, TeamSessionCommandResult } from "@/types/team-session";
import { cn } from "@/lib/utils";

const TeamSessionTerminal = dynamic(
  () =>
    import("@/components/team-sessions/terminal/TeamSessionTerminal").then(
      (module) => module.TeamSessionTerminal
    ),
  {
    ssr: false,
    loading: () => (
      <div className="h-full space-y-3 bg-background p-5" aria-label="Loading terminal">
        <div className="h-4 w-48 animate-pulse rounded bg-muted" />
        <div className="h-3 w-2/3 animate-pulse rounded bg-muted" />
        <div className="h-3 w-1/2 animate-pulse rounded bg-muted" />
      </div>
    ),
  }
);

type WorkspaceTab = "conversation" | "terminal" | "people";
type MutationScope = "conversation" | "governance" | "invitation";

interface SessionWorkspaceProps {
  sessionId: string;
  transportEnabled: boolean | null;
}

function errorMessage(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback;
}

function SessionWorkspaceSkeleton() {
  return (
    <div className="flex h-full min-h-0 flex-col" aria-label="Loading session">
      <div className="h-20 shrink-0 animate-pulse border-b border-border bg-card" />
      <div className="grid min-h-0 flex-1 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-5 p-6">
          {["w-2/3", "w-4/5", "w-1/2"].map((width) => (
            <div key={width} className={cn("h-20 animate-pulse rounded-lg bg-muted", width)} />
          ))}
        </div>
        <div className="hidden border-l border-border bg-card p-4 lg:block">
          <div className="h-4 w-32 animate-pulse rounded bg-muted" />
          <div className="mt-5 h-24 animate-pulse rounded-lg bg-muted" />
        </div>
      </div>
    </div>
  );
}

export function SessionWorkspace({ sessionId, transportEnabled }: SessionWorkspaceProps) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const view = searchParams.get("view");
  const activeTab: WorkspaceTab = view === "terminal" || view === "people" ? view : "conversation";
  const { session, isLoading, error, refresh } = useTeamSession(sessionId);
  const admissionEnabled =
    session?.viewer.capabilities.manageShares === true ||
    session?.viewer.capabilities.createInvitation === true ||
    session?.viewer.capabilities.revokeInvitation === true;
  const {
    admission,
    isLoading: isAdmissionLoading,
    error: admissionError,
    refresh: refreshAdmission,
  } = useTeamSessionAdmission(sessionId, admissionEnabled);
  const {
    events,
    historyTruncated,
    connectionState,
    error: eventError,
    retry: retryEvents,
  } = useTeamSessionEvents(sessionId, session?.latestSequence ?? 0, transportEnabled === true);
  const [mutationScope, setMutationScope] = useState<MutationScope | null>(null);
  const [mutationError, setMutationError] = useState<{
    scope: MutationScope;
    message: string;
  } | null>(null);
  const [resolvingSuggestionId, setResolvingSuggestionId] = useState<string | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const commandIntentRef = useRef<
    Partial<
      Record<
        MutationScope,
        {
          fingerprint: string;
          idempotencyKey: string;
          command: TeamSessionCommandBody;
        }
      >
    >
  >({});
  const mutationInFlightRef = useRef(false);
  const lastEventErrorRef = useRef<Error | null>(null);

  const latestEventSequence = events.at(-1)?.sequence ?? 0;
  useEffect(() => {
    if (!session || latestEventSequence <= session.latestSequence) return;
    const admissionChanged =
      admissionEnabled && shouldRefreshTeamSessionAdmission(events, session.latestSequence);
    const refreshTimer = window.setTimeout(
      () =>
        void Promise.all([refresh(), admissionChanged ? refreshAdmission() : Promise.resolve()]),
      120
    );
    return () => window.clearTimeout(refreshTimer);
  }, [admissionEnabled, events, latestEventSequence, refresh, refreshAdmission, session]);

  useEffect(() => {
    if (!eventError || lastEventErrorRef.current === eventError) return;
    lastEventErrorRef.current = eventError;
    void refresh();
  }, [eventError, refresh]);

  const selectTab = (tab: WorkspaceTab) => {
    const next = new URLSearchParams(searchParams.toString());
    if (tab === "conversation") next.delete("view");
    else next.set("view", tab);
    router.replace(`${pathname}${next.size > 0 ? `?${next.toString()}` : ""}`, { scroll: false });
  };

  const runCommand = async (
    scope: MutationScope,
    command: TeamSessionCommandBody
  ): Promise<TeamSessionCommandResult> => {
    if (mutationInFlightRef.current) {
      throw new Error("Another session action is still in progress");
    }
    const fingerprint = teamSessionCommandIntentFingerprint(command);
    const previousIntent = commandIntentRef.current[scope];
    const intent =
      previousIntent?.fingerprint === fingerprint
        ? previousIntent
        : { fingerprint, idempotencyKey: createTeamSessionIdempotencyKey(), command };
    commandIntentRef.current[scope] = intent;
    mutationInFlightRef.current = true;
    setMutationScope(scope);
    setMutationError(null);
    try {
      const result = await submitTeamSessionCommand(intent.command, {
        idempotencyKey: intent.idempotencyKey,
      });
      await Promise.all([
        refresh(),
        scope === "conversation" || !admissionEnabled ? Promise.resolve() : refreshAdmission(),
      ]);
      delete commandIntentRef.current[scope];
      return result;
    } catch (cause) {
      if (!shouldPreserveTeamSessionCommandIntent(cause)) {
        delete commandIntentRef.current[scope];
      }
      setMutationError({
        scope,
        message: errorMessage(cause, "The session changed before this action completed."),
      });
      await Promise.all([
        refresh(),
        scope === "conversation" || !admissionEnabled ? Promise.resolve() : refreshAdmission(),
      ]);
      throw cause;
    } finally {
      mutationInFlightRef.current = false;
      setMutationScope(null);
    }
  };

  if (isLoading && !session) return <SessionWorkspaceSkeleton />;

  if (error || !session) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <div className="max-w-md rounded-lg border border-destructive/30 bg-destructive/5 p-5">
          <div className="flex items-center gap-2 text-destructive">
            <AlertCircle className="size-5" aria-hidden="true" />
            <h1 className="text-sm font-semibold">Couldn&apos;t open this session</h1>
          </div>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">
            It may have been revoked, removed, or temporarily unavailable. Your access is checked
            again on every request.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Button type="button" size="lg" className="min-h-10" onClick={() => void refresh()}>
              <RefreshCw aria-hidden="true" />
              Try again
            </Button>
            <Button
              render={<Link href="/team-sessions" />}
              nativeButton={false}
              size="lg"
              variant="outline"
              className="min-h-10"
            >
              Back to sessions
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const capabilities = session.viewer.capabilities;

  const submitConversation = async (intent: ConversationIntent, body: string) => {
    const command: TeamSessionCommandBody =
      intent === "comment"
        ? { type: "comment.add", sessionId, body }
        : intent === "suggestion"
          ? { type: "suggestion.add", sessionId, body }
          : {
              type: "directive.enqueue",
              sessionId,
              body,
              expectedSteeringRevision: session.viewer.basis.steeringRevision,
            };
    await runCommand("conversation", command);
  };

  const resolveSuggestion = async (
    suggestionId: string,
    suggestionVersion: number,
    resolution: "accept" | "reject"
  ) => {
    setResolvingSuggestionId(suggestionId);
    try {
      await runCommand("conversation", {
        type: "suggestion.resolve",
        sessionId,
        suggestionId,
        resolution,
        expectedSuggestionVersion: suggestionVersion,
        expectedSteeringRevision: session.viewer.basis.steeringRevision,
      });
    } finally {
      setResolvingSuggestionId(null);
    }
  };

  const runGovernanceAction = async (action: GovernanceAction) => {
    const basis = session.viewer.basis;
    let command: TeamSessionCommandBody;
    if (action.type === "transfer-control") {
      command = {
        type: "session.control.transfer",
        sessionId,
        userId: action.participant.userId,
        expectedControlRevision: basis.controlRevision,
        expectedControlEpoch: basis.controlEpoch,
        expectedParticipantVersion: action.participant.version,
      };
    } else if (action.type === "release-control") {
      command = {
        type: "session.control.release",
        sessionId,
        expectedControlRevision: basis.controlRevision,
        expectedControlEpoch: basis.controlEpoch,
      };
    } else if (action.type === "claim-assignee") {
      command = {
        type: "session.assignee.claim",
        sessionId,
        expectedAssigneeRevision: basis.assigneeRevision,
        expectedAccessRevision: basis.accessRevision,
      };
    } else if (action.type === "revoke-share") {
      command = {
        type: "session.share.revoke",
        sessionId,
        userId: action.share.userId,
        expectedShareVersion: action.share.version,
      };
    } else if (action.type === "revoke-invitation") {
      command = {
        type: "session.invitation.revoke",
        sessionId,
        invitationId: action.invitation.invitationId,
        expectedInvitationVersion: action.invitation.version,
      };
    } else if (action.type === "grant-share") {
      command = {
        type: "session.share.create",
        sessionId,
        userId: action.guest.userId,
        expectedAccessRevision: Math.max(admission?.accessRevision ?? 0, basis.accessRevision),
      };
    } else if (action.type === "grant-project-access") {
      command = {
        type: "project.access.grant",
        projectId: session.projectId,
        userId: action.member.userId,
        role: "contributor",
        expectedAccessVersion: action.member.expectedProjectAccessVersion,
      };
    } else if (action.type === "offer-handoff") {
      const offeredUnder = session.viewer.responsibilities.includes("assignee")
        ? "assignee"
        : "supervisor";
      const offererResponsibilityVersion = basis.responsibilityVersions[offeredUnder];
      if (offererResponsibilityVersion === undefined) {
        throw new Error("Handoff authority changed; refresh and try again");
      }
      command = {
        type: "session.handoff.offer",
        sessionId,
        recipientParticipantId: action.participant.participantId,
        expectedAssigneeRevision: basis.assigneeRevision,
        expectedRecipientParticipantVersion: action.participant.version,
        expectedOffererResponsibilityVersion: offererResponsibilityVersion,
        expiresAtMs: action.expiresAtMs,
        briefing: action.briefing,
      };
    } else if (action.type === "accept-handoff") {
      command = {
        type: "session.handoff.accept",
        sessionId,
        handoffId: action.handoff.handoffId,
        expectedHandoffVersion: action.handoff.version,
      };
    } else if (action.type === "cancel-handoff") {
      command = {
        type: "session.handoff.cancel",
        sessionId,
        handoffId: action.handoff.handoffId,
        expectedHandoffVersion: action.handoff.version,
      };
    } else if (action.type === "grant-responsibility") {
      command =
        action.responsibility === "steerer"
          ? {
              type: "session.responsibility.grant",
              sessionId,
              userId: action.participant.userId,
              responsibility: "steerer",
              expectedSteeringRevision: basis.steeringRevision,
              expectedParticipantVersion: action.participant.version,
            }
          : {
              type: "session.responsibility.grant",
              sessionId,
              userId: action.participant.userId,
              responsibility: "supervisor",
              expectedSupervisionRevision: basis.supervisionRevision,
              expectedParticipantVersion: action.participant.version,
            };
    } else {
      command =
        action.responsibility === "steerer"
          ? {
              type: "session.responsibility.revoke",
              sessionId,
              userId: action.participant.userId,
              responsibility: "steerer",
              expectedSteeringRevision: basis.steeringRevision,
              expectedControlRevision: basis.controlRevision,
              expectedControlEpoch: basis.controlEpoch,
            }
          : {
              type: "session.responsibility.revoke",
              sessionId,
              userId: action.participant.userId,
              responsibility: "supervisor",
              expectedSupervisionRevision: basis.supervisionRevision,
            };
    }
    await runCommand("governance", command);
  };

  const createInvitation = async (
    membershipRole: "member" | "guest",
    expiresAtMs: number
  ): Promise<string> => {
    const result = await runCommand("invitation", {
      type: "session.invitation.create",
      sessionId,
      membershipRole,
      expiresAtMs,
      expectedAccessRevision: Math.max(
        admission?.accessRevision ?? 0,
        session.viewer.basis.accessRevision
      ),
    });
    const token = result.data.invitationToken;
    if (typeof token !== "string" || token.length === 0) {
      const message =
        result.data.invitationTokenUnavailable === true
          ? "The invitation was created, but its one-time token cannot be shown after a retry. Revoke it under Active invitations, then create another."
          : "The one-time invitation token was unavailable";
      setMutationError({ scope: "invitation", message });
      throw new Error(message);
    }
    return token;
  };

  const tabs: Array<{ value: WorkspaceTab; label: string; icon: typeof MessageSquareText }> = [
    { value: "conversation", label: "Conversation", icon: MessageSquareText },
    { value: "terminal", label: "Terminal", icon: TerminalSquare },
    { value: "people", label: "People", icon: UsersRound },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <SessionHeader
        session={session}
        connectionState={connectionState}
        transportEnabled={transportEnabled}
      />

      <div
        className="flex min-h-12 shrink-0 items-center border-b border-border bg-card px-2"
        role="tablist"
        aria-label="Session view"
      >
        {tabs.map(({ value, label, icon: Icon }) => (
          <button
            key={value}
            type="button"
            role="tab"
            aria-selected={activeTab === value}
            aria-controls={`team-session-${value}`}
            className={cn(
              "flex min-h-10 items-center gap-2 rounded-md px-3 text-xs font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring",
              value === "people" && "lg:hidden",
              activeTab === value
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground hover:bg-muted hover:text-foreground"
            )}
            onClick={() => selectTab(value)}
          >
            <Icon className="size-4" aria-hidden="true" />
            {label}
          </button>
        ))}
      </div>

      {eventError ? (
        <div className="flex shrink-0 items-center gap-3 border-b border-destructive/20 bg-destructive/5 px-4 py-2 text-xs">
          <AlertCircle className="size-4 shrink-0 text-destructive" aria-hidden="true" />
          <p className="min-w-0 flex-1 text-muted-foreground">
            {transportEnabled === true
              ? "Live updates paused. The canonical history remains on the server."
              : "Could not load the canonical conversation history."}
          </p>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="min-h-10"
            onClick={retryEvents}
          >
            Retry
          </Button>
        </div>
      ) : null}

      <div className="grid min-h-0 flex-1 lg:grid-cols-[minmax(0,1fr)_320px] xl:grid-cols-[minmax(0,1fr)_360px]">
        <section
          id={activeTab === "terminal" ? "team-session-terminal" : "team-session-conversation"}
          role="tabpanel"
          className={cn("min-h-0", activeTab === "people" ? "hidden lg:flex" : "flex")}
        >
          {activeTab === "terminal" ? (
            <TeamSessionTerminal
              className="h-full min-h-0 w-full"
              sessionId={sessionId}
              canObserve={capabilities.observeTerminal}
              canMutate={capabilities.mutateTerminal}
              sessionStatus={session.status}
              transportEnabled={transportEnabled}
            />
          ) : (
            <div className="flex h-full min-h-0 w-full flex-col">
              <div className="min-h-0 flex-1">
                <ConversationTimeline
                  events={events}
                  historyTruncated={historyTruncated}
                  viewerUserId={session.viewer.userId}
                  canResolveSuggestions={capabilities.resolveSuggestion}
                  isLoading={connectionState === "connecting" && events.length === 0}
                  resolvingSuggestionId={resolvingSuggestionId}
                  onResolveSuggestion={resolveSuggestion}
                />
              </div>
              <ConversationComposer
                capabilities={capabilities}
                sessionStatus={session.status}
                isSubmitting={mutationScope !== null}
                error={mutationError?.scope === "conversation" ? mutationError.message : null}
                onSubmit={submitConversation}
              />
            </div>
          )}
        </section>

        <div
          id="team-session-people"
          role="tabpanel"
          className={cn(
            "min-h-0 border-l border-border",
            activeTab === "people" ? "block" : "hidden lg:block"
          )}
        >
          <ParticipantsPanel
            session={session}
            admission={admission}
            isAdmissionLoading={isAdmissionLoading}
            admissionError={admissionError?.message}
            isMutating={mutationScope !== null}
            error={mutationError?.scope === "governance" ? mutationError.message : null}
            onAction={runGovernanceAction}
            onInviteGuest={() => {
              setMutationError(null);
              setInviteOpen(true);
            }}
            onRetryAdmission={() => void refreshAdmission()}
          />
        </div>
      </div>

      <InviteGuestDialog
        open={inviteOpen}
        isSubmitting={mutationScope !== null}
        error={mutationError?.scope === "invitation" ? mutationError.message : null}
        onOpenChange={setInviteOpen}
        onCreate={createInvitation}
      />
    </div>
  );
}
