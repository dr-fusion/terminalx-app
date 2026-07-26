"use client";

import { useState } from "react";
import {
  Crown,
  Handshake,
  KeyRound,
  LoaderCircle,
  Shield,
  ShieldCheck,
  UserPlus,
  UsersRound,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type {
  TeamSessionActiveInvitation,
  TeamSessionAdmission,
  TeamSessionDetail,
  TeamSessionGuestAccessCandidate,
  TeamSessionMemberAccessCandidate,
  TeamSessionOpenHandoff,
  TeamSessionParticipant,
  TeamSessionResponsibility,
  TeamSessionShare,
} from "@/types/team-session";
import { cn } from "@/lib/utils";
import { OfferHandoffDialog, type HandoffBriefingInput } from "./OfferHandoffDialog";

export type GovernanceAction =
  | { type: "transfer-control"; participant: TeamSessionParticipant }
  | { type: "release-control" }
  | { type: "claim-assignee" }
  | { type: "revoke-share"; share: TeamSessionShare }
  | { type: "revoke-invitation"; invitation: TeamSessionActiveInvitation }
  | { type: "grant-share"; guest: TeamSessionGuestAccessCandidate }
  | { type: "grant-project-access"; member: TeamSessionMemberAccessCandidate }
  | {
      type: "offer-handoff";
      participant: TeamSessionParticipant;
      briefing: HandoffBriefingInput;
      expiresAtMs: number;
    }
  | { type: "accept-handoff"; handoff: TeamSessionOpenHandoff }
  | { type: "cancel-handoff"; handoff: TeamSessionOpenHandoff }
  | {
      type: "grant-responsibility" | "revoke-responsibility";
      responsibility: "supervisor" | "steerer";
      participant: TeamSessionParticipant;
    };

interface ParticipantsPanelProps {
  session: TeamSessionDetail;
  admission: TeamSessionAdmission | null;
  isAdmissionLoading: boolean;
  admissionError?: string | null;
  isMutating: boolean;
  error?: string | null;
  onAction: (action: GovernanceAction) => Promise<void>;
  onInviteGuest: () => void;
  onRetryAdmission: () => void;
}

function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  return (
    words
      .slice(0, 2)
      .map((word) => word[0])
      .join("")
      .toUpperCase() || "?"
  );
}

function responsibilityLabel(responsibility: TeamSessionResponsibility): string {
  if (responsibility === "controller") return "controller";
  return responsibility;
}

function actionCopy(action: GovernanceAction): {
  title: string;
  description: string;
  confirm: string;
  destructive?: boolean;
} {
  if (action.type === "release-control") {
    return {
      title: "Release terminal control?",
      description:
        "No participant will be able to type until a session manager or the current Controller transfers control again.",
      confirm: "Release control",
    };
  }
  if (action.type === "claim-assignee") {
    return {
      title: "Claim this session?",
      description:
        "You will become the Assignee and Supervisor, and the session can return to active work.",
      confirm: "Claim session",
    };
  }
  if (action.type === "revoke-share") {
    return {
      title: "Revoke " + action.share.displayName + "'s guest access?",
      description:
        "Their Session Share and active participation will be revoked immediately. Any queued directives they authored will be cancelled.",
      confirm: "Revoke guest access",
      destructive: true,
    };
  }
  if (action.type === "revoke-invitation") {
    return {
      title: "Revoke this invitation?",
      description:
        "The one-time token will stop working immediately. Existing members or guests are unaffected.",
      confirm: "Revoke invitation",
      destructive: true,
    };
  }
  if (action.type === "grant-share") {
    return {
      title: "Grant " + action.guest.displayName + " access to this session?",
      description:
        "This creates the explicit revocable Guest Session Share required by policy. They still join as an Observer by default.",
      confirm: "Grant guest access",
    };
  }
  if (action.type === "grant-project-access") {
    return {
      title: "Grant " + action.member.displayName + " access to this project?",
      description:
        "This grants Contributor access to the project. They can then join this session as an Observer.",
      confirm: "Grant project access",
    };
  }
  if (action.type === "offer-handoff") {
    return {
      title: "Offer responsibility to " + action.participant.displayName + "?",
      description:
        "They must accept before anything changes. The offer records your briefing and expires automatically.",
      confirm: "Offer handoff",
    };
  }
  if (action.type === "accept-handoff") {
    return {
      title: "Accept this responsibility handoff?",
      description:
        "You become the Assignee, Supervisor, Steerer, and terminal Controller atomically. Competing handoff offers close, and the previous Controller loses input immediately.",
      confirm: "Accept handoff",
    };
  }
  if (action.type === "cancel-handoff") {
    return {
      title: "Cancel this handoff offer?",
      description: "The recipient will no longer be able to accept this offer.",
      confirm: "Cancel handoff",
      destructive: true,
    };
  }
  if (action.type === "transfer-control") {
    return {
      title: "Transfer control to " + action.participant.displayName + "?",
      description:
        "The current Controller will immediately lose terminal input. The recipient becomes a Steerer when required.",
      confirm: "Transfer control",
    };
  }
  const removing = action.type === "revoke-responsibility";
  const role = action.responsibility === "steerer" ? "Steerer" : "Supervisor";
  return {
    title: (removing ? "Remove" : "Make") + " " + action.participant.displayName + " " + role + "?",
    description:
      removing && action.responsibility === "steerer"
        ? "Removing steering authority cancels that person's queued directives. If they control the terminal, control is also released."
        : "This changes who can act as a " + role + " in the shared session.",
    confirm: (removing ? "Remove" : "Make") + " " + role,
    destructive: removing,
  };
}

function ResponsibilityBadge({ responsibility }: { responsibility: TeamSessionResponsibility }) {
  const Icon =
    responsibility === "assignee"
      ? Crown
      : responsibility === "controller"
        ? KeyRound
        : responsibility === "supervisor"
          ? ShieldCheck
          : Shield;
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground">
      <Icon className="size-3" aria-hidden="true" />
      {responsibilityLabel(responsibility)}
    </span>
  );
}

export function ParticipantsPanel({
  session,
  admission,
  isAdmissionLoading,
  admissionError,
  isMutating,
  error,
  onAction,
  onInviteGuest,
  onRetryAdmission,
}: ParticipantsPanelProps) {
  const [pendingAction, setPendingAction] = useState<GovernanceAction | null>(null);
  const [handoffOpen, setHandoffOpen] = useState(false);
  const [projectionNowMs] = useState(() => Date.now());
  const capabilities = session.viewer.capabilities;
  const canInspectAdmission =
    capabilities.manageShares || capabilities.createInvitation || capabilities.revokeInvitation;
  const currentControllerId = session.responsibilities.controller?.userId;
  const activeInvitations = admission?.activeInvitations ?? [];
  const pendingGuests = (admission?.accessCandidates ?? []).filter(
    (candidate): candidate is TeamSessionGuestAccessCandidate =>
      candidate.requiredGrant === "session-share"
  );
  const pendingMembers = (admission?.accessCandidates ?? []).filter(
    (candidate): candidate is TeamSessionMemberAccessCandidate =>
      candidate.requiredGrant === "project-access"
  );
  const handoffRecipients = session.participants.filter(
    (participant) =>
      participant.userId !== session.viewer.userId &&
      !participant.responsibilities.includes("assignee")
  );

  const runPendingAction = async () => {
    if (!pendingAction) return;
    try {
      await onAction(pendingAction);
      setPendingAction(null);
    } catch {
      // Keep the confirmation open; the scoped inline error explains recovery.
    }
  };

  return (
    <>
      <aside className="flex h-full min-h-0 flex-col bg-card" aria-label="Participants and control">
        <header className="flex min-h-14 items-center gap-3 border-b border-border px-4">
          <UsersRound className="size-4 text-primary" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold">People and control</h2>
            <p className="text-xs text-muted-foreground">
              {session.participants.length}{" "}
              {session.participants.length === 1 ? "participant" : "participants"}
            </p>
          </div>
          {capabilities.createInvitation ? (
            <Button
              type="button"
              size="icon-lg"
              className="size-10"
              variant="outline"
              disabled={isMutating}
              onClick={onInviteGuest}
              aria-label="Invite a guest"
              title="Invite a guest"
            >
              <UserPlus aria-hidden="true" />
            </Button>
          ) : null}
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-3">
          {session.status === "awaiting_assignee" && capabilities.claimAssignee ? (
            <div className="mb-3 rounded-lg border border-[color:var(--amber-dim)] bg-[var(--amber-ghost)] p-3">
              <p className="text-sm font-medium text-[var(--amber)]">
                This session needs an Assignee
              </p>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                Claim it to resume active steering and terminal work.
              </p>
              <Button
                type="button"
                size="lg"
                className="mt-3 min-h-10"
                disabled={isMutating}
                onClick={() => setPendingAction({ type: "claim-assignee" })}
              >
                <Crown aria-hidden="true" />
                Claim session
              </Button>
            </div>
          ) : null}

          <ol className="space-y-2">
            {session.participants.map((participant) => {
              const isViewer = participant.userId === session.viewer.userId;
              const isController = participant.userId === currentControllerId;
              const isSteerer = participant.responsibilities.includes("steerer");
              const isSupervisor = participant.responsibilities.includes("supervisor");
              const isAssignee = participant.responsibilities.includes("assignee");
              const canRemoveSupervisor =
                !isAssignee && session.responsibilities.supervisors.length > 1;
              return (
                <li key={participant.participantId} className="rounded-lg border border-border p-3">
                  <div className="flex items-start gap-3">
                    <div
                      className={cn(
                        "flex size-9 shrink-0 items-center justify-center rounded-full border text-xs font-semibold",
                        isViewer
                          ? "border-primary/50 bg-primary/10 text-primary"
                          : "border-border bg-muted text-foreground"
                      )}
                      aria-hidden="true"
                    >
                      {initials(participant.displayName)}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-baseline gap-2">
                        <p className="truncate text-sm font-medium">{participant.displayName}</p>
                        {isViewer ? (
                          <span className="text-xs text-muted-foreground">you</span>
                        ) : null}
                        <span className="text-xs text-muted-foreground">
                          {participant.membershipRole}
                        </span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {participant.responsibilities.length > 0 ? (
                          participant.responsibilities.map((responsibility) => (
                            <ResponsibilityBadge
                              key={responsibility}
                              responsibility={responsibility}
                            />
                          ))
                        ) : (
                          <span className="text-xs text-muted-foreground">observer</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {(capabilities.transferControl ||
                    capabilities.manageSteerers ||
                    capabilities.manageSupervisors) && (
                    <div className="mt-3 flex flex-wrap gap-2 border-t border-border pt-3">
                      {capabilities.transferControl && !isController ? (
                        <Button
                          type="button"
                          size="lg"
                          variant="outline"
                          className="min-h-10"
                          disabled={isMutating}
                          onClick={() =>
                            setPendingAction({ type: "transfer-control", participant })
                          }
                        >
                          <KeyRound aria-hidden="true" />
                          Give control
                        </Button>
                      ) : null}
                      {capabilities.manageSteerers &&
                      (session.steeringPolicy === "shared" || isSteerer) ? (
                        <Button
                          type="button"
                          size="lg"
                          variant={isSteerer ? "destructive" : "outline"}
                          className="min-h-10"
                          disabled={isMutating}
                          onClick={() =>
                            setPendingAction({
                              type: isSteerer ? "revoke-responsibility" : "grant-responsibility",
                              responsibility: "steerer",
                              participant,
                            })
                          }
                        >
                          <Shield aria-hidden="true" />
                          {isSteerer ? "Remove Steerer" : "Make Steerer"}
                        </Button>
                      ) : null}
                      {capabilities.manageSupervisors ? (
                        <Button
                          type="button"
                          size="lg"
                          variant={isSupervisor ? "destructive" : "outline"}
                          className="min-h-10"
                          disabled={isMutating || (isSupervisor && !canRemoveSupervisor)}
                          title={
                            isSupervisor && !canRemoveSupervisor
                              ? isAssignee
                                ? "The Assignee must remain a Supervisor"
                                : "A session must retain at least one Supervisor"
                              : undefined
                          }
                          onClick={() =>
                            setPendingAction({
                              type: isSupervisor ? "revoke-responsibility" : "grant-responsibility",
                              responsibility: "supervisor",
                              participant,
                            })
                          }
                        >
                          <ShieldCheck aria-hidden="true" />
                          {isSupervisor
                            ? canRemoveSupervisor
                              ? "Remove Supervisor"
                              : "Required Supervisor"
                            : "Make Supervisor"}
                        </Button>
                      ) : null}
                    </div>
                  )}
                </li>
              );
            })}
          </ol>

          {capabilities.releaseControl && currentControllerId === session.viewer.userId ? (
            <Button
              type="button"
              size="lg"
              variant="outline"
              className="mt-3 min-h-10 w-full"
              disabled={isMutating}
              onClick={() => setPendingAction({ type: "release-control" })}
            >
              <KeyRound aria-hidden="true" />
              Release my terminal control
            </Button>
          ) : null}

          {capabilities.offerHandoff ? (
            <Button
              type="button"
              size="lg"
              variant="outline"
              className="mt-3 min-h-10 w-full"
              disabled={isMutating || handoffRecipients.length === 0}
              title={
                handoffRecipients.length === 0
                  ? "Another active participant is required"
                  : "Offer an accountable handoff"
              }
              onClick={() => setHandoffOpen(true)}
            >
              <Handshake aria-hidden="true" />
              Offer responsibility handoff
            </Button>
          ) : null}

          {session.openHandoffs.length > 0 ? (
            <section className="mt-5 border-t border-border pt-4">
              <h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <Handshake className="size-3.5" aria-hidden="true" />
                Open handoffs
              </h3>
              <ul className="mt-2 space-y-2">
                {session.openHandoffs.map((handoff) => {
                  const isRecipient = handoff.recipientUserId === session.viewer.userId;
                  return (
                    <li key={handoff.handoffId} className="rounded-lg border border-border p-3">
                      <p className="text-sm leading-5">{handoff.briefing.summary}</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        Offered to{" "}
                        {session.participants.find(
                          (participant) => participant.userId === handoff.recipientUserId
                        )?.displayName ?? handoff.recipientUserId}
                        {" · expires "}
                        {new Date(handoff.expiresAtMs).toLocaleString()}
                      </p>
                      {handoff.briefing.currentState ? (
                        <div className="mt-2">
                          <p className="text-xs font-medium text-muted-foreground">Current state</p>
                          <p className="mt-0.5 whitespace-pre-wrap break-words text-xs leading-5 text-foreground">
                            {handoff.briefing.currentState}
                          </p>
                        </div>
                      ) : null}
                      {handoff.briefing.blockers.length > 0 ? (
                        <div className="mt-2 rounded-md border border-[color:var(--amber-dim)] bg-[var(--amber-ghost)] p-2">
                          <p className="text-xs font-semibold uppercase tracking-wide text-[var(--amber)]">
                            {handoff.briefing.blockers.length}{" "}
                            {handoff.briefing.blockers.length === 1 ? "blocker" : "blockers"}
                          </p>
                          <ul className="mt-1 space-y-0.5">
                            {handoff.briefing.blockers.map((blocker, index) => (
                              <li
                                key={index}
                                className="flex gap-1.5 break-words text-xs leading-5 text-foreground"
                              >
                                <span aria-hidden="true" className="text-[var(--amber)]">
                                  •
                                </span>
                                <span>{blocker}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {handoff.briefing.nextSteps.length > 0 ? (
                        <div className="mt-2">
                          <p className="text-xs font-medium text-muted-foreground">Next steps</p>
                          <ol className="mt-0.5 list-decimal space-y-0.5 pl-4">
                            {handoff.briefing.nextSteps.map((step, index) => (
                              <li
                                key={index}
                                className="break-words text-xs leading-5 text-foreground"
                              >
                                {step}
                              </li>
                            ))}
                          </ol>
                        </div>
                      ) : null}
                      {handoff.briefing.artifactRefs.length > 0 ? (
                        <div className="mt-2">
                          <p className="text-xs font-medium text-muted-foreground">
                            Evidence / Runs
                          </p>
                          <ul className="mt-0.5 space-y-0.5">
                            {handoff.briefing.artifactRefs.map((ref, index) => (
                              <li
                                key={index}
                                className="break-all font-mono text-xs leading-5 text-[var(--cyan)]"
                              >
                                {ref}
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {isRecipient && handoff.briefing.blockers.length > 0 ? (
                        <p className="mt-2 text-xs leading-5 text-muted-foreground">
                          Accepting the handoff makes you the Assignee; resolve these blockers as
                          you carry the work forward.
                        </p>
                      ) : null}
                      <div className="mt-3 flex flex-wrap gap-2">
                        {capabilities.acceptHandoff &&
                        handoff.recipientUserId === session.viewer.userId ? (
                          <Button
                            type="button"
                            size="sm"
                            className="min-h-10"
                            disabled={isMutating}
                            onClick={() => setPendingAction({ type: "accept-handoff", handoff })}
                          >
                            Accept handoff
                          </Button>
                        ) : null}
                        {capabilities.cancelHandoff ? (
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            className="min-h-10"
                            disabled={isMutating}
                            onClick={() => setPendingAction({ type: "cancel-handoff", handoff })}
                          >
                            Cancel offer
                          </Button>
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </section>
          ) : null}

          {canInspectAdmission && isAdmissionLoading && admission === null ? (
            <section
              className="mt-5 border-t border-border pt-4"
              aria-label="Loading access requests"
            >
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Access requests
              </h3>
              <div className="mt-2 space-y-2" role="status">
                <span className="sr-only">Loading access requests…</span>
                {["first", "second"].map((item) => (
                  <div
                    key={item}
                    className="h-12 animate-pulse rounded-md bg-muted motion-reduce:animate-none"
                  />
                ))}
              </div>
            </section>
          ) : null}

          {canInspectAdmission && admissionError ? (
            <div className="mt-5 border-t border-border pt-4">
              <p className="text-xs leading-5 text-destructive" role="alert">
                Couldn&apos;t load private access requests. {admissionError}
              </p>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="mt-2 min-h-10"
                disabled={isMutating || isAdmissionLoading}
                onClick={onRetryAdmission}
              >
                Retry access requests
              </Button>
            </div>
          ) : null}

          {admission &&
          admission.activeInvitations.length === 0 &&
          admission.accessCandidates.length === 0 ? (
            <section className="mt-5 border-t border-border pt-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Access requests
              </h3>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                {capabilities.manageShares
                  ? "No one is waiting for an access grant."
                  : "No active invitations need attention."}
              </p>
            </section>
          ) : null}

          {admission?.capabilities.canGrantGuestShare && pendingGuests.length > 0 ? (
            <section className="mt-5 border-t border-border pt-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Guests awaiting access
              </h3>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                Their identity and Team Membership are verified. Session content remains hidden
                until you grant an explicit share.
              </p>
              <ul className="mt-2 space-y-2">
                {pendingGuests.map((guest) => (
                  <li
                    key={guest.invitationId}
                    className="rounded-md border border-border p-2 text-xs"
                  >
                    <p className="truncate text-sm font-medium">{guest.displayName}</p>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      className="mt-2 min-h-10"
                      disabled={isMutating}
                      onClick={() => setPendingAction({ type: "grant-share", guest })}
                    >
                      Grant session access
                    </Button>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {pendingMembers.length > 0 ? (
            <section className="mt-5 border-t border-border pt-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Members awaiting project access
              </h3>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                A Member needs explicit Project Access before they can join this session.
              </p>
              <ul className="mt-2 space-y-2">
                {pendingMembers.map((member) => (
                  <li key={member.userId} className="rounded-md border border-border p-2 text-xs">
                    <p className="truncate text-sm font-medium">{member.displayName}</p>
                    {admission?.capabilities.canGrantProjectAccess ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="mt-2 min-h-10"
                        disabled={isMutating}
                        onClick={() => setPendingAction({ type: "grant-project-access", member })}
                      >
                        Grant Contributor access
                      </Button>
                    ) : (
                      <p className="mt-1 leading-5 text-muted-foreground">
                        A Project Maintainer or Team Admin must grant Contributor access.
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {admission?.capabilities.canRevokeInvitations && activeInvitations.length > 0 ? (
            <section className="mt-5 border-t border-border pt-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Active invitations
              </h3>
              <ul className="mt-2 space-y-2">
                {activeInvitations.map((invitation) => (
                  <li
                    key={invitation.invitationId}
                    className="flex min-h-12 items-center gap-2 rounded-md border border-border p-2 text-xs"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block font-medium capitalize text-foreground">
                        {invitation.membershipRole} invite
                      </span>
                      <span className="block text-muted-foreground">
                        {invitation.expiresAtMs <= projectionNowMs
                          ? "expired"
                          : `expires ${new Date(invitation.expiresAtMs).toLocaleString()}`}
                      </span>
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      variant="destructive"
                      className="min-h-10"
                      disabled={isMutating}
                      onClick={() => setPendingAction({ type: "revoke-invitation", invitation })}
                    >
                      Revoke
                    </Button>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {session.shares.length > 0 ? (
            <section className="mt-5 border-t border-border pt-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Direct session access
              </h3>
              <ul className="mt-2 space-y-2 text-xs text-muted-foreground">
                {session.shares.map((share) => (
                  <li
                    key={share.userId}
                    className="flex min-h-10 items-center gap-2 rounded-md border border-border px-2"
                  >
                    <span className="min-w-0 flex-1 truncate">{share.displayName}</span>
                    {capabilities.manageShares ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="destructive"
                        className="min-h-10"
                        disabled={isMutating}
                        onClick={() => setPendingAction({ type: "revoke-share", share })}
                      >
                        Revoke guest
                      </Button>
                    ) : null}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {error ? (
            <p
              className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive"
              role="alert"
            >
              {error}
            </p>
          ) : null}
        </div>
      </aside>

      {handoffOpen ? (
        <OfferHandoffDialog
          open
          participants={handoffRecipients}
          isSubmitting={isMutating}
          error={error}
          onOpenChange={setHandoffOpen}
          onOffer={async (participant, briefing, expiresAtMs) => {
            await onAction({
              type: "offer-handoff",
              participant,
              briefing,
              expiresAtMs,
            });
            setHandoffOpen(false);
          }}
        />
      ) : null}

      <Dialog
        open={pendingAction !== null}
        onOpenChange={(open) => {
          if (!open && !isMutating) setPendingAction(null);
        }}
      >
        <DialogContent showCloseButton={false}>
          {pendingAction ? (
            <>
              <DialogHeader>
                <DialogTitle>{actionCopy(pendingAction).title}</DialogTitle>
                <DialogDescription>{actionCopy(pendingAction).description}</DialogDescription>
              </DialogHeader>
              {error ? (
                <p
                  className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive"
                  role="alert"
                >
                  {error}
                </p>
              ) : null}
              <DialogFooter>
                <DialogClose
                  render={
                    <Button
                      type="button"
                      variant="outline"
                      className="min-h-10"
                      disabled={isMutating}
                    />
                  }
                >
                  Cancel
                </DialogClose>
                <Button
                  type="button"
                  className="min-h-10"
                  variant={actionCopy(pendingAction).destructive ? "destructive" : "default"}
                  disabled={isMutating}
                  aria-busy={isMutating}
                  onClick={() => void runPendingAction()}
                >
                  {isMutating ? (
                    <LoaderCircle
                      className="animate-spin motion-reduce:animate-none"
                      aria-hidden="true"
                    />
                  ) : null}
                  {actionCopy(pendingAction).confirm}
                </Button>
              </DialogFooter>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  );
}
