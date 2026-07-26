"use client";

import { useId, useRef, useState } from "react";
import { Handshake, LoaderCircle } from "lucide-react";
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
import type { TeamSessionParticipant } from "@/types/team-session";

export interface HandoffBriefingInput {
  summary: string;
  currentState: string;
  blockers: string[];
  nextSteps: string[];
  artifactRefs: string[];
}

interface OfferHandoffDialogProps {
  open: boolean;
  participants: TeamSessionParticipant[];
  isSubmitting: boolean;
  error?: string | null;
  onOpenChange: (open: boolean) => void;
  onOffer: (
    participant: TeamSessionParticipant,
    briefing: HandoffBriefingInput,
    expiresAtMs: number
  ) => Promise<void>;
}

const EXPIRATIONS = [
  { value: "1h", label: "1 hour", durationMs: 60 * 60 * 1_000 },
  { value: "24h", label: "24 hours", durationMs: 24 * 60 * 60 * 1_000 },
  { value: "7d", label: "7 days", durationMs: 7 * 24 * 60 * 60 * 1_000 },
] as const;

/** Split a textarea (one item per line) into a bounded, trimmed, non-empty list. */
export function linesToList(value: string): string[] {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function OfferHandoffDialog({
  open,
  participants,
  isSubmitting,
  error,
  onOpenChange,
  onOffer,
}: OfferHandoffDialogProps) {
  const [participantId, setParticipantId] = useState(participants[0]?.participantId ?? "");
  const [summary, setSummary] = useState("");
  const [currentState, setCurrentState] = useState("");
  const [blockers, setBlockers] = useState("");
  const [nextSteps, setNextSteps] = useState("");
  const [artifactRefs, setArtifactRefs] = useState("");
  const [expiration, setExpiration] = useState<(typeof EXPIRATIONS)[number]["value"]>("24h");
  const intentRef = useRef<{
    fingerprint: string;
    expiresAtMs: number;
  } | null>(null);
  const participantInputId = useId();
  const summaryInputId = useId();
  const currentStateInputId = useId();
  const blockersInputId = useId();
  const nextStepsInputId = useId();
  const artifactsInputId = useId();
  const expirationInputId = useId();
  const selectedParticipant = participants.find(
    (participant) => participant.participantId === participantId
  );
  const normalizedSummary = summary.trim();

  const resetIntent = () => {
    intentRef.current = null;
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen && isSubmitting) return;
        onOpenChange(nextOpen);
      }}
    >
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-lg" showCloseButton={false}>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (!selectedParticipant || !normalizedSummary || isSubmitting) return;
            const selectedExpiration = EXPIRATIONS.find((option) => option.value === expiration);
            if (!selectedExpiration) return;
            const briefing: HandoffBriefingInput = {
              summary: normalizedSummary,
              currentState: currentState.trim(),
              blockers: linesToList(blockers),
              nextSteps: linesToList(nextSteps),
              artifactRefs: linesToList(artifactRefs),
            };
            const fingerprint = JSON.stringify({
              participantId: selectedParticipant.participantId,
              briefing,
              expiration,
            });
            const previous = intentRef.current;
            const intent =
              previous?.fingerprint === fingerprint
                ? previous
                : {
                    fingerprint,
                    expiresAtMs: Date.now() + selectedExpiration.durationMs,
                  };
            intentRef.current = intent;
            void onOffer(selectedParticipant, briefing, intent.expiresAtMs).catch(() => undefined);
          }}
        >
          <DialogHeader>
            <div className="flex size-10 items-center justify-center rounded-full border border-border bg-background">
              <Handshake className="size-5 text-primary" aria-hidden="true" />
            </div>
            <DialogTitle>Offer responsibility handoff</DialogTitle>
            <DialogDescription>
              The recipient must accept. Acceptance atomically transfers Assignee responsibility,
              steering, and terminal control; the durable briefing stays with the Session.
            </DialogDescription>
          </DialogHeader>

          <div className="mt-5 space-y-4">
            <div className="space-y-1.5">
              <label htmlFor={participantInputId} className="text-xs font-medium">
                Recipient
              </label>
              <select
                id={participantInputId}
                value={participantId}
                disabled={isSubmitting || participants.length === 0}
                className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                onChange={(event) => {
                  resetIntent();
                  setParticipantId(event.target.value);
                }}
              >
                {participants.map((participant) => (
                  <option key={participant.participantId} value={participant.participantId}>
                    {participant.displayName}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1.5">
              <label htmlFor={summaryInputId} className="text-xs font-medium">
                Briefing summary
              </label>
              <textarea
                id={summaryInputId}
                value={summary}
                rows={3}
                required
                maxLength={1_000}
                disabled={isSubmitting}
                className="max-h-48 min-h-20 w-full resize-y rounded-md border border-input bg-background p-3 text-sm leading-6 focus-visible:ring-2 focus-visible:ring-ring"
                placeholder="What is done, what remains, and what needs attention?"
                onChange={(event) => {
                  resetIntent();
                  setSummary(event.target.value);
                }}
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor={currentStateInputId} className="text-xs font-medium">
                Current state <span className="text-muted-foreground">(optional)</span>
              </label>
              <textarea
                id={currentStateInputId}
                value={currentState}
                rows={2}
                maxLength={2_000}
                disabled={isSubmitting}
                className="max-h-48 min-h-16 w-full resize-y rounded-md border border-input bg-background p-3 text-sm leading-6 focus-visible:ring-2 focus-visible:ring-ring"
                placeholder="Where the work stands right now (branch, running processes, decisions in flight)."
                onChange={(event) => {
                  resetIntent();
                  setCurrentState(event.target.value);
                }}
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor={blockersInputId} className="text-xs font-medium">
                Blockers <span className="text-muted-foreground">(one per line)</span>
              </label>
              <textarea
                id={blockersInputId}
                value={blockers}
                rows={2}
                disabled={isSubmitting}
                aria-describedby={`${blockersInputId}-hint`}
                className="max-h-48 min-h-16 w-full resize-y rounded-md border border-input bg-background p-3 text-sm leading-6 focus-visible:ring-2 focus-visible:ring-ring"
                placeholder={"Waiting on prod deploy approval\nFlaky integration test in CI"}
                onChange={(event) => {
                  resetIntent();
                  setBlockers(event.target.value);
                }}
              />
              <p id={`${blockersInputId}-hint`} className="text-xs text-muted-foreground">
                Each blocker is listed for the recipient to triage.
              </p>
            </div>

            <div className="space-y-1.5">
              <label htmlFor={nextStepsInputId} className="text-xs font-medium">
                Next steps <span className="text-muted-foreground">(one per line)</span>
              </label>
              <textarea
                id={nextStepsInputId}
                value={nextSteps}
                rows={2}
                disabled={isSubmitting}
                className="max-h-48 min-h-16 w-full resize-y rounded-md border border-input bg-background p-3 text-sm leading-6 focus-visible:ring-2 focus-visible:ring-ring"
                placeholder={"Re-run the migration on staging\nAsk @dana to review the auth change"}
                onChange={(event) => {
                  resetIntent();
                  setNextSteps(event.target.value);
                }}
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor={artifactsInputId} className="text-xs font-medium">
                Evidence / Run links <span className="text-muted-foreground">(one per line)</span>
              </label>
              <textarea
                id={artifactsInputId}
                value={artifactRefs}
                rows={2}
                disabled={isSubmitting}
                className="max-h-48 min-h-16 w-full resize-y rounded-md border border-input bg-background p-3 text-sm leading-6 focus-visible:ring-2 focus-visible:ring-ring"
                placeholder={"run:agent-run-42\nhttps://example.test/evidence/123"}
                onChange={(event) => {
                  resetIntent();
                  setArtifactRefs(event.target.value);
                }}
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor={expirationInputId} className="text-xs font-medium">
                Offer expires
              </label>
              <select
                id={expirationInputId}
                value={expiration}
                disabled={isSubmitting}
                className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                onChange={(event) => {
                  resetIntent();
                  setExpiration(event.target.value as (typeof EXPIRATIONS)[number]["value"]);
                }}
              >
                {EXPIRATIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            {participants.length === 0 ? (
              <p className="rounded-md border border-[color:var(--amber-dim)] bg-[var(--amber-ghost)] p-3 text-xs text-[var(--amber)]">
                Add another active participant before offering a handoff.
              </p>
            ) : null}

            {error ? (
              <p
                className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive"
                role="alert"
              >
                {error}
              </p>
            ) : null}
          </div>

          <DialogFooter className="mt-5">
            <DialogClose
              render={
                <Button
                  type="button"
                  variant="outline"
                  className="min-h-10"
                  disabled={isSubmitting}
                />
              }
            >
              Cancel
            </DialogClose>
            <Button
              type="submit"
              className="min-h-10"
              disabled={isSubmitting || !selectedParticipant || !normalizedSummary}
              aria-busy={isSubmitting}
            >
              {isSubmitting ? (
                <LoaderCircle
                  className="animate-spin motion-reduce:animate-none"
                  aria-hidden="true"
                />
              ) : (
                <Handshake aria-hidden="true" />
              )}
              {isSubmitting ? "Offering" : "Offer handoff"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
