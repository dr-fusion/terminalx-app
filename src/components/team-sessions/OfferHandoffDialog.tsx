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

interface OfferHandoffDialogProps {
  open: boolean;
  participants: TeamSessionParticipant[];
  isSubmitting: boolean;
  error?: string | null;
  onOpenChange: (open: boolean) => void;
  onOffer: (
    participant: TeamSessionParticipant,
    summary: string,
    expiresAtMs: number
  ) => Promise<void>;
}

const EXPIRATIONS = [
  { value: "1h", label: "1 hour", durationMs: 60 * 60 * 1_000 },
  { value: "24h", label: "24 hours", durationMs: 24 * 60 * 60 * 1_000 },
  { value: "7d", label: "7 days", durationMs: 7 * 24 * 60 * 60 * 1_000 },
] as const;

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
  const [expiration, setExpiration] = useState<(typeof EXPIRATIONS)[number]["value"]>("24h");
  const intentRef = useRef<{
    fingerprint: string;
    expiresAtMs: number;
  } | null>(null);
  const participantInputId = useId();
  const summaryInputId = useId();
  const expirationInputId = useId();
  const selectedParticipant = participants.find(
    (participant) => participant.participantId === participantId
  );
  const normalizedSummary = summary.trim();

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen && isSubmitting) return;
        onOpenChange(nextOpen);
      }}
    >
      <DialogContent className="sm:max-w-lg" showCloseButton={false}>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (!selectedParticipant || !normalizedSummary || isSubmitting) return;
            const selectedExpiration = EXPIRATIONS.find((option) => option.value === expiration);
            if (!selectedExpiration) return;
            const fingerprint = JSON.stringify({
              participantId: selectedParticipant.participantId,
              summary: normalizedSummary,
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
            void onOffer(selectedParticipant, normalizedSummary, intent.expiresAtMs).catch(
              () => undefined
            );
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
                  intentRef.current = null;
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
                rows={4}
                required
                maxLength={1_000}
                disabled={isSubmitting}
                className="max-h-48 min-h-24 w-full resize-y rounded-md border border-input bg-background p-3 text-sm leading-6 focus-visible:ring-2 focus-visible:ring-ring"
                placeholder="What is done, what remains, and what needs attention?"
                onChange={(event) => {
                  intentRef.current = null;
                  setSummary(event.target.value);
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
                  intentRef.current = null;
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
