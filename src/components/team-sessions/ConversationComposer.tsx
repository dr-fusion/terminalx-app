"use client";

import { useId, useState } from "react";
import { CornerDownRight, Lightbulb, LoaderCircle, MessageSquareText, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type ConversationIntent = "comment" | "suggestion" | "directive";

interface ConversationComposerProps {
  capabilities: {
    addComment: boolean;
    addSuggestion: boolean;
    enqueueDirective: boolean;
  };
  sessionStatus: "active" | "awaiting_assignee" | "ended";
  isSubmitting: boolean;
  error?: string | null;
  onSubmit: (intent: ConversationIntent, body: string) => Promise<void>;
}

const MAX_BODY_BYTES = 16 * 1024;
const INTENTS: Array<{
  value: ConversationIntent;
  label: string;
  description: string;
  icon: typeof MessageSquareText;
}> = [
  {
    value: "comment",
    label: "Comment",
    description: "Share context without steering",
    icon: MessageSquareText,
  },
  {
    value: "suggestion",
    label: "Suggestion",
    description: "Propose an instruction for a Steerer",
    icon: Lightbulb,
  },
  {
    value: "directive",
    label: "Directive",
    description: "Queue an ordered instruction",
    icon: CornerDownRight,
  },
];
const DEFAULT_INTENT = INTENTS[0]!;

function canUseIntent(
  intent: ConversationIntent,
  capabilities: ConversationComposerProps["capabilities"]
): boolean {
  if (intent === "comment") return capabilities.addComment;
  if (intent === "suggestion") return capabilities.addSuggestion;
  return capabilities.enqueueDirective;
}

function intentUnavailableReason(
  intent: ConversationIntent,
  sessionStatus: ConversationComposerProps["sessionStatus"]
): string {
  if (sessionStatus === "ended" && intent !== "comment") {
    return "Ended sessions accept postmortem comments only.";
  }
  if (sessionStatus === "awaiting_assignee" && intent === "directive") {
    return "Assign responsibility before queueing directives.";
  }
  if (intent === "directive") return "Only an active Steerer can queue directives.";
  if (intent === "suggestion") return "Join the session to add suggestions.";
  return "Join the session to comment.";
}

export function ConversationComposer({
  capabilities,
  sessionStatus,
  isSubmitting,
  error,
  onSubmit,
}: ConversationComposerProps) {
  const [intent, setIntent] = useState<ConversationIntent>("comment");
  const [body, setBody] = useState("");
  const inputId = useId();
  const errorId = `${inputId}-error`;
  const hintId = `${inputId}-hint`;
  const byteLength = new TextEncoder().encode(body).byteLength;
  const isTooLong = byteLength > MAX_BODY_BYTES;
  const trimmedBody = body.trim();
  const selectedAllowed = canUseIntent(intent, capabilities);
  const effectiveIntent = selectedAllowed
    ? intent
    : (INTENTS.find((candidate) => canUseIntent(candidate.value, capabilities))?.value ?? intent);
  const effectiveAllowed = canUseIntent(effectiveIntent, capabilities);

  const submit = async () => {
    if (!trimmedBody || isTooLong || isSubmitting || !effectiveAllowed) return;
    try {
      await onSubmit(effectiveIntent, trimmedBody);
      setBody("");
    } catch {
      // The parent renders the scoped server error; preserve the draft for retry.
    }
  };

  const current =
    INTENTS.find((candidate) => candidate.value === effectiveIntent) ?? DEFAULT_INTENT;

  return (
    <form
      className="border-t border-border bg-card p-3 md:p-4"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <div className="mx-auto max-w-3xl space-y-3">
        <fieldset>
          <legend className="mb-2 text-xs font-medium text-muted-foreground">Message intent</legend>
          <div className="flex flex-wrap gap-2">
            {INTENTS.map((option) => {
              const Icon = option.icon;
              const allowed = canUseIntent(option.value, capabilities);
              return (
                <button
                  key={option.value}
                  type="button"
                  className={cn(
                    "flex min-h-10 items-center gap-2 rounded-md border px-3 text-xs font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring",
                    effectiveIntent === option.value
                      ? "border-primary/60 bg-primary/10 text-primary"
                      : "border-border bg-background text-muted-foreground hover:bg-muted hover:text-foreground",
                    !allowed && "cursor-not-allowed opacity-50"
                  )}
                  aria-pressed={effectiveIntent === option.value}
                  aria-describedby={!allowed ? `${inputId}-${option.value}-reason` : undefined}
                  disabled={!allowed || isSubmitting}
                  title={
                    allowed
                      ? option.description
                      : intentUnavailableReason(option.value, sessionStatus)
                  }
                  onClick={() => setIntent(option.value)}
                >
                  <Icon className="size-4" aria-hidden="true" />
                  {option.label}
                  {!allowed ? (
                    <span id={`${inputId}-${option.value}-reason`} className="sr-only">
                      {intentUnavailableReason(option.value, sessionStatus)}
                    </span>
                  ) : null}
                </button>
              );
            })}
          </div>
        </fieldset>

        <div className="space-y-1.5">
          <label htmlFor={inputId} className="text-xs font-medium text-foreground">
            {current.label}
          </label>
          <div
            className={cn(
              "rounded-lg border bg-background transition-colors focus-within:border-primary/70 focus-within:ring-2 focus-within:ring-ring/30",
              isTooLong ? "border-destructive" : "border-input"
            )}
          >
            <textarea
              id={inputId}
              value={body}
              rows={3}
              disabled={!effectiveAllowed || isSubmitting}
              aria-invalid={isTooLong || Boolean(error) ? "true" : undefined}
              aria-describedby={error || isTooLong ? errorId : hintId}
              className="max-h-48 min-h-20 w-full resize-y bg-transparent px-3 pt-3 text-sm leading-6 text-foreground placeholder:text-muted-foreground focus:outline-none disabled:cursor-not-allowed disabled:opacity-60"
              placeholder={
                effectiveIntent === "directive"
                  ? "Describe the next instruction to queue…"
                  : effectiveIntent === "suggestion"
                    ? "Propose a change or next step…"
                    : "Share context with everyone in this session…"
              }
              onChange={(event) => setBody(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                  event.preventDefault();
                  void submit();
                }
              }}
            />
            <div className="flex items-center gap-3 px-3 pb-2">
              <p id={hintId} className="min-w-0 flex-1 text-xs text-muted-foreground">
                {effectiveIntent === "directive"
                  ? "This records an ordered queued directive; it does not claim agent execution."
                  : current.description}
              </p>
              <span
                className={cn(
                  "shrink-0 text-xs",
                  isTooLong ? "text-destructive" : "text-muted-foreground"
                )}
              >
                {byteLength.toLocaleString()}/{MAX_BODY_BYTES.toLocaleString()} bytes
              </span>
            </div>
          </div>
          {isTooLong || error ? (
            <p id={errorId} role="alert" className="text-xs text-destructive">
              {isTooLong ? "Message must be 16 KiB or smaller." : error}
            </p>
          ) : null}
        </div>

        <div className="flex items-center justify-between gap-3">
          <span className="hidden text-xs text-muted-foreground sm:inline">
            ⌘/Ctrl + Enter to send
          </span>
          <Button
            type="submit"
            size="lg"
            className="ml-auto min-h-10"
            disabled={!trimmedBody || isTooLong || isSubmitting || !effectiveAllowed}
            aria-busy={isSubmitting}
          >
            {isSubmitting ? (
              <LoaderCircle
                className="animate-spin motion-reduce:animate-none"
                aria-hidden="true"
              />
            ) : (
              <Send aria-hidden="true" />
            )}
            {isSubmitting ? "Sending" : `Send ${current.label.toLowerCase()}`}
          </Button>
        </div>
      </div>
    </form>
  );
}
