"use client";

import { useEffect, useMemo, useRef } from "react";
import {
  Check,
  CircleDot,
  CornerDownRight,
  Lightbulb,
  MessageSquareText,
  ShieldCheck,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface ConversationEvent {
  eventId: string;
  sessionId: string;
  sequence: number;
  type: string;
  occurredAtMs: number;
  actor: {
    userId: string;
    displayName: string;
  };
  sourceAdapter: "web" | "slack" | "telegram" | "runtime" | "internal";
  payload: Record<string, unknown>;
}

interface ConversationTimelineProps {
  events: ConversationEvent[];
  historyTruncated?: boolean;
  viewerUserId: string;
  canResolveSuggestions: boolean;
  isLoading?: boolean;
  onResolveSuggestion: (
    suggestionId: string,
    suggestionVersion: number,
    resolution: "accept" | "reject"
  ) => Promise<void>;
  resolvingSuggestionId?: string | null;
}

const timestamp = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
});

function text(payload: Record<string, unknown>, key: string): string | undefined {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
}

function number(payload: Record<string, unknown>, key: string): number | undefined {
  const value = payload[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "?";
  return words
    .slice(0, 2)
    .map((word) => word[0])
    .join("")
    .toUpperCase();
}

export function conversationActivityLabel(event: ConversationEvent): string {
  const actor = event.actor.displayName;
  switch (event.type) {
    case "session.started":
      return `${actor} started the session`;
    case "session.participant.joined":
      return `${actor} joined the session`;
    case "session.ended":
      return `${actor} ended the session`;
    case "session.control.transferred":
      return `${actor} transferred terminal control`;
    case "session.control.released":
      return `${actor} released terminal control`;
    case "session.responsibility.granted":
      return `${actor} assigned a session responsibility`;
    case "session.responsibility.revoked":
      return `${actor} revoked a session responsibility`;
    case "session.participant.granted":
      return `${actor} added a participant`;
    case "session.participant.revoked":
      return `${actor} removed a participant`;
    case "session.handoff.offered":
      return `${actor} offered a handoff`;
    case "session.handoff.accepted":
      return `${actor} accepted a handoff`;
    case "session.handoff.cancelled":
    case "session.handoff.expired":
      return `A session handoff was closed`;
    case "session.runtime-authorization.advanced":
      return `Runtime authorization is being updated`;
    case "session.runtime-authorization.enforced":
      return `Runtime authorization is enforced`;
    case "session.runtime-authorization.quarantined":
      return `Runtime authorization entered quarantine`;
    default:
      return `Session state changed`;
  }
}

/**
 * Client virtualization for long timelines: keep the DOM bounded by rendering
 * only the most recent `max` events (the tail the user is reading), reporting
 * how many older events were withheld so the UI can show a stable notice.
 * Combined with per-item `content-visibility:auto`, this keeps very long
 * conversations responsive without a heavyweight windowing dependency.
 */
export const MAX_RENDERED_CONVERSATION_EVENTS = 200;

export function windowConversation<T>(
  events: readonly T[],
  max: number = MAX_RENDERED_CONVERSATION_EVENTS
): { visible: T[]; hiddenBefore: number } {
  if (!Number.isSafeInteger(max) || max < 1 || events.length <= max) {
    return { visible: [...events], hiddenBefore: 0 };
  }
  return { visible: events.slice(events.length - max), hiddenBefore: events.length - max };
}

export interface CommentSegment {
  kind: "text" | "mention";
  value: string;
}

/**
 * Split a comment body into plain-text and `@mention` segments so mentions can
 * render as highlighted chips. Purely syntactic (an `@token`); resolution to a
 * canonical User happens server-side when the mention is recorded.
 */
export function splitMentionSegments(body: string): CommentSegment[] {
  const segments: CommentSegment[] = [];
  const pattern = /@([A-Za-z0-9][A-Za-z0-9._:-]{0,127})/g;
  let lastIndex = 0;
  for (const match of body.matchAll(pattern)) {
    const start = match.index ?? 0;
    if (start > lastIndex) {
      segments.push({ kind: "text", value: body.slice(lastIndex, start) });
    }
    segments.push({ kind: "mention", value: match[0] });
    lastIndex = start + match[0].length;
  }
  if (lastIndex < body.length) {
    segments.push({ kind: "text", value: body.slice(lastIndex) });
  }
  return segments;
}

function CommentBody({ body }: { body: string }) {
  const segments = useMemo(() => splitMentionSegments(body), [body]);
  return (
    <p className="whitespace-pre-wrap break-words text-sm leading-6 text-foreground">
      {segments.map((segment, index) =>
        segment.kind === "mention" ? (
          <span
            key={index}
            className="rounded bg-primary/10 px-1 font-medium text-primary"
            data-mention
          >
            {segment.value}
          </span>
        ) : (
          <span key={index}>{segment.value}</span>
        )
      )}
    </p>
  );
}

function TimelineSkeleton() {
  return (
    <div className="space-y-5 p-5" aria-label="Loading conversation">
      {["w-2/3", "w-4/5", "w-1/2"].map((width) => (
        <div key={width} className="flex gap-3">
          <div className="size-8 shrink-0 animate-pulse rounded-full bg-muted" />
          <div className={cn("space-y-2", width)}>
            <div className="h-3 w-28 animate-pulse rounded bg-muted" />
            <div className="h-16 animate-pulse rounded-lg bg-muted" />
          </div>
        </div>
      ))}
    </div>
  );
}

export function ConversationTimeline({
  events,
  historyTruncated = false,
  viewerUserId,
  canResolveSuggestions,
  isLoading = false,
  onResolveSuggestion,
  resolvingSuggestionId,
}: ConversationTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const shouldStickToBottom = useRef(true);
  const resolutions = useMemo(() => {
    const resolved = new Map<string, "accept" | "accept-edited" | "reject">();
    for (const event of events) {
      if (event.type !== "suggestion.resolved") continue;
      const suggestionId = text(event.payload, "suggestionId");
      const resolution = text(event.payload, "resolution");
      if (
        suggestionId &&
        (resolution === "accept" || resolution === "accept-edited" || resolution === "reject")
      ) {
        resolved.set(suggestionId, resolution);
      }
    }
    return resolved;
  }, [events]);

  useEffect(() => {
    const container = scrollRef.current;
    if (!container || !shouldStickToBottom.current) return;
    container.scrollTop = container.scrollHeight;
  }, [events.length]);

  const { visible: windowedEvents, hiddenBefore } = windowConversation(events);

  if (isLoading) return <TimelineSkeleton />;

  if (events.length === 0) {
    return (
      <div className="flex h-full min-h-64 flex-col items-center justify-center gap-3 p-8 text-center">
        <div className="flex size-11 items-center justify-center rounded-full border border-border bg-card">
          <MessageSquareText className="size-5 text-primary" aria-hidden="true" />
        </div>
        <div className="max-w-sm space-y-1">
          <p className="text-sm font-medium">Start the working conversation</p>
          <p className="text-sm text-muted-foreground">
            Add context as a comment, propose a suggestion, or queue a directive if you can steer.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={scrollRef}
      className="h-full overflow-y-auto overscroll-contain px-4 py-5 md:px-6"
      onScroll={(event) => {
        const element = event.currentTarget;
        shouldStickToBottom.current =
          element.scrollHeight - element.scrollTop - element.clientHeight < 96;
      }}
      aria-live="polite"
      aria-label="Session conversation"
    >
      {historyTruncated || hiddenBefore > 0 ? (
        <p className="mx-auto mb-4 max-w-3xl rounded-md border border-border bg-muted/40 px-3 py-2 text-xs leading-5 text-muted-foreground">
          {hiddenBefore > 0
            ? `Showing the latest ${windowedEvents.length.toLocaleString()} of ${events.length.toLocaleString()} loaded events for a responsive view. `
            : `Showing the latest ${events.length.toLocaleString()} events. `}
          Earlier canonical history remains safely stored on the server.
        </p>
      ) : null}
      <ol className="mx-auto max-w-3xl space-y-5">
        {windowedEvents.map((event) => {
          const own = event.actor.userId === viewerUserId;
          const body = text(event.payload, "body");

          if (event.type === "comment.added" && body !== undefined) {
            return (
              <li
                key={event.eventId}
                className="flex items-start gap-3 [contain-intrinsic-size:auto_5rem] [content-visibility:auto]"
              >
                <div
                  className={cn(
                    "flex size-8 shrink-0 items-center justify-center rounded-full border text-xs font-semibold",
                    own
                      ? "border-primary/50 bg-primary/10 text-primary"
                      : "border-border bg-muted text-foreground"
                  )}
                  aria-hidden="true"
                >
                  {initials(event.actor.displayName)}
                </div>
                <article className="min-w-0 flex-1">
                  <header className="mb-1 flex flex-wrap items-baseline gap-x-2 gap-y-1">
                    <span className="text-sm font-medium">{event.actor.displayName}</span>
                    {own ? <span className="text-xs text-muted-foreground">you</span> : null}
                    <time
                      className="text-xs text-muted-foreground"
                      dateTime={new Date(event.occurredAtMs).toISOString()}
                    >
                      {timestamp.format(event.occurredAtMs)}
                    </time>
                    {event.sourceAdapter !== "web" ? (
                      <span className="rounded-full border border-border px-1.5 py-0.5 text-xs text-muted-foreground">
                        {event.sourceAdapter}
                      </span>
                    ) : null}
                  </header>
                  <CommentBody body={body} />
                </article>
              </li>
            );
          }

          if (event.type === "suggestion.added" && body !== undefined) {
            const suggestionId = text(event.payload, "suggestionId");
            const suggestionVersion = number(event.payload, "suggestionVersion") ?? 1;
            const resolution = suggestionId ? resolutions.get(suggestionId) : undefined;
            const isResolving = resolvingSuggestionId === suggestionId;
            return (
              <li
                key={event.eventId}
                className="[contain-intrinsic-size:auto_8rem] [content-visibility:auto]"
              >
                <article className="ml-0 rounded-lg border border-[color:var(--cyan-dim)] bg-[var(--cyan-ghost)] p-4 md:ml-11">
                  <header className="flex flex-wrap items-center gap-2">
                    <Lightbulb className="size-4 text-[var(--cyan)]" aria-hidden="true" />
                    <span className="text-sm font-medium">
                      Suggestion from {event.actor.displayName}
                    </span>
                    <time
                      className="text-xs text-muted-foreground"
                      dateTime={new Date(event.occurredAtMs).toISOString()}
                    >
                      {timestamp.format(event.occurredAtMs)}
                    </time>
                    <span className="ml-auto rounded-full border border-[color:var(--cyan-dim)] px-2 py-0.5 text-xs text-[var(--cyan)]">
                      {resolution === "reject" ? "rejected" : resolution ? "accepted" : "open"}
                    </span>
                  </header>
                  <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6">{body}</p>
                  {!resolution && canResolveSuggestions && suggestionId ? (
                    <div className="mt-4 flex flex-wrap gap-2 border-t border-[color:var(--cyan-dim)] pt-3">
                      <Button
                        type="button"
                        size="lg"
                        className="min-h-10"
                        disabled={isResolving}
                        aria-busy={isResolving}
                        onClick={() =>
                          void onResolveSuggestion(suggestionId, suggestionVersion, "accept").catch(
                            () => undefined
                          )
                        }
                      >
                        <Check aria-hidden="true" />
                        Accept and queue
                      </Button>
                      <Button
                        type="button"
                        size="lg"
                        variant="outline"
                        className="min-h-10"
                        disabled={isResolving}
                        onClick={() =>
                          void onResolveSuggestion(suggestionId, suggestionVersion, "reject").catch(
                            () => undefined
                          )
                        }
                      >
                        <X aria-hidden="true" />
                        Reject
                      </Button>
                    </div>
                  ) : null}
                </article>
              </li>
            );
          }

          if (event.type === "directive.queued" && body !== undefined) {
            return (
              <li
                key={event.eventId}
                className="ml-0 [contain-intrinsic-size:auto_8rem] [content-visibility:auto] md:ml-11"
              >
                <article className="rounded-lg border border-[color:var(--amber-dim)] bg-[var(--amber-ghost)] p-4">
                  <header className="flex flex-wrap items-center gap-2">
                    <CornerDownRight className="size-4 text-[var(--amber)]" aria-hidden="true" />
                    <span className="text-sm font-medium">Directive queued</span>
                    <span className="rounded-full border border-[color:var(--amber-dim)] px-2 py-0.5 text-xs text-[var(--amber)]">
                      queued · #{event.sequence}
                    </span>
                    <time
                      className="ml-auto text-xs text-muted-foreground"
                      dateTime={new Date(event.occurredAtMs).toISOString()}
                    >
                      {timestamp.format(event.occurredAtMs)}
                    </time>
                  </header>
                  <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6">{body}</p>
                  <p className="mt-3 text-xs text-muted-foreground">
                    Queued by {event.actor.displayName}. Agent execution is not connected in this
                    phase.
                  </p>
                </article>
              </li>
            );
          }

          if (event.type === "suggestion.resolved") return null;

          if (event.type === "directive.cancelled") {
            return (
              <li
                key={event.eventId}
                className="flex items-center gap-2 py-1 text-xs text-muted-foreground [contain-intrinsic-size:auto_2rem] [content-visibility:auto]"
              >
                <X className="size-3.5 text-destructive" aria-hidden="true" />
                <span>A queued directive was cancelled after authority changed.</span>
                <span className="ml-auto">#{event.sequence}</span>
              </li>
            );
          }

          return (
            <li
              key={event.eventId}
              className="flex items-center gap-2 py-1 text-xs text-muted-foreground [contain-intrinsic-size:auto_2rem] [content-visibility:auto]"
            >
              {event.type === "session.runtime-authorization.enforced" ? (
                <ShieldCheck className="size-3.5 text-primary" aria-hidden="true" />
              ) : (
                <CircleDot className="size-3.5" aria-hidden="true" />
              )}
              <span>{conversationActivityLabel(event)}</span>
              <time className="ml-auto" dateTime={new Date(event.occurredAtMs).toISOString()}>
                {timestamp.format(event.occurredAtMs)}
              </time>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
