"use client";

import { useCallback, useId, useRef, useState } from "react";
import { LoaderCircle, Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { searchTeamSessionConversation } from "@/lib/team-sessions/browser-client";
import type { TeamSessionConversationSearchMatch } from "@/types/team-session";

interface ConversationSearchProps {
  sessionId: string;
  viewerUserId: string;
}

const timestamp = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

/** Split a body around case-insensitive matches of `needle` for highlight. */
export function highlightSegments(
  body: string,
  needle: string
): Array<{ text: string; match: boolean }> {
  const trimmed = needle.trim();
  if (trimmed.length === 0) return [{ text: body, match: false }];
  const lowerBody = body.toLowerCase();
  const lowerNeedle = trimmed.toLowerCase();
  const segments: Array<{ text: string; match: boolean }> = [];
  let index = 0;
  while (index < body.length) {
    const found = lowerBody.indexOf(lowerNeedle, index);
    if (found === -1) {
      segments.push({ text: body.slice(index), match: false });
      break;
    }
    if (found > index) segments.push({ text: body.slice(index, found), match: false });
    segments.push({ text: body.slice(found, found + lowerNeedle.length), match: true });
    index = found + lowerNeedle.length;
  }
  return segments;
}

export function ConversationSearch({ sessionId, viewerUserId }: ConversationSearchProps) {
  const inputId = useId();
  const resultsId = useId();
  const [text, setText] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [matches, setMatches] = useState<TeamSessionConversationSearchMatch[]>([]);
  const [nextAfterSequence, setNextAfterSequence] = useState<number | null>(null);
  const [status, setStatus] = useState<"idle" | "searching" | "error" | "done">("idle");
  const abortRef = useRef<AbortController | null>(null);

  const runSearch = useCallback(
    async (query: string, afterSequence: number | undefined) => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      setStatus("searching");
      try {
        const result = await searchTeamSessionConversation(sessionId, query, {
          afterSequence,
          limit: 25,
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setMatches((previous) =>
          afterSequence === undefined ? result.matches : [...previous, ...result.matches]
        );
        setNextAfterSequence(result.nextAfterSequence);
        setStatus("done");
      } catch {
        if (controller.signal.aborted) return;
        setStatus("error");
      }
    },
    [sessionId]
  );

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    const query = text.trim();
    if (query.length === 0) return;
    setSubmitted(query);
    setMatches([]);
    setNextAfterSequence(null);
    void runSearch(query, undefined);
  };

  const onClear = () => {
    abortRef.current?.abort();
    setText("");
    setSubmitted("");
    setMatches([]);
    setNextAfterSequence(null);
    setStatus("idle");
  };

  return (
    <section
      role="search"
      aria-label="Search conversation"
      className="shrink-0 border-b border-border bg-card px-4 py-3 md:px-6"
    >
      <form onSubmit={onSubmit} className="flex items-center gap-2">
        <label htmlFor={inputId} className="sr-only">
          Search this session&apos;s comments
        </label>
        <div className="relative flex-1">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <input
            id={inputId}
            type="search"
            value={text}
            maxLength={200}
            placeholder="Search comments in this session"
            {...(submitted ? { "aria-controls": resultsId } : {})}
            className="min-h-10 w-full rounded-md border border-input bg-background pl-9 pr-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
            onChange={(event) => setText(event.target.value)}
          />
        </div>
        <Button type="submit" size="lg" className="min-h-10" disabled={text.trim().length === 0}>
          {status === "searching" ? (
            <LoaderCircle className="animate-spin motion-reduce:animate-none" aria-hidden="true" />
          ) : (
            <Search aria-hidden="true" />
          )}
          Search
        </Button>
        {submitted ? (
          <Button
            type="button"
            size="icon-lg"
            variant="ghost"
            className="size-10"
            onClick={onClear}
            aria-label="Clear search"
          >
            <X aria-hidden="true" />
          </Button>
        ) : null}
      </form>

      {submitted ? (
        <div id={resultsId} className="mt-3" aria-live="polite">
          {status === "error" ? (
            <p className="text-sm text-destructive" role="alert">
              Search is unavailable right now. Try again.
            </p>
          ) : status === "searching" && matches.length === 0 ? (
            <p className="text-sm text-muted-foreground">Searching…</p>
          ) : matches.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No comments match &ldquo;{submitted}&rdquo;.
            </p>
          ) : (
            <>
              <p className="mb-2 text-xs text-muted-foreground">
                {matches.length.toLocaleString()}
                {nextAfterSequence !== null ? "+" : ""} matching{" "}
                {matches.length === 1 ? "comment" : "comments"}
              </p>
              <ol className="space-y-2">
                {matches.map((match) => (
                  <li
                    key={match.eventId}
                    className="rounded-md border border-border bg-background p-3"
                  >
                    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                      <span className="text-sm font-medium">
                        {match.actor.displayName}
                        {match.actor.userId === viewerUserId ? (
                          <span className="ml-1 text-xs font-normal text-muted-foreground">
                            you
                          </span>
                        ) : null}
                      </span>
                      <time
                        className="text-xs text-muted-foreground"
                        dateTime={new Date(match.occurredAtMs).toISOString()}
                      >
                        {timestamp.format(match.occurredAtMs)}
                      </time>
                    </div>
                    <p className="mt-1 whitespace-pre-wrap break-words text-sm leading-6">
                      {highlightSegments(match.body, submitted).map((segment, index) =>
                        segment.match ? (
                          <mark key={index} className="rounded bg-primary/20 text-foreground">
                            {segment.text}
                          </mark>
                        ) : (
                          <span key={index}>{segment.text}</span>
                        )
                      )}
                    </p>
                  </li>
                ))}
              </ol>
              {nextAfterSequence !== null ? (
                <Button
                  type="button"
                  size="lg"
                  variant="outline"
                  className="mt-3 min-h-10 w-full"
                  disabled={status === "searching"}
                  onClick={() => void runSearch(submitted, nextAfterSequence)}
                >
                  {status === "searching" ? (
                    <LoaderCircle
                      className="animate-spin motion-reduce:animate-none"
                      aria-hidden="true"
                    />
                  ) : null}
                  Load more results
                </Button>
              ) : null}
            </>
          )}
        </div>
      ) : null}
    </section>
  );
}
