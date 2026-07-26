"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { AtSign, BellRing, Inbox, LoaderCircle, ShieldAlert, UserRoundPlus } from "lucide-react";
import { cn } from "@/lib/utils";

export type AttentionItemKind = "mention" | "handoff-offer" | "assignee-required";

export interface AttentionItemView {
  itemId: string;
  kind: AttentionItemKind;
  sessionId: string;
  teamId: string;
  projectId: string;
  sessionName: string;
  sessionStatus: "active" | "awaiting_assignee" | "ended";
  itemSequence: number;
  createdAtMs: number;
  deadlineAtMs: number | null;
  read: boolean;
  escalated: boolean;
  actorUserId: string | null;
  summary: string;
}

interface InboxPage {
  items: AttentionItemView[];
  unreadCount: number;
  nextCursor: string | null;
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** Human phrasing for an item's deadline relative to now (pure; unit-tested). */
export function describeDeadline(deadlineAtMs: number | null, nowMs: number): string | null {
  if (deadlineAtMs === null) return null;
  const deltaMs = deadlineAtMs - nowMs;
  const minutes = Math.round(deltaMs / 60_000);
  if (Math.abs(minutes) < 60) return relative.format(minutes, "minute");
  const hours = Math.round(deltaMs / 3_600_000);
  if (Math.abs(hours) < 48) return relative.format(hours, "hour");
  return relative.format(Math.round(deltaMs / 86_400_000), "day");
}

/** Whether an item is past its deadline. Pure; drives the overdue affordance. */
export function isOverdue(item: AttentionItemView, nowMs: number): boolean {
  return item.deadlineAtMs !== null && item.deadlineAtMs <= nowMs;
}

const KIND_ICON: Record<AttentionItemKind, typeof AtSign> = {
  mention: AtSign,
  "handoff-offer": UserRoundPlus,
  "assignee-required": BellRing,
};

const KIND_LABEL: Record<AttentionItemKind, string> = {
  mention: "Mention",
  "handoff-offer": "Handoff offer",
  "assignee-required": "Needs an assignee",
};

async function fetchInbox(cursor: string | null, unreadOnly: boolean): Promise<InboxPage> {
  const params = new URLSearchParams();
  if (cursor) params.set("cursor", cursor);
  if (unreadOnly) params.set("unreadOnly", "true");
  const query = params.toString();
  const response = await fetch(`/api/attention${query ? `?${query}` : ""}`, {
    headers: { accept: "application/json" },
  });
  if (!response.ok) throw new Error(`Inbox request failed with ${response.status}`);
  const body = (await response.json()) as { inbox: InboxPage };
  return body.inbox;
}

async function markRead(sessionId: string, throughSequence: number): Promise<void> {
  await fetch("/api/attention/read", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ sessionId, throughSequence }),
  });
}

export function AttentionInboxView() {
  const [page, setPage] = useState<InboxPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(
    async (options: { unreadOnly: boolean }) => {
      setLoading(true);
      setError(null);
      try {
        setPage(await fetchInbox(null, options.unreadOnly));
      } catch {
        setError("Could not load your inbox. Refresh to try again.");
      } finally {
        setLoading(false);
      }
    },
    [setPage]
  );

  useEffect(() => {
    void load({ unreadOnly });
  }, [load, unreadOnly]);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  const onMarkRead = useCallback(
    async (item: AttentionItemView) => {
      await markRead(item.sessionId, item.itemSequence).catch(() => undefined);
      await load({ unreadOnly });
    },
    [load, unreadOnly]
  );

  return (
    <div className="mx-auto flex h-full max-w-3xl flex-col gap-4 p-4 md:p-6">
      <header className="flex flex-wrap items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-full border border-border bg-card">
          <Inbox className="size-4 text-primary" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <h1 className="text-lg font-semibold">Attention inbox</h1>
          <p className="text-sm text-muted-foreground">
            Mentions, handoff offers, and assignment asks across all your sessions.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input
            type="checkbox"
            checked={unreadOnly}
            onChange={(event) => setUnreadOnly(event.target.checked)}
            className="size-4 rounded border-border"
          />
          Unread only
        </label>
      </header>

      {page && page.unreadCount > 0 ? (
        <p className="text-sm text-muted-foreground" aria-live="polite">
          {page.unreadCount.toLocaleString()} unread
        </p>
      ) : null}

      {loading ? (
        <div className="flex items-center gap-2 p-8 text-sm text-muted-foreground">
          <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
          Loading your inbox…
        </div>
      ) : error ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive"
        >
          {error}
        </p>
      ) : !page || page.items.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border p-10 text-center">
          <Inbox className="size-6 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm font-medium">You&apos;re all caught up</p>
          <p className="text-sm text-muted-foreground">Nothing needs your attention right now.</p>
        </div>
      ) : (
        <ol className="space-y-2" aria-live="polite" aria-label="Attention items">
          {page.items.map((item) => {
            const Icon = KIND_ICON[item.kind];
            const overdue = isOverdue(item, now);
            const deadline = describeDeadline(item.deadlineAtMs, now);
            return (
              <li
                key={item.itemId}
                className={cn(
                  "rounded-lg border p-3 transition-colors",
                  item.read ? "border-border bg-card" : "border-primary/40 bg-primary/5"
                )}
              >
                <div className="flex items-start gap-3">
                  <div className="flex size-8 shrink-0 items-center justify-center rounded-full border border-border bg-muted">
                    <Icon className="size-4 text-primary" aria-hidden="true" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                        {KIND_LABEL[item.kind]}
                      </span>
                      {item.escalated ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-[color:var(--amber-dim)] px-1.5 py-0.5 text-xs text-[var(--amber)]">
                          <ShieldAlert className="size-3" aria-hidden="true" /> escalated
                        </span>
                      ) : null}
                      {deadline ? (
                        <span
                          className={cn(
                            "text-xs",
                            overdue ? "text-destructive" : "text-muted-foreground"
                          )}
                        >
                          {overdue ? "overdue " : "due "}
                          {deadline}
                        </span>
                      ) : null}
                    </div>
                    <Link
                      href={`/team-sessions/${item.sessionId}`}
                      className="mt-0.5 block truncate text-sm font-medium hover:underline"
                    >
                      {item.summary}
                    </Link>
                    <p className="truncate text-xs text-muted-foreground">{item.sessionName}</p>
                  </div>
                  {item.read ? null : (
                    <button
                      type="button"
                      onClick={() => void onMarkRead(item)}
                      className="shrink-0 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                    >
                      Mark read
                    </button>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
