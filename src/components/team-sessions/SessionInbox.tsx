"use client";

import { useMemo } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ChevronRight, Inbox, KeyRound, Plus, RefreshCw, Search, UsersRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { TeamSessionDiscovery, TeamSessionInboxItem } from "@/types/team-session";
import { cn } from "@/lib/utils";

interface SessionInboxProps {
  discovery: TeamSessionDiscovery | null;
  sessions: TeamSessionInboxItem[];
  selectedSessionId?: string;
  isLoading: boolean;
  error: Error | null;
  onRetry: () => void;
  onCreateSession: () => void;
}

function statusCopy(status: TeamSessionInboxItem["status"]): string {
  if (status === "awaiting_assignee") return "needs assignee";
  return status;
}

function participantSummary(session: TeamSessionInboxItem): string {
  const people = new Set<string>();
  const responsibility = session.responsibilities;
  if (responsibility.assignee) people.add(responsibility.assignee.userId);
  if (responsibility.controller) people.add(responsibility.controller.userId);
  for (const person of responsibility.supervisors) people.add(person.userId);
  for (const person of responsibility.steerers) people.add(person.userId);
  const count = people.size;
  return count === 1 ? "1 responsible person" : `${count} responsible people`;
}

function SessionInboxSkeleton() {
  return (
    <div className="space-y-3 p-3" aria-label="Loading sessions">
      {[0, 1, 2, 3].map((item) => (
        <div key={item} className="space-y-3 rounded-lg border border-border p-3">
          <div className="h-4 w-3/4 animate-pulse rounded bg-muted" />
          <div className="h-3 w-1/2 animate-pulse rounded bg-muted" />
          <div className="h-3 w-2/3 animate-pulse rounded bg-muted" />
        </div>
      ))}
    </div>
  );
}

export function SessionInbox({
  discovery,
  sessions,
  selectedSessionId,
  isLoading,
  error,
  onRetry,
  onCreateSession,
}: SessionInboxProps) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const query = searchParams.get("q") ?? "";
  const teamId = searchParams.get("team") ?? "all";

  const projectNames = useMemo(() => {
    const names = new Map<string, string>();
    for (const team of discovery?.teams ?? []) {
      for (const project of team.projects) names.set(project.projectId, project.name);
    }
    return names;
  }, [discovery]);

  const visibleSessions = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    return sessions.filter((session) => {
      if (teamId !== "all" && session.teamId !== teamId) return false;
      if (!normalized) return true;
      return `${session.name} ${projectNames.get(session.projectId) ?? ""}`
        .toLocaleLowerCase()
        .includes(normalized);
    });
  }, [projectNames, query, sessions, teamId]);

  const updateFilter = (key: "q" | "team", value: string) => {
    const next = new URLSearchParams(searchParams.toString());
    if (!value || value === "all") next.delete(key);
    else next.set(key, value);
    router.replace(`${pathname}${next.size > 0 ? `?${next.toString()}` : ""}`, { scroll: false });
  };

  return (
    <section className="flex h-full min-h-0 flex-col bg-card" aria-label="Session inbox">
      <header className="flex min-h-14 items-center gap-3 border-b border-border px-3">
        <div className="min-w-0 flex-1">
          <h1 className="truncate text-sm font-semibold">Team sessions</h1>
          <p className="text-xs text-muted-foreground">Shared work and attention</p>
        </div>
        <Button
          render={<Link href="/team-sessions/join" />}
          nativeButton={false}
          size="icon-lg"
          className="size-10"
          variant="outline"
          aria-label="Join with an invitation"
          title="Join with an invitation"
        >
          <KeyRound aria-hidden="true" />
        </Button>
        <Button
          type="button"
          size="icon-lg"
          className="size-10"
          variant="outline"
          disabled={isLoading}
          onClick={onCreateSession}
          aria-label="Create team session"
          title="Create team session"
        >
          <Plus aria-hidden="true" />
        </Button>
      </header>

      <div className="space-y-3 border-b border-border p-3">
        <div className="space-y-1.5">
          <label htmlFor="session-search" className="text-xs font-medium text-foreground">
            Find a session
          </label>
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <input
              id="session-search"
              type="search"
              value={query}
              autoComplete="off"
              className="min-h-10 w-full rounded-md border border-input bg-background py-2 pl-9 pr-3 text-sm placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring"
              placeholder="Search by session or project"
              onChange={(event) => updateFilter("q", event.target.value)}
            />
          </div>
        </div>
        {(discovery?.teams.length ?? 0) > 1 ? (
          <div className="space-y-1.5">
            <label htmlFor="session-team-filter" className="text-xs font-medium text-foreground">
              Team
            </label>
            <select
              id="session-team-filter"
              value={teamId}
              className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
              onChange={(event) => updateFilter("team", event.target.value)}
            >
              <option value="all">All teams</option>
              {(discovery?.teams ?? []).map((team) => (
                <option key={team.teamId} value={team.teamId}>
                  {team.name}
                </option>
              ))}
            </select>
          </div>
        ) : null}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
        {isLoading ? <SessionInboxSkeleton /> : null}
        {!isLoading && error ? (
          <div className="m-3 rounded-lg border border-destructive/30 bg-destructive/5 p-4">
            <p className="text-sm font-medium text-destructive">Couldn&apos;t load team sessions</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Check the connection, then try again. Your existing sessions are unchanged.
            </p>
            <Button
              type="button"
              variant="outline"
              size="lg"
              className="mt-3 min-h-10"
              onClick={onRetry}
            >
              <RefreshCw aria-hidden="true" />
              Try again
            </Button>
          </div>
        ) : null}
        {!isLoading && !error && visibleSessions.length === 0 ? (
          <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
            <div className="flex size-11 items-center justify-center rounded-full border border-border bg-background">
              <Inbox className="size-5 text-primary" aria-hidden="true" />
            </div>
            <div className="space-y-1">
              <p className="text-sm font-medium">
                {query ? "No matching sessions" : "No sessions yet"}
              </p>
              <p className="text-xs leading-5 text-muted-foreground">
                {query
                  ? "Try a different name or clear the team filter."
                  : "Create a shared session to collaborate on a terminal task."}
              </p>
            </div>
            {query ? (
              <Button
                type="button"
                size="lg"
                variant="outline"
                className="min-h-10"
                onClick={() => updateFilter("q", "")}
              >
                Clear search
              </Button>
            ) : (
              <Button type="button" size="lg" className="min-h-10" onClick={onCreateSession}>
                <Plus aria-hidden="true" />
                Create session
              </Button>
            )}
          </div>
        ) : null}
        {!isLoading && !error && visibleSessions.length > 0 ? (
          <ol className="space-y-1 p-2">
            {visibleSessions.map((session) => {
              const selected = session.sessionId === selectedSessionId;
              const controller = session.responsibilities.controller;
              return (
                <li key={session.sessionId}>
                  <Link
                    href={`/team-sessions/${encodeURIComponent(session.sessionId)}${searchParams.size > 0 ? `?${searchParams.toString()}` : ""}`}
                    aria-current={selected ? "page" : undefined}
                    className={cn(
                      "group block min-h-24 rounded-lg border p-3 transition-colors focus-visible:ring-2 focus-visible:ring-ring",
                      selected
                        ? "border-primary/50 bg-primary/10"
                        : "border-transparent hover:border-border hover:bg-muted/60"
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-foreground">
                          {session.name}
                        </p>
                        <p className="mt-0.5 truncate text-xs text-muted-foreground">
                          {projectNames.get(session.projectId) ?? "Restricted project"}
                        </p>
                      </div>
                      <ChevronRight
                        className="mt-0.5 size-4 shrink-0 text-muted-foreground group-hover:text-foreground"
                        aria-hidden="true"
                      />
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <span
                        className={cn(
                          "inline-flex items-center gap-1 rounded-full border px-2 py-0.5",
                          session.status === "active"
                            ? "border-primary/40 text-primary"
                            : session.status === "ended"
                              ? "border-border"
                              : "border-[color:var(--amber-dim)] text-[var(--amber)]"
                        )}
                      >
                        <span
                          className={cn(
                            "size-1.5 rounded-full",
                            session.status === "active"
                              ? "bg-primary"
                              : session.status === "ended"
                                ? "bg-muted-foreground"
                                : "bg-[var(--amber)]"
                          )}
                          aria-hidden="true"
                        />
                        {statusCopy(session.status)}
                      </span>
                      <span className="inline-flex items-center gap-1">
                        <UsersRound className="size-3.5" aria-hidden="true" />
                        {participantSummary(session)}
                      </span>
                    </div>
                    {controller ? (
                      <p className="mt-2 truncate text-xs text-muted-foreground">
                        terminal · {controller.displayName}
                      </p>
                    ) : null}
                  </Link>
                </li>
              );
            })}
          </ol>
        ) : null}
      </div>
    </section>
  );
}
