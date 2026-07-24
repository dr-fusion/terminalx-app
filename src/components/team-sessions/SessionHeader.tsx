"use client";

import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  Radio,
  ShieldAlert,
  TerminalSquare,
  UsersRound,
} from "lucide-react";
import type { TeamSessionDetail } from "@/types/team-session";
import { cn } from "@/lib/utils";

interface SessionHeaderProps {
  session: TeamSessionDetail;
  connectionState: "idle" | "connecting" | "syncing" | "live" | "reconnecting";
  transportEnabled: boolean | null;
}

function sessionStatus(status: TeamSessionDetail["status"]): string {
  if (status === "awaiting_assignee") return "needs assignee";
  return status;
}

export function SessionHeader({ session, connectionState, transportEnabled }: SessionHeaderProps) {
  const controller = session.responsibilities.controller;
  const connectionCopy =
    connectionState === "live"
      ? "live"
      : connectionState === "reconnecting"
        ? "reconnecting"
        : connectionState === "syncing"
          ? "syncing"
          : connectionState === "connecting"
            ? "connecting"
            : "offline";

  return (
    <header className="shrink-0 border-b border-border bg-card">
      <div className="flex min-h-14 items-center gap-3 px-3 md:px-4">
        <Link
          href="/team-sessions"
          className="flex size-10 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring md:hidden"
          aria-label="Back to team sessions"
        >
          <ArrowLeft aria-hidden="true" />
        </Link>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="truncate text-sm font-semibold">{session.name}</h1>
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs",
                session.status === "active"
                  ? "border-primary/40 text-primary"
                  : session.status === "ended"
                    ? "border-border text-muted-foreground"
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
              {sessionStatus(session.status)}
            </span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1">
              <UsersRound className="size-3.5" aria-hidden="true" />
              {session.steeringPolicy === "shared" ? "shared steering" : "single steering"}
            </span>
            <span className="inline-flex items-center gap-1">
              <TerminalSquare className="size-3.5" aria-hidden="true" />
              {controller ? `${controller.displayName} controls terminal` : "terminal unclaimed"}
            </span>
          </div>
        </div>
        <div
          className={cn(
            "hidden items-center gap-1.5 rounded-full border px-2 py-1 text-xs sm:flex",
            connectionState === "live"
              ? "border-primary/40 text-primary"
              : "border-border text-muted-foreground"
          )}
          role="status"
        >
          <Radio className="size-3.5" aria-hidden="true" />
          {connectionCopy}
        </div>
      </div>

      {transportEnabled === false ? (
        <div className="flex items-start gap-2 border-t border-[color:var(--amber-dim)] bg-[var(--amber-ghost)] px-4 py-2 text-xs text-[var(--amber)]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <p>
            Multiplayer WebSockets are disabled on this server. Set{" "}
            <code className="text-foreground">TERMINALX_MULTIPLAYER_ENABLED=true</code> and restart
            the custom server to enable live events and terminal access.
          </p>
        </div>
      ) : null}

      <div className="flex items-start gap-2 border-t border-border bg-background/60 px-4 py-2 text-xs text-muted-foreground">
        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-[var(--amber)]" aria-hidden="true" />
        <p>
          LocalTmux is a trusted same-host development runtime, not an isolated Sandbox. Danger
          Zone/YOLO grants remain unavailable here.
        </p>
      </div>
    </header>
  );
}
