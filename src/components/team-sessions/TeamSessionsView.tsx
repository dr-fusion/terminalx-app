"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { MessageSquareText, TerminalSquare, UsersRound } from "lucide-react";
import { SessionInbox } from "@/components/team-sessions/SessionInbox";
import { SessionWorkspace } from "@/components/team-sessions/SessionWorkspace";
import {
  NewSessionDialog,
  type NewSessionInput,
} from "@/components/team-sessions/NewSessionDialog";
import { useTeamSessions } from "@/hooks/team-sessions/useTeamSessions";
import {
  createTeamSessionIdempotencyKey,
  submitTeamSessionCommand,
} from "@/lib/team-sessions/browser-client";

interface TeamSessionsViewProps {
  selectedSessionId?: string;
}

interface CreateFlow {
  fingerprint: string;
  teamFingerprint: string;
  projectFingerprint: string;
  teamKey: string;
  projectKey: string;
  sessionKey: string;
  teamId?: string;
  projectId?: string;
}

function resultId(
  data: Record<string, unknown>,
  key: "teamId" | "projectId" | "sessionId"
): string {
  const value = data[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Server did not return ${key}`);
  }
  return value;
}

function inputFingerprint(input: NewSessionInput): string {
  return JSON.stringify(input);
}

function teamInputFingerprint(input: NewSessionInput): string {
  return JSON.stringify({ teamId: input.teamId, teamName: input.teamName });
}

function projectInputFingerprint(input: NewSessionInput, teamFingerprint: string): string {
  return JSON.stringify({
    teamFingerprint,
    projectId: input.projectId,
    projectName: input.projectName,
  });
}

export function TeamSessionsView({ selectedSessionId }: TeamSessionsViewProps) {
  const router = useRouter();
  const { discovery, sessions, isLoading, error, refresh } = useTeamSessions();
  const [createOpen, setCreateOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [transportEnabled, setTransportEnabled] = useState<boolean | null>(null);
  const createFlowRef = useRef<CreateFlow | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/team-sessions/status", {
      signal: controller.signal,
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(async (response) => {
        if (!response.ok) throw new Error("Status request failed");
        const value = (await response.json()) as unknown;
        if (
          value === null ||
          typeof value !== "object" ||
          typeof (value as { enabled?: unknown }).enabled !== "boolean"
        ) {
          throw new Error("Status response is invalid");
        }
        setTransportEnabled((value as { enabled: boolean }).enabled);
      })
      .catch((cause: unknown) => {
        if (cause instanceof DOMException && cause.name === "AbortError") return;
        setTransportEnabled(null);
      });
    return () => controller.abort();
  }, []);

  const createSession = async (input: NewSessionInput) => {
    setIsCreating(true);
    setCreateError(null);
    const fingerprint = inputFingerprint(input);
    const teamFingerprint = teamInputFingerprint(input);
    const projectFingerprint = projectInputFingerprint(input, teamFingerprint);
    if (createFlowRef.current?.fingerprint !== fingerprint) {
      const previous = createFlowRef.current;
      const sameTeam = previous?.teamFingerprint === teamFingerprint;
      const sameProject = previous?.projectFingerprint === projectFingerprint;
      createFlowRef.current = {
        fingerprint,
        teamFingerprint,
        projectFingerprint,
        teamKey: sameTeam ? previous.teamKey : createTeamSessionIdempotencyKey(),
        projectKey: sameProject ? previous.projectKey : createTeamSessionIdempotencyKey(),
        sessionKey: createTeamSessionIdempotencyKey(),
        ...(sameTeam && previous.teamId ? { teamId: previous.teamId } : {}),
        ...(sameProject && previous.projectId ? { projectId: previous.projectId } : {}),
      };
    }
    const flow = createFlowRef.current;

    try {
      let teamId = input.teamId ?? flow.teamId;
      if (!teamId) {
        const createdTeam = await submitTeamSessionCommand(
          { type: "team.create", name: input.teamName ?? "" },
          { idempotencyKey: flow.teamKey }
        );
        teamId = resultId(createdTeam.data, "teamId");
        flow.teamId = teamId;
      }

      let projectId = input.projectId ?? flow.projectId;
      if (!projectId) {
        const createdProject = await submitTeamSessionCommand(
          { type: "project.create", teamId, name: input.projectName ?? "" },
          { idempotencyKey: flow.projectKey }
        );
        projectId = resultId(createdProject.data, "projectId");
        flow.projectId = projectId;
      }

      const createdSession = await submitTeamSessionCommand(
        {
          type: "session.start",
          teamId,
          projectId,
          name: input.sessionName,
          steeringPolicy: input.steeringPolicy,
        },
        { idempotencyKey: flow.sessionKey }
      );
      const sessionId = resultId(createdSession.data, "sessionId");
      createFlowRef.current = null;
      setCreateOpen(false);
      await refresh();
      router.push(`/team-sessions/${encodeURIComponent(sessionId)}`);
    } catch (cause) {
      setCreateError(cause instanceof Error ? cause.message : "Could not create the session");
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="grid h-full min-h-0 bg-background md:grid-cols-[300px_minmax(0,1fr)]">
      <div
        className={
          selectedSessionId
            ? "hidden min-h-0 border-r border-border md:block"
            : "min-h-0 border-r border-border"
        }
      >
        <SessionInbox
          discovery={discovery}
          sessions={sessions}
          selectedSessionId={selectedSessionId}
          isLoading={isLoading}
          error={error}
          onRetry={() => void refresh()}
          onCreateSession={() => {
            setCreateError(null);
            setCreateOpen(true);
          }}
        />
      </div>

      {selectedSessionId ? (
        <div className="min-h-0">
          <SessionWorkspace sessionId={selectedSessionId} transportEnabled={transportEnabled} />
        </div>
      ) : (
        <div className="hidden min-h-0 items-center justify-center p-8 md:flex">
          <div className="max-w-lg text-center">
            <div className="mx-auto grid size-20 grid-cols-2 gap-1 rounded-xl border border-border bg-card p-2">
              <div className="flex items-center justify-center rounded-md bg-primary/10 text-primary">
                <MessageSquareText className="size-5" aria-hidden="true" />
              </div>
              <div className="flex items-center justify-center rounded-md bg-muted text-muted-foreground">
                <TerminalSquare className="size-5" aria-hidden="true" />
              </div>
              <div className="col-span-2 flex items-center justify-center rounded-md bg-muted text-muted-foreground">
                <UsersRound className="size-5" aria-hidden="true" />
              </div>
            </div>
            <h1 className="mt-5 text-base font-semibold">Pick up shared work where it left off</h1>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              Select a session to review its durable conversation, observe the terminal, or hand
              steering and control to another teammate.
            </p>
          </div>
        </div>
      )}

      {createOpen ? (
        <NewSessionDialog
          open
          discovery={discovery}
          isSubmitting={isCreating}
          error={createError}
          onOpenChange={(open) => {
            setCreateOpen(open);
            if (!open) {
              setCreateError(null);
              createFlowRef.current = null;
            }
          }}
          onCreate={createSession}
        />
      ) : null}
    </div>
  );
}
