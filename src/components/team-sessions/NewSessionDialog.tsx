"use client";

import { useId, useMemo, useState } from "react";
import { AlertTriangle, LoaderCircle, Plus, UsersRound } from "lucide-react";
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
import type { TeamSessionDiscovery } from "@/types/team-session";

export interface NewSessionInput {
  teamId?: string;
  teamName?: string;
  projectId?: string;
  projectName?: string;
  sessionName: string;
  steeringPolicy: "single" | "shared";
}

interface NewSessionDialogProps {
  open: boolean;
  discovery: TeamSessionDiscovery | null;
  isSubmitting: boolean;
  error?: string | null;
  onOpenChange: (open: boolean) => void;
  onCreate: (input: NewSessionInput) => Promise<void>;
}

const CREATE_NEW = "__new__";

export function NewSessionDialog({
  open,
  discovery,
  isSubmitting,
  error,
  onOpenChange,
  onCreate,
}: NewSessionDialogProps) {
  const firstTeamId = discovery?.teams[0]?.teamId ?? CREATE_NEW;
  const firstProjectId =
    discovery?.teams[0]?.projects.find((project) => project.capabilities.startSession)?.projectId ??
    CREATE_NEW;
  const [teamId, setTeamId] = useState(firstTeamId);
  const [projectId, setProjectId] = useState(firstProjectId);
  const [teamName, setTeamName] = useState("");
  const [projectName, setProjectName] = useState("");
  const [sessionName, setSessionName] = useState("");
  const [steeringPolicy, setSteeringPolicy] = useState<"single" | "shared">("shared");
  const teamInputId = useId();
  const projectInputId = useId();
  const sessionInputId = useId();
  const policyGroupId = useId();

  const requestedTeam = useMemo(
    () => discovery?.teams.find((team) => team.teamId === teamId),
    [discovery, teamId]
  );
  const effectiveTeamId = teamId === CREATE_NEW || requestedTeam ? teamId : firstTeamId;
  const selectedTeam = useMemo(
    () => discovery?.teams.find((team) => team.teamId === effectiveTeamId),
    [discovery, effectiveTeamId]
  );
  const eligibleProjects = useMemo(
    () => selectedTeam?.projects.filter((project) => project.capabilities.startSession) ?? [],
    [selectedTeam]
  );
  const canCreateProject =
    effectiveTeamId === CREATE_NEW || Boolean(selectedTeam?.capabilities.createProject);
  const cannotChooseProject = eligibleProjects.length === 0 && !canCreateProject;
  const effectiveProjectId =
    projectId === CREATE_NEW || eligibleProjects.some((project) => project.projectId === projectId)
      ? projectId
      : (eligibleProjects[0]?.projectId ?? CREATE_NEW);

  const needsTeam = effectiveTeamId === CREATE_NEW;
  const needsProject = needsTeam || effectiveProjectId === CREATE_NEW;
  const valid =
    sessionName.trim().length > 0 &&
    (!needsTeam || teamName.trim().length > 0) &&
    (!needsProject || projectName.trim().length > 0) &&
    !cannotChooseProject;

  return (
    <Dialog open={open} onOpenChange={(next) => !isSubmitting && onOpenChange(next)}>
      <DialogContent className="sm:max-w-lg" showCloseButton={false}>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (!valid) return;
            void onCreate({
              ...(needsTeam ? { teamName: teamName.trim() } : { teamId: effectiveTeamId }),
              ...(needsProject
                ? { projectName: projectName.trim() }
                : { projectId: effectiveProjectId }),
              sessionName: sessionName.trim(),
              steeringPolicy,
            });
          }}
        >
          <DialogHeader>
            <div className="flex size-10 items-center justify-center rounded-full border border-border bg-background">
              <UsersRound className="size-5 text-primary" aria-hidden="true" />
            </div>
            <DialogTitle>Create a team session</DialogTitle>
            <DialogDescription>
              Start a durable shared workspace with explicit steering and terminal control.
            </DialogDescription>
          </DialogHeader>

          <div className="mt-5 space-y-4">
            {(discovery?.teams.length ?? 0) > 0 ? (
              <div className="space-y-1.5">
                <label htmlFor={teamInputId} className="text-xs font-medium">
                  Team
                </label>
                <select
                  id={teamInputId}
                  value={effectiveTeamId}
                  disabled={isSubmitting}
                  className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                  onChange={(event) => {
                    const nextTeamId = event.target.value;
                    const nextTeam = discovery?.teams.find((team) => team.teamId === nextTeamId);
                    const nextProject = nextTeam?.projects.find(
                      (project) => project.capabilities.startSession
                    );
                    setTeamId(nextTeamId);
                    setProjectId(nextProject?.projectId ?? CREATE_NEW);
                  }}
                >
                  {discovery?.teams.map((team) => (
                    <option key={team.teamId} value={team.teamId}>
                      {team.name}
                    </option>
                  ))}
                  <option value={CREATE_NEW}>Create a new team…</option>
                </select>
              </div>
            ) : null}

            {needsTeam ? (
              <div className="space-y-1.5">
                <label htmlFor={`${teamInputId}-name`} className="text-xs font-medium">
                  Team name
                </label>
                <input
                  id={`${teamInputId}-name`}
                  type="text"
                  value={teamName}
                  maxLength={120}
                  autoComplete="organization"
                  disabled={isSubmitting}
                  className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                  placeholder="Platform engineering"
                  onChange={(event) => setTeamName(event.target.value)}
                />
              </div>
            ) : null}

            {!needsTeam && (eligibleProjects.length > 0 || canCreateProject) ? (
              <div className="space-y-1.5">
                <label htmlFor={projectInputId} className="text-xs font-medium">
                  Project
                </label>
                <select
                  id={projectInputId}
                  value={effectiveProjectId}
                  disabled={isSubmitting}
                  className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                  onChange={(event) => setProjectId(event.target.value)}
                >
                  {eligibleProjects.map((project) => (
                    <option key={project.projectId} value={project.projectId}>
                      {project.name}
                    </option>
                  ))}
                  {canCreateProject ? (
                    <option value={CREATE_NEW}>Create a new project…</option>
                  ) : null}
                </select>
              </div>
            ) : null}

            {needsProject && !cannotChooseProject ? (
              <div className="space-y-1.5">
                <label htmlFor={`${projectInputId}-name`} className="text-xs font-medium">
                  Project name
                </label>
                <input
                  id={`${projectInputId}-name`}
                  type="text"
                  value={projectName}
                  maxLength={120}
                  autoComplete="off"
                  disabled={isSubmitting}
                  className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                  placeholder="Payments API"
                  onChange={(event) => setProjectName(event.target.value)}
                />
              </div>
            ) : null}

            {cannotChooseProject ? (
              <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
                You need explicit Project Access to start a session. Ask a Team Owner or Admin to
                grant it.
              </div>
            ) : null}

            <div className="space-y-1.5">
              <label htmlFor={sessionInputId} className="text-xs font-medium">
                Session name
              </label>
              <input
                id={sessionInputId}
                type="text"
                value={sessionName}
                maxLength={160}
                autoComplete="off"
                disabled={isSubmitting}
                className="min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-2 focus-visible:ring-ring"
                placeholder="Investigate checkout latency"
                onChange={(event) => setSessionName(event.target.value)}
              />
            </div>

            <fieldset id={policyGroupId}>
              <legend className="text-xs font-medium">Steering policy</legend>
              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                {(["shared", "single"] as const).map((policy) => (
                  <label
                    key={policy}
                    className="flex min-h-16 cursor-pointer items-start gap-3 rounded-lg border border-border p-3 has-[:checked]:border-primary/60 has-[:checked]:bg-primary/10"
                  >
                    <input
                      type="radio"
                      name={policyGroupId}
                      value={policy}
                      checked={steeringPolicy === policy}
                      disabled={isSubmitting}
                      className="mt-0.5 size-4 accent-primary"
                      onChange={() => setSteeringPolicy(policy)}
                    />
                    <span>
                      <span className="block text-sm font-medium capitalize">{policy}</span>
                      <span className="mt-0.5 block text-xs leading-5 text-muted-foreground">
                        {policy === "shared"
                          ? "Multiple Steerers can queue ordered directives."
                          : "Only the current Controller can steer."}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="flex items-start gap-2 rounded-md border border-[color:var(--amber-dim)] bg-[var(--amber-ghost)] p-3 text-xs leading-5 text-muted-foreground">
              <AlertTriangle
                className="mt-0.5 size-4 shrink-0 text-[var(--amber)]"
                aria-hidden="true"
              />
              <p>
                This phase uses trusted-host LocalTmux. It is not a Daytona Sandbox, and Danger
                Zone/YOLO mode is unavailable.
              </p>
            </div>

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
              disabled={!valid || isSubmitting}
              aria-busy={isSubmitting}
            >
              {isSubmitting ? (
                <LoaderCircle
                  className="animate-spin motion-reduce:animate-none"
                  aria-hidden="true"
                />
              ) : (
                <Plus aria-hidden="true" />
              )}
              {isSubmitting ? "Creating" : "Create session"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
