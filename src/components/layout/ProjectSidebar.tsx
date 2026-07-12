"use client";

// Project sidebar (issue #12, corrected Project → Workspace model).
//
// A Project is a REPO container rendered as a HEADER (name + "+" add-workspace +
// a context menu with "Delete project"). Its workspaces are nested rows: status
// icon + branch name + diff stat + a "⋮" menu (Collapse, Archive). Collapse/
// expand toggles the whole group.
//
// Deleting a project is IRREVERSIBLE (it drops the project and removes ALL of
// its workspaces), so the menu item never deletes directly — it opens an in-app
// confirmation dialog (ConfirmDeleteDialog) that names the project and warns
// about the workspaces. deleteProject fires ONLY on explicit confirm.
//
// CLIENT/SERVER BOUNDARY: this file imports ONLY browser-safe modules
// (@/types/project formatters + the useProjects hook, which fetches the API).
// It never imports the project store / resolve / git / github server modules —
// those use Node builtins and would break the client bundle.

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  Archive,
  ChevronDown,
  ChevronRight,
  GitBranch,
  GitMerge,
  GitPullRequest,
  Loader2,
  MoreVertical,
  Plus,
  RotateCcw,
  Terminal,
  Trash2,
} from "lucide-react";
import { useProjects } from "@/hooks/useProjects";
import { useSessions, type TmuxSession } from "@/hooks/useSessions";
import { formatDiffStat, statusIcon } from "@/types/project";
import type { WorkspaceStatus, WorkspaceView, ProjectView } from "@/types/project";

function StatusIcon({ status }: { status: WorkspaceStatus }) {
  const kind = statusIcon(status);
  if (kind === "spinner") {
    return (
      <Loader2
        size={13}
        className="shrink-0 animate-spin text-[#6b7569]"
        data-testid="wt-icon-loading"
      />
    );
  }
  if (kind === "pr-merged") {
    return <GitMerge size={13} className="shrink-0 text-[#d58fff]" data-testid="wt-icon-merged" />;
  }
  if (kind === "pr-open") {
    return (
      <GitPullRequest size={13} className="shrink-0 text-[#00ff88]" data-testid="wt-icon-open" />
    );
  }
  return (
    <GitBranch size={13} className="shrink-0 text-[#6b7569]" data-testid="wt-icon-in-progress" />
  );
}

function sessionKindLabel(kind?: string): string {
  return kind || "bash";
}

function StandaloneSessionRow({
  session,
  activeSession,
  onOpen,
}: {
  session: TmuxSession;
  activeSession: string | null;
  onOpen: (sessionName: string) => void;
}) {
  const active = session.name === activeSession;
  const kind = sessionKindLabel(session.kind);

  return (
    <button
      type="button"
      data-testid="standalone-session-row"
      data-session={session.name}
      onClick={() => onOpen(session.name)}
      className={`group flex h-8 w-full items-center gap-2 rounded px-2 text-left text-[12px] transition-colors focus-visible:ring-2 focus-visible:ring-[#00cc6e] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0f1117] ${
        active ? "bg-[#14161e] text-[#e6f0e4]" : "text-[#a8b3a6] hover:bg-[#14161e]"
      }`}
    >
      <Terminal size={13} className={`shrink-0 ${active ? "text-[#00ff88]" : "text-[#6b7569]"}`} />
      <span className="min-w-0 flex-1 truncate" title={session.name}>
        {session.name}
      </span>
      <span className="shrink-0 rounded border border-[#1a1d24] px-1.5 py-0.5 text-[10px] text-[#6b7569] group-hover:text-[#a8b3a6]">
        {kind}
      </span>
    </button>
  );
}

function StandaloneSessionsSection({
  sessions,
  isLoading,
  activeSession,
  onOpen,
}: {
  sessions: TmuxSession[];
  isLoading: boolean;
  activeSession: string | null;
  onOpen: (sessionName: string) => void;
}) {
  const standalone = sessions.filter((session) => !session.worktree);

  if (isLoading && standalone.length === 0) {
    return (
      <div className="mt-3 border-t border-[#1a1d24] px-2 py-3 text-[11px] text-[#6b7569]">
        loading sessions...
      </div>
    );
  }

  if (standalone.length === 0) return null;

  return (
    <div data-testid="standalone-sessions-section" className="mt-3 border-t border-[#1a1d24] pt-2">
      <div className="flex items-center gap-1.5 px-1 py-1.5 text-[12px] text-[#6b7569]">
        <Terminal size={12} />
        <span className="font-medium">Sessions</span>
        <span
          data-testid="standalone-sessions-count"
          className="ml-1 rounded-full bg-[#1a1d24] px-1.5 text-[10px] text-[#a8b3a6]"
        >
          {standalone.length}
        </span>
      </div>
      <div className="mt-0.5 space-y-0.5" data-testid="standalone-sessions-list">
        {standalone.map((session) => (
          <StandaloneSessionRow
            key={session.name}
            session={session}
            activeSession={activeSession}
            onOpen={onOpen}
          />
        ))}
      </div>
    </div>
  );
}

/** Lightweight popover menu anchored to its trigger; closes on outside click / Esc. */
function Menu({
  open,
  onClose,
  children,
  testid,
}: {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
  testid: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div
      ref={ref}
      data-testid={testid}
      role="menu"
      className="absolute right-0 top-6 z-20 min-w-[150px] rounded border border-[#252933] bg-[#14161e] py-1 shadow-lg shadow-black/40"
    >
      {children}
    </div>
  );
}

function MenuItem({
  onClick,
  children,
  danger,
  testid,
}: {
  onClick: () => void;
  children: React.ReactNode;
  danger?: boolean;
  testid?: string;
}) {
  return (
    <button
      role="menuitem"
      data-testid={testid}
      onClick={onClick}
      className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-[12px] transition-colors hover:bg-[#1a1d24] ${
        danger ? "text-[#ff6b6b]" : "text-[#a8b3a6]"
      }`}
    >
      {children}
    </button>
  );
}

/**
 * Confirmation dialog for the irreversible "Delete project" action (issue #9).
 * Renders a dark-theme modal that names the project, warns it removes every
 * workspace, and exposes Cancel / Delete. The destructive callback fires ONLY
 * when the user clicks Delete; closing or Cancel never deletes. Esc + backdrop
 * click both cancel.
 */
function ConfirmDeleteDialog({
  project,
  workspaceCount,
  onCancel,
  onConfirm,
}: {
  project: ProjectView;
  workspaceCount: number;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onCancel]);

  return (
    <div
      data-testid="project-delete-confirm"
      role="alertdialog"
      aria-modal="true"
      aria-label={`Delete project ${project.name}`}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onMouseDown={(e) => {
        // Backdrop click cancels; clicks inside the panel do not bubble here.
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div className="w-full max-w-[340px] rounded-lg border border-[#252933] bg-[#14161e] p-4 shadow-xl shadow-black/50">
        <div className="flex items-start gap-2.5">
          <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[#2a1416] text-[#ff6b6b]">
            <AlertTriangle size={15} />
          </span>
          <div className="min-w-0">
            <h2 className="text-[13px] font-medium text-[#e6f0e4]">Delete project</h2>
            <p className="mt-1 text-[12px] leading-relaxed text-[#a8b3a6]">
              Delete{" "}
              <span
                className="font-medium text-[#e6f0e4]"
                data-testid="project-delete-confirm-name"
              >
                {project.name}
              </span>
              ? This removes the project and{" "}
              {workspaceCount === 0
                ? "all of its workspaces"
                : `all ${workspaceCount} of its workspace${workspaceCount === 1 ? "" : "s"}`}
              . This action cannot be undone.
            </p>
          </div>
        </div>
        <div className="mt-4 flex justify-end gap-2">
          <button
            data-testid="project-delete-confirm-cancel"
            onClick={onCancel}
            className="rounded border border-[#252933] px-3 py-1.5 text-[12px] text-[#a8b3a6] transition-colors hover:bg-[#1a1d24] hover:text-[#e6f0e4]"
          >
            Cancel
          </button>
          <button
            data-testid="project-delete-confirm-accept"
            onClick={onConfirm}
            className="rounded bg-[#ff6b6b] px-3 py-1.5 text-[12px] font-medium text-[#1a0c0d] transition-colors hover:bg-[#ff8585]"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}

function WorkspaceRow({
  workspace,
  activeSession,
  onOpen,
  onCollapse,
  onArchive,
}: {
  workspace: WorkspaceView;
  activeSession: string | null;
  onOpen: (sessionName: string) => void;
  onCollapse: (sessionName: string, collapsed: boolean) => void;
  onArchive: (sessionName: string) => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const active = workspace.sessionName === activeSession;
  const stat = formatDiffStat(workspace.diffStat);

  return (
    <div
      data-testid="workspace-row"
      data-session={workspace.sessionName}
      data-status={workspace.status}
      className={`group relative flex h-8 w-full items-center gap-2 rounded px-2 text-[12px] transition-colors ${
        active ? "bg-[#14161e] text-[#e6f0e4]" : "text-[#a8b3a6] hover:bg-[#14161e]"
      }`}
    >
      <button
        onClick={() => onOpen(workspace.sessionName)}
        className="flex min-w-0 flex-1 items-center gap-2 text-left"
        data-testid="workspace-open"
      >
        <StatusIcon status={workspace.status} />
        <span className="min-w-0 flex-1 truncate" data-testid="workspace-name">
          {workspace.branch}
        </span>
      </button>

      {stat && (
        <span
          data-testid="workspace-diffstat"
          className="shrink-0 font-mono text-[10px] tabular-nums text-[#6b7569]"
        >
          {workspace.diffStat.additions > 0 && (
            <span className="text-[#00cc6e]">+{workspace.diffStat.additions}</span>
          )}
          {workspace.diffStat.additions > 0 && workspace.diffStat.deletions > 0 && " "}
          {workspace.diffStat.deletions > 0 && (
            <span className="text-[#ff6b6b]">−{workspace.diffStat.deletions}</span>
          )}
        </span>
      )}

      <div className="relative shrink-0">
        <button
          data-testid="workspace-menu-trigger"
          aria-label="workspace menu"
          onClick={() => setMenuOpen((o) => !o)}
          className="flex h-5 w-5 items-center justify-center rounded text-[#6b7569] opacity-0 transition-colors hover:bg-[#1a1d24] hover:text-[#e6f0e4] group-hover:opacity-100 data-[open=true]:opacity-100"
          data-open={menuOpen}
        >
          <MoreVertical size={13} />
        </button>
        <Menu open={menuOpen} onClose={() => setMenuOpen(false)} testid="workspace-menu">
          <MenuItem
            testid="workspace-menu-collapse"
            onClick={() => {
              onCollapse(workspace.sessionName, !workspace.collapsed);
              setMenuOpen(false);
            }}
          >
            <ChevronRight size={13} /> Collapse
          </MenuItem>
          <MenuItem
            testid="workspace-menu-archive"
            onClick={() => {
              onArchive(workspace.sessionName);
              setMenuOpen(false);
            }}
          >
            <Archive size={13} /> Archive
          </MenuItem>
        </Menu>
      </div>
    </div>
  );
}

function ProjectGroup({
  project,
  activeSession,
  onOpenWorkspace,
  onAddWorkspace,
  onRequestDelete,
  onCollapseWorkspace,
  onArchiveWorkspace,
}: {
  project: ProjectView;
  activeSession: string | null;
  onOpenWorkspace: (sessionName: string) => void;
  onAddWorkspace: (repoRoot: string) => void;
  onRequestDelete: (project: ProjectView) => void;
  onCollapseWorkspace: (sessionName: string, collapsed: boolean) => void;
  onArchiveWorkspace: (sessionName: string) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const [menuOpen, setMenuOpen] = useState(false);
  // Collapsed workspaces are hidden from the group (issue #9 keeps them in archive).
  const visible = project.workspaces.filter((w) => !w.collapsed && !w.archived);

  return (
    <div data-testid="project-group" data-project-id={project.id} className="mb-2">
      <div className="relative flex items-center gap-1.5 rounded px-1 py-1.5 text-[13px] text-[#e6f0e4]">
        <button
          data-testid="project-toggle"
          aria-label={expanded ? "collapse project" : "expand project"}
          onClick={() => setExpanded((e) => !e)}
          className="flex h-4 w-4 items-center justify-center rounded text-[#6b7569] hover:text-[#e6f0e4]"
        >
          {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </button>
        <span className="flex h-5 w-5 items-center justify-center rounded bg-[#002a17] text-[10px] text-[#00ff88]">
          {project.name.slice(0, 2).toLowerCase()}
        </span>
        <span
          data-testid="project-name"
          className="min-w-0 flex-1 truncate font-medium"
          title={project.repoRoot}
        >
          {project.name}
        </span>
        <button
          data-testid="project-add-workspace"
          aria-label="new workspace"
          onClick={() => onAddWorkspace(project.repoRoot)}
          className="flex h-5 w-5 items-center justify-center rounded text-[#6b7569] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4]"
        >
          <Plus size={13} />
        </button>
        <div className="relative shrink-0">
          <button
            data-testid="project-menu-trigger"
            aria-label="project menu"
            onClick={() => setMenuOpen((o) => !o)}
            className="flex h-5 w-5 items-center justify-center rounded text-[#6b7569] transition-colors hover:bg-[#14161e] hover:text-[#e6f0e4]"
          >
            <MoreVertical size={13} />
          </button>
          <Menu open={menuOpen} onClose={() => setMenuOpen(false)} testid="project-menu">
            <MenuItem
              testid="project-menu-delete"
              danger
              onClick={() => {
                // Never deletes directly — opens the confirmation dialog (#9).
                onRequestDelete(project);
                setMenuOpen(false);
              }}
            >
              <Trash2 size={13} /> Delete project
            </MenuItem>
          </Menu>
        </div>
      </div>

      {expanded && (
        <div className="mt-0.5 space-y-0.5 pl-3" data-testid="project-workspaces">
          {visible.length === 0 ? (
            <div className="px-2 py-1.5 text-[11px] text-[#6b7569]">no workspaces</div>
          ) : (
            visible.map((ws) => (
              <WorkspaceRow
                key={ws.sessionName}
                workspace={ws}
                activeSession={activeSession}
                onOpen={onOpenWorkspace}
                onCollapse={onCollapseWorkspace}
                onArchive={onArchiveWorkspace}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

/** One archived workspace row with a Restore action (issue #9 Archived view). */
function ArchivedRow({
  workspace,
  onRestore,
}: {
  workspace: WorkspaceView;
  onRestore: (sessionName: string) => void;
}) {
  return (
    <div
      data-testid="archived-workspace-row"
      data-session={workspace.sessionName}
      className="group flex h-8 w-full items-center gap-2 rounded px-2 text-[12px] text-[#6b7569] hover:bg-[#14161e]"
    >
      <Archive size={13} className="shrink-0 text-[#6b7569]" />
      <span className="min-w-0 flex-1 truncate" data-testid="archived-workspace-name">
        {workspace.branch}
      </span>
      <button
        data-testid="archived-workspace-restore"
        aria-label="restore workspace"
        onClick={() => onRestore(workspace.sessionName)}
        className="flex shrink-0 items-center gap-1 rounded border border-[#1a1d24] px-1.5 py-0.5 text-[10px] text-[#a8b3a6] opacity-0 transition-colors hover:bg-[#1a1d24] hover:text-[#e6f0e4] group-hover:opacity-100"
      >
        <RotateCcw size={11} /> Restore
      </button>
    </div>
  );
}

/**
 * The "Archived" section: a collapsible list of every archived workspace across
 * all projects, each with a Restore action (issue #9). Hidden entirely when
 * nothing is archived so it never clutters the rail.
 */
function ArchivedSection({
  projects,
  onRestore,
}: {
  projects: ProjectView[];
  onRestore: (sessionName: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const archived = projects.flatMap((proj) => proj.workspaces.filter((w) => w.archived));
  if (archived.length === 0) return null;

  return (
    <div data-testid="archived-section" className="mt-3 border-t border-[#1a1d24] pt-2">
      <button
        data-testid="archived-toggle"
        aria-label={expanded ? "collapse archived" : "expand archived"}
        onClick={() => setExpanded((e) => !e)}
        className="flex w-full items-center gap-1.5 rounded px-1 py-1.5 text-[12px] text-[#6b7569] hover:text-[#a8b3a6]"
      >
        {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <Archive size={12} />
        <span className="font-medium">Archived</span>
        <span
          data-testid="archived-count"
          className="ml-1 rounded-full bg-[#1a1d24] px-1.5 text-[10px] text-[#a8b3a6]"
        >
          {archived.length}
        </span>
      </button>
      {expanded && (
        <div className="mt-0.5 space-y-0.5 pl-3" data-testid="archived-list">
          {archived.map((ws) => (
            <ArchivedRow key={ws.sessionName} workspace={ws} onRestore={onRestore} />
          ))}
        </div>
      )}
    </div>
  );
}

export function ProjectSidebar({ activeSession }: { activeSession: string | null }) {
  const router = useRouter();
  const {
    projects,
    isLoading,
    deleteProject,
    setWorkspaceCollapsed,
    archiveWorkspace,
    restoreWorkspace,
    refresh: refreshProjects,
  } = useProjects();
  const {
    sessions,
    isLoading: sessionsLoading,
    hasLoadedSuccessfully,
    membershipVersion,
  } = useSessions();

  // Project workspaces are derived from session/worktree metadata. Refresh the
  // derived project view only when that membership changes; ordinary session
  // revalidations do not fan out into another projects request.
  useEffect(() => {
    if (!hasLoadedSuccessfully) return;
    void refreshProjects();
  }, [hasLoadedSuccessfully, membershipVersion, refreshProjects]);

  // The review-panel Archive button (ReviewStatusBar) dispatches this event for
  // the CURRENT workspace; the sidebar owns the archive flow (#9), so it listens
  // and archives that session through the same API path the "⋮ → Archive" uses.
  useEffect(() => {
    const onArchiveRequest = (e: Event) => {
      const detail = (e as CustomEvent<{ sessionId?: string }>).detail;
      if (detail?.sessionId) void archiveWorkspace(detail.sessionId);
    };
    window.addEventListener("terminalx:archive-request", onArchiveRequest);
    return () => window.removeEventListener("terminalx:archive-request", onArchiveRequest);
  }, [archiveWorkspace]);

  // The project pending an irreversible delete — set when the user picks
  // "Delete project" from the menu, cleared on Cancel/confirm. The actual
  // deleteProject call happens ONLY when the dialog's Delete is confirmed (#9).
  const [pendingDelete, setPendingDelete] = useState<ProjectView | null>(null);

  const openWorkspace = (sessionName: string) => {
    router.push(`/workspace/${encodeURIComponent(sessionName)}`);
  };

  // The "+" opens the existing new-session dialog pre-scoped to this repo so a
  // new workspace lands inside the project (#12).
  const addWorkspace = (repoRoot: string) => {
    router.push(`/dashboard?newWorkspace=${encodeURIComponent(repoRoot)}`);
  };

  const confirmDelete = () => {
    if (pendingDelete) void deleteProject(pendingDelete.id);
    setPendingDelete(null);
  };

  return (
    <div className="mt-1 space-y-1" data-testid="project-sidebar">
      {isLoading && projects.length === 0 ? (
        <div className="px-2 py-3 text-[11px] text-[#6b7569]">loading projects…</div>
      ) : projects.length === 0 ? (
        <div className="px-2 py-3 text-[11px] text-[#6b7569]" data-testid="project-empty">
          no projects yet
        </div>
      ) : (
        <>
          {projects.map((proj) => (
            <ProjectGroup
              key={proj.id}
              project={proj}
              activeSession={activeSession}
              onOpenWorkspace={openWorkspace}
              onAddWorkspace={addWorkspace}
              onRequestDelete={setPendingDelete}
              onCollapseWorkspace={(name, collapsed) => void setWorkspaceCollapsed(name, collapsed)}
              onArchiveWorkspace={(name) => void archiveWorkspace(name)}
            />
          ))}
          <ArchivedSection projects={projects} onRestore={(name) => void restoreWorkspace(name)} />
        </>
      )}

      <StandaloneSessionsSection
        sessions={sessions}
        isLoading={sessionsLoading}
        activeSession={activeSession}
        onOpen={openWorkspace}
      />

      {pendingDelete && (
        <ConfirmDeleteDialog
          project={pendingDelete}
          workspaceCount={pendingDelete.workspaces.length}
          onCancel={() => setPendingDelete(null)}
          onConfirm={confirmDelete}
        />
      )}
    </div>
  );
}
