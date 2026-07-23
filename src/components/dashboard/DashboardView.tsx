"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Bot,
  Boxes,
  ChevronUp,
  Code,
  Copy,
  Folder,
  FolderOpen,
  GitBranch,
  Plus,
  RefreshCw,
  Sparkles,
  Terminal,
  X,
} from "lucide-react";
import {
  useSessions,
  type SessionKind,
  type TelegramViewMode,
  type TmuxSession,
} from "@/hooks/useSessions";
// Issue #4: harness registry drives the new-session kind toggle + icons so
// adding cursor/opencode needs no dashboard edit.
import { listHarnesses, getHarness } from "@/lib/harnesses/registry";
// Workspace config (feature #5): default kind + setup summary in the dialog.
import { useWorkspaceConfig } from "@/hooks/useWorkspaceConfig";

function slugify(raw: string): string {
  // Preserve characters the session API already accepts (a-z 0-9 _ . -) so a
  // typed name like "e2e-symlink-123" round-trips to the same session name.
  return raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9 _.-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function KindIcon({ kind }: { kind?: SessionKind }) {
  // Issue #4: keep existing claude/codex mappings; add cursor/opencode.
  if (kind === "claude") return <Sparkles size={14} className="text-[#d58fff] shrink-0" />;
  if (kind === "codex") return <Bot size={14} className="text-[#5ccfe6] shrink-0" />;
  if (kind === "cursor") return <Code size={14} className="text-[#7dd3fc] shrink-0" />;
  if (kind === "opencode") return <Boxes size={14} className="text-[#ffa657] shrink-0" />;
  return <Terminal size={14} className="text-[#6b7569] shrink-0" />;
}

interface DirectoryEntry {
  name: string;
  path: string;
}

interface GitDirectoryInfo {
  isRepo: boolean;
  root?: string;
  branch?: string;
  repoName?: string;
}

function parentDirectory(path: string, root: string): string {
  if (!path || path === root) return root || ".";
  const trimmed = path.replace(/\/+$/, "");
  const idx = trimmed.lastIndexOf("/");
  if (idx <= 0) return root || ".";
  const parent = trimmed.slice(0, idx);
  if (root && parent !== root && !parent.startsWith(`${root}/`)) return root;
  return parent || root || ".";
}

function defaultBranchName(sessionName: string): string {
  return sessionName ? `feature/${sessionName}` : "feature/";
}

function branchLooksValid(branch: string): boolean {
  const trimmed = branch.trim();
  return Boolean(
    trimmed &&
    trimmed.length <= 200 &&
    /^[A-Za-z0-9._/-]+$/.test(trimmed) &&
    !trimmed.startsWith("-") &&
    !trimmed.includes("..") &&
    !trimmed.includes("//") &&
    !trimmed.endsWith("/")
  );
}

function SessionRow({
  s,
  onAttach,
  onKill,
  onTelegramMode,
}: {
  s: TmuxSession;
  onAttach: (s: TmuxSession) => void;
  onKill: (name: string) => void;
  onTelegramMode: (sessionName: string, mode: TelegramViewMode) => void;
}) {
  const canKill = s.managed !== false;

  return (
    <div
      onClick={() => {
        onAttach(s);
      }}
      className={`flex items-center gap-3 sm:gap-4 px-3 sm:px-4 py-3 bg-[#0f1117] border border-[#1a1d24]
        rounded transition-colors group cursor-pointer hover:border-[#363b47]`}
    >
      <span
        className="w-2 h-2 rounded-full bg-[#00ff88] shrink-0"
        style={{ boxShadow: s.attached ? "0 0 6px #00ff88" : "none" }}
      />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <KindIcon kind={s.kind} />
          <span className="flex-1 min-w-0 text-[13px] font-medium text-[#e6f0e4] truncate">
            {s.name}
          </span>
          {s.kind && s.kind !== "bash" && (
            <span
              className={`shrink-0 px-1 py-0.5 text-[9px] uppercase tracking-wider rounded leading-none hidden sm:inline ${
                s.kind === "claude"
                  ? "bg-[#d58fff]/20 text-[#d58fff]"
                  : "bg-[#5ccfe6]/20 text-[#5ccfe6]"
              }`}
            >
              {s.kind}
            </span>
          )}
          <select
            value={s.telegram?.viewMode ?? "off"}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => {
              e.stopPropagation();
              onTelegramMode(s.name, e.target.value as TelegramViewMode);
            }}
            className="hidden sm:block shrink-0 rounded border border-[#252933] bg-[#07080c] px-1 py-0.5 text-[9px] uppercase tracking-wider text-[#5ccfe6] outline-none"
            aria-label={`Telegram responses for ${s.name}`}
          >
            <option value="chat">tg chat</option>
            <option value="screen">tg screen</option>
            <option value="off">tg off</option>
          </select>
          {s.attached && (
            <span className="shrink-0 px-1 py-0.5 text-[9px] uppercase tracking-wider rounded bg-[#00ff88]/20 text-[#00ff88] leading-none hidden sm:inline">
              attached
            </span>
          )}
          {s.managed === false && (
            <span className="shrink-0 px-1 py-0.5 text-[9px] uppercase tracking-wider rounded bg-[#ffb454]/10 text-[#ffb454] leading-none hidden sm:inline">
              external
            </span>
          )}
        </div>
        <div className="text-[10px] text-[#6b7569] mt-1 truncate">
          {s.windows} window{s.windows !== 1 ? "s" : ""} · {s.attached ? "live" : "idle"}
          <span className="hidden sm:inline">
            {" "}
            · created {new Date(s.created).toLocaleString()}
          </span>
        </div>
      </div>
      <span className="hidden sm:inline text-[10px] text-[#6b7569] tabular-nums shrink-0">
        {s.attached ? "live" : "idle"}
      </span>
      <button
        onClick={(e) => {
          e.stopPropagation();
          if (!canKill) return;
          onKill(s.name);
        }}
        className={`hidden sm:block p-1.5 opacity-0 group-hover:opacity-100 transition-all shrink-0 ${
          canKill ? "text-[#6b7569] hover:text-[#ff5c5c]" : "text-[#3f4742] cursor-not-allowed"
        }`}
        title={canKill ? "kill session" : "unmanaged tmux session"}
        aria-label={`kill session ${s.name}`}
        disabled={!canKill}
      >
        <X size={14} />
      </button>
      <span className="shrink-0 px-2.5 py-1 text-[10px] rounded border border-[#00cc6e] text-[#00ff88] bg-transparent transition-colors group-hover:bg-[#00ff88]/10">
        attach →
      </span>
    </div>
  );
}

export function DashboardView() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const {
    sessions,
    isLoading,
    error: sessionError,
    createSession,
    killSession,
    setTelegramViewMode,
    refresh,
  } = useSessions();
  const [showDialog, setShowDialog] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<SessionKind>("bash");
  const [directoryPath, setDirectoryPath] = useState(".");
  const [directoryRoot, setDirectoryRoot] = useState("");
  const [directoryInput, setDirectoryInput] = useState(".");
  const [directoryEntries, setDirectoryEntries] = useState<DirectoryEntry[]>([]);
  const [directoryLoading, setDirectoryLoading] = useState(false);
  const [directoryError, setDirectoryError] = useState<string | null>(null);
  const [gitInfo, setGitInfo] = useState<GitDirectoryInfo>({ isRepo: false });
  const [createWorktree, setCreateWorktree] = useState(false);
  const [worktreeBranch, setWorktreeBranch] = useState("");
  const [symlinkShared, setSymlinkShared] = useState(false);
  const [symlinkPaths, setSymlinkPaths] = useState("node_modules");
  const [createError, setCreateError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  // Workspace config (feature #5): run-setup-on-create + kind-from-config.
  const [runSetupOnCreate, setRunSetupOnCreate] = useState(true);
  const [kindTouched, setKindTouched] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Resolve workspace config for the selected repo (when the dir is a git repo).
  const { config: workspaceConfig } = useWorkspaceConfig(
    showDialog && gitInfo.isRepo && gitInfo.root ? { repoRoot: gitInfo.root } : null
  );

  // Default the kind selector to config.defaultKind unless the user picked one.
  useEffect(() => {
    if (workspaceConfig && !kindTouched) {
      setKind(workspaceConfig.defaultKind);
    }
  }, [workspaceConfig, kindTouched]);

  // Models settings (feature #11, §5.1): seed the new-session kind from the
  // resolved Default model's harness when the dialog opens and neither the user
  // nor a workspace config has already chosen a kind. Per-session overrides do
  // NOT write back to settings. Best-effort; never blocks dialog use.
  useEffect(() => {
    if (!showDialog || kindTouched || workspaceConfig) return;
    let cancelled = false;
    fetch("/api/settings?scope=user")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        const modelId: string | undefined = d?.resolved?.defaultModel?.modelId;
        const harness = modelId?.includes(":") ? modelId.split(":")[0] : undefined;
        if (!cancelled && harness && getHarness(harness)) {
          setKind(harness as SessionKind);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [showDialog, kindTouched, workspaceConfig]);

  const live = sessions.filter((s) => s.attached).length;
  const idle = sessions.length - live;
  const preview = slugify(name);

  const loadDirectories = useCallback(async (path: string) => {
    try {
      setDirectoryLoading(true);
      setDirectoryError(null);
      const res = await fetch(`/api/directories?path=${encodeURIComponent(path || ".")}`);
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        throw new Error(data?.error ?? `Failed to list directories: ${res.status}`);
      }
      setDirectoryPath(data.path ?? ".");
      setDirectoryRoot(data.root ?? "");
      setDirectoryInput(data.path ?? ".");
      setDirectoryEntries((data.entries ?? []) as DirectoryEntry[]);
      const nextGitInfo = (data.git ?? { isRepo: false }) as GitDirectoryInfo;
      setGitInfo(nextGitInfo);
      if (!nextGitInfo.isRepo) {
        setCreateWorktree(false);
        setWorktreeBranch("");
        setSymlinkShared(false);
      }
    } catch (err) {
      setDirectoryError(err instanceof Error ? err.message : "Failed to list directories");
      setGitInfo({ isRepo: false });
      setCreateWorktree(false);
    } finally {
      setDirectoryLoading(false);
    }
  }, []);

  const openDialog = useCallback(
    // Multi-workspace (#12): the sidebar's workspace "+" opens this dialog
    // pre-scoped to a repo dir (and pre-enables worktree creation) so a new
    // worktree lands inside that workspace's project.
    (scopeDirectory?: string) => {
      const dir = scopeDirectory && scopeDirectory.trim() ? scopeDirectory.trim() : ".";
      setName("");
      setKind("bash");
      setDirectoryPath(dir);
      setDirectoryRoot("");
      setDirectoryInput(dir);
      setDirectoryEntries([]);
      setDirectoryError(null);
      setGitInfo({ isRepo: false });
      setCreateWorktree(Boolean(scopeDirectory));
      setWorktreeBranch("");
      setSymlinkShared(false);
      setSymlinkPaths("node_modules");
      setCreateError(null);
      setRunSetupOnCreate(true);
      setKindTouched(false);
      setShowDialog(true);
      void loadDirectories(dir);
      setTimeout(() => inputRef.current?.focus(), 50);
    },
    [loadDirectories]
  );

  // Multi-project (#12): the project-header "+" navigates here with
  // ?newWorkspace=<repoRoot>; open the new-workspace dialog scoped to that repo
  // once, then strip the param so a refresh doesn't re-open it.
  const newWorkspaceParam = searchParams?.get("newWorkspace");
  useEffect(() => {
    if (!newWorkspaceParam) return;
    openDialog(newWorkspaceParam);
    router.replace("/dashboard");
    // openDialog is stable (memoized on loadDirectories); intentionally run on
    // param change only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [newWorkspaceParam]);

  useEffect(() => {
    if (showDialog && directoryPath === "." && directoryEntries.length === 0 && !directoryLoading) {
      void loadDirectories(".");
    }
  }, [directoryEntries.length, directoryLoading, directoryPath, loadDirectories, showDialog]);

  const attach = useCallback(
    (s: TmuxSession) => {
      router.push(`/workspace/${encodeURIComponent(s.name)}`);
    },
    [router]
  );

  const handleCreate = useCallback(async () => {
    const n = preview;
    if (!n) return setCreateError("name required");
    if (!/^[a-zA-Z0-9_.\-]+$/.test(n)) return setCreateError("only letters, numbers, _ - .");
    if (sessions.some((s) => s.name === n)) return setCreateError("name already exists");
    if (!directoryPath || directoryError) return setCreateError("select a valid directory");
    const branch = worktreeBranch.trim();
    if (createWorktree && !branchLooksValid(branch)) {
      return setCreateError("enter a valid branch name");
    }
    setCreateError(null);
    const sharedPaths =
      createWorktree && symlinkShared
        ? symlinkPaths
            .split(/[,\n]/)
            .map((p) => p.trim())
            .filter(Boolean)
        : [];
    const session = await createSession(n, kind, {
      cwd: directoryPath,
      worktree: createWorktree
        ? { create: true, branch, symlinkPaths: symlinkShared ? sharedPaths : undefined }
        : undefined,
      // Only meaningful when a worktree + setup script exist; server enforces.
      skipSetup: !runSetupOnCreate,
    });
    if (session) {
      setShowDialog(false);
      router.push(`/workspace/${encodeURIComponent(session.name)}`);
    }
  }, [
    preview,
    kind,
    directoryPath,
    directoryError,
    createWorktree,
    worktreeBranch,
    symlinkShared,
    symlinkPaths,
    sessions,
    createSession,
    router,
    runSetupOnCreate,
  ]);

  const copyAttachUrl = useCallback(() => {
    const url = `${window.location.host} · /workspace/<session>`;
    void navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, []);

  return (
    <div className="h-full overflow-y-auto contain-scroll">
      <div className="max-w-[960px] mx-auto px-4 sm:px-6 py-6 sm:py-8">
        <div className="flex items-baseline gap-4 mb-1">
          <h1 className="text-[26px] font-bold tracking-tight text-[#e6f0e4]">sessions</h1>
          <span className="text-[11px] text-[#6b7569]">
            {sessions.length} total · <span className="text-[#00ff88]">{live} live</span> · {idle}{" "}
            idle
          </span>
        </div>

        <div className="flex items-center gap-2 mt-5 mb-4">
          <button
            onClick={() => openDialog()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#002a17]
              border border-[#00cc6e] text-[#00ff88] text-[11px] hover:bg-[#00ff88]/10 transition-colors"
            style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
          >
            <Plus size={12} /> new session
          </button>
          <button
            onClick={() => refresh()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#14161e]
              border border-[#252933] text-[#e6f0e4] text-[11px] hover:border-[#363b47] transition-colors"
            title="refresh"
          >
            <RefreshCw size={12} /> refresh
          </button>
          <div className="flex-1" />
          <div className="flex items-center gap-1.5 text-[10px] text-[#6b7569]">
            <kbd className="px-1 py-0.5 bg-[#0a0b10] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
              ⌘
            </kbd>
            <kbd className="px-1 py-0.5 bg-[#0a0b10] border border-[#252933] border-b-2 rounded-[2px] text-[10px] text-[#e6f0e4]">
              K
            </kbd>
            <span className="ml-1">commands</span>
          </div>
        </div>

        {isLoading && sessions.length === 0 ? (
          <div className="mt-10 p-10 text-center text-[11px] text-[#6b7569] border border-dashed border-[#252933] rounded">
            resurrecting tmux…
          </div>
        ) : sessions.length === 0 ? (
          <div className="mt-10 p-10 text-center border border-dashed border-[#252933] rounded">
            <div className="text-[13px] text-[#a8b3a6]">no sessions. the box is lonely.</div>
            <button
              onClick={() => openDialog()}
              className="mt-3 px-4 py-1.5 rounded bg-[#002a17] border border-[#00cc6e]
                text-[#00ff88] text-[11px] hover:bg-[#00ff88]/10 transition-colors"
              style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
            >
              spawn one →
            </button>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {sessions.map((s) => (
              <SessionRow
                key={s.name}
                s={s}
                onAttach={attach}
                onKill={killSession}
                onTelegramMode={setTelegramViewMode}
              />
            ))}
          </div>
        )}

        <div className="mt-10">
          <span className="text-[9px] uppercase tracking-wider text-[#6b7569] font-medium">
            attach from cli
          </span>
          <div className="mt-2 flex items-center gap-3 px-3 py-2.5 rounded bg-[#07080c] border border-[#1a1d24] text-[10px]">
            <span className="text-[#6b7569]">$</span>
            <code className="flex-1 bg-transparent border-0 px-0 text-[#00cc6e]">
              ssh {typeof window !== "undefined" ? window.location.hostname : "<host>"} -t tmux
              attach -t &lt;session&gt;
            </code>
            <button
              onClick={copyAttachUrl}
              className="text-[10px] text-[#6b7569] hover:text-[#00ff88] flex items-center gap-1 transition-colors"
            >
              <Copy size={10} /> {copied ? "copied" : "copy"}
            </button>
          </div>
        </div>
      </div>

      {showDialog && (
        <div
          onClick={() => setShowDialog(false)}
          className="fixed inset-0 z-[200] flex items-start justify-center pt-[14vh]"
          style={{ background: "rgba(5, 6, 10, 0.7)", backdropFilter: "blur(6px)" }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-[560px] max-w-[92vw] max-h-[80vh] overflow-y-auto rounded bg-[#14161e] border border-[#363b47] p-4"
            style={{ boxShadow: "0 8px 24px rgba(0, 0, 0, 0.6)" }}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] uppercase tracking-wider font-medium text-[#6b7569]">
                new session
              </span>
              <button
                onClick={() => setShowDialog(false)}
                className="p-0.5 text-[#6b7569] hover:text-[#e6f0e4] transition-colors"
              >
                <X size={12} />
              </button>
            </div>

            <input
              ref={inputRef}
              value={name}
              onChange={(e) => {
                // Allow the same characters the session API accepts (letters,
                // numbers, space, and _ . -) so hyphenated names survive.
                const nextName = e.target.value.replace(/[^A-Za-z0-9 _.-]/g, "");
                setName(nextName);
                if (createWorktree && (!worktreeBranch.trim() || worktreeBranch === "feature/")) {
                  setWorktreeBranch(defaultBranchName(slugify(nextName)));
                }
                setCreateError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleCreate();
                if (e.key === "Escape") setShowDialog(false);
              }}
              placeholder="my-project"
              className="w-full px-2 py-1.5 rounded bg-[#07080c] border border-[#252933]
                text-[#e6f0e4] text-[13px] placeholder:text-[#6b7569]/50
                focus:outline-none focus:border-[#00ff88] transition-colors"
              style={{ boxShadow: "none" }}
            />
            {name.trim() && (
              <p className="text-[10px] text-[#6b7569] mt-1">
                →{" "}
                <code className="text-[#00cc6e] bg-transparent border-0 px-0">
                  {preview || "—"}
                </code>
              </p>
            )}

            <div className="mt-3">
              <span className="block text-[10px] uppercase tracking-wider text-[#6b7569] mb-1.5">
                session kind
              </span>
              {/* Issue #4: registry-driven harness toggle (bash/claude/codex/cursor/opencode). */}
              <div
                data-testid="session-harness-toggle"
                className="flex flex-wrap rounded bg-[#07080c] border border-[#1a1d24] p-0.5"
              >
                {listHarnesses().map((h) => (
                  <button
                    key={h.id}
                    data-testid={`session-harness-${h.id}`}
                    onClick={() => {
                      // Issue #4: registry id is the session kind.
                      setKind(h.id);
                      // Feature #5: a manual pick wins over the repo default-kind.
                      setKindTouched(true);
                    }}
                    className={`flex-1 inline-flex items-center justify-center gap-1 px-2 py-1 rounded text-[11px] transition-colors ${
                      kind === h.id
                        ? "text-[#05060a] font-medium"
                        : "text-[#6b7569] hover:text-[#e6f0e4]"
                    }`}
                    style={{ background: kind === h.id ? h.color : "transparent" }}
                  >
                    {h.label}
                    {h.badge === "NEW" && (
                      <span
                        className={`px-1 text-[8px] uppercase tracking-wider rounded leading-none ${
                          kind === h.id
                            ? "bg-[#05060a]/20 text-[#05060a]"
                            : "bg-[#ffa657]/20 text-[#ffa657]"
                        }`}
                      >
                        NEW
                      </span>
                    )}
                  </button>
                ))}
              </div>
              {workspaceConfig?.hasRepoConfig &&
                workspaceConfig.provenance.defaultKind === "repo" && (
                  <span className="mt-1 block text-[9px] text-[#6b7569]">
                    default kind from repo settings.toml
                  </span>
                )}
            </div>

            {/* Workspace config summary (feature #5) — only when a repo is selected. */}
            {workspaceConfig && gitInfo.isRepo && (
              <div
                data-testid="workspace-config-summary"
                className="mt-3 rounded border border-[#1a1d24] bg-[#07080c] px-2.5 py-2 text-[10px] text-[#a8b3a6] space-y-1.5"
              >
                <div className="flex items-center gap-1.5 text-[#6b7569]">
                  <span className="uppercase tracking-wider">workspace</span>
                  {workspaceConfig.hasRepoConfig ? (
                    <span className="text-[#00ff88]">.terminalx/settings.toml</span>
                  ) : (
                    <span>defaults (no committed config)</span>
                  )}
                </div>
                <div className="font-mono text-[#a8b3a6]">
                  will copy: {workspaceConfig.copyFiles.join(" · ") || "—"} • inject TERMINALX_PORT
                </div>
                {workspaceConfig.setup && createWorktree && (
                  <label className="flex items-center gap-2 text-[10px] text-[#a8b3a6]">
                    <input
                      type="checkbox"
                      data-testid="new-session-run-setup"
                      checked={runSetupOnCreate}
                      onChange={(e) => setRunSetupOnCreate(e.target.checked)}
                      className="accent-[#00ff88]"
                    />
                    run setup on create:{" "}
                    <span className="font-mono text-[#e6f0e4] truncate">
                      {workspaceConfig.setup.command}
                    </span>
                  </label>
                )}
                {workspaceConfig.scripts.length > 0 && (
                  <div className="text-[#6b7569]" data-testid="workspace-summary-scripts">
                    run scripts: {workspaceConfig.scripts.map((s) => s.name).join(" · ")}
                  </div>
                )}
              </div>
            )}

            <div className="mt-3">
              <div className="flex items-center justify-between mb-1.5">
                <span className="block text-[10px] uppercase tracking-wider text-[#6b7569]">
                  start directory
                </span>
                <button
                  type="button"
                  onClick={() => loadDirectories(".")}
                  className="text-[10px] text-[#6b7569] hover:text-[#00ff88] transition-colors"
                >
                  root
                </button>
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => loadDirectories(parentDirectory(directoryPath, directoryRoot))}
                  disabled={
                    directoryLoading || Boolean(directoryRoot && directoryPath === directoryRoot)
                  }
                  className="shrink-0 h-[30px] w-[30px] grid place-items-center rounded bg-[#07080c] border border-[#252933]
                    text-[#6b7569] hover:text-[#00ff88] hover:border-[#00cc6e] disabled:opacity-40 disabled:hover:text-[#6b7569]
                    disabled:hover:border-[#252933] transition-colors"
                  title="parent directory"
                  aria-label="parent directory"
                >
                  <ChevronUp size={14} />
                </button>
                <input
                  value={directoryInput}
                  onChange={(e) => setDirectoryInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void loadDirectories(directoryInput);
                    if (e.key === "Escape") setShowDialog(false);
                  }}
                  className="flex-1 min-w-0 px-2 py-1.5 rounded bg-[#07080c] border border-[#252933]
                    text-[#e6f0e4] text-[12px] placeholder:text-[#6b7569]/50 font-mono
                    focus:outline-none focus:border-[#00ff88] transition-colors"
                  placeholder="select a directory"
                />
                <button
                  type="button"
                  onClick={() => loadDirectories(directoryInput)}
                  disabled={directoryLoading}
                  className="shrink-0 px-2.5 py-1.5 rounded bg-[#14161e] border border-[#252933]
                    text-[#e6f0e4] text-[11px] hover:border-[#363b47] disabled:opacity-50 transition-colors"
                >
                  open
                </button>
              </div>
              <div className="mt-2 max-h-[150px] overflow-y-auto rounded border border-[#1a1d24] bg-[#07080c]">
                {directoryLoading ? (
                  <div className="px-2 py-3 text-[11px] text-[#6b7569]">loading directories…</div>
                ) : directoryError ? (
                  <div className="px-2 py-3 text-[11px] text-[#ff5c5c]">{directoryError}</div>
                ) : directoryEntries.length === 0 ? (
                  <div className="px-2 py-3 text-[11px] text-[#6b7569]">no child directories</div>
                ) : (
                  directoryEntries.map((entry) => (
                    <button
                      key={entry.path}
                      type="button"
                      onClick={() => loadDirectories(entry.path)}
                      className="w-full flex items-center gap-2 px-2 py-1.5 text-left text-[12px] text-[#a8b3a6]
                        hover:bg-[#10131a] hover:text-[#e6f0e4] transition-colors"
                    >
                      <Folder size={13} className="shrink-0 text-[#00cc6e]" />
                      <span className="min-w-0 truncate">{entry.name}</span>
                    </button>
                  ))
                )}
              </div>
              <div className="mt-1 flex items-center gap-1.5 text-[10px] text-[#6b7569] min-w-0">
                <FolderOpen size={11} className="shrink-0 text-[#00cc6e]" />
                <code className="min-w-0 truncate bg-transparent border-0 px-0 text-[#00cc6e]">
                  {directoryPath}
                </code>
              </div>
            </div>

            {gitInfo.isRepo && (
              <div className="mt-3 rounded border border-[#1a1d24] bg-[#07080c] p-2">
                <div className="flex items-center gap-2 min-w-0">
                  <GitBranch size={13} className="shrink-0 text-[#00cc6e]" />
                  <span className="min-w-0 flex-1 truncate text-[11px] text-[#a8b3a6]">
                    {gitInfo.repoName ?? "git repository"}
                    {gitInfo.branch ? ` · ${gitInfo.branch}` : ""}
                  </span>
                </div>
                <label className="mt-2 flex items-center gap-2 text-[11px] text-[#e6f0e4] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={createWorktree}
                    onChange={(e) => {
                      const checked = e.target.checked;
                      setCreateWorktree(checked);
                      if (checked && !worktreeBranch.trim()) {
                        setWorktreeBranch(defaultBranchName(preview));
                      }
                      setCreateError(null);
                    }}
                    className="accent-[#00cc6e] cursor-pointer"
                  />
                  create Git worktree for this session
                </label>
                {createWorktree && (
                  <div className="mt-2">
                    <input
                      value={worktreeBranch}
                      onChange={(e) => {
                        setWorktreeBranch(e.target.value);
                        setCreateError(null);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleCreate();
                        if (e.key === "Escape") setShowDialog(false);
                      }}
                      placeholder={defaultBranchName(preview)}
                      className="w-full px-2 py-1.5 rounded bg-[#0f1117] border border-[#252933]
                        text-[#e6f0e4] text-[12px] placeholder:text-[#6b7569]/50 font-mono
                        focus:outline-none focus:border-[#00ff88] transition-colors"
                    />
                    <p className="mt-1 text-[10px] text-[#6b7569] leading-tight">
                      starts from the selected repo HEAD and opens the new session in that worktree.
                    </p>

                    <label className="mt-3 flex items-center gap-2 text-[11px] text-[#e6f0e4] cursor-pointer">
                      <input
                        type="checkbox"
                        data-testid="worktree-symlink-toggle"
                        checked={symlinkShared}
                        onChange={(e) => {
                          setSymlinkShared(e.target.checked);
                          setCreateError(null);
                        }}
                        className="accent-[#00cc6e] cursor-pointer"
                      />
                      symlink shared paths into the worktree
                    </label>
                    {symlinkShared && (
                      <div className="mt-2">
                        <label
                          htmlFor="worktree-symlink-paths"
                          className="block text-[10px] uppercase tracking-wider text-[#6b7569] mb-1.5"
                        >
                          shared paths
                        </label>
                        <input
                          id="worktree-symlink-paths"
                          data-testid="worktree-symlink-paths"
                          value={symlinkPaths}
                          onChange={(e) => {
                            setSymlinkPaths(e.target.value);
                            setCreateError(null);
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") handleCreate();
                            if (e.key === "Escape") setShowDialog(false);
                          }}
                          placeholder="node_modules, .next/cache"
                          spellCheck={false}
                          autoComplete="off"
                          autoCorrect="off"
                          autoCapitalize="off"
                          className="w-full px-2 py-1.5 rounded bg-[#0f1117] border border-[#252933]
                            text-[#e6f0e4] text-[12px] placeholder:text-[#6b7569]/50 font-mono
                            focus:outline-none focus:border-[#00ff88] transition-colors"
                        />
                        <p className="mt-1 text-[10px] text-[#6b7569] leading-tight">
                          comma-separated, repo-relative. heavy dirs like{" "}
                          <code className="text-[#e6f0e4] bg-transparent border-0 px-0">
                            node_modules
                          </code>{" "}
                          are linked to the shared copy instead of re-installed (copied if symlinks
                          aren&apos;t supported).
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {(createError || sessionError) && (
              <p
                className="text-[11px] text-[#ff5c5c] mt-2"
                role="alert"
                data-testid="session-create-error"
              >
                {createError || sessionError}
              </p>
            )}

            <button
              onClick={handleCreate}
              disabled={directoryLoading || Boolean(directoryError)}
              className="w-full mt-3 px-3 py-1.5 rounded bg-[#002a17] border border-[#00cc6e]
                text-[#00ff88] text-[13px] font-medium hover:bg-[#00ff88]/10 disabled:opacity-50
                disabled:hover:bg-[#002a17] transition-colors"
              style={{ boxShadow: "0 0 6px rgba(0, 255, 136, 0.35)" }}
            >
              create →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
