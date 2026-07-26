"use client";

import { useCallback, useState } from "react";
import { FileCode, Save } from "lucide-react";
import { useSessions } from "@/hooks/useSessions";
import { useWorkspaceConfig, type ConfigScope } from "@/hooks/useWorkspaceConfig";

type Scope = "repo" | "user";

function ProvenanceBadge({ scope }: { scope: ConfigScope }) {
  const label =
    scope === "repo" ? "from repo" : scope === "user" ? "from your defaults" : "default";
  const cls =
    scope === "repo"
      ? "bg-[#00ff88]/20 text-[#00ff88]"
      : scope === "user"
        ? "bg-[#5ccfe6]/20 text-[#5ccfe6]"
        : "bg-[#899384]/20 text-[#899384]";
  return (
    <span
      data-testid="workspace-provenance-badge"
      className={`px-1.5 py-0.5 text-[9px] rounded uppercase tracking-wider font-medium ${cls}`}
    >
      {label}
    </span>
  );
}

/**
 * Settings → Workspace section. User/Repo scope tabs (Conductor parity), a
 * read-only render of the resolved repo config with provenance badges, and an
 * "Edit settings.toml" / "Create settings.toml" affordance backed by the raw
 * editor route.
 */
export function WorkspaceSettings() {
  const { sessions } = useSessions();
  // Pick the first managed session that has a repo root so we have something to
  // resolve against. The Repo tab is keyed to that session's repo.
  const repoSession = sessions.find((s) => s.worktree?.repoRoot || s.cwd)?.name ?? null;

  const [scope, setScope] = useState<Scope>("repo");
  const { config, refresh } = useWorkspaceConfig(repoSession);

  const [editorOpen, setEditorOpen] = useState(false);
  const [rawContent, setRawContent] = useState("");
  const [rawExists, setRawExists] = useState(false);
  const [rawPath, setRawPath] = useState("");
  const [saveStatus, setSaveStatus] = useState<string | null>(null);

  const openEditor = useCallback(async () => {
    if (!repoSession) return;
    const res = await fetch(`/api/workspace/config/raw?session=${encodeURIComponent(repoSession)}`);
    if (!res.ok) {
      setSaveStatus("could not open settings.toml");
      return;
    }
    const data = (await res.json()) as { path: string; content: string; exists: boolean };
    setRawContent(data.content);
    setRawExists(data.exists);
    setRawPath(data.path);
    setEditorOpen(true);
  }, [repoSession]);

  const saveEditor = useCallback(async () => {
    if (!repoSession) return;
    setSaveStatus("saving…");
    const res = await fetch(`/api/workspace/config/raw`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session: repoSession, content: rawContent }),
    });
    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { error?: string } | null;
      setSaveStatus(body?.error ?? "save failed");
      return;
    }
    setSaveStatus("saved");
    setEditorOpen(false);
    await refresh();
    setTimeout(() => setSaveStatus(null), 2000);
  }, [repoSession, rawContent, refresh]);

  const selectScope = useCallback((s: Scope) => {
    setScope(s);
    setSaveStatus(null);
  }, []);

  const editLabel = config?.hasRepoConfig ? "Edit settings.toml" : "Create settings.toml";

  return (
    <div
      data-testid="workspace-settings-section"
      className="bg-[#0f1117] border border-[#1a1d24] rounded p-4 mb-3"
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-baseline gap-3">
          <h2 className="text-[13px] font-medium text-[#e6f0e4]">project</h2>
          <span className="text-[10px] text-[#899384]">setup · run scripts · injected port</span>
        </div>
        {scope === "repo" && repoSession && (
          <button
            data-testid="workspace-edit-toml-button"
            onClick={openEditor}
            className="inline-flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-2.5 py-1 text-[10px] text-[#00ff88] hover:bg-[#00ff88]/10"
          >
            <FileCode size={11} /> {editLabel}
          </button>
        )}
      </div>

      {/* User / Repo scope tabs (Conductor parity) */}
      <div className="flex gap-1 mb-3" role="tablist">
        {(["user", "repo"] as Scope[]).map((s) => (
          <button
            key={s}
            role="tab"
            data-testid={`workspace-scope-tab-${s}`}
            aria-selected={scope === s}
            onClick={() => selectScope(s)}
            className={`px-3 py-1 text-[10px] uppercase tracking-wider rounded ${
              scope === s
                ? "bg-[#002a17] text-[#00ff88] border border-[#00cc6e]"
                : "text-[#899384] border border-[#1a1d24] hover:text-[#a8b3a6]"
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {!repoSession && (
        <p className="text-[11px] text-[#899384]">
          open a worktree-backed session to resolve its repo config.
        </p>
      )}

      {scope === "repo" && repoSession && config && (
        <div data-testid="workspace-repo-config" className="space-y-2">
          {config.warnings.length > 0 && (
            <div
              data-testid="workspace-config-warnings"
              className="rounded border border-[#c08a00] bg-[#2a1f00] px-2 py-1.5 text-[10px] text-[#ffcc66]"
            >
              {config.warnings.map((w, i) => (
                <div key={i}>{w}</div>
              ))}
            </div>
          )}

          <div className="flex items-center gap-3 py-1 text-[11px]">
            <span className="text-[#899384] w-28 shrink-0 uppercase tracking-wider text-[10px]">
              default kind
            </span>
            <span className="text-[#e6f0e4] font-mono" data-testid="workspace-default-kind">
              {config.defaultKind}
            </span>
            <ProvenanceBadge scope={config.provenance.defaultKind} />
          </div>

          <div className="flex items-center gap-3 py-1 text-[11px]">
            <span className="text-[#899384] w-28 shrink-0 uppercase tracking-wider text-[10px]">
              copy files
            </span>
            <span className="text-[#e6f0e4] font-mono truncate">
              {config.copyFiles.join(" · ") || "—"}
            </span>
            <ProvenanceBadge scope={config.provenance.copyFiles} />
          </div>

          <div className="flex items-center gap-3 py-1 text-[11px]">
            <span className="text-[#899384] w-28 shrink-0 uppercase tracking-wider text-[10px]">
              env keys
            </span>
            <span className="text-[#e6f0e4] font-mono truncate">
              {Object.keys(config.env).join(" · ") || "—"}
            </span>
            <ProvenanceBadge scope={config.provenance.env} />
          </div>

          <div className="flex items-center gap-3 py-1 text-[11px]">
            <span className="text-[#899384] w-28 shrink-0 uppercase tracking-wider text-[10px]">
              setup
            </span>
            <span
              className="text-[#e6f0e4] font-mono truncate"
              data-testid="workspace-setup-command"
            >
              {config.setup?.command ?? "—"}
            </span>
            <ProvenanceBadge scope={config.provenance.setup} />
          </div>

          <div className="pt-1">
            <div className="flex items-center gap-3 py-1 text-[11px]">
              <span className="text-[#899384] w-28 shrink-0 uppercase tracking-wider text-[10px]">
                run scripts
              </span>
              <ProvenanceBadge scope={config.provenance.scripts} />
            </div>
            <div className="mt-1 space-y-1" data-testid="workspace-run-scripts">
              {config.scripts.length === 0 && (
                <div className="text-[11px] text-[#899384]">no run scripts configured.</div>
              )}
              {config.scripts.map((s) => (
                <div
                  key={s.name}
                  data-testid={`workspace-run-script-${s.name}`}
                  className="flex items-center gap-2 rounded border border-[#1a1d24] bg-[#07080c] px-2 py-1.5 text-[11px]"
                >
                  <span className="text-[#00ff88] font-mono">run · {s.name}</span>
                  <span className="text-[#899384] truncate">{s.description ?? s.command}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {scope === "user" && (
        <div data-testid="workspace-user-config" className="space-y-2">
          <p className="text-[11px] text-[#a8b3a6] leading-relaxed">
            user-scope defaults apply to repos lacking a committed{" "}
            <code className="text-[#00cc6e] bg-transparent border-0 px-0">
              .terminalx/settings.toml
            </code>
            . the committed repo config always wins where present.
          </p>
          <p className="text-[11px] text-[#899384]">
            stored at <span className="font-mono">data/workspace-config.json</span>.
          </p>
        </div>
      )}

      {saveStatus && <span className="mt-2 block text-[11px] text-[#899384]">{saveStatus}</span>}

      {/* Raw settings.toml editor (Edit / Create affordance) */}
      {editorOpen && (
        <div
          onClick={() => setEditorOpen(false)}
          className="fixed inset-0 z-[200] flex items-start justify-center pt-[10vh]"
          style={{ background: "rgba(5, 6, 10, 0.7)", backdropFilter: "blur(6px)" }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            data-testid="workspace-toml-editor"
            className="w-[640px] max-w-[92vw] rounded bg-[#14161e] border border-[#363b47] overflow-hidden"
            style={{ boxShadow: "0 8px 24px rgba(0, 0, 0, 0.6)" }}
          >
            <div className="flex items-center justify-between px-3 py-2 border-b border-[#1a1d24]">
              <span className="text-[11px] text-[#e6f0e4] font-mono truncate">{rawPath}</span>
              <span className="text-[9px] uppercase tracking-wider text-[#899384]">
                {rawExists ? "edit" : "create"}
              </span>
            </div>
            <textarea
              data-testid="workspace-toml-textarea"
              value={rawContent}
              onChange={(e) => setRawContent(e.target.value)}
              spellCheck={false}
              className="w-full h-[360px] bg-[#07080c] px-3 py-2 text-[11px] font-mono text-[#e6f0e4] outline-none resize-none"
            />
            <div className="flex items-center gap-2 px-3 py-2 border-t border-[#1a1d24]">
              <button
                data-testid="workspace-toml-save"
                onClick={saveEditor}
                className="inline-flex items-center gap-1.5 rounded border border-[#00cc6e] bg-[#002a17] px-3 py-1.5 text-[11px] text-[#00ff88] hover:bg-[#00ff88]/10"
              >
                <Save size={12} /> save
              </button>
              <button
                onClick={() => setEditorOpen(false)}
                className="rounded border border-[#252933] px-3 py-1.5 text-[11px] text-[#a8b3a6] hover:text-[#e6f0e4]"
              >
                cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
