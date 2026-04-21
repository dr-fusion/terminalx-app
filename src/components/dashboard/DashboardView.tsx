"use client";

import { useCallback, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, Bot, Copy, Plus, RefreshCw, Sparkles, Terminal, X } from "lucide-react";
import { useSessions, type SessionKind, type TmuxSession } from "@/hooks/useSessions";

function slugify(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function KindIcon({ kind }: { kind?: SessionKind }) {
  if (kind === "claude") return <Sparkles size={14} className="text-[#d58fff]" />;
  if (kind === "codex") return <Bot size={14} className="text-[#5ccfe6]" />;
  return <Terminal size={14} className="text-[#6b7569]" />;
}

function SessionRow({
  s,
  onAttach,
  onKill,
}: {
  s: TmuxSession;
  onAttach: (s: TmuxSession) => void;
  onKill: (name: string) => void;
}) {
  return (
    <div
      onClick={() => onAttach(s)}
      className="grid items-center gap-4 px-4 py-3 bg-[#0f1117] border border-[#1a1d24]
        rounded cursor-pointer hover:border-[#363b47] transition-colors group"
      style={{ gridTemplateColumns: "auto 1fr auto auto auto" }}
    >
      <span
        className="w-2 h-2 rounded-full bg-[#00ff88] shrink-0"
        style={{ boxShadow: s.attached ? "0 0 6px #00ff88" : "none" }}
      />
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <KindIcon kind={s.kind} />
          <span className="text-[13px] font-medium text-[#e6f0e4] truncate">{s.name}</span>
          {s.kind && s.kind !== "bash" && (
            <span
              className={`px-1 py-0.5 text-[9px] uppercase tracking-wider rounded leading-none ${
                s.kind === "claude"
                  ? "bg-[#d58fff]/20 text-[#d58fff]"
                  : "bg-[#5ccfe6]/20 text-[#5ccfe6]"
              }`}
            >
              {s.kind}
            </span>
          )}
          {s.attached && (
            <span className="px-1 py-0.5 text-[9px] uppercase tracking-wider rounded bg-[#00ff88]/20 text-[#00ff88] leading-none">
              attached
            </span>
          )}
        </div>
        <div className="text-[10px] text-[#6b7569] mt-1">
          {s.windows} window{s.windows !== 1 ? "s" : ""} · created{" "}
          {new Date(s.created).toLocaleString()}
        </div>
      </div>
      <span className="text-[10px] text-[#6b7569] tabular-nums">
        {s.attached ? "live" : "idle"}
      </span>
      <button
        onClick={(e) => {
          e.stopPropagation();
          onKill(s.name);
        }}
        className="p-1.5 text-[#6b7569] opacity-0 group-hover:opacity-100 hover:text-[#ff5c5c] transition-all"
        title="kill session"
        aria-label={`kill session ${s.name}`}
      >
        <X size={14} />
      </button>
      <span
        className="px-2.5 py-1 text-[10px] rounded border border-[#00cc6e] text-[#00ff88]
          bg-transparent group-hover:bg-[#00ff88]/10 transition-colors"
      >
        attach →
      </span>
    </div>
  );
}

export function DashboardView() {
  const router = useRouter();
  const { sessions, isLoading, createSession, killSession, refresh } = useSessions();
  const [showDialog, setShowDialog] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<SessionKind>("bash");
  const [skipPermissions, setSkipPermissions] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const live = sessions.filter((s) => s.attached).length;
  const idle = sessions.length - live;
  const preview = slugify(name);

  const openDialog = useCallback(() => {
    setName("");
    setKind("bash");
    setSkipPermissions(false);
    setCreateError(null);
    setShowDialog(true);
    setTimeout(() => inputRef.current?.focus(), 50);
  }, []);

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
    setCreateError(null);
    const session = await createSession(n, kind, {
      dangerouslySkipPermissions: kind === "claude" ? skipPermissions : undefined,
    });
    if (session) {
      setShowDialog(false);
      router.push(`/workspace/${encodeURIComponent(session.name)}`);
    }
  }, [preview, kind, skipPermissions, sessions, createSession, router]);

  const copyAttachUrl = useCallback(() => {
    const url = `${window.location.host} · /workspace/<session>`;
    void navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, []);

  return (
    <div className="h-full overflow-y-auto">
      <div className="max-w-[960px] mx-auto px-6 py-8">
        <div className="flex items-baseline gap-4 mb-1">
          <h1 className="text-[26px] font-bold tracking-tight text-[#e6f0e4]">sessions</h1>
          <span className="text-[11px] text-[#6b7569]">
            {sessions.length} total · <span className="text-[#00ff88]">{live} live</span> · {idle}{" "}
            idle
          </span>
        </div>

        <div className="flex items-center gap-2 mt-5 mb-4">
          <button
            onClick={openDialog}
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
              onClick={openDialog}
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
              <SessionRow key={s.name} s={s} onAttach={attach} onKill={killSession} />
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
            className="w-[440px] max-w-[90vw] rounded bg-[#14161e] border border-[#363b47] p-4"
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
                setName(e.target.value.replace(/[^A-Za-z0-9 ]/g, ""));
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
              <div className="flex rounded bg-[#07080c] border border-[#1a1d24] p-0.5">
                {(
                  [
                    { value: "bash", label: "bash", color: "#00cc6e" },
                    { value: "claude", label: "claude", color: "#d58fff" },
                    { value: "codex", label: "codex", color: "#5ccfe6" },
                  ] as const
                ).map((k) => (
                  <button
                    key={k.value}
                    onClick={() => setKind(k.value)}
                    className={`flex-1 px-2 py-1 rounded text-[11px] transition-colors ${
                      kind === k.value
                        ? "text-[#05060a] font-medium"
                        : "text-[#6b7569] hover:text-[#e6f0e4]"
                    }`}
                    style={{ background: kind === k.value ? k.color : "transparent" }}
                  >
                    {k.label}
                  </button>
                ))}
              </div>
            </div>

            {kind === "claude" && (
              <label
                className={`mt-3 flex items-start gap-2 px-2 py-1.5 rounded border cursor-pointer transition-colors ${
                  skipPermissions
                    ? "bg-[#ff5c5c]/10 border-[#ff5c5c]/50"
                    : "bg-[#07080c] border-[#1a1d24] hover:border-[#ff5c5c]/40"
                }`}
              >
                <input
                  type="checkbox"
                  checked={skipPermissions}
                  onChange={(e) => setSkipPermissions(e.target.checked)}
                  className="mt-0.5 accent-[#ff5c5c] cursor-pointer"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1 text-[11px] font-medium text-[#ff5c5c]">
                    <AlertTriangle size={11} /> dangerously skip permissions
                  </div>
                  <p className="text-[10px] text-[#6b7569] mt-0.5 leading-tight">
                    passes{" "}
                    <code className="text-[#e6f0e4] bg-transparent border-0 px-0">
                      --dangerously-skip-permissions
                    </code>
                    . sandbox only.
                  </p>
                </div>
              </label>
            )}

            {createError && <p className="text-[11px] text-[#ff5c5c] mt-2">{createError}</p>}

            <button
              onClick={handleCreate}
              className="w-full mt-3 px-3 py-1.5 rounded bg-[#002a17] border border-[#00cc6e]
                text-[#00ff88] text-[13px] font-medium hover:bg-[#00ff88]/10 transition-colors"
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
