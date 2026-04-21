"use client";

import { useCallback, useEffect, useState } from "react";
import { Plus, Play, FileText, Trash2, X } from "lucide-react";
import { emitToActiveTerminal } from "@/lib/terminal-bus";
import type { Snippet } from "@/lib/snippets";

export function SnippetsPanel() {
  const [snippets, setSnippets] = useState<Snippet[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showDialog, setShowDialog] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", command: "", description: "" });

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/snippets");
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      setSnippets(data.snippets ?? []);
    } catch {
      // keep previous list
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleCreate = async () => {
    const name = form.name.trim();
    const command = form.command;
    if (!name) {
      setError("Name required");
      return;
    }
    if (!command) {
      setError("Command required");
      return;
    }
    try {
      const res = await fetch("/api/snippets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          command,
          description: form.description.trim() || undefined,
        }),
      });
      if (!res.ok) {
        const j = await res.json();
        setError(j.error ?? "Failed to create");
        return;
      }
      setForm({ name: "", command: "", description: "" });
      setError(null);
      setShowDialog(false);
      load();
    } catch {
      setError("Network error");
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await fetch(`/api/snippets/${id}`, { method: "DELETE" });
      load();
    } catch {
      // ignore
    }
  };

  const run = (snippet: Snippet) => {
    const text = snippet.command.endsWith("\n") ? snippet.command : snippet.command + "\n";
    emitToActiveTerminal(text);
  };

  const insert = (snippet: Snippet) => {
    emitToActiveTerminal(snippet.command);
  };

  return (
    <div className="flex flex-col h-full text-[13px] font-sans">
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#1a1d24]">
        <span className="text-[11px] text-[#6b7569] uppercase tracking-wider font-medium">
          Snippets
        </span>
        <button
          onClick={() => setShowDialog(true)}
          className="p-1 text-[#6b7569] hover:text-[#00cc6e] transition-colors"
          title="New snippet"
          aria-label="New snippet"
        >
          <Plus size={14} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto py-1">
        {isLoading && snippets.length === 0 ? (
          <div className="px-3 py-4 text-[#6b7569] text-center">Loading...</div>
        ) : snippets.length === 0 ? (
          <div className="px-3 py-4 text-[#6b7569] text-center">No snippets yet</div>
        ) : (
          snippets.map((snippet) => (
            <div key={snippet.id} className="px-3 py-2 hover:bg-[#14161e] transition-colors group">
              <div className="flex items-start gap-2">
                <FileText size={14} className="text-[#6b7569] shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <div className="text-[#e6f0e4] truncate font-medium">{snippet.name}</div>
                  {snippet.description && (
                    <div className="text-[11px] text-[#6b7569] truncate">{snippet.description}</div>
                  )}
                  <div
                    className="text-[11px] text-[#6b7569] truncate font-mono"
                    title={snippet.command}
                  >
                    {snippet.command.split("\n")[0]}
                  </div>
                </div>
                <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => insert(snippet)}
                    className="p-1 text-[#6b7569] hover:text-[#e6f0e4] transition-colors"
                    title="Insert into terminal (no Enter)"
                    aria-label="Insert into terminal (no Enter)"
                  >
                    <FileText size={12} />
                  </button>
                  <button
                    onClick={() => run(snippet)}
                    className="p-1 text-[#6b7569] hover:text-[#00ff88] transition-colors"
                    title="Run (paste + Enter)"
                    aria-label="Run (paste + Enter)"
                  >
                    <Play size={12} />
                  </button>
                  <button
                    onClick={() => handleDelete(snippet.id)}
                    className="p-1 text-[#6b7569] hover:text-[#ff5c5c] transition-colors"
                    title="Delete"
                    aria-label="Delete"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {showDialog && (
        <div className="px-3 py-3 border-t border-[#1a1d24] bg-[#14161e]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] text-[#6b7569] uppercase tracking-wider font-medium">
              New Snippet
            </span>
            <button
              onClick={() => {
                setShowDialog(false);
                setError(null);
              }}
              className="p-0.5 text-[#6b7569] hover:text-[#e6f0e4] transition-colors"
            >
              <X size={12} />
            </button>
          </div>
          <div className="flex flex-col gap-1.5">
            <input
              type="text"
              placeholder="Name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="px-2 py-1.5 rounded bg-[#0a0b10] border border-[#1a1d24]
                text-[#e6f0e4] text-[12px] placeholder:text-[#6b7569]/50
                focus:outline-none focus:border-[#00cc6e]"
            />
            <input
              type="text"
              placeholder="Description (optional)"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              className="px-2 py-1.5 rounded bg-[#0a0b10] border border-[#1a1d24]
                text-[#e6f0e4] text-[12px] placeholder:text-[#6b7569]/50
                focus:outline-none focus:border-[#00cc6e]"
            />
            <textarea
              placeholder="Command (bash/zsh; multi-line supported)"
              value={form.command}
              onChange={(e) => setForm({ ...form, command: e.target.value })}
              rows={4}
              className="px-2 py-1.5 rounded bg-[#0a0b10] border border-[#1a1d24]
                text-[#e6f0e4] text-[12px] font-mono placeholder:text-[#6b7569]/50
                focus:outline-none focus:border-[#00cc6e] resize-none"
            />
            {error && <p className="text-[11px] text-[#ff5c5c]">{error}</p>}
            <button
              onClick={handleCreate}
              className="flex items-center justify-center gap-1.5 px-3 py-1.5
                rounded bg-[#00cc6e] text-white text-[12px] font-medium
                hover:bg-[#00ff88] transition-colors"
            >
              Save
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
