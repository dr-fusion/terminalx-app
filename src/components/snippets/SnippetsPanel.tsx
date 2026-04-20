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
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#2A2D3A]">
        <span className="text-[11px] text-[#6B7280] uppercase tracking-wider font-medium">
          Snippets
        </span>
        <button
          onClick={() => setShowDialog(true)}
          className="p-1 text-[#6B7280] hover:text-[#3B82F6] transition-colors"
          title="New snippet"
          aria-label="New snippet"
        >
          <Plus size={14} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto py-1">
        {isLoading && snippets.length === 0 ? (
          <div className="px-3 py-4 text-[#6B7280] text-center">Loading...</div>
        ) : snippets.length === 0 ? (
          <div className="px-3 py-4 text-[#6B7280] text-center">No snippets yet</div>
        ) : (
          snippets.map((snippet) => (
            <div key={snippet.id} className="px-3 py-2 hover:bg-[#1C1F2B] transition-colors group">
              <div className="flex items-start gap-2">
                <FileText size={14} className="text-[#6B7280] shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <div className="text-[#E4E4E7] truncate font-medium">{snippet.name}</div>
                  {snippet.description && (
                    <div className="text-[11px] text-[#6B7280] truncate">{snippet.description}</div>
                  )}
                  <div
                    className="text-[11px] text-[#6B7280] truncate font-mono"
                    title={snippet.command}
                  >
                    {snippet.command.split("\n")[0]}
                  </div>
                </div>
                <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => insert(snippet)}
                    className="p-1 text-[#6B7280] hover:text-[#E4E4E7] transition-colors"
                    title="Insert into terminal (no Enter)"
                    aria-label="Insert into terminal (no Enter)"
                  >
                    <FileText size={12} />
                  </button>
                  <button
                    onClick={() => run(snippet)}
                    className="p-1 text-[#6B7280] hover:text-[#22C55E] transition-colors"
                    title="Run (paste + Enter)"
                    aria-label="Run (paste + Enter)"
                  >
                    <Play size={12} />
                  </button>
                  <button
                    onClick={() => handleDelete(snippet.id)}
                    className="p-1 text-[#6B7280] hover:text-[#EF4444] transition-colors"
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
        <div className="px-3 py-3 border-t border-[#2A2D3A] bg-[#1C1F2B]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] text-[#6B7280] uppercase tracking-wider font-medium">
              New Snippet
            </span>
            <button
              onClick={() => {
                setShowDialog(false);
                setError(null);
              }}
              className="p-0.5 text-[#6B7280] hover:text-[#E4E4E7] transition-colors"
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
              className="px-2 py-1.5 rounded bg-[#0D0F12] border border-[#2A2D3A]
                text-[#E4E4E7] text-[12px] placeholder:text-[#6B7280]/50
                focus:outline-none focus:border-[#3B82F6]"
            />
            <input
              type="text"
              placeholder="Description (optional)"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              className="px-2 py-1.5 rounded bg-[#0D0F12] border border-[#2A2D3A]
                text-[#E4E4E7] text-[12px] placeholder:text-[#6B7280]/50
                focus:outline-none focus:border-[#3B82F6]"
            />
            <textarea
              placeholder="Command (bash/zsh; multi-line supported)"
              value={form.command}
              onChange={(e) => setForm({ ...form, command: e.target.value })}
              rows={4}
              className="px-2 py-1.5 rounded bg-[#0D0F12] border border-[#2A2D3A]
                text-[#E4E4E7] text-[12px] font-mono placeholder:text-[#6B7280]/50
                focus:outline-none focus:border-[#3B82F6] resize-none"
            />
            {error && <p className="text-[11px] text-[#EF4444]">{error}</p>}
            <button
              onClick={handleCreate}
              className="flex items-center justify-center gap-1.5 px-3 py-1.5
                rounded bg-[#3B82F6] text-white text-[12px] font-medium
                hover:bg-[#2563EB] transition-colors"
            >
              Save
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
