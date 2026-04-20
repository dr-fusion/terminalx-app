"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Film } from "lucide-react";

interface Recording {
  id: string;
  sessionId: string;
  startedAt: string;
  sizeBytes: number;
}

export default function RecordingsListPage() {
  const [recordings, setRecordings] = useState<Recording[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch("/api/recordings");
        if (!res.ok) {
          setError(`HTTP ${res.status}`);
          return;
        }
        const data = await res.json();
        setRecordings(data.recordings ?? []);
        setEnabled(data.enabled ?? false);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load");
      }
    }
    load();
  }, []);

  return (
    <div className="h-dvh w-screen flex flex-col bg-[#0D0F12] overflow-hidden">
      <div className="flex items-center h-11 px-3 bg-[#151820] border-b border-[#2A2D3A] shrink-0 gap-3">
        <Link
          href="/"
          className="flex items-center gap-1.5 text-[#6B7280] hover:text-[#E4E4E7] transition-colors text-[13px]"
        >
          <ArrowLeft size={14} />
          Back
        </Link>
        <span
          className="text-[13px] font-bold text-[#3B82F6]"
          style={{ fontFamily: "var(--font-jetbrains-mono), monospace" }}
        >
          TerminalX / Recordings
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-4 max-w-3xl w-full mx-auto">
        {!enabled && (
          <div className="mb-4 px-3 py-2 rounded bg-[#1C1F2B] border border-[#2A2D3A] text-[12px] text-[#6B7280]">
            Recording is disabled. Set <code className="text-[#E4E4E7]">TERMINUS_RECORD_SESSIONS=true</code> to enable.
          </div>
        )}

        {error ? (
          <div className="text-[#EF4444] text-[13px]">{error}</div>
        ) : recordings.length === 0 ? (
          <div className="text-[#6B7280] text-[13px] text-center py-8">
            No recordings yet
          </div>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {recordings.map((r) => (
              <li key={r.id}>
                <Link
                  href={`/replay/${encodeURIComponent(r.id)}`}
                  className="flex items-center gap-3 px-3 py-2.5 rounded bg-[#151820] border border-[#2A2D3A]
                    hover:border-[#3B82F6] transition-colors group"
                >
                  <Film size={16} className="text-[#6B7280] group-hover:text-[#3B82F6] transition-colors" />
                  <div className="flex-1 min-w-0">
                    <div className="text-[#E4E4E7] text-[13px] font-medium truncate">
                      {r.sessionId || r.id}
                    </div>
                    <div className="text-[11px] text-[#6B7280]">
                      {r.startedAt} · {formatSize(r.sizeBytes)}
                    </div>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
