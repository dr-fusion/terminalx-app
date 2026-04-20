"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Search } from "lucide-react";
import { Terminal, type TerminalHandle } from "@wterm/react";
import "@wterm/react/css";
import { useWebSocket } from "@/hooks/useWebSocket";

interface LogFile {
  name: string;
  path: string;
}

const CLEAR = "\x1b[2J\x1b[3J\x1b[H";

export function LogViewer() {
  const [logFiles, setLogFiles] = useState<LogFile[]>([]);
  const [selectedLog, setSelectedLog] = useState<LogFile | null>(null);
  const [filter, setFilter] = useState("");
  const termRef = useRef<TerminalHandle>(null);
  const linesRef = useRef<string[]>([]);
  const [lineCount, setLineCount] = useState(0);

  useEffect(() => {
    async function fetchLogs() {
      try {
        const res = await fetch("/api/logs");
        if (!res.ok) return;
        const data = await res.json();
        setLogFiles(data.files ?? data);
      } catch {
        // API not available yet
      }
    }
    fetchLogs();
  }, []);

  const wsUrl = selectedLog
    ? `/ws/logs/${encodeURIComponent(selectedLog.path)}`
    : null;

  const passesFilter = useCallback(
    (line: string) => {
      if (!filter) return true;
      return line.toLowerCase().includes(filter.toLowerCase());
    },
    [filter]
  );

  const handleMessage = useCallback(
    (data: string | ArrayBuffer) => {
      const text =
        typeof data === "string"
          ? data
          : new TextDecoder().decode(data as ArrayBuffer);
      const incoming = text.split("\n").filter((l) => l.length > 0);
      if (incoming.length === 0) return;
      linesRef.current.push(...incoming);
      if (linesRef.current.length > 5000) {
        linesRef.current.splice(0, linesRef.current.length - 5000);
      }
      setLineCount(linesRef.current.length);
      const term = termRef.current;
      if (!term) return;
      const matched = incoming.filter(passesFilter);
      if (matched.length > 0) {
        term.write(matched.join("\r\n") + "\r\n");
      }
    },
    [passesFilter]
  );

  const { readyState } = useWebSocket(wsUrl, {
    onMessage: handleMessage,
  });

  useEffect(() => {
    linesRef.current = [];
    setLineCount(0);
    termRef.current?.write(CLEAR);
  }, [selectedLog]);

  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    term.write(CLEAR);
    const filtered = linesRef.current.filter(passesFilter);
    if (filtered.length > 0) {
      term.write(filtered.join("\r\n") + "\r\n");
    }
  }, [passesFilter]);

  return (
    <div className="flex flex-col h-full text-[13px] font-sans">
      <div className="flex flex-col gap-1.5 px-2 py-2 border-b border-[#2A2D3A]">
        <select
          value={selectedLog?.path ?? ""}
          onChange={(e) => {
            const log = logFiles.find((l) => l.path === e.target.value);
            setSelectedLog(log ?? null);
          }}
          className="w-full bg-[#1C1F2B] text-[#E4E4E7] border border-[#2A2D3A]
            rounded px-2 py-1 text-[12px] outline-none focus:border-[#3B82F6]"
        >
          <option value="">Select a log file...</option>
          {logFiles.map((log) => (
            <option key={log.path} value={log.path}>
              {log.name}
            </option>
          ))}
        </select>

        <div className="flex items-center gap-1.5">
          <div className="flex items-center flex-1 gap-1 bg-[#1C1F2B] border border-[#2A2D3A] rounded px-2">
            <Search size={12} className="text-[#6B7280] shrink-0" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter lines (or use Ctrl+F in page)…"
              className="flex-1 bg-transparent text-[#E4E4E7] text-[12px] py-1
                outline-none placeholder:text-[#6B7280]"
            />
          </div>
        </div>
      </div>

      {selectedLog && (
        <div className="flex items-center gap-1.5 px-2 py-1 border-b border-[#2A2D3A] text-[11px]">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{
              backgroundColor:
                readyState === "open"
                  ? "#22C55E"
                  : readyState === "connecting"
                    ? "#EAB308"
                    : "#EF4444",
            }}
          />
          <span className="text-[#6B7280]">
            {readyState === "open"
              ? "Streaming · ANSI rendered"
              : readyState === "connecting"
                ? "Connecting..."
                : "Disconnected"}
          </span>
          <span className="text-[#6B7280] ml-auto">{lineCount} lines</span>
        </div>
      )}

      <div className="flex-1 overflow-hidden bg-[#0D0F12]">
        {!selectedLog ? (
          <div className="px-3 py-4 text-[#6B7280] text-center font-sans">
            Select a log file to start tailing
          </div>
        ) : (
          <Terminal
            ref={termRef}
            autoResize
            wasmUrl="/wterm.wasm"
            className="h-full w-full"
          />
        )}
      </div>
    </div>
  );
}
