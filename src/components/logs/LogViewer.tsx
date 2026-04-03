"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Search, Pause, Play } from "lucide-react";
import { useWebSocket } from "@/hooks/useWebSocket";

interface LogFile {
  name: string;
  path: string;
}

export function LogViewer() {
  const [logFiles, setLogFiles] = useState<LogFile[]>([]);
  const [selectedLog, setSelectedLog] = useState<LogFile | null>(null);
  const [lines, setLines] = useState<string[]>([]);
  const [filter, setFilter] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Fetch available log files
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

  const handleMessage = useCallback((data: string | ArrayBuffer) => {
    const text = typeof data === "string" ? data : new TextDecoder().decode(data as ArrayBuffer);
    setLines((prev) => {
      const updated = [...prev, ...text.split("\n").filter(Boolean)];
      // Cap at 5000 lines
      return updated.length > 5000 ? updated.slice(-5000) : updated;
    });
  }, []);

  const { readyState } = useWebSocket(wsUrl, {
    onMessage: handleMessage,
  });

  // Clear lines when switching logs
  useEffect(() => {
    setLines([]);
  }, [selectedLog]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines, autoScroll]);

  const filteredLines = filter
    ? lines.filter((line) =>
        line.toLowerCase().includes(filter.toLowerCase())
      )
    : lines;

  const colorizeLevel = (line: string): string => {
    const lower = line.toLowerCase();
    if (lower.includes("error") || lower.includes("err"))
      return "#F87171";
    if (lower.includes("warn") || lower.includes("warning"))
      return "#FBBF24";
    if (lower.includes("info")) return "#60A5FA";
    return "#E4E4E7";
  };

  return (
    <div className="flex flex-col h-full text-[13px] font-sans">
      {/* Controls */}
      <div className="flex flex-col gap-1.5 px-2 py-2 border-b border-[#2A2D3A]">
        {/* Log file selector */}
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

        {/* Search + auto-scroll */}
        <div className="flex items-center gap-1.5">
          <div className="flex items-center flex-1 gap-1 bg-[#1C1F2B] border border-[#2A2D3A] rounded px-2">
            <Search size={12} className="text-[#6B7280] shrink-0" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter logs..."
              className="flex-1 bg-transparent text-[#E4E4E7] text-[12px] py-1
                outline-none placeholder:text-[#6B7280]"
            />
          </div>
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1.5 rounded transition-colors ${
              autoScroll
                ? "bg-[#3B82F6]/20 text-[#3B82F6]"
                : "text-[#6B7280] hover:text-[#E4E4E7]"
            }`}
            title={autoScroll ? "Pause auto-scroll" : "Resume auto-scroll"}
          >
            {autoScroll ? <Pause size={12} /> : <Play size={12} />}
          </button>
        </div>
      </div>

      {/* Status indicator */}
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
              ? "Streaming"
              : readyState === "connecting"
                ? "Connecting..."
                : "Disconnected"}
          </span>
          <span className="text-[#6B7280] ml-auto">
            {filteredLines.length} lines
          </span>
        </div>
      )}

      {/* Log output */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto overflow-x-hidden font-mono text-[12px] leading-[1.6]"
      >
        {!selectedLog ? (
          <div className="px-3 py-4 text-[#6B7280] text-center font-sans">
            Select a log file to start tailing
          </div>
        ) : filteredLines.length === 0 ? (
          <div className="px-3 py-4 text-[#6B7280] text-center font-sans">
            {lines.length === 0 ? "Waiting for log output..." : "No matching lines"}
          </div>
        ) : (
          filteredLines.map((line, i) => (
            <div
              key={i}
              className="px-2 py-px hover:bg-[#1C1F2B] transition-colors whitespace-pre-wrap break-all"
              style={{ color: colorizeLevel(line) }}
            >
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
