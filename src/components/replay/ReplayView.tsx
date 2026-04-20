"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal, type TerminalHandle } from "@wterm/react";
import "@wterm/react/css";
import { Play, Pause, Rewind, FastForward } from "lucide-react";

interface Entry {
  t: number;
  d: string;
}

interface Header {
  v?: number;
  sessionId?: string;
  username?: string;
  startedAt?: string;
  cols?: number;
  rows?: number;
}

interface ReplayViewProps {
  id: string;
}

const SPEEDS = [0.5, 1, 2, 4, 8] as const;

export function ReplayView({ id }: ReplayViewProps) {
  const termRef = useRef<TerminalHandle>(null);
  const [header, setHeader] = useState<Header | null>(null);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<number>(1);
  const [position, setPosition] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const cursorRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const baseTimeRef = useRef(0);
  const scheduleRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch(`/api/recordings/${encodeURIComponent(id)}`);
        if (!res.ok) {
          setError(`Failed to load (HTTP ${res.status})`);
          return;
        }
        const text = await res.text();
        if (cancelled) return;
        const lines = text.split("\n").filter((l) => l.length > 0);
        if (lines.length === 0) {
          setError("Empty recording");
          return;
        }
        const parsedHeader = JSON.parse(lines[0]!) as Header;
        const parsedEntries: Entry[] = [];
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i];
          if (!line) continue;
          try {
            const obj = JSON.parse(line);
            if (typeof obj.t === "number" && typeof obj.d === "string") {
              parsedEntries.push(obj);
            }
          } catch {
            // skip malformed line
          }
        }
        setHeader(parsedHeader);
        setEntries(parsedEntries);
        setLoaded(true);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load");
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [id]);

  const clearTerminal = useCallback(() => {
    termRef.current?.write("\x1b[2J\x1b[3J\x1b[H");
  }, []);

  const stop = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setPlaying(false);
  }, []);

  const scheduleNext = useCallback(() => {
    const term = termRef.current;
    if (!term) return;
    if (cursorRef.current >= entries.length) {
      stop();
      return;
    }
    const entry = entries[cursorRef.current];
    if (!entry) {
      stop();
      return;
    }
    const startedAt = baseTimeRef.current;
    const targetWall = startedAt + entry.t / speed;
    const now = performance.now();
    const delay = Math.max(0, targetWall - now);
    timerRef.current = setTimeout(() => {
      term.write(entry.d);
      setPosition(entry.t);
      cursorRef.current += 1;
      scheduleRef.current?.();
    }, delay);
  }, [entries, speed, stop]);

  useEffect(() => {
    scheduleRef.current = scheduleNext;
  }, [scheduleNext]);

  const play = useCallback(() => {
    if (!termRef.current) return;
    if (cursorRef.current >= entries.length) {
      cursorRef.current = 0;
      clearTerminal();
    }
    const last = cursorRef.current > 0 ? (entries[cursorRef.current - 1]?.t ?? 0) : 0;
    baseTimeRef.current = performance.now() - last / speed;
    setPlaying(true);
    scheduleNext();
  }, [entries, speed, scheduleNext, clearTerminal]);

  const rewind = useCallback(() => {
    stop();
    cursorRef.current = 0;
    setPosition(0);
    clearTerminal();
  }, [stop, clearTerminal]);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  useEffect(() => {
    if (!playing) return;
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    const last = cursorRef.current > 0 ? (entries[cursorRef.current - 1]?.t ?? 0) : 0;
    baseTimeRef.current = performance.now() - last / speed;
    scheduleNext();
  }, [speed, playing, entries, scheduleNext]);

  const totalDuration = entries.length > 0 ? (entries[entries.length - 1]?.t ?? 0) : 0;
  const percent = totalDuration > 0 ? (position / totalDuration) * 100 : 0;

  return (
    <div className="flex flex-col h-full bg-[#0D0F12]">
      <div className="flex items-center gap-3 h-11 px-3 bg-[#151820] border-b border-[#2A2D3A]">
        <button
          onClick={rewind}
          className="p-1.5 text-[#6B7280] hover:text-[#E4E4E7] transition-colors"
          title="Rewind"
          aria-label="Rewind"
        >
          <Rewind size={14} />
        </button>
        <button
          onClick={() => (playing ? stop() : play())}
          disabled={!loaded || !!error}
          className="flex items-center gap-1 px-3 py-1 rounded bg-[#3B82F6] text-white
            hover:bg-[#2563EB] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {playing ? <Pause size={12} /> : <Play size={12} />}
          <span className="text-[12px]">{playing ? "Pause" : "Play"}</span>
        </button>
        <div className="flex items-center gap-1">
          <FastForward size={12} className="text-[#6B7280]" />
          <select
            value={speed}
            onChange={(e) => setSpeed(parseFloat(e.target.value))}
            className="bg-[#1C1F2B] text-[#E4E4E7] border border-[#2A2D3A] rounded px-1 py-0.5 text-[11px]"
          >
            {SPEEDS.map((s) => (
              <option key={s} value={s}>
                {s}×
              </option>
            ))}
          </select>
        </div>
        <div className="flex-1 h-1.5 bg-[#1C1F2B] rounded-full overflow-hidden">
          <div
            className="h-full bg-[#3B82F6] transition-[width] duration-100"
            style={{ width: `${percent}%` }}
          />
        </div>
        <span
          className="text-[11px] text-[#6B7280] tabular-nums"
          style={{ fontFamily: "var(--font-jetbrains-mono), monospace" }}
        >
          {formatMs(position)} / {formatMs(totalDuration)}
        </span>
      </div>

      {header && (
        <div className="flex items-center gap-3 px-3 py-1.5 text-[11px] text-[#6B7280] border-b border-[#2A2D3A]">
          <span>{header.sessionId}</span>
          <span>·</span>
          <span>{header.startedAt}</span>
          {header.username && (
            <>
              <span>·</span>
              <span>{header.username}</span>
            </>
          )}
          <span className="ml-auto">{entries.length} events</span>
        </div>
      )}

      {error ? (
        <div className="flex-1 flex items-center justify-center text-[#EF4444] text-[13px]">
          {error}
        </div>
      ) : (
        <div className="flex-1 overflow-hidden p-2">
          <Terminal ref={termRef} autoResize wasmUrl="/wterm.wasm" className="h-full w-full" />
        </div>
      )}
    </div>
  );
}

function formatMs(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}
