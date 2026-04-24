"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import { Terminal } from "xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { SearchAddon } from "@xterm/addon-search";
import { Upload, Copy, Check } from "lucide-react";
import "xterm/css/xterm.css";

import { subscribeToTerminalBus } from "@/lib/terminal-bus";
import type { TerminalViewProps } from "./types";

export function TerminalViewXterm({
  sessionId,
  onDisconnect,
  onReconnect,
  onSessionEnded,
}: TerminalViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const intentionalCloseRef = useRef(false);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [hasSelection, setHasSelection] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyBtnPos, setCopyBtnPos] = useState<{ x: number; y: number } | null>(null);
  const [isMobile, setIsMobile] = useState(false);
  const [ctrlActive, setCtrlActive] = useState(false);
  const [altActive, setAltActive] = useState(false);
  const dragCounterRef = useRef(0);
  const connectWsRef = useRef<(() => void) | null>(null);
  // Touch-scroll bookkeeping. Mobile browsers sometimes don't forward
  // touch-drag to xterm's viewport (the canvas swallows events for
  // selection/focus), so we manage scrolling ourselves on touchmove.
  const touchStartYRef = useRef<number | null>(null);
  const touchLastYRef = useRef<number | null>(null);
  const touchScrolledRef = useRef(false);

  // Keep callbacks in refs so connectWs doesn't change identity when the
  // parent re-renders. Otherwise the terminal + WebSocket rebuild on every
  // tab/state change upstream, which can briefly leave two WebSockets open
  // on mobile and doubles keystrokes through both PTYs.
  const onDisconnectRef = useRef(onDisconnect);
  const onReconnectRef = useRef(onReconnect);
  const onSessionEndedRef = useRef(onSessionEnded);
  useEffect(() => {
    onDisconnectRef.current = onDisconnect;
    onReconnectRef.current = onReconnect;
    onSessionEndedRef.current = onSessionEnded;
  }, [onDisconnect, onReconnect, onSessionEnded]);

  const connectWs = useCallback(() => {
    if (!terminalRef.current) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/terminal/${encodeURIComponent(sessionId)}`;

    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectAttemptRef.current = 0;
      onReconnectRef.current?.();

      // Send terminal dimensions
      const term = terminalRef.current;
      if (term) {
        ws.send(
          JSON.stringify({
            type: "resize",
            cols: term.cols,
            rows: term.rows,
          })
        );
      }
    };

    ws.onmessage = (event) => {
      if (!terminalRef.current) return;

      if (event.data instanceof ArrayBuffer) {
        terminalRef.current.write(new Uint8Array(event.data));
      } else {
        // Filter out JSON control messages from the server
        const data = event.data as string;
        if (data.startsWith("{")) {
          try {
            const msg = JSON.parse(data);
            if (msg.type === "pty-id" || msg.type === "event") {
              return; // Skip control messages
            }
            if (msg.type === "scrollback" && typeof msg.data === "string") {
              // Seed xterm's scrollback with tmux's pane history. We write
              // the captured bytes (which include ANSI color codes) so it
              // lands in scrollback the same way live output would. The
              // subsequent tmux attach will redraw the current screen on
              // top, which is exactly what we want.
              terminalRef.current.write(msg.data);
              // Make sure the captured chunk ends with a clean line so
              // the live redraw doesn't glue onto the last line.
              if (!msg.data.endsWith("\n")) terminalRef.current.write("\r\n");
              return;
            }
            if (msg.type === "session-ended") {
              // Shell exited / tmux session killed from inside the terminal.
              // Suppress the auto-reconnect loop so we don't silently spawn
              // a new tmux session with the same name.
              intentionalCloseRef.current = true;
              onSessionEndedRef.current?.(sessionId);
              return;
            }
          } catch {
            // Not JSON, write to terminal
          }
        }
        terminalRef.current.write(data);
      }
    };

    ws.onclose = () => {
      onDisconnectRef.current?.();

      if (!intentionalCloseRef.current) {
        const attempt = reconnectAttemptRef.current;
        const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
        reconnectAttemptRef.current = attempt + 1;

        reconnectTimerRef.current = setTimeout(() => {
          connectWsRef.current?.();
        }, delay);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [sessionId]);

  useEffect(() => {
    connectWsRef.current = connectWs;
  }, [connectWs]);

  useEffect(() => {
    if (!containerRef.current) return;

    const terminal = new Terminal({
      fontFamily: "var(--font-jetbrains-mono), 'JetBrains Mono', monospace",
      fontSize: 14,
      lineHeight: 1.4,
      cursorBlink: true,
      cursorStyle: "block",
      allowProposedApi: true,
      scrollback: 10000,
      // Keep xterm.js's default scrollbar / wheel behavior so browser
      // native scroll and text selection work. Tmux mouse-mode is off.
      theme: {
        background: "#07080c",
        foreground: "#e6f0e4",
        cursor: "#00ff88",
        cursorAccent: "#05060a",
        selectionBackground: "#002a17",
        selectionForeground: "#4dffa8",
        black: "#0a0b10",
        red: "#ff5c5c",
        green: "#00cc6e",
        yellow: "#ffb454",
        blue: "#7aa2ff",
        magenta: "#d58fff",
        cyan: "#5ccfe6",
        white: "#c8d0c6",
        brightBlack: "#3f4742",
        brightRed: "#ff8080",
        brightGreen: "#4dffa8",
        brightYellow: "#ffd080",
        brightBlue: "#a8c0ff",
        brightMagenta: "#e6b3ff",
        brightCyan: "#8fdff0",
        brightWhite: "#e6f0e4",
      },
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();
    const searchAddon = new SearchAddon();

    terminal.loadAddon(fitAddon);
    terminal.loadAddon(webLinksAddon);
    terminal.loadAddon(searchAddon);

    terminal.open(containerRef.current);
    fitAddon.fit();

    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    // Send input to WebSocket. We do NOT also listen to terminal.onBinary()
    // — on some mobile IMEs (Android Gboard in particular) both onData and
    // onBinary fire for the same keystroke, which doubles every character
    // through the PTY. onData already covers regular typing and escape
    // sequences; binary paste is an edge case we intentionally don't handle.
    terminal.onData((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(data);
      }
    });

    // Connect WebSocket
    intentionalCloseRef.current = false;
    connectWs();

    // Resize observer
    const resizeObserver = new ResizeObserver(() => {
      try {
        fitAddon.fit();
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(
            JSON.stringify({
              type: "resize",
              cols: terminal.cols,
              rows: terminal.rows,
            })
          );
        }
      } catch {
        // fit() can throw if container not visible
      }
    });

    resizeObserver.observe(containerRef.current);

    return () => {
      intentionalCloseRef.current = true;
      resizeObserver.disconnect();

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }

      terminal.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, [connectWs]);

  // Detect mobile
  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 768 || "ontouchstart" in window);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  // Track text selection in terminal
  useEffect(() => {
    const term = terminalRef.current;
    if (!term) return;
    const disposable = term.onSelectionChange(() => {
      const sel = term.getSelection();
      const has = sel.length > 0;
      setHasSelection(has);
      setCopied(false);
      // Selection cleared (user clicked away or typed) — hide the button.
      if (!has) setCopyBtnPos(null);
    });
    return () => disposable.dispose();
  }, []);

  // Anchor the copy button to where the user finished selecting, so
  // they don't have to sling the mouse to a top-right corner button.
  // We listen at the wrapper level and read the selection after the
  // pointer-up so xterm has had a chance to update.
  const handlePointerUp = useCallback((e: React.PointerEvent) => {
    const wrapper = wrapperRef.current;
    const term = terminalRef.current;
    if (!wrapper || !term) return;
    // A touch-scroll gesture also fires pointerup when the finger lifts;
    // in that case we don't want to anchor the copy button because the
    // user wasn't selecting, just scrolling.
    if (touchScrolledRef.current) {
      touchScrolledRef.current = false;
      return;
    }
    const clientX = e.clientX;
    const clientY = e.clientY;
    // Give xterm a frame to finalize the selection before we peek at it.
    requestAnimationFrame(() => {
      if (!terminalRef.current) return;
      const sel = terminalRef.current.getSelection();
      if (!sel) {
        setCopyBtnPos(null);
        return;
      }
      const rect = wrapper.getBoundingClientRect();
      // Approximate button size for edge clamping (measured render ~82×30).
      const BW = 84;
      const BH = 32;
      const gap = 8;
      let x = clientX - rect.left + gap;
      let y = clientY - rect.top + gap;
      if (x + BW > rect.width) x = clientX - rect.left - BW - gap;
      if (y + BH > rect.height) y = clientY - rect.top - BH - gap;
      x = Math.max(4, x);
      y = Math.max(4, y);
      setCopyBtnPos({ x, y });
    });
  }, []);

  // Touch scroll handlers — on mobile, drag a finger vertically in the
  // terminal area to scroll xterm's scrollback. Below a small threshold
  // the gesture is treated as a tap so focus / selection still work.
  const handleTouchStart = useCallback((e: React.TouchEvent) => {
    if (e.touches.length !== 1) return;
    const y = e.touches[0]!.clientY;
    touchStartYRef.current = y;
    touchLastYRef.current = y;
    touchScrolledRef.current = false;
  }, []);

  const handleTouchMove = useCallback((e: React.TouchEvent) => {
    if (e.touches.length !== 1) return;
    const term = terminalRef.current;
    const startY = touchStartYRef.current;
    const lastY = touchLastYRef.current;
    if (!term || startY === null || lastY === null) return;
    const y = e.touches[0]!.clientY;
    // Ignore short drags so a tap still focuses / starts selection.
    const totalDelta = Math.abs(y - startY);
    const SCROLL_THRESHOLD = 8;
    if (!touchScrolledRef.current && totalDelta < SCROLL_THRESHOLD) return;
    const fontSize = (term.options.fontSize ?? 14) as number;
    const lineHeightMult = (term.options.lineHeight ?? 1.4) as number;
    const lineHeightPx = Math.max(1, Math.round(fontSize * lineHeightMult));
    const delta = y - lastY;
    const lines = Math.trunc(delta / lineHeightPx);
    if (lines !== 0) {
      // Finger down = scroll up into history (negative lines for xterm).
      term.scrollLines(-lines);
      // Advance the baseline by the whole number of lines we consumed so
      // remainder pixels accumulate for the next move event.
      touchLastYRef.current = lastY + lines * lineHeightPx;
    }
    touchScrolledRef.current = true;
  }, []);

  const handleTouchEnd = useCallback(() => {
    touchStartYRef.current = null;
    touchLastYRef.current = null;
    // touchScrolledRef stays true for the onPointerUp that fires right
    // after — handlePointerUp reads + clears it.
  }, []);

  // Receive snippet injections from the terminal bus
  useEffect(() => {
    return subscribeToTerminalBus((text) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(text);
      }
      terminalRef.current?.focus();
    });
  }, []);

  const handleCopy = useCallback(async () => {
    const term = terminalRef.current;
    if (!term) return;
    const sel = term.getSelection();
    if (!sel) return;
    const finish = () => {
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
        setCopyBtnPos(null);
      }, 1200);
    };
    try {
      await navigator.clipboard.writeText(sel);
      finish();
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = sel;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      finish();
    }
  }, []);

  const sendKey = useCallback(
    (key: string) => {
      if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;

      let data = key;

      // Apply modifiers
      if (ctrlActive && key.length === 1) {
        // Ctrl+letter = char code 1-26
        const code = key.toLowerCase().charCodeAt(0) - 96;
        if (code >= 1 && code <= 26) {
          data = String.fromCharCode(code);
        }
        setCtrlActive(false);
      } else if (altActive && key.length === 1) {
        data = "\x1b" + key;
        setAltActive(false);
      }

      wsRef.current.send(data);
      terminalRef.current?.focus();
    },
    [ctrlActive, altActive]
  );

  const uploadFile = useCallback(async (file: File) => {
    setUploadStatus(`Uploading ${file.name}...`);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData,
        headers: { "X-Requested-With": "TerminalX" },
      });
      if (!res.ok) {
        const err = await res.json();
        setUploadStatus(`Failed: ${err.error}`);
        setTimeout(() => setUploadStatus(null), 3000);
        return;
      }
      const data = await res.json();
      // Paste the file path into the terminal
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(data.path + " ");
      }
      setUploadStatus(`Uploaded: ${data.filename}`);
      setTimeout(() => setUploadStatus(null), 2000);
    } catch {
      setUploadStatus("Upload failed");
      setTimeout(() => setUploadStatus(null), 3000);
    }
  }, []);

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current++;
    if (e.dataTransfer.types.includes("Files")) {
      setIsDragging(true);
    }
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current--;
    if (dragCounterRef.current === 0) {
      setIsDragging(false);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
      dragCounterRef.current = 0;

      const files = Array.from(e.dataTransfer.files);
      for (const file of files) {
        await uploadFile(file);
      }
    },
    [uploadFile]
  );

  return (
    <div
      ref={wrapperRef}
      className="h-full w-full relative"
      style={{ touchAction: "pan-y" }}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      onPointerUp={handlePointerUp}
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
    >
      <div ref={containerRef} className="h-full w-full" style={{ backgroundColor: "#0a0b10" }} />

      {/* Drag overlay */}
      {isDragging && (
        <div className="absolute inset-0 bg-[#00cc6e]/10 border-2 border-dashed border-[#00cc6e] rounded flex items-center justify-center z-50 pointer-events-none">
          <div className="flex flex-col items-center gap-2 text-[#00cc6e]">
            <Upload size={32} />
            <span className="text-[14px] font-medium">Drop files to upload</span>
            <span className="text-[12px] text-[#6b7569]">
              File path will be pasted into terminal
            </span>
          </div>
        </div>
      )}

      {/* Copy button — only shown while we have both an active selection
          and a pointer-up anchor. After copy we clear the anchor so the
          button hides cleanly instead of snapping back to a corner. */}
      {hasSelection && copyBtnPos && (
        <button
          onClick={handleCopy}
          // Stop pointer events from bubbling to the wrapper — otherwise
          // the wrapper's onPointerUp handler re-anchors the button to
          // the tap coordinates on the button itself, making it jump
          // down-right with every tap (especially visible on mobile
          // where the tap offset differs from the mouse click origin).
          onPointerDown={(e) => e.stopPropagation()}
          onPointerUp={(e) => e.stopPropagation()}
          className="absolute flex items-center gap-1.5 px-2.5 py-1.5
            rounded bg-[#14161e] border border-[#252933] text-[12px] text-[#e6f0e4]
            hover:bg-[#1a1d24] transition-colors shadow-lg z-50 cursor-pointer"
          style={{ left: copyBtnPos.x, top: copyBtnPos.y }}
        >
          {copied ? (
            <>
              <Check size={14} className="text-[#00ff88]" />
              copied
            </>
          ) : (
            <>
              <Copy size={14} />
              copy
            </>
          )}
        </button>
      )}

      {/* Mobile special keys toolbar */}
      {isMobile && (
        <div
          className="absolute bottom-0 left-0 right-0 flex items-center gap-1
          px-2 py-1.5 bg-[#0f1117] border-t border-[#1a1d24] z-40 overflow-x-auto"
        >
          {/* Modifier keys (toggle) */}
          <button
            onClick={() => setCtrlActive(!ctrlActive)}
            className={`shrink-0 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors
              ${
                ctrlActive
                  ? "bg-[#00cc6e] text-white"
                  : "bg-[#14161e] text-[#e6f0e4] border border-[#1a1d24]"
              }`}
          >
            Ctrl
          </button>
          <button
            onClick={() => setAltActive(!altActive)}
            className={`shrink-0 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors
              ${
                altActive
                  ? "bg-[#00cc6e] text-white"
                  : "bg-[#14161e] text-[#e6f0e4] border border-[#1a1d24]"
              }`}
          >
            Alt
          </button>

          <div className="w-px h-5 bg-[#1a1d24] shrink-0" />

          {/* Common keys */}
          {[
            { label: "Esc", key: "\x1b" },
            { label: "Tab", key: "\t" },
            { label: "↑", key: "\x1b[A" },
            { label: "↓", key: "\x1b[B" },
            { label: "←", key: "\x1b[D" },
            { label: "→", key: "\x1b[C" },
          ].map(({ label, key }) => (
            <button
              key={label}
              onClick={() => sendKey(key)}
              className="shrink-0 px-2.5 py-1 rounded bg-[#14161e] text-[#e6f0e4]
                border border-[#1a1d24] text-[11px] font-mono font-medium
                active:bg-[#1a1d24] transition-colors"
            >
              {label}
            </button>
          ))}

          <div className="w-px h-5 bg-[#1a1d24] shrink-0" />

          {/* Ctrl combos */}
          {[
            { label: "^C", key: "\x03" },
            { label: "^D", key: "\x04" },
            { label: "^Z", key: "\x1a" },
            { label: "^L", key: "\x0c" },
            { label: "^A", key: "\x01" },
            { label: "^E", key: "\x05" },
          ].map(({ label, key }) => (
            <button
              key={label}
              onClick={() => {
                wsRef.current?.send(key);
                terminalRef.current?.focus();
              }}
              className="shrink-0 px-2.5 py-1 rounded bg-[#14161e] text-[#e6f0e4]
                border border-[#1a1d24] text-[11px] font-mono font-medium
                active:bg-[#1a1d24] transition-colors"
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Upload status toast */}
      {uploadStatus && (
        <div
          className={`absolute ${isMobile ? "bottom-12" : "bottom-4"} left-1/2 -translate-x-1/2 px-3 py-1.5 rounded bg-[#14161e] border border-[#1a1d24] text-[12px] text-[#e6f0e4] shadow-lg z-50`}
        >
          {uploadStatus}
        </div>
      )}
    </div>
  );
}
