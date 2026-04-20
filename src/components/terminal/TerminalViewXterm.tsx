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
  const [isMobile, setIsMobile] = useState(false);
  const [ctrlActive, setCtrlActive] = useState(false);
  const [altActive, setAltActive] = useState(false);
  const dragCounterRef = useRef(0);
  const connectWsRef = useRef<(() => void) | null>(null);

  const connectWs = useCallback(() => {
    if (!terminalRef.current) return;

    const protocol =
      window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/terminal/${encodeURIComponent(sessionId)}`;

    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectAttemptRef.current = 0;
      onReconnect?.();

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
          } catch {
            // Not JSON, write to terminal
          }
        }
        terminalRef.current.write(data);
      }
    };

    ws.onclose = () => {
      onDisconnect?.();

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
  }, [sessionId, onDisconnect, onReconnect]);

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
      theme: {
        background: "#0D0F12",
        foreground: "#E4E4E7",
        cursor: "#3B82F6",
        cursorAccent: "#0D0F12",
        selectionBackground: "#3B82F640",
        selectionForeground: "#E4E4E7",
        black: "#1C1F2B",
        red: "#EF4444",
        green: "#22C55E",
        yellow: "#EAB308",
        blue: "#3B82F6",
        magenta: "#A855F7",
        cyan: "#06B6D4",
        white: "#E4E4E7",
        brightBlack: "#6B7280",
        brightRed: "#F87171",
        brightGreen: "#4ADE80",
        brightYellow: "#FBBF24",
        brightBlue: "#60A5FA",
        brightMagenta: "#C084FC",
        brightCyan: "#22D3EE",
        brightWhite: "#FFFFFF",
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

    // Send input to WebSocket
    terminal.onData((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(data);
      }
    });

    // Send binary input to WebSocket
    terminal.onBinary((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        const buffer = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
          buffer[i] = data.charCodeAt(i) & 255;
        }
        wsRef.current.send(buffer);
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
      setHasSelection(sel.length > 0);
      setCopied(false);
    });
    return () => disposable.dispose();
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
    try {
      await navigator.clipboard.writeText(sel);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement("textarea");
      textarea.value = sel;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
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
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <div
        ref={containerRef}
        className="h-full w-full"
        style={{ backgroundColor: "#0D0F12" }}
      />

      {/* Drag overlay */}
      {isDragging && (
        <div className="absolute inset-0 bg-[#3B82F6]/10 border-2 border-dashed border-[#3B82F6] rounded flex items-center justify-center z-50 pointer-events-none">
          <div className="flex flex-col items-center gap-2 text-[#3B82F6]">
            <Upload size={32} />
            <span className="text-[14px] font-medium">
              Drop files to upload
            </span>
            <span className="text-[12px] text-[#6B7280]">
              File path will be pasted into terminal
            </span>
          </div>
        </div>
      )}

      {/* Copy button — appears when text is selected */}
      {hasSelection && (
        <button
          onClick={handleCopy}
          className="absolute top-2 right-2 flex items-center gap-1.5 px-2.5 py-1.5
            rounded bg-[#1C1F2B] border border-[#2A2D3A] text-[12px] text-[#E4E4E7]
            hover:bg-[#252838] transition-colors shadow-lg z-50 cursor-pointer"
        >
          {copied ? (
            <>
              <Check size={14} className="text-[#22C55E]" />
              Copied
            </>
          ) : (
            <>
              <Copy size={14} />
              Copy
            </>
          )}
        </button>
      )}

      {/* Mobile special keys toolbar */}
      {isMobile && (
        <div className="absolute bottom-0 left-0 right-0 flex items-center gap-1
          px-2 py-1.5 bg-[#151820] border-t border-[#2A2D3A] z-40 overflow-x-auto">
          {/* Modifier keys (toggle) */}
          <button
            onClick={() => setCtrlActive(!ctrlActive)}
            className={`shrink-0 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors
              ${ctrlActive
                ? "bg-[#3B82F6] text-white"
                : "bg-[#1C1F2B] text-[#E4E4E7] border border-[#2A2D3A]"
              }`}
          >
            Ctrl
          </button>
          <button
            onClick={() => setAltActive(!altActive)}
            className={`shrink-0 px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors
              ${altActive
                ? "bg-[#3B82F6] text-white"
                : "bg-[#1C1F2B] text-[#E4E4E7] border border-[#2A2D3A]"
              }`}
          >
            Alt
          </button>

          <div className="w-px h-5 bg-[#2A2D3A] shrink-0" />

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
              className="shrink-0 px-2.5 py-1 rounded bg-[#1C1F2B] text-[#E4E4E7]
                border border-[#2A2D3A] text-[11px] font-mono font-medium
                active:bg-[#252838] transition-colors"
            >
              {label}
            </button>
          ))}

          <div className="w-px h-5 bg-[#2A2D3A] shrink-0" />

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
              className="shrink-0 px-2.5 py-1 rounded bg-[#1C1F2B] text-[#E4E4E7]
                border border-[#2A2D3A] text-[11px] font-mono font-medium
                active:bg-[#252838] transition-colors"
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Upload status toast */}
      {uploadStatus && (
        <div className={`absolute ${isMobile ? "bottom-12" : "bottom-4"} left-1/2 -translate-x-1/2 px-3 py-1.5 rounded bg-[#1C1F2B] border border-[#2A2D3A] text-[12px] text-[#E4E4E7] shadow-lg z-50`}>
          {uploadStatus}
        </div>
      )}
    </div>
  );
}
