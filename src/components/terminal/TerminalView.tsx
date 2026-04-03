"use client";

import { useEffect, useRef, useCallback } from "react";
import { Terminal } from "xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { SearchAddon } from "@xterm/addon-search";
import "xterm/css/xterm.css";

interface TerminalViewProps {
  sessionId: string;
  onDisconnect?: () => void;
  onReconnect?: () => void;
}

export function TerminalView({
  sessionId,
  onDisconnect,
  onReconnect,
}: TerminalViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const intentionalCloseRef = useRef(false);

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
      if (terminalRef.current) {
        if (event.data instanceof ArrayBuffer) {
          terminalRef.current.write(new Uint8Array(event.data));
        } else {
          terminalRef.current.write(event.data);
        }
      }
    };

    ws.onclose = () => {
      onDisconnect?.();

      if (!intentionalCloseRef.current) {
        const attempt = reconnectAttemptRef.current;
        const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
        reconnectAttemptRef.current = attempt + 1;

        reconnectTimerRef.current = setTimeout(() => {
          connectWs();
        }, delay);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [sessionId, onDisconnect, onReconnect]);

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

  return (
    <div
      ref={containerRef}
      className="h-full w-full"
      style={{ backgroundColor: "#0D0F12" }}
    />
  );
}
