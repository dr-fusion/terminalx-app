"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal, type TerminalHandle } from "@wterm/react";
import "@wterm/react/css";
import { Upload } from "lucide-react";
import { subscribeToTerminalBus } from "@/lib/terminal-bus";
import type { TerminalViewProps } from "./types";

export function TerminalViewWterm({
  sessionId,
  onDisconnect,
  onReconnect,
}: TerminalViewProps) {
  const termRef = useRef<TerminalHandle>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const intentionalCloseRef = useRef(false);
  const dimsRef = useRef<{ cols: number; rows: number }>({ cols: 80, rows: 24 });
  const [isDragging, setIsDragging] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const dragCounterRef = useRef(0);
  const connectRef = useRef<(() => void) | null>(null);

  const connect = useCallback(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/terminal/${encodeURIComponent(sessionId)}`;
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectAttemptRef.current = 0;
      onReconnect?.();
      ws.send(
        JSON.stringify({
          type: "resize",
          cols: dimsRef.current.cols,
          rows: dimsRef.current.rows,
        })
      );
    };

    ws.onmessage = (event) => {
      const term = termRef.current;
      if (!term) return;
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
      } else {
        const data = event.data as string;
        if (data.startsWith("{")) {
          try {
            const msg = JSON.parse(data);
            if (msg.type === "pty-id" || msg.type === "event") return;
          } catch {
            // not JSON, fall through
          }
        }
        term.write(data);
      }
    };

    ws.onclose = () => {
      onDisconnect?.();
      if (!intentionalCloseRef.current) {
        const attempt = reconnectAttemptRef.current;
        const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
        reconnectAttemptRef.current = attempt + 1;
        reconnectTimerRef.current = setTimeout(() => connectRef.current?.(), delay);
      }
    };

    ws.onerror = () => ws.close();
  }, [sessionId, onDisconnect, onReconnect]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    intentionalCloseRef.current = false;
    connect();
    return () => {
      intentionalCloseRef.current = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [connect]);

  useEffect(() => {
    return subscribeToTerminalBus((text) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(text);
      }
      termRef.current?.focus();
    });
  }, []);

  const handleData = useCallback((data: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(data);
    }
  }, []);

  const handleResize = useCallback((cols: number, rows: number) => {
    dimsRef.current = { cols, rows };
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "resize", cols, rows }));
    }
  }, []);

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
    if (e.dataTransfer.types.includes("Files")) setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current--;
    if (dragCounterRef.current === 0) setIsDragging(false);
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
      for (const file of Array.from(e.dataTransfer.files)) {
        await uploadFile(file);
      }
    },
    [uploadFile]
  );

  return (
    <div
      className="h-full w-full relative"
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <Terminal
        ref={termRef}
        autoResize
        wasmUrl="/wterm.wasm"
        onData={handleData}
        onResize={handleResize}
        className="h-full w-full"
        style={{ backgroundColor: "#0D0F12" }}
      />

      {isDragging && (
        <div className="absolute inset-0 bg-[#3B82F6]/10 border-2 border-dashed border-[#3B82F6] rounded flex items-center justify-center z-50 pointer-events-none">
          <div className="flex flex-col items-center gap-2 text-[#3B82F6]">
            <Upload size={32} />
            <span className="text-[14px] font-medium">Drop files to upload</span>
            <span className="text-[12px] text-[#6B7280]">
              File path will be pasted into terminal
            </span>
          </div>
        </div>
      )}

      {uploadStatus && (
        <div className="absolute bottom-4 left-1/2 -translate-x-1/2 px-3 py-1.5 rounded bg-[#1C1F2B] border border-[#2A2D3A] text-[12px] text-[#E4E4E7] shadow-lg z-50">
          {uploadStatus}
        </div>
      )}
    </div>
  );
}
