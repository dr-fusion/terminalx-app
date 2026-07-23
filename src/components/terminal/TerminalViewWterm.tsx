"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal, type TerminalHandle } from "@wterm/react";
import "@wterm/react/css";
import { Check, Copy, Upload } from "lucide-react";
import { subscribeToTerminalBus } from "@/lib/terminal-bus";
import type { TerminalViewProps } from "./types";

function nodeIsInside(element: HTMLElement, node: Node): boolean {
  const target = node.nodeType === Node.ELEMENT_NODE ? node : node.parentNode;
  return element.contains(target);
}

function getSelectionTextInside(element: HTMLElement): string {
  const selection = window.getSelection();
  if (!selection || selection.isCollapsed || selection.rangeCount === 0) return "";

  const text = selection.toString();
  if (!text) return "";

  for (let i = 0; i < selection.rangeCount; i++) {
    const range = selection.getRangeAt(i);
    if (
      nodeIsInside(element, range.commonAncestorContainer) ||
      nodeIsInside(element, range.startContainer) ||
      nodeIsInside(element, range.endContainer)
    ) {
      return text;
    }
  }

  return "";
}

export function TerminalViewWterm({
  sessionId,
  onDisconnect,
  onReconnect,
  onSessionEnded,
}: TerminalViewProps) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<TerminalHandle>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const intentionalCloseRef = useRef(false);
  const dimsRef = useRef<{ cols: number; rows: number } | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [hasSelection, setHasSelection] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyBtnPos, setCopyBtnPos] = useState<{ x: number; y: number } | null>(null);
  const dragCounterRef = useRef(0);
  const connectRef = useRef<(() => void) | null>(null);
  const selectedTextRef = useRef("");

  // Keep callback identity changes from rebuilding the WebSocket. Parent state
  // changes (for example, adding or closing tabs) should not reattach tmux.
  const onDisconnectRef = useRef(onDisconnect);
  const onReconnectRef = useRef(onReconnect);
  const onSessionEndedRef = useRef(onSessionEnded);
  useEffect(() => {
    onDisconnectRef.current = onDisconnect;
    onReconnectRef.current = onReconnect;
    onSessionEndedRef.current = onSessionEnded;
  }, [onDisconnect, onReconnect, onSessionEnded]);

  const connect = useCallback(() => {
    const dimensions = dimsRef.current;
    if (intentionalCloseRef.current || !dimensions || wsRef.current) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const query = new URLSearchParams({
      cols: String(dimensions.cols),
      rows: String(dimensions.rows),
    });
    const wsUrl = `${protocol}//${window.location.host}/ws/terminal/${encodeURIComponent(sessionId)}?${query}`;
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => {
      if (wsRef.current !== ws) {
        ws.close();
        return;
      }

      reconnectAttemptRef.current = 0;
      onReconnectRef.current?.();
      const currentDimensions = dimsRef.current;
      if (!currentDimensions) return;
      ws.send(
        JSON.stringify({
          type: "resize",
          cols: currentDimensions.cols,
          rows: currentDimensions.rows,
        })
      );
    };

    ws.onmessage = (event) => {
      if (wsRef.current !== ws) return;
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
            if (msg.type === "scrollback" && typeof msg.data === "string") {
              term.write(msg.data);
              if (!msg.data.endsWith("\n")) term.write("\r\n");
              return;
            }
            // Chunked scrollback — see TerminalViewXterm for details.
            if (msg.type === "scrollback-begin") return;
            if (msg.type === "scrollback-chunk" && typeof msg.data === "string") {
              term.write(msg.data);
              return;
            }
            if (msg.type === "scrollback-end") {
              term.write("\r\n");
              return;
            }
            if (msg.type === "session-ended") {
              // Shell exited / tmux session killed from inside the terminal.
              // Suppress reconnect so we don't spawn a new session.
              intentionalCloseRef.current = true;
              onSessionEndedRef.current?.(sessionId);
              return;
            }
          } catch {
            // not JSON, fall through
          }
        }
        term.write(data);
      }
    };

    ws.onclose = () => {
      if (wsRef.current !== ws) return;
      wsRef.current = null;
      onDisconnectRef.current?.();

      if (!intentionalCloseRef.current) {
        const attempt = reconnectAttemptRef.current;
        const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
        reconnectAttemptRef.current = attempt + 1;
        reconnectTimerRef.current = setTimeout(() => {
          reconnectTimerRef.current = null;
          connectRef.current?.();
        }, delay);
      }
    };

    ws.onerror = () => {
      if (wsRef.current === ws) ws.close();
    };
  }, [sessionId]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    intentionalCloseRef.current = false;
    reconnectAttemptRef.current = 0;
    if (dimsRef.current) connect();

    return () => {
      intentionalCloseRef.current = true;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      const ws = wsRef.current;
      wsRef.current = null;
      ws?.close();
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
    const ws = wsRef.current;
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "resize", cols, rows }));
    } else if (!ws && reconnectAttemptRef.current === 0 && !intentionalCloseRef.current) {
      // autoResize has now measured the rendered terminal. This is the first
      // safe point to attach tmux without briefly forcing it to 80x24.
      connectRef.current?.();
    }
  }, []);

  const syncSelection = useCallback(() => {
    const wrapper = wrapperRef.current;
    const text = wrapper ? getSelectionTextInside(wrapper) : "";
    selectedTextRef.current = text;

    const has = text.length > 0;
    setHasSelection(has);
    setCopied(false);
    if (!has) setCopyBtnPos(null);
    return text;
  }, []);

  const anchorCopyButton = useCallback(
    (clientX: number, clientY: number) => {
      const wrapper = wrapperRef.current;
      if (!wrapper) return;

      requestAnimationFrame(() => {
        const text = syncSelection();
        if (!text) return;

        const rect = wrapper.getBoundingClientRect();
        const buttonWidth = 84;
        const buttonHeight = 32;
        const gap = 8;
        let x = clientX - rect.left + gap;
        let y = clientY - rect.top + gap;

        if (x + buttonWidth > rect.width) x = clientX - rect.left - buttonWidth - gap;
        if (y + buttonHeight > rect.height) y = clientY - rect.top - buttonHeight - gap;
        x = Math.max(4, Math.min(x, Math.max(4, rect.width - buttonWidth - 4)));
        y = Math.max(4, Math.min(y, Math.max(4, rect.height - buttonHeight - 4)));

        setCopyBtnPos({ x, y });
      });
    },
    [syncSelection]
  );

  useEffect(() => {
    const onSelectionChange = () => {
      syncSelection();
    };

    const onPointerUp = (event: PointerEvent) => {
      const target = event.target;
      if (target instanceof Element && target.closest("[data-terminal-copy-button='true']")) {
        return;
      }
      anchorCopyButton(event.clientX, event.clientY);
    };

    document.addEventListener("selectionchange", onSelectionChange);
    document.addEventListener("pointerup", onPointerUp);
    return () => {
      document.removeEventListener("selectionchange", onSelectionChange);
      document.removeEventListener("pointerup", onPointerUp);
    };
  }, [anchorCopyButton, syncSelection]);

  const handleCopy = useCallback(async () => {
    const wrapper = wrapperRef.current;
    const text = selectedTextRef.current || (wrapper ? getSelectionTextInside(wrapper) : "");
    if (!text) return;

    const finish = () => {
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
        setCopyBtnPos(null);
      }, 1200);
    };

    try {
      await navigator.clipboard.writeText(text);
      finish();
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      finish();
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
      ref={wrapperRef}
      className="h-full w-full relative"
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <Terminal
        ref={termRef}
        cols={1}
        rows={1}
        autoResize
        wasmUrl="/wterm.wasm"
        onData={handleData}
        onResize={handleResize}
        className="h-full w-full"
        style={{ backgroundColor: "#0a0b10" }}
      />

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

      {hasSelection && copyBtnPos && (
        <button
          type="button"
          data-terminal-copy-button="true"
          aria-label={copied ? "copied selection" : "copy selection"}
          onClick={handleCopy}
          onPointerDown={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
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

      {uploadStatus && (
        <div className="absolute bottom-4 left-1/2 -translate-x-1/2 px-3 py-1.5 rounded bg-[#14161e] border border-[#1a1d24] text-[12px] text-[#e6f0e4] shadow-lg z-50">
          {uploadStatus}
        </div>
      )}
    </div>
  );
}
