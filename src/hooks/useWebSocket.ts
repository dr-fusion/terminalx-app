"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type ReadyState = "connecting" | "open" | "closing" | "closed";

interface UseWebSocketOptions {
  /** Called when a message is received */
  onMessage?: (data: string | ArrayBuffer) => void;
  /** Called when connection opens */
  onOpen?: () => void;
  /** Called when connection closes */
  onClose?: () => void;
  /** Called on connection error */
  onError?: (event: Event) => void;
  /** Whether to auto-reconnect on disconnect (default true) */
  reconnect?: boolean;
  /** Maximum reconnect delay in ms (default 30000) */
  maxReconnectDelay?: number;
  /** Use binary messages (default false) */
  binaryType?: BinaryType;
}

interface UseWebSocketReturn {
  send: (data: string | ArrayBuffer | Blob) => void;
  lastMessage: string | ArrayBuffer | null;
  readyState: ReadyState;
  disconnect: () => void;
}

export function useWebSocket(
  url: string | null,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    onMessage,
    onOpen,
    onClose,
    onError,
    reconnect = true,
    maxReconnectDelay = 30000,
    binaryType = "arraybuffer",
  } = options;

  const [readyState, setReadyState] = useState<ReadyState>("closed");
  const [lastMessage, setLastMessage] = useState<string | ArrayBuffer | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const intentionalCloseRef = useRef(false);

  // Store callbacks in refs to avoid reconnect loops
  const onMessageRef = useRef(onMessage);
  const onOpenRef = useRef(onOpen);
  const onCloseRef = useRef(onClose);
  const onErrorRef = useRef(onError);
  const connectRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);
  useEffect(() => {
    onOpenRef.current = onOpen;
  }, [onOpen]);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);
  useEffect(() => {
    onErrorRef.current = onError;
  }, [onError]);

  const connect = useCallback(() => {
    if (!url) return;

    // Build absolute WebSocket URL
    const wsUrl = url.startsWith("ws")
      ? url
      : `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}${url}`;

    setReadyState("connecting");

    const ws = new WebSocket(wsUrl);
    ws.binaryType = binaryType;
    wsRef.current = ws;

    ws.onopen = () => {
      setReadyState("open");
      reconnectAttemptRef.current = 0;
      onOpenRef.current?.();
    };

    ws.onmessage = (event) => {
      setLastMessage(event.data);
      onMessageRef.current?.(event.data);
    };

    ws.onerror = (event) => {
      onErrorRef.current?.(event);
    };

    ws.onclose = () => {
      setReadyState("closed");
      wsRef.current = null;
      onCloseRef.current?.();

      // Auto-reconnect with exponential backoff
      if (reconnect && !intentionalCloseRef.current) {
        const attempt = reconnectAttemptRef.current;
        const delay = Math.min(1000 * Math.pow(2, attempt), maxReconnectDelay);
        reconnectAttemptRef.current = attempt + 1;

        reconnectTimerRef.current = setTimeout(() => {
          connectRef.current?.();
        }, delay);
      }
    };
  }, [url, reconnect, maxReconnectDelay, binaryType]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  const disconnect = useCallback(() => {
    intentionalCloseRef.current = true;
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setReadyState("closed");
  }, []);

  const send = useCallback((data: string | ArrayBuffer | Blob) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(data);
    }
  }, []);

  useEffect(() => {
    intentionalCloseRef.current = false;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- connect() intentionally opens WS and may setState(CONNECTING) on mount
    connect();
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return { send, lastMessage, readyState, disconnect };
}
