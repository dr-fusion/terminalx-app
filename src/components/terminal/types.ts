export interface TerminalViewProps {
  sessionId: string;
  onDisconnect?: () => void;
  onReconnect?: () => void;
}

export type TerminalEngine = "xterm" | "wterm";
