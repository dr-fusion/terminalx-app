export interface TerminalViewProps {
  sessionId: string;
  onDisconnect?: () => void;
  onReconnect?: () => void;
  onSessionEnded?: (sessionId: string) => void;
}

export type TerminalEngine = "xterm" | "wterm";
