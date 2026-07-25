import type { HostedTeamSessionTerminalBinding } from "../team-session-terminal-gateway";

/** Provider-neutral hosted terminal exposed to the canonical WebSocket layer. */
export interface HostedTerminalConnection {
  /** Echoed immutable plan identity; a mismatch fails the attach closed. */
  readonly binding: HostedTeamSessionTerminalBinding;
  onData(listener: (data: string) => void): { dispose(): void };
  onExit(listener: () => void): { dispose(): void };
  input(data: string, signal: AbortSignal): Promise<void>;
  resize(cols: number, rows: number, signal: AbortSignal): Promise<void>;
  interrupt(signal: AbortSignal): Promise<void>;
  destroy(): Promise<void>;
}

/** Provider IDs, transport credentials, and provider errors stay behind this port. */
export interface HostedTerminalAdapter {
  connect(options: {
    binding: HostedTeamSessionTerminalBinding;
    cols: number;
    rows: number;
    signal: AbortSignal;
  }): Promise<HostedTerminalConnection>;
}
