import * as pty from "node-pty";
import { hasSession, createSession } from "./tmux";

export interface PtyInstance {
  id: string;
  sessionName: string;
  process: pty.IPty;
  createdAt: Date;
}

const activePtys = new Map<string, PtyInstance>();

let maxSessions = 20;

export function setMaxSessions(max: number): void {
  maxSessions = max;
}

export function getMaxSessions(): number {
  return maxSessions;
}

export function getActivePtyCount(): number {
  return activePtys.size;
}

export function createPty(
  sessionName: string,
  shell: string,
  cols: number,
  rows: number
): PtyInstance {
  if (activePtys.size >= maxSessions) {
    throw new Error(
      `Maximum number of PTY sessions reached (${maxSessions})`
    );
  }

  // Validate sessionName
  if (!/^[a-zA-Z0-9_.\-]+$/.test(sessionName)) {
    throw new Error("Invalid session name");
  }

  // Ensure the tmux session exists
  if (!hasSession(sessionName)) {
    createSession(sessionName);
  }

  const id = `pty-${sessionName}-${Date.now()}`;

  // Spawn node-pty that attaches to the tmux session
  const proc = pty.spawn("tmux", ["attach-session", "-t", sessionName], {
    name: "xterm-256color",
    cols: Math.max(1, Math.min(cols, 500)),
    rows: Math.max(1, Math.min(rows, 200)),
    cwd: process.env.TERMINUS_ROOT || process.env.HOME || "/",
    env: {
      ...process.env,
      TERM: "xterm-256color",
      SHELL: shell,
    } as Record<string, string>,
  });

  const instance: PtyInstance = {
    id,
    sessionName,
    process: proc,
    createdAt: new Date(),
  };

  activePtys.set(id, instance);

  // Auto-cleanup when process exits
  proc.onExit(() => {
    activePtys.delete(id);
  });

  return instance;
}

export function resizePty(id: string, cols: number, rows: number): void {
  const instance = activePtys.get(id);
  if (!instance) {
    throw new Error(`PTY not found: ${id}`);
  }
  instance.process.resize(
    Math.max(1, Math.min(cols, 500)),
    Math.max(1, Math.min(rows, 200))
  );
}

export function destroyPty(id: string): void {
  const instance = activePtys.get(id);
  if (!instance) {
    return;
  }
  try {
    instance.process.kill();
  } catch {
    // Process may already be dead
  }
  activePtys.delete(id);
}

export function getPty(id: string): PtyInstance | undefined {
  return activePtys.get(id);
}

export function listPtys(): PtyInstance[] {
  return Array.from(activePtys.values());
}

export function destroyAllPtys(): void {
  for (const [id] of activePtys) {
    destroyPty(id);
  }
}
