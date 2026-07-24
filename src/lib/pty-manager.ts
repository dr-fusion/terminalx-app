import * as pty from "node-pty";
import { randomUUID } from "node:crypto";
import { hasSession, isValidTmuxSessionName, tmuxTarget } from "./tmux";
import { CANONICAL_TMUX_CONFIG_FILE, canonicalTmuxTarget } from "./runtime";

export interface CanonicalPtyBinding {
  teamSessionId: string;
  runtimeAuthorizationGeneration: number;
  tmuxSocketName: string;
  readOnly: boolean;
}

export interface PtyInstance {
  id: string;
  sessionName: string;
  process: pty.IPty;
  createdAt: Date;
  canonicalBinding?: CanonicalPtyBinding;
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
    throw new Error(`Maximum number of PTY sessions reached (${maxSessions})`);
  }

  if (!isValidTmuxSessionName(sessionName)) {
    throw new Error("Invalid session name");
  }

  if (!hasSession(sessionName)) {
    throw new Error("Session does not exist. Create it from the dashboard first.");
  }

  return spawnPty(sessionName, shell, cols, rows, [
    "attach-session",
    "-t",
    tmuxTarget(sessionName),
  ]);
}

export function createCanonicalPty(
  sessionName: string,
  shell: string,
  cols: number,
  rows: number,
  binding: CanonicalPtyBinding
): PtyInstance {
  if (activePtys.size >= maxSessions) {
    throw new Error(`Maximum number of PTY sessions reached (${maxSessions})`);
  }
  if (!isValidTmuxSessionName(sessionName)) throw new Error("Invalid session name");
  if (
    !binding.teamSessionId ||
    binding.teamSessionId.length > 256 ||
    /[\0\r\n\t]/.test(binding.teamSessionId) ||
    !Number.isSafeInteger(binding.runtimeAuthorizationGeneration) ||
    binding.runtimeAuthorizationGeneration < 1 ||
    !/^[a-zA-Z0-9_-]{1,64}$/.test(binding.tmuxSocketName) ||
    typeof binding.readOnly !== "boolean"
  ) {
    throw new Error("Invalid canonical PTY binding");
  }
  const args = [
    "-L",
    binding.tmuxSocketName,
    "-f",
    CANONICAL_TMUX_CONFIG_FILE,
    "attach-session",
    "-E",
  ];
  if (binding.readOnly) args.push("-r");
  args.push("-t", canonicalTmuxTarget(sessionName));
  return spawnPty(sessionName, shell, cols, rows, args, Object.freeze({ ...binding }));
}

function spawnPty(
  sessionName: string,
  shell: string,
  cols: number,
  rows: number,
  args: string[],
  canonicalBinding?: CanonicalPtyBinding
): PtyInstance {
  const id = `pty-${sessionName}-${randomUUID()}`;

  // Build a sanitized environment for PTY processes.
  // NEVER spread process.env — it contains server secrets (JWT secret, admin password, etc.)
  const safeEnvKeys = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_COLLATE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_MONETARY",
    "TZ",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "LESS",
    "LESSOPEN",
    "LESSCLOSE",
    "COLORTERM",
    "DISPLAY",
    "SSH_AUTH_SOCK",
    "XDG_RUNTIME_DIR",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "TERMINUS_ROOT",
  ];
  const safeEnv: Record<string, string> = {};
  for (const key of safeEnvKeys) {
    if (process.env[key]) {
      safeEnv[key] = process.env[key] as string;
    }
  }
  safeEnv.TERM = "xterm-256color";
  safeEnv.SHELL = shell;

  const proc = pty.spawn("tmux", args, {
    name: "xterm-256color",
    cols: Math.max(1, Math.min(cols, 500)),
    rows: Math.max(1, Math.min(rows, 200)),
    cwd: process.env.TERMINUS_ROOT || process.env.HOME || "/",
    env: safeEnv,
  });

  const instance: PtyInstance = {
    id,
    sessionName,
    process: proc,
    createdAt: new Date(),
    ...(canonicalBinding ? { canonicalBinding } : {}),
  };

  activePtys.set(id, instance);

  // Auto-cleanup when process exits
  proc.onExit(() => {
    activePtys.delete(id);
  });

  return instance;
}

export function destroyCanonicalPtys(input: {
  teamSessionId: string;
  runtimeAuthorizationGeneration: number;
  includeCurrentGeneration?: boolean;
}): number {
  let destroyed = 0;
  for (const instance of [...activePtys.values()]) {
    const binding = instance.canonicalBinding;
    if (!binding || binding.teamSessionId !== input.teamSessionId) continue;
    const stale = input.includeCurrentGeneration
      ? binding.runtimeAuthorizationGeneration <= input.runtimeAuthorizationGeneration
      : binding.runtimeAuthorizationGeneration < input.runtimeAuthorizationGeneration;
    if (!stale) continue;
    destroyPty(instance.id);
    destroyed += 1;
  }
  return destroyed;
}

export function resizePty(id: string, cols: number, rows: number): void {
  const instance = activePtys.get(id);
  if (!instance) {
    throw new Error(`PTY not found: ${id}`);
  }
  instance.process.resize(Math.max(1, Math.min(cols, 500)), Math.max(1, Math.min(rows, 200)));
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
