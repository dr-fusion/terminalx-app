import { execFileSync } from "child_process";

export interface TmuxSession {
  name: string;
  windows: number;
  attached: boolean;
  created: string;
  lastActivity?: string;
  activePath?: string;
}

const TMUX_BIN = "tmux";

function sanitizeSessionName(name: string): string {
  // tmux session names: alphanumeric, underscore, hyphen, dot
  if (!/^[a-zA-Z0-9_.\-]+$/.test(name)) {
    throw new Error("Invalid session name: only alphanumeric, underscore, hyphen, and dot allowed");
  }
  if (name.length > 128) {
    throw new Error("Session name too long (max 128 characters)");
  }
  return name;
}

export function listSessions(): TmuxSession[] {
  try {
    const output = execFileSync(
      TMUX_BIN,
      [
        "list-sessions",
        "-F",
        "#{session_name}\t#{session_windows}\t#{session_attached}\t#{session_created}\t#{session_activity}\t#{session_path}",
      ],
      { encoding: "utf-8", timeout: 5000 }
    );

    return output
      .trim()
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => {
        const [name = "", windows = "0", attached = "0", created = "0", activity = "0", path = ""] =
          line.split("\t");
        const createdN = parseInt(created, 10);
        const activityN = parseInt(activity, 10);
        return {
          name,
          windows: parseInt(windows, 10),
          attached: attached === "1",
          created: new Date(createdN * 1000).toISOString(),
          lastActivity: activityN > 0 ? new Date(activityN * 1000).toISOString() : undefined,
          activePath: path || undefined,
        };
      });
  } catch (err: unknown) {
    // tmux returns error when no server is running
    const message = err instanceof Error ? err.message : String(err);
    if (
      message.includes("no server running") ||
      message.includes("no sessions") ||
      message.includes("No such file or directory") ||
      message.includes("error connecting")
    ) {
      return [];
    }
    throw err;
  }
}

export function createSession(name: string, command?: string, cwd?: string): void {
  const safeName = sanitizeSessionName(name);
  const args = ["new-session", "-d", "-s", safeName];
  if (cwd) {
    args.push("-c", cwd);
  }
  if (command) {
    args.push(command);
  }
  execFileSync(TMUX_BIN, args, {
    encoding: "utf-8",
    timeout: 5000,
  });
}

export function killSession(name: string): void {
  const safeName = sanitizeSessionName(name);
  execFileSync(TMUX_BIN, ["kill-session", "-t", safeName], {
    encoding: "utf-8",
    timeout: 5000,
  });
}

export function renameSession(oldName: string, newName: string): void {
  const safeOld = sanitizeSessionName(oldName);
  const safeNew = sanitizeSessionName(newName);
  execFileSync(TMUX_BIN, ["rename-session", "-t", safeOld, safeNew], {
    encoding: "utf-8",
    timeout: 5000,
  });
}

export function hasSession(name: string): boolean {
  const safeName = sanitizeSessionName(name);
  try {
    execFileSync(TMUX_BIN, ["has-session", "-t", safeName], {
      encoding: "utf-8",
      timeout: 5000,
    });
    return true;
  } catch {
    return false;
  }
}
