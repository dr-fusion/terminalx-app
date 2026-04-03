import { execSync, exec } from "child_process";

export interface TmuxSession {
  name: string;
  windows: number;
  attached: boolean;
  created: string;
}

const TMUX_BIN = "tmux";

function sanitizeSessionName(name: string): string {
  // tmux session names: alphanumeric, underscore, hyphen, dot
  if (!/^[a-zA-Z0-9_.\-]+$/.test(name)) {
    throw new Error(
      "Invalid session name: only alphanumeric, underscore, hyphen, and dot allowed"
    );
  }
  if (name.length > 128) {
    throw new Error("Session name too long (max 128 characters)");
  }
  return name;
}

export function listSessions(): TmuxSession[] {
  try {
    const output = execSync(
      [
        TMUX_BIN,
        "list-sessions",
        "-F",
        "#{session_name}\t#{session_windows}\t#{session_attached}\t#{session_created}",
      ].join(" "),
      { encoding: "utf-8", timeout: 5000 }
    );

    return output
      .trim()
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => {
        const [name, windows, attached, created] = line.split("\t");
        return {
          name,
          windows: parseInt(windows, 10),
          attached: attached === "1",
          created: new Date(parseInt(created, 10) * 1000).toISOString(),
        };
      });
  } catch (err: unknown) {
    // tmux returns error when no server is running
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("no server running") || message.includes("no sessions")) {
      return [];
    }
    throw err;
  }
}

export function createSession(name: string): void {
  const safeName = sanitizeSessionName(name);
  execSync(
    [TMUX_BIN, "new-session", "-d", "-s", safeName].join(" "),
    { encoding: "utf-8", timeout: 5000 }
  );
}

export function killSession(name: string): void {
  const safeName = sanitizeSessionName(name);
  execSync(
    [TMUX_BIN, "kill-session", "-t", safeName].join(" "),
    { encoding: "utf-8", timeout: 5000 }
  );
}

export function renameSession(oldName: string, newName: string): void {
  const safeOld = sanitizeSessionName(oldName);
  const safeNew = sanitizeSessionName(newName);
  execSync(
    [TMUX_BIN, "rename-session", "-t", safeOld, safeNew].join(" "),
    { encoding: "utf-8", timeout: 5000 }
  );
}

export function hasSession(name: string): boolean {
  const safeName = sanitizeSessionName(name);
  try {
    execSync(
      [TMUX_BIN, "has-session", "-t", safeName].join(" "),
      { encoding: "utf-8", timeout: 5000 }
    );
    return true;
  } catch {
    return false;
  }
}
