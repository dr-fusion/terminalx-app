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

/**
 * Capture the last N lines of a session's scrollback as a single chunk,
 * with ANSI escape codes preserved (colors, cursor movement).
 *
 * We use this at WS attach time to seed xterm.js's scrollback buffer so
 * the user can scroll up with the mouse wheel / touch swipe to see history,
 * without needing tmux's mouse-mode (which would break browser-native
 * text selection + Cmd+C copy).
 */
export function capturePaneHistory(name: string, lines = 10000): string {
  const safeName = sanitizeSessionName(name);
  try {
    return execFileSync(
      TMUX_BIN,
      ["capture-pane", "-p", "-e", "-J", "-S", `-${lines}`, "-t", safeName],
      { encoding: "utf-8", timeout: 5000, maxBuffer: 16 * 1024 * 1024 }
    );
  } catch {
    return "";
  }
}

/**
 * Capture only the *visible* pane — the live screen the user would see if
 * they were attached. No history padding, no scrollback. Used by the
 * Telegram streamer to render a screen snapshot every few seconds.
 */
export function captureVisiblePane(name: string): string {
  const safeName = sanitizeSessionName(name);
  try {
    return execFileSync(TMUX_BIN, ["capture-pane", "-p", "-e", "-J", "-t", safeName], {
      encoding: "utf-8",
      timeout: 5000,
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch {
    return "";
  }
}

/**
 * True when the pane's foreground program is using the alternate screen
 * buffer (vim, htop, less, etc.). Note: Claude Code renders in the main
 * buffer so this returns false for it — see `paneForegroundCommand` /
 * `isPaneTui` for a more reliable TUI check.
 */
export function isPaneAlternate(name: string): boolean {
  const safeName = sanitizeSessionName(name);
  try {
    const out = execFileSync(
      TMUX_BIN,
      ["display-message", "-p", "-t", safeName, "#{alternate_on}"],
      { encoding: "utf-8", timeout: 2000 }
    );
    return out.trim() === "1";
  } catch {
    return false;
  }
}

/**
 * The basename of the pane's foreground process — what `tmux
 * display-message #{pane_current_command}` returns. Empty string on
 * failure.
 */
export function paneForegroundCommand(name: string): string {
  const safeName = sanitizeSessionName(name);
  try {
    return execFileSync(
      TMUX_BIN,
      ["display-message", "-p", "-t", safeName, "#{pane_current_command}"],
      { encoding: "utf-8", timeout: 2000 }
    ).trim();
  } catch {
    return "";
  }
}

const SHELL_COMMANDS = new Set(["bash", "zsh", "sh", "fish", "dash", "ash", "ksh", "tcsh"]);

/**
 * Heuristic: is the pane currently running something other than a plain
 * shell? Used to decide whether chat-mode line-diffing is going to be
 * useful (it isn't, against any TUI app — claude code, vim, htop, less).
 */
export function isPaneTui(name: string): boolean {
  if (isPaneAlternate(name)) return true;
  const cmd = paneForegroundCommand(name);
  if (!cmd) return false;
  return !SHELL_COMMANDS.has(cmd);
}

/**
 * Raise tmux's per-session scrollback limit for any session the server
 * creates from now on. Runs at server startup; also invoked defensively
 * from createSession. Failures are ignored (e.g. no tmux server running
 * yet — the next new-session call will start one and pick up the option).
 */
export function applyGlobalOptions(historyLimit = 50000): void {
  try {
    execFileSync(TMUX_BIN, ["set-option", "-g", "history-limit", String(historyLimit)], {
      encoding: "utf-8",
      timeout: 2000,
    });
  } catch {
    // no tmux server or option not supported — ignore
  }
}

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
  // Idempotent: raises the history-limit option on whatever tmux server
  // this call is about to touch. Guarantees deep scrollback on the very
  // first session a server ever creates.
  applyGlobalOptions();
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

/**
 * Unix-epoch milliseconds at which the named session was created. Used by
 * the Telegram JSONL router to match a topic to its own claude transcript
 * file (claude writes one JSONL per session, file ctime ≈ session start).
 */
export function getSessionCreatedMs(name: string): number | null {
  const safeName = sanitizeSessionName(name);
  try {
    const out = execFileSync(
      TMUX_BIN,
      ["display-message", "-p", "-t", safeName, "#{session_created}"],
      { encoding: "utf-8", timeout: 2000 }
    );
    const secs = parseInt(out.trim(), 10);
    return Number.isFinite(secs) && secs > 0 ? secs * 1000 : null;
  } catch {
    return null;
  }
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
