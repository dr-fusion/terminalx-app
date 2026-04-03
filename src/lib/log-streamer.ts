import { spawn, ChildProcess } from "child_process";
import { EventEmitter } from "events";
import * as fs from "fs";
import * as path from "path";

export interface LogStream {
  id: string;
  filePath: string;
  emitter: EventEmitter;
}

export interface LogFileEntry {
  name: string;
  path: string;
  size: number;
  modified: string;
}

const activeStreams = new Map<string, { stream: LogStream; process: ChildProcess }>();

let streamIdCounter = 0;

function getLogPaths(): string[] {
  const raw = process.env.TERMINUS_LOG_PATHS || "/var/log,~/.pm2/logs";
  return raw.split(",").map((p) => {
    const trimmed = p.trim();
    if (trimmed.startsWith("~")) {
      return path.join(process.env.HOME || "/", trimmed.slice(1));
    }
    return path.resolve(trimmed);
  });
}

/**
 * Validate that a file path is within one of the allowed log directories.
 */
function validateLogPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  const allowedDirs = getLogPaths();

  const isAllowed = allowedDirs.some(
    (dir) => resolved.startsWith(dir + path.sep) || resolved === dir
  );

  if (!isAllowed) {
    throw new Error("Path is not within allowed log directories");
  }

  return resolved;
}

export function createLogStream(filePath: string): LogStream {
  const safePath = validateLogPath(filePath);

  if (!fs.existsSync(safePath)) {
    throw new Error("Log file does not exist");
  }

  const stats = fs.statSync(safePath);
  if (!stats.isFile()) {
    throw new Error("Path is not a file");
  }

  const id = `log-${++streamIdCounter}-${Date.now()}`;
  const emitter = new EventEmitter();

  // Spawn tail -f using argument array (no shell interpolation)
  const tailProcess = spawn("tail", ["-f", "-n", "100", safePath], {
    stdio: ["ignore", "pipe", "pipe"],
  });

  tailProcess.stdout.on("data", (data: Buffer) => {
    emitter.emit("data", data.toString("utf-8"));
  });

  tailProcess.stderr.on("data", (data: Buffer) => {
    emitter.emit("error", data.toString("utf-8"));
  });

  tailProcess.on("close", (code) => {
    emitter.emit("close", code);
    activeStreams.delete(id);
  });

  tailProcess.on("error", (err) => {
    emitter.emit("error", err.message);
    activeStreams.delete(id);
  });

  const stream: LogStream = { id, filePath: safePath, emitter };
  activeStreams.set(id, { stream, process: tailProcess });

  return stream;
}

export function destroyLogStream(id: string): void {
  const entry = activeStreams.get(id);
  if (!entry) return;

  try {
    entry.process.kill("SIGTERM");
  } catch {
    // Process may already be dead
  }
  entry.stream.emitter.removeAllListeners();
  activeStreams.delete(id);
}

export function listLogFiles(): LogFileEntry[] {
  const logPaths = getLogPaths();
  const results: LogFileEntry[] = [];

  for (const dir of logPaths) {
    try {
      if (!fs.existsSync(dir)) continue;

      const stats = fs.statSync(dir);
      if (!stats.isDirectory()) continue;

      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (
          entry.isFile() &&
          (entry.name.endsWith(".log") ||
            entry.name.endsWith(".out") ||
            entry.name.endsWith(".err"))
        ) {
          const fullPath = path.join(dir, entry.name);
          try {
            const fileStat = fs.statSync(fullPath);
            results.push({
              name: entry.name,
              path: fullPath,
              size: fileStat.size,
              modified: fileStat.mtime.toISOString(),
            });
          } catch {
            // Skip files we can't stat
          }
        }
      }
    } catch {
      // Skip directories we can't read
    }
  }

  return results.sort((a, b) => a.name.localeCompare(b.name));
}

export function destroyAllLogStreams(): void {
  for (const [id] of activeStreams) {
    destroyLogStream(id);
  }
}
