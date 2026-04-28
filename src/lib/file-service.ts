import * as fs from "fs";
import * as path from "path";

const MAX_FILE_SIZE = 1 * 1024 * 1024; // 1MB
const SENSITIVE_DATA_FILES = new Set([
  "users.json",
  ".revoked-tokens.json",
  "telegram-state.json",
  "ai-sessions.json",
  "snippets.json",
]);

export interface FileEntry {
  name: string;
  path: string;
  type: "file" | "directory" | "symlink" | "other";
  size: number;
  modified: string;
}

export interface FileInfo {
  name: string;
  path: string;
  type: "file" | "directory" | "symlink" | "other";
  size: number;
  modified: string;
  created: string;
  permissions: string;
}

function getTerminusRoot(): string {
  return path.resolve(process.env.TERMINUS_ROOT || process.env.HOME || "/");
}

function sensitiveFileAccessAllowed(): boolean {
  return process.env.TERMINALX_ALLOW_SENSITIVE_FILE_ACCESS === "true";
}

export function isSensitivePath(filePath: string): boolean {
  if (sensitiveFileAccessAllowed()) return false;

  const root = getTerminusRoot();
  const resolved = path.resolve(filePath);
  const rel = path.relative(root, resolved);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return false;

  const parts = rel.split(path.sep).filter(Boolean);
  const base = parts[parts.length - 1] || "";

  if (base === ".env" || base.startsWith(".env.")) return true;
  if (base === ".terminalx-secret") return true;
  if (parts.includes(".git") || parts.includes(".ssh") || parts.includes(".gnupg")) return true;
  if (parts.length >= 2 && parts[0] === ".config" && parts[1] === "secrets") return true;
  const secondPart = parts[1];
  if (
    parts.length >= 2 &&
    parts[0] === "data" &&
    secondPart &&
    SENSITIVE_DATA_FILES.has(secondPart)
  ) {
    return true;
  }

  return false;
}

export function assertNotSensitivePath(filePath: string): void {
  if (isSensitivePath(filePath)) {
    throw new Error("Access denied to sensitive path");
  }
}

/**
 * Resolve and validate a path to ensure it's within TERMINUS_ROOT.
 * Prevents directory traversal attacks.
 */
export function resolveSafePath(requestedPath: string): string {
  const root = getTerminusRoot();

  // Handle empty, ".", "/", "~" as root
  if (!requestedPath || requestedPath === "." || requestedPath === "/" || requestedPath === "~") {
    return root;
  }

  // Expand ~ to root
  const expanded = requestedPath.startsWith("~/")
    ? path.join(root, requestedPath.slice(2))
    : path.resolve(root, requestedPath);

  // Ensure the resolved path is within or equal to root
  if (!expanded.startsWith(root + path.sep) && expanded !== root) {
    throw new Error("Path is outside the allowed root directory");
  }

  // Follow symlinks and re-check to prevent symlink traversal
  try {
    const realPath = fs.realpathSync(expanded);
    if (!realPath.startsWith(root + path.sep) && realPath !== root) {
      throw new Error("Path is outside the allowed root directory");
    }
    return realPath;
  } catch (err) {
    // realpathSync throws if the path doesn't exist yet (e.g. new file creation).
    // In that case the initial check above is sufficient since no symlink exists.
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return expanded;
    }
    throw err;
  }
}

function entryType(dirent: fs.Dirent): "file" | "directory" | "symlink" | "other" {
  if (dirent.isSymbolicLink()) return "symlink";
  if (dirent.isDirectory()) return "directory";
  if (dirent.isFile()) return "file";
  return "other";
}

function statType(stats: fs.Stats): "file" | "directory" | "symlink" | "other" {
  if (stats.isSymbolicLink()) return "symlink";
  if (stats.isDirectory()) return "directory";
  if (stats.isFile()) return "file";
  return "other";
}

export function listDirectory(requestedPath: string): FileEntry[] {
  const safePath = resolveSafePath(requestedPath);
  assertNotSensitivePath(safePath);

  const stats = fs.statSync(safePath);
  if (!stats.isDirectory()) {
    throw new Error("Path is not a directory");
  }

  const entries = fs.readdirSync(safePath, { withFileTypes: true });

  return entries
    .map((entry) => {
      try {
        const entryPath = path.join(safePath, entry.name);
        if (isSensitivePath(entryPath)) return null;
        const stat = fs.statSync(entryPath);
        return {
          name: entry.name,
          path: entryPath,
          type: entryType(entry),
          size: stat.size,
          modified: stat.mtime.toISOString(),
        };
      } catch {
        // Skip entries we can't stat (e.g. broken symlinks)
        return null;
      }
    })
    .filter((entry): entry is FileEntry => entry !== null)
    .sort((a, b) => {
      // Directories first, then alphabetical
      if (a.type === "directory" && b.type !== "directory") return -1;
      if (a.type !== "directory" && b.type === "directory") return 1;
      return a.name.localeCompare(b.name);
    });
}

export function readFile(requestedPath: string): string {
  const safePath = resolveSafePath(requestedPath);
  assertNotSensitivePath(safePath);

  const stats = fs.statSync(safePath);
  if (!stats.isFile()) {
    throw new Error("Path is not a file");
  }

  if (stats.size > MAX_FILE_SIZE) {
    throw new Error(
      `File too large (${(stats.size / 1024 / 1024).toFixed(1)}MB). Maximum is ${MAX_FILE_SIZE / 1024 / 1024}MB`
    );
  }

  return fs.readFileSync(safePath, "utf-8");
}

export function getFileInfo(requestedPath: string): FileInfo {
  const safePath = resolveSafePath(requestedPath);
  assertNotSensitivePath(safePath);

  const stats = fs.lstatSync(safePath);

  return {
    name: path.basename(safePath),
    path: safePath,
    type: statType(stats),
    size: stats.size,
    modified: stats.mtime.toISOString(),
    created: stats.birthtime.toISOString(),
    permissions: (stats.mode & 0o777).toString(8),
  };
}
