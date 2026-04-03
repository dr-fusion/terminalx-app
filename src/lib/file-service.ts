import * as fs from "fs";
import * as path from "path";

const MAX_FILE_SIZE = 1 * 1024 * 1024; // 1MB

export interface FileEntry {
  name: string;
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

/**
 * Resolve and validate a path to ensure it's within TERMINUS_ROOT.
 * Prevents directory traversal attacks.
 */
export function resolveSafePath(requestedPath: string): string {
  const root = getTerminusRoot();
  const resolved = path.resolve(root, requestedPath);

  // Ensure the resolved path is within or equal to root
  if (!resolved.startsWith(root + path.sep) && resolved !== root) {
    throw new Error("Path is outside the allowed root directory");
  }

  return resolved;
}

function entryType(
  dirent: fs.Dirent
): "file" | "directory" | "symlink" | "other" {
  if (dirent.isSymbolicLink()) return "symlink";
  if (dirent.isDirectory()) return "directory";
  if (dirent.isFile()) return "file";
  return "other";
}

function statType(
  stats: fs.Stats
): "file" | "directory" | "symlink" | "other" {
  if (stats.isSymbolicLink()) return "symlink";
  if (stats.isDirectory()) return "directory";
  if (stats.isFile()) return "file";
  return "other";
}

export function listDirectory(requestedPath: string): FileEntry[] {
  const safePath = resolveSafePath(requestedPath);

  const stats = fs.statSync(safePath);
  if (!stats.isDirectory()) {
    throw new Error("Path is not a directory");
  }

  const entries = fs.readdirSync(safePath, { withFileTypes: true });

  return entries
    .map((entry) => {
      try {
        const entryPath = path.join(safePath, entry.name);
        const stat = fs.statSync(entryPath);
        return {
          name: entry.name,
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
