import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { execFileSync } from "child_process";
import { assertNotSensitivePath, getTerminusRoot, resolveSafePath } from "./file-service";

const GIT_TIMEOUT_MS = 5000;
const GIT_REFRESH_TIMEOUT_MS = 60000;
const GIT_WORKTREE_TIMEOUT_MS = 20000;
const WORKTREE_BASE_BRANCH = "main";

export interface GitDirectoryInfo {
  isRepo: boolean;
  root?: string;
  branch?: string;
  repoName?: string;
}

export interface CreatedGitWorktree {
  repoRoot: string;
  worktreePath: string;
  startDir: string;
  branch: string;
  /**
   * Absolute paths, inside the worktree, that were linked (or copied) from the
   * shared source repo root. Reported back so the caller can persist them and
   * removeGitWorktree can drop them without touching the shared source.
   */
  linkedPaths: string[];
}

export interface CreateGitWorktreeOptions {
  /**
   * Repo-root-relative paths (e.g. "node_modules", "build/.cache") to share
   * into the new worktree via symlink, falling back to a recursive copy when
   * the symlink syscall fails. When omitted, defaults to the comma-separated
   * list in the TERMINALX_WORKTREE_SYMLINK_PATHS env var.
   */
  symlinkPaths?: string[];
}

export interface RestoredGitWorktree {
  repoRoot: string;
  worktreePath: string;
  branch: string;
  /** Absolute paths inside the restored worktree re-linked from the shared source. */
  linkedPaths: string[];
}

function git(args: string[], timeout = GIT_TIMEOUT_MS): string {
  return execFileSync("git", args, {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout,
    maxBuffer: 4 * 1024 * 1024,
  }).trim();
}

function gitErrorMessage(err: unknown): string {
  const e = err as { stderr?: Buffer | string; stdout?: Buffer | string; message?: string };
  const stderr = Buffer.isBuffer(e.stderr) ? e.stderr.toString("utf-8") : e.stderr;
  const stdout = Buffer.isBuffer(e.stdout) ? e.stdout.toString("utf-8") : e.stdout;
  return (stderr || stdout || e.message || String(err)).trim();
}

function branchPathSlug(branch: string): string {
  const slug = branch
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[.-]+|[.-]+$/g, "")
    .slice(0, 80);
  return slug || "worktree";
}

function repoHash(repoRoot: string): string {
  return crypto.createHash("sha1").update(repoRoot).digest("hex").slice(0, 8);
}

function worktreesBaseDir(): string {
  const configured = process.env.TERMINALX_WORKTREES_ROOT?.trim();
  const base = configured || path.join(getTerminusRoot(), ".terminalx-worktrees");
  const safeBase = resolveSafePath(base);
  assertNotSensitivePath(safeBase);
  fs.mkdirSync(safeBase, { recursive: true, mode: 0o700 });
  return safeBase;
}

/**
 * The resolved + validated worktrees base directory (issue #9 sweep reuses this
 * so orphan pruning is confined to the same root, validated against
 * TERMINUS_ROOT and never a sensitive path). Creates the dir if missing.
 */
export function getWorktreesBaseDir(): string {
  return worktreesBaseDir();
}

function branchExists(repoRoot: string, branch: string): boolean {
  try {
    git(["-C", repoRoot, "rev-parse", "--verify", "--quiet", `refs/heads/${branch}`]);
    return true;
  } catch {
    return false;
  }
}

function refExists(repoRoot: string, ref: string): boolean {
  try {
    git(["-C", repoRoot, "show-ref", "--verify", "--quiet", ref]);
    return true;
  } catch {
    return false;
  }
}

function currentBranch(repoRoot: string): string | undefined {
  const branch = git(["-C", repoRoot, "branch", "--show-current"]);
  return branch || undefined;
}

function worktreePathForBranch(repoRoot: string, branch: string): string | undefined {
  const raw = git(["-C", repoRoot, "worktree", "list", "--porcelain"]);
  let currentPath: string | undefined;
  for (const line of raw.split("\n")) {
    if (line.startsWith("worktree ")) {
      currentPath = line.slice("worktree ".length);
      continue;
    }
    if (line === `branch refs/heads/${branch}`) {
      return currentPath;
    }
    if (line === "") {
      currentPath = undefined;
    }
  }
  return undefined;
}

function assertCleanGitWorktree(repoRoot: string, label: string): void {
  const status = git(["-C", repoRoot, "status", "--porcelain"]);
  if (status) {
    throw new Error(
      `${label} has uncommitted changes; commit or stash them before creating a worktree`
    );
  }
}

function checkoutMainBranch(repoRoot: string): void {
  if (branchExists(repoRoot, WORKTREE_BASE_BRANCH)) {
    git(["-C", repoRoot, "checkout", WORKTREE_BASE_BRANCH], GIT_REFRESH_TIMEOUT_MS);
    return;
  }

  const originMain = `origin/${WORKTREE_BASE_BRANCH}`;
  if (refExists(repoRoot, `refs/remotes/${originMain}`)) {
    git(
      ["-C", repoRoot, "checkout", "-b", WORKTREE_BASE_BRANCH, "--track", originMain],
      GIT_REFRESH_TIMEOUT_MS
    );
    return;
  }

  throw new Error(`Branch "${WORKTREE_BASE_BRANCH}" does not exist`);
}

function hasUpstream(repoRoot: string): boolean {
  try {
    git(["-C", repoRoot, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"]);
    return true;
  } catch {
    return false;
  }
}

function pullLatestMain(repoRoot: string): void {
  if (hasUpstream(repoRoot)) {
    git(["-C", repoRoot, "pull", "--ff-only"], GIT_REFRESH_TIMEOUT_MS);
    return;
  }

  if (refExists(repoRoot, `refs/remotes/origin/${WORKTREE_BASE_BRANCH}`)) {
    git(
      ["-C", repoRoot, "pull", "--ff-only", "origin", WORKTREE_BASE_BRANCH],
      GIT_REFRESH_TIMEOUT_MS
    );
  }
}

function refreshMainBeforeWorktree(repoRoot: string): void {
  git(["-C", repoRoot, "fetch", "--all", "--prune"], GIT_REFRESH_TIMEOUT_MS);

  const mainWorktree = worktreePathForBranch(repoRoot, WORKTREE_BASE_BRANCH);
  if (mainWorktree) {
    const safeMainWorktree = resolveSafePath(mainWorktree);
    assertNotSensitivePath(safeMainWorktree);
    assertCleanGitWorktree(safeMainWorktree, "Main checkout");
    pullLatestMain(safeMainWorktree);
    return;
  }

  assertCleanGitWorktree(repoRoot, "Selected checkout");
  checkoutMainBranch(repoRoot);
  if (currentBranch(repoRoot) !== WORKTREE_BASE_BRANCH) {
    throw new Error(`Failed to check out ${WORKTREE_BASE_BRANCH}`);
  }
  assertCleanGitWorktree(repoRoot, "Main checkout");
  pullLatestMain(repoRoot);
}

export function getGitDirectoryInfo(directory: string): GitDirectoryInfo {
  try {
    const safeDir = resolveSafePath(directory);
    assertNotSensitivePath(safeDir);
    if (!fs.existsSync(safeDir) || !fs.statSync(safeDir).isDirectory()) {
      return { isRepo: false };
    }

    const inside = git(["-C", safeDir, "rev-parse", "--is-inside-work-tree"]);
    if (inside !== "true") return { isRepo: false };

    const root = resolveSafePath(git(["-C", safeDir, "rev-parse", "--show-toplevel"]));
    assertNotSensitivePath(root);
    const branch = git(["-C", safeDir, "branch", "--show-current"]);
    return {
      isRepo: true,
      root,
      branch: branch || undefined,
      repoName: path.basename(root),
    };
  } catch {
    return { isRepo: false };
  }
}

export function validateGitBranchName(rawBranch: unknown): string {
  const branch = typeof rawBranch === "string" ? rawBranch.trim() : "";
  if (!branch) {
    throw new Error("Branch name is required");
  }
  if (branch.length > 200) {
    throw new Error("Branch name is too long");
  }
  if (branch.startsWith("-") || !/^[A-Za-z0-9._/-]+$/.test(branch)) {
    throw new Error("Branch name can only use letters, numbers, slash, dot, underscore, or hyphen");
  }
  try {
    git(["check-ref-format", "--branch", branch]);
  } catch {
    throw new Error("Invalid Git branch name");
  }
  return branch;
}

/**
 * Resolve the configured list of repo-root-relative paths to share into a new
 * worktree. Falls back to the TERMINALX_WORKTREE_SYMLINK_PATHS env var
 * (comma-separated) when no explicit list is supplied.
 */
function resolveSymlinkPaths(symlinkPaths?: string[]): string[] {
  const fromOption = symlinkPaths;
  const raw =
    fromOption !== undefined
      ? fromOption
      : (process.env.TERMINALX_WORKTREE_SYMLINK_PATHS ?? "").split(",");
  const seen = new Set<string>();
  const result: string[] = [];
  for (const entry of raw) {
    const trimmed = typeof entry === "string" ? entry.trim() : "";
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

/**
 * Validate a repo-root-relative share path resolves to a real location inside
 * TERMINUS_ROOT that is not sensitive (.git/.ssh/.env/...). Returns the absolute
 * source path inside the repo root and the matching destination in the worktree.
 * Throws on traversal / sensitive targets (caller must surface that).
 */
function resolveShareTarget(
  repoRoot: string,
  worktreePath: string,
  relPath: string
): { source: string; dest: string } {
  if (path.isAbsolute(relPath)) {
    throw new Error(`Symlink path must be relative to the repo root: ${relPath}`);
  }
  const sourceCandidate = path.resolve(repoRoot, relPath);
  const destCandidate = path.resolve(worktreePath, relPath);

  // Both ends must stay inside TERMINUS_ROOT and avoid sensitive locations.
  const safeSource = resolveSafePath(sourceCandidate);
  assertNotSensitivePath(safeSource);
  const safeDest = resolveSafePath(destCandidate);
  assertNotSensitivePath(safeDest);

  return { source: safeSource, dest: safeDest };
}

/**
 * Link (or, on failure, copy) the configured shared paths into a freshly
 * created worktree. Each source is validated against TERMINUS_ROOT before any
 * filesystem mutation. Symlinks are created AFTER `git worktree add`, atomically
 * (build at a temp name + rename into place); when the symlink syscall throws we
 * fall back to a recursive copy so a heavy dir is still present. On win32 this is
 * a no-op (never hard-fails). Returns the absolute destination paths created.
 */
function linkSharedPaths(repoRoot: string, worktreePath: string, relPaths: string[]): string[] {
  if (relPaths.length === 0) return [];

  const linked: string[] = [];
  const isWindows = process.platform === "win32";

  for (const relPath of relPaths) {
    // Validation runs on every platform so escapes/sensitive targets are
    // rejected even on win32 (where we then skip the actual link/copy).
    const { source, dest } = resolveShareTarget(repoRoot, worktreePath, relPath);

    // Cross-platform: don't attempt symlinks on win32 (would need elevated
    // privileges / developer mode). No-op rather than hard-fail.
    if (isWindows) continue;

    // Only share paths that actually exist in the source repo root.
    if (!fs.existsSync(source)) continue;

    // If the worktree already materialized this path (e.g. tracked content),
    // leave it alone rather than clobbering committed files.
    if (fs.existsSync(dest)) continue;

    fs.mkdirSync(path.dirname(dest), { recursive: true });

    const sourceIsDir = fs.statSync(source).isDirectory();
    const tmpDest = `${dest}.tx-link-${crypto.randomBytes(4).toString("hex")}.tmp`;

    try {
      // Atomic: build the link under a temp name, then rename into place. If a
      // racing create planted something at dest, the rename throws and we treat
      // it like any other symlink failure (copy fallback).
      const symlinkType = sourceIsDir ? "junction" : "file";
      fs.symlinkSync(source, tmpDest, process.platform === "win32" ? symlinkType : undefined);
      fs.renameSync(tmpDest, dest);
      linked.push(dest);
    } catch {
      // Symlink syscall failed (EPERM, unsupported FS, race, ...). Clean up any
      // partial temp link and fall back to a recursive copy of the source.
      try {
        fs.rmSync(tmpDest, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
      try {
        fs.cpSync(source, dest, { recursive: true, errorOnExist: false, force: true });
        linked.push(dest);
      } catch {
        // Copy also failed: leave the worktree without this shared path rather
        // than aborting the whole session create.
      }
    }
  }

  return linked;
}

export function createGitWorktreeForSession(
  selectedDirectory: string,
  rawBranch: unknown,
  options: CreateGitWorktreeOptions = {}
): CreatedGitWorktree {
  const selectedSafe = resolveSafePath(selectedDirectory);
  assertNotSensitivePath(selectedSafe);
  if (!fs.existsSync(selectedSafe) || !fs.statSync(selectedSafe).isDirectory()) {
    throw new Error("Path is not a directory");
  }

  const info = getGitDirectoryInfo(selectedSafe);
  if (!info.isRepo || !info.root) {
    throw new Error("Selected directory is not inside a Git repository");
  }

  const branch = validateGitBranchName(rawBranch);
  if (branchExists(info.root, branch)) {
    throw new Error("Branch already exists");
  }

  const relativeStart = path.relative(info.root, selectedSafe);
  if (relativeStart.startsWith("..") || path.isAbsolute(relativeStart)) {
    throw new Error("Selected directory is outside the Git repository");
  }

  try {
    refreshMainBeforeWorktree(info.root);
  } catch (err) {
    throw new Error(`Failed to refresh main before creating Git worktree: ${gitErrorMessage(err)}`);
  }

  const baseDir = worktreesBaseDir();
  const repoName = info.repoName || path.basename(info.root);
  const worktreeName = `${repoName}-${repoHash(info.root)}-${branchPathSlug(branch)}`;
  const worktreePath = resolveSafePath(path.join(baseDir, worktreeName));
  assertNotSensitivePath(worktreePath);
  if (fs.existsSync(worktreePath)) {
    throw new Error("Worktree path already exists");
  }

  // Resolve + validate share paths BEFORE the worktree exists so an invalid
  // (escaping / sensitive) target aborts without leaving a stray worktree behind.
  const relSymlinkPaths = resolveSymlinkPaths(options.symlinkPaths);
  for (const relPath of relSymlinkPaths) {
    // Throws on traversal / sensitive targets; worktreePath does not exist yet
    // but resolveShareTarget only validates, it does not touch the filesystem.
    resolveShareTarget(info.root, worktreePath, relPath);
  }

  try {
    git(
      ["-C", info.root, "worktree", "add", "-b", branch, worktreePath, WORKTREE_BASE_BRANCH],
      GIT_WORKTREE_TIMEOUT_MS
    );
  } catch (err) {
    throw new Error(`Failed to create Git worktree: ${gitErrorMessage(err)}`);
  }

  let linkedPaths: string[] = [];
  try {
    linkedPaths = linkSharedPaths(info.root, worktreePath, relSymlinkPaths);
  } catch (err) {
    // Linking must never leave a half-built worktree around: tear it down and
    // surface the failure (validation errors are already handled above).
    removeGitWorktree(worktreePath, info.root);
    throw err;
  }

  const requestedStartDir =
    relativeStart && relativeStart !== "." ? path.join(worktreePath, relativeStart) : worktreePath;
  const startDir =
    fs.existsSync(requestedStartDir) && fs.statSync(requestedStartDir).isDirectory()
      ? requestedStartDir
      : worktreePath;

  return {
    repoRoot: info.root,
    worktreePath,
    startDir,
    branch,
    linkedPaths,
  };
}

/**
 * Recreate a git worktree from a PRESERVED branch (issue #9 restore). Archive
 * removes the on-disk worktree via removeGitWorktree but keeps the branch, so
 * restore is `git worktree add <path> <branch>` on the existing ref, followed by
 * re-linking the shared paths (#10) so a restored worktree behaves like a fresh
 * one. The worktree path is validated against TERMINUS_ROOT and confined to the
 * worktrees base dir; the branch must already exist (it must NOT be re-created).
 */
export function restoreGitWorktree(
  worktreePath: string,
  repoRoot: string,
  rawBranch: unknown,
  options: CreateGitWorktreeOptions = {}
): RestoredGitWorktree {
  // Validate the branch name BEFORE any filesystem work (throws on escapes).
  const branch = validateGitBranchName(rawBranch);

  const safeRepoRoot = resolveSafePath(repoRoot);
  assertNotSensitivePath(safeRepoRoot);

  // Confine the restore target to the worktrees base dir so a crafted path can't
  // plant a worktree elsewhere in (or outside) the sandbox.
  const safeWorktreePath = resolveSafePath(worktreePath);
  assertNotSensitivePath(safeWorktreePath);
  const baseDir = worktreesBaseDir();
  const relToBase = path.relative(baseDir, safeWorktreePath);
  if (relToBase.startsWith("..") || path.isAbsolute(relToBase) || relToBase === "") {
    throw new Error("Worktree path is outside the worktrees directory");
  }

  if (!branchExists(safeRepoRoot, branch)) {
    throw new Error("Preserved branch no longer exists — cannot restore");
  }

  if (fs.existsSync(safeWorktreePath)) {
    throw new Error("Worktree path already exists");
  }

  // Resolve + validate share paths BEFORE the worktree exists so an invalid
  // (escaping / sensitive) target aborts without leaving a stray worktree behind.
  const relSymlinkPaths = resolveSymlinkPaths(options.symlinkPaths);
  for (const relPath of relSymlinkPaths) {
    resolveShareTarget(safeRepoRoot, safeWorktreePath, relPath);
  }

  try {
    // No -b: attach the EXISTING preserved branch to the recreated worktree.
    git(["-C", safeRepoRoot, "worktree", "add", safeWorktreePath, branch], GIT_WORKTREE_TIMEOUT_MS);
  } catch (err) {
    throw new Error(`Failed to restore Git worktree: ${gitErrorMessage(err)}`);
  }

  let linkedPaths: string[] = [];
  try {
    linkedPaths = linkSharedPaths(safeRepoRoot, safeWorktreePath, relSymlinkPaths);
  } catch (err) {
    // Re-linking must never leave a half-built worktree: tear it down + surface.
    removeGitWorktree(safeWorktreePath, safeRepoRoot);
    throw err;
  }

  return {
    repoRoot: safeRepoRoot,
    worktreePath: safeWorktreePath,
    branch,
    linkedPaths,
  };
}

export function removeGitWorktree(
  worktreePath: string,
  repoRoot: string,
  linkedPaths: string[] = []
): void {
  // Drop any shared symlinks first. fs.rmSync on a symlink unlinks the LINK
  // (it never follows into the target), so the shared source is left untouched
  // even if the path resolves to a heavy dir like node_modules.
  for (const linked of linkedPaths) {
    try {
      const stat = fs.lstatSync(linked);
      if (stat.isSymbolicLink()) {
        fs.unlinkSync(linked);
      } else {
        // Copy fallback produced a real dir/file: safe to remove recursively
        // since it is a private copy inside the worktree, not the shared source.
        fs.rmSync(linked, { recursive: true, force: true });
      }
    } catch {
      // Already gone / never created — nothing to clean up.
    }
  }

  try {
    git(["-C", repoRoot, "worktree", "remove", "--force", worktreePath], GIT_WORKTREE_TIMEOUT_MS);
  } catch {
    // Best effort cleanup for a worktree created during a failed session create.
  }

  // If git left the directory behind (e.g. the worktree was already detached),
  // remove it directly. rmSync unlinks symlinks rather than following them, so
  // any remaining shared links are dropped without harming their targets.
  try {
    if (fs.existsSync(worktreePath)) {
      fs.rmSync(worktreePath, { recursive: true, force: true });
    }
  } catch {
    // Best effort.
  }
}
