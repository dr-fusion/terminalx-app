import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";

// Server-side auto-archive trigger (issue #9). When a worktree's PR is merged,
// auto-archive it: removeGitWorktree (branch preserved) + set archived. The
// trigger is best-effort, idempotent, and injects its PR-status lookup so it is
// testable without GitHub. Store captures cwd at load → chdir + fresh modules.

function hasGit(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function git(repo: string, args: string[]): string {
  return execFileSync("git", ["-C", repo, ...args], {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function branchExists(repo: string, branch: string): boolean {
  try {
    git(repo, ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`]);
    return true;
  } catch {
    return false;
  }
}

const describeGit = hasGit() ? describe : describe.skip;

describeGit("autoArchiveMergedWorktrees (issue #9)", () => {
  let cwd: string;
  let prevCwd: string;
  let repoDir: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    cwd = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-autoarch-")));
    process.chdir(cwd);
    process.env.TERMINUS_ROOT = cwd;
    repoDir = path.join(cwd, "repo");
    fs.mkdirSync(repoDir, { recursive: true });
    git(cwd, ["init", "-b", "main", repoDir]);
    git(repoDir, ["config", "user.email", "terminalx@example.test"]);
    git(repoDir, ["config", "user.name", "TerminalX Test"]);
    fs.writeFileSync(path.join(repoDir, "README.md"), "hi\n");
    git(repoDir, ["add", "."]);
    git(repoDir, ["commit", "-m", "init"]);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    fs.rmSync(cwd, { recursive: true, force: true });
    delete process.env.TERMINUS_ROOT;
    delete process.env.TERMINALX_WORKTREES_ROOT;
  });

  async function seed(name: string, branch: string) {
    vi.resetModules();
    const { createGitWorktreeForSession } = await import("@/lib/git-worktree");
    const created = createGitWorktreeForSession(repoDir, branch);
    const { saveMeta } = await import("@/lib/ai-sessions");
    await saveMeta({
      name,
      kind: "bash",
      createdAt: new Date().toISOString(),
      worktree: {
        repoRoot: created.repoRoot,
        path: created.worktreePath,
        branch: created.branch,
        linkedPaths: created.linkedPaths,
      },
    });
    return created;
  }

  it("archives a merged worktree (branch preserved) and leaves an open one alone", async () => {
    const merged = await seed("merged-wt", "feature/merged");
    const open = await seed("open-wt", "feature/open");

    vi.resetModules();
    const { autoArchiveMergedWorktrees } = await import("@/lib/auto-archive");
    const sessions = await import("@/lib/ai-sessions");

    const result = await autoArchiveMergedWorktrees({
      resolvePrStatus: async (meta) => (meta.name === "merged-wt" ? "merged" : "open"),
    });

    expect(result.archived).toEqual(["merged-wt"]);
    // Merged worktree archived + removed on disk, branch kept.
    expect(sessions.getMeta("merged-wt")?.archived).toBe(true);
    expect(fs.existsSync(merged.worktreePath)).toBe(false);
    expect(branchExists(repoDir, "feature/merged")).toBe(true);
    // Open worktree untouched.
    expect(sessions.getMeta("open-wt")?.archived).toBeFalsy();
    expect(fs.existsSync(open.worktreePath)).toBe(true);
  });

  it("is idempotent: an already-archived worktree is not re-archived", async () => {
    await seed("done-wt", "feature/done");
    vi.resetModules();
    const sessions = await import("@/lib/ai-sessions");
    await sessions.patchMeta("done-wt", { archived: true, archivedAt: new Date().toISOString() });

    vi.resetModules();
    const { autoArchiveMergedWorktrees } = await import("@/lib/auto-archive");
    const result = await autoArchiveMergedWorktrees({ resolvePrStatus: async () => "merged" });
    expect(result.archived).toEqual([]);
  });

  it("never throws when a PR lookup fails for one worktree", async () => {
    await seed("ok-wt", "feature/ok");
    await seed("boom-wt", "feature/boom");
    vi.resetModules();
    const { autoArchiveMergedWorktrees } = await import("@/lib/auto-archive");
    const result = await autoArchiveMergedWorktrees({
      resolvePrStatus: async (meta) => {
        if (meta.name === "boom-wt") throw new Error("lookup failed");
        return "merged";
      },
    });
    expect(result.archived).toEqual(["ok-wt"]);
  });
});
