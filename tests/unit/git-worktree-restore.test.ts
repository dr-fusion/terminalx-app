import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import {
  createGitWorktreeForSession,
  removeGitWorktree,
  restoreGitWorktree,
} from "@/lib/git-worktree";

// restoreGitWorktree recreates a worktree from a PRESERVED branch (issue #9
// archive keeps the branch; removeGitWorktree never deletes it). It re-links the
// shared paths so a restored worktree behaves like a freshly created one.

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

describeGit("restoreGitWorktree (issue #9)", () => {
  let tmpDir: string;
  let repoDir: string;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-restore-")));
    repoDir = path.join(tmpDir, "repo");
    process.env.TERMINUS_ROOT = tmpDir;
    fs.mkdirSync(repoDir, { recursive: true });
    git(tmpDir, ["init", "-b", "main", repoDir]);
    git(repoDir, ["config", "user.email", "terminalx@example.test"]);
    git(repoDir, ["config", "user.name", "TerminalX Test"]);
    // A shared dir we can symlink into the worktree (the #10 path-sharing).
    // node_modules is gitignored (the realistic case) so it never materializes
    // in the worktree from git — the share link is what brings it in.
    fs.writeFileSync(path.join(repoDir, ".gitignore"), "node_modules/\n");
    fs.writeFileSync(path.join(repoDir, "README.md"), "hello\n");
    git(repoDir, ["add", "."]);
    git(repoDir, ["commit", "-m", "initial"]);
    fs.mkdirSync(path.join(repoDir, "node_modules"), { recursive: true });
    fs.writeFileSync(path.join(repoDir, "node_modules", "dep.txt"), "shared\n");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TERMINUS_ROOT;
    delete process.env.TERMINALX_WORKTREES_ROOT;
  });

  it("re-creates a worktree from a preserved branch after archive (remove kept the branch)", () => {
    const created = createGitWorktreeForSession(repoDir, "feature/restore-me", {
      symlinkPaths: ["node_modules"],
    });
    expect(fs.existsSync(created.worktreePath)).toBe(true);
    expect(branchExists(repoDir, "feature/restore-me")).toBe(true);

    // Archive: remove the worktree but KEEP the branch.
    removeGitWorktree(created.worktreePath, created.repoRoot, created.linkedPaths);
    expect(fs.existsSync(created.worktreePath)).toBe(false);
    expect(branchExists(repoDir, "feature/restore-me")).toBe(true);

    // Restore: rebuild the worktree from the preserved branch + re-link shares.
    const restored = restoreGitWorktree(
      created.worktreePath,
      created.repoRoot,
      "feature/restore-me",
      { symlinkPaths: ["node_modules"] }
    );

    expect(restored.worktreePath).toBe(created.worktreePath);
    expect(restored.branch).toBe("feature/restore-me");
    expect(fs.existsSync(created.worktreePath)).toBe(true);
    expect(git(created.worktreePath, ["branch", "--show-current"])).toBe("feature/restore-me");
    // Committed content from the branch is present.
    expect(fs.existsSync(path.join(created.worktreePath, "README.md"))).toBe(true);
    // The shared path was re-linked.
    expect(restored.linkedPaths.length).toBe(1);
    expect(fs.existsSync(path.join(created.worktreePath, "node_modules", "dep.txt"))).toBe(true);
  });

  it("throws when the preserved branch no longer exists", () => {
    expect(() =>
      restoreGitWorktree(
        path.join(tmpDir, ".terminalx-worktrees", "ghost"),
        repoDir,
        "feature/does-not-exist"
      )
    ).toThrow();
  });

  it("rejects an invalid branch name without touching the filesystem", () => {
    expect(() =>
      restoreGitWorktree(path.join(tmpDir, ".terminalx-worktrees", "x"), repoDir, "../escape")
    ).toThrow();
  });
});
