import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";
import {
  createGitWorktreeForSession,
  getGitDirectoryInfo,
  validateGitBranchName,
} from "@/lib/git-worktree";

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

describeGit("git worktree helpers", () => {
  let tmpDir: string;
  let repoDir: string;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-git-worktree-")));
    repoDir = path.join(tmpDir, "repo");
    process.env.TERMINUS_ROOT = tmpDir;
    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    git(tmpDir, ["init", "-b", "main", repoDir]);
    git(repoDir, ["config", "user.email", "terminalx@example.test"]);
    git(repoDir, ["config", "user.name", "TerminalX Test"]);
    fs.writeFileSync(path.join(repoDir, "README.md"), "hello\n");
    fs.writeFileSync(path.join(repoDir, "src", "index.ts"), "export const value = 1;\n");
    git(repoDir, ["add", "."]);
    git(repoDir, ["commit", "-m", "initial"]);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TERMINUS_ROOT;
    delete process.env.TERMINALX_WORKTREES_ROOT;
  });

  it("detects a selected directory inside a Git repository", () => {
    const info = getGitDirectoryInfo(path.join(repoDir, "src"));

    expect(info.isRepo).toBe(true);
    expect(info.root).toBe(repoDir);
    expect(info.repoName).toBe("repo");
  });

  it("creates a branch worktree under TERMINUS_ROOT and preserves selected subdirectory", () => {
    const result = createGitWorktreeForSession(path.join(repoDir, "src"), "feature/test-one");

    expect(result.repoRoot).toBe(repoDir);
    expect(result.branch).toBe("feature/test-one");
    expect(result.worktreePath).toContain(path.join(tmpDir, ".terminalx-worktrees"));
    expect(result.startDir).toBe(path.join(result.worktreePath, "src"));
    expect(fs.existsSync(path.join(result.worktreePath, "README.md"))).toBe(true);
    expect(git(result.worktreePath, ["branch", "--show-current"])).toBe("feature/test-one");
  });

  it("fetches and fast-forwards main before creating the new branch worktree", () => {
    const originDir = path.join(tmpDir, "origin.git");
    const seedDir = path.join(tmpDir, "seed");
    const cloneDir = path.join(tmpDir, "clone");

    git(tmpDir, ["init", "--bare", originDir]);
    git(tmpDir, ["clone", originDir, seedDir]);
    git(seedDir, ["checkout", "-b", "main"]);
    git(seedDir, ["config", "user.email", "terminalx@example.test"]);
    git(seedDir, ["config", "user.name", "TerminalX Test"]);
    fs.writeFileSync(path.join(seedDir, "README.md"), "old\n");
    git(seedDir, ["add", "."]);
    git(seedDir, ["commit", "-m", "initial"]);
    git(seedDir, ["push", "-u", "origin", "main"]);
    git(originDir, ["symbolic-ref", "HEAD", "refs/heads/main"]);

    git(tmpDir, ["clone", originDir, cloneDir]);
    git(cloneDir, ["checkout", "-b", "topic/old-base"]);

    fs.writeFileSync(path.join(seedDir, "README.md"), "latest\n");
    git(seedDir, ["add", "."]);
    git(seedDir, ["commit", "-m", "latest"]);
    git(seedDir, ["push"]);

    const result = createGitWorktreeForSession(cloneDir, "feature/from-latest-main");

    expect(git(cloneDir, ["branch", "--show-current"])).toBe("main");
    expect(fs.readFileSync(path.join(result.worktreePath, "README.md"), "utf-8")).toBe("latest\n");
    expect(git(result.worktreePath, ["rev-parse", "HEAD"])).toBe(
      git(cloneDir, ["rev-parse", "main"])
    );
  });

  it("fails before creating a worktree when main has uncommitted changes", () => {
    fs.writeFileSync(path.join(repoDir, "README.md"), "dirty\n");

    expect(() => createGitWorktreeForSession(repoDir, "feature/dirty-main")).toThrow(
      /uncommitted changes/
    );

    expect(branchExists(repoDir, "feature/dirty-main")).toBe(false);
    expect(fs.existsSync(path.join(tmpDir, ".terminalx-worktrees"))).toBe(false);
  });

  it("rejects invalid branch names before running worktree add", () => {
    expect(() => validateGitBranchName("../escape")).toThrow();
    expect(() => createGitWorktreeForSession(repoDir, "../escape")).toThrow();
  });
});
