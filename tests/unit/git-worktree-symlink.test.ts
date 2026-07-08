import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";

/**
 * Controls whether the mocked fs.symlinkSync throws, so the COPY-fallback test
 * can deterministically force a symlink failure. ESM forbids spying on the fs
 * namespace directly (vi.spyOn(fs, "symlinkSync") -> "Module namespace is not
 * configurable"), so we mock the module and gate the throw behind a flag.
 */
const symlinkControl = { forceFail: false, calls: 0 };

vi.mock("fs", async () => {
  const actual = await vi.importActual<typeof import("fs")>("fs");
  return {
    ...actual,
    default: actual,
    symlinkSync: (...args: Parameters<typeof actual.symlinkSync>) => {
      symlinkControl.calls += 1;
      if (symlinkControl.forceFail) {
        const err = new Error("EPERM: operation not permitted, symlink") as NodeJS.ErrnoException;
        err.code = "EPERM";
        throw err;
      }
      return actual.symlinkSync(...args);
    },
  };
});

import { createGitWorktreeForSession, removeGitWorktree } from "@/lib/git-worktree";

/**
 * TDD spec for Issue #10 — "symlink shared paths into git worktrees for large repos".
 *
 * createGitWorktreeForSession must accept a `symlinkPaths` option. After
 * `git worktree add` succeeds it links each configured path (relative to the
 * repo root) into the new worktree:
 *   - atomic symlink creation AFTER the worktree exists
 *   - fall back to COPY when the symlink syscall throws
 *   - cross-platform: on win32 it must not hard-fail (no-op or copy)
 *   - symlink target paths validated against TERMINUS_ROOT
 *     (assertNotSensitivePath / resolveSafePath)
 * removeGitWorktree must drop the symlinks WITHOUT touching the shared source.
 *
 * These tests are written RED on purpose: the feature is not implemented yet.
 */

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

const describeGit = hasGit() ? describe : describe.skip;

describeGit("createGitWorktreeForSession symlinkPaths", () => {
  let tmpDir: string;
  let repoDir: string;

  beforeEach(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-symlink-worktree-")));
    repoDir = path.join(tmpDir, "repo");
    process.env.TERMINUS_ROOT = tmpDir;
    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    git(tmpDir, ["init", "-b", "main", repoDir]);
    git(repoDir, ["config", "user.email", "terminalx@example.test"]);
    git(repoDir, ["config", "user.name", "TerminalX Test"]);
    fs.writeFileSync(path.join(repoDir, "README.md"), "hello\n");
    fs.writeFileSync(path.join(repoDir, ".gitignore"), "node_modules/\n");
    fs.writeFileSync(path.join(repoDir, "src", "index.ts"), "export const value = 1;\n");
    git(repoDir, ["add", "."]);
    git(repoDir, ["commit", "-m", "initial"]);

    // Heavy shared dir living in the repo root (NOT committed; gitignored).
    const sharedNodeModules = path.join(repoDir, "node_modules");
    fs.mkdirSync(path.join(sharedNodeModules, "leftpad"), { recursive: true });
    fs.writeFileSync(
      path.join(sharedNodeModules, "leftpad", "index.js"),
      "module.exports = () => 'pad';\n"
    );
    fs.writeFileSync(path.join(sharedNodeModules, "MARKER"), "shared-install\n");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    symlinkControl.forceFail = false;
    symlinkControl.calls = 0;
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TERMINUS_ROOT;
    delete process.env.TERMINALX_WORKTREES_ROOT;
  });

  it("creates the symlink atomically AFTER git worktree add, pointing at the shared source", () => {
    const result = createGitWorktreeForSession(repoDir, "feature/link-one", {
      symlinkPaths: ["node_modules"],
    });

    const linked = path.join(result.worktreePath, "node_modules");
    expect(fs.existsSync(linked)).toBe(true);

    const lst = fs.lstatSync(linked);
    expect(lst.isSymbolicLink()).toBe(true);

    // It resolves to the shared source in the repo root, so a heavy dir
    // (node_modules) need not be re-installed inside the worktree.
    const resolved = fs.realpathSync(linked);
    expect(resolved).toBe(fs.realpathSync(path.join(repoDir, "node_modules")));
    expect(fs.readFileSync(path.join(linked, "MARKER"), "utf-8")).toBe("shared-install\n");

    // The created links are reported back for later cleanup.
    expect(result.linkedPaths).toContain(linked);
  });

  it("falls back to COPY when the symlink syscall throws", () => {
    symlinkControl.forceFail = true;

    const result = createGitWorktreeForSession(repoDir, "feature/copy-fallback", {
      symlinkPaths: ["node_modules"],
    });

    // The implementation must have attempted a symlink before copying.
    expect(symlinkControl.calls).toBeGreaterThan(0);

    const linked = path.join(result.worktreePath, "node_modules");
    expect(fs.existsSync(linked)).toBe(true);

    // Symlink failed, so it must be a real (copied) directory, not a link.
    const lst = fs.lstatSync(linked);
    expect(lst.isSymbolicLink()).toBe(false);
    expect(lst.isDirectory()).toBe(true);
    expect(fs.readFileSync(path.join(linked, "MARKER"), "utf-8")).toBe("shared-install\n");
  });

  it("rejects symlink target paths that escape / are sensitive", () => {
    expect(() =>
      createGitWorktreeForSession(repoDir, "feature/escape-link", {
        symlinkPaths: ["../../etc"],
      })
    ).toThrow();

    expect(() =>
      createGitWorktreeForSession(repoDir, "feature/sensitive-link", {
        symlinkPaths: [".git"],
      })
    ).toThrow();
  });

  it("on win32 does not hard-fail (no-op or copy, never throws)", () => {
    const platformSpy = vi.spyOn(process, "platform", "get").mockReturnValue("win32");

    expect(() =>
      createGitWorktreeForSession(repoDir, "feature/win32-link", {
        symlinkPaths: ["node_modules"],
      })
    ).not.toThrow();

    platformSpy.mockRestore();
  });

  it("removeGitWorktree drops the symlink WITHOUT touching the shared source", () => {
    const result = createGitWorktreeForSession(repoDir, "feature/cleanup-link", {
      symlinkPaths: ["node_modules"],
    });

    const linked = path.join(result.worktreePath, "node_modules");
    expect(fs.existsSync(linked)).toBe(true);

    removeGitWorktree(result.worktreePath, result.repoRoot);

    // Worktree (and its symlink) gone…
    expect(fs.existsSync(linked)).toBe(false);
    expect(fs.existsSync(result.worktreePath)).toBe(false);

    // …but the shared source is untouched.
    const source = path.join(repoDir, "node_modules");
    expect(fs.existsSync(source)).toBe(true);
    expect(fs.readFileSync(path.join(source, "MARKER"), "utf-8")).toBe("shared-install\n");
  });

  it("is a no-op when symlinkPaths is empty / omitted (back-compat)", () => {
    const result = createGitWorktreeForSession(repoDir, "feature/no-links", {
      symlinkPaths: [],
    });
    expect(fs.existsSync(path.join(result.worktreePath, "node_modules"))).toBe(false);
    expect(result.linkedPaths ?? []).toEqual([]);
  });
});
