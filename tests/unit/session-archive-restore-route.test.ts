import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";

// POST /api/sessions/[name]/archive + /restore (issue #9). Archive removes the
// git worktree (symlinks unlinked, source untouched) but KEEPS the branch and
// sets archived/archivedAt. Restore recreates the worktree from the preserved
// branch, re-links shares, and clears archived. Recordings are NOT pruned on
// archive (only on a confirmed delete). The store captures cwd at module load,
// so each case chdir's into a tmp repo and loads fresh modules.

const ADMIN = { "x-username": "admin", "x-user-role": "admin" };

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

function mockReq(headers: Record<string, string>, body?: unknown) {
  return {
    headers: { get: (h: string) => headers[h.toLowerCase()] ?? null },
    json: async () => {
      if (body === undefined) throw new Error("no body");
      return body;
    },
  } as never;
}

async function freshModules() {
  vi.resetModules();
  const sessions = await import("@/lib/ai-sessions");
  const archive = await import("@/app/api/sessions/[name]/archive/route");
  const restore = await import("@/app/api/sessions/[name]/restore/route");
  return { sessions, archivePOST: archive.POST, restorePOST: restore.POST };
}

const describeGit = hasGit() ? describe : describe.skip;

describeGit("POST /api/sessions/[name]/archive + /restore (issue #9)", () => {
  let cwd: string;
  let prevCwd: string;
  let repoDir: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    cwd = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-arx-")));
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

  async function seedWorktreeSession(name: string, branch: string) {
    // Reset first so the freshly imported store captures THIS test's cwd as its
    // DATA_DIR (modules cache DATA_DIR at load; a stale instance would write to a
    // prior test's deleted tmp dir).
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

  it("archive removes the worktree, keeps the branch, sets archived/archivedAt", async () => {
    const created = await seedWorktreeSession("feat-a", "feature/a");
    expect(fs.existsSync(created.worktreePath)).toBe(true);

    const { archivePOST, sessions } = await freshModules();
    const res = await archivePOST(mockReq(ADMIN, {}), {
      params: Promise.resolve({ name: "feat-a" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.archived).toBe(true);

    const meta = sessions.getMeta("feat-a");
    expect(meta?.archived).toBe(true);
    expect(meta?.archivedAt).toBeTruthy();
    // Worktree gone on disk, but the branch is preserved for restore.
    expect(fs.existsSync(created.worktreePath)).toBe(false);
    expect(branchExists(repoDir, "feature/a")).toBe(true);
    // Worktree meta is preserved so restore knows where to rebuild.
    expect(meta?.worktree?.branch).toBe("feature/a");
  });

  it("archive 404s for an unknown session", async () => {
    const { archivePOST } = await freshModules();
    const res = await archivePOST(mockReq(ADMIN, {}), {
      params: Promise.resolve({ name: "ghost" }),
    });
    expect(res.status).toBe(404);
  });

  it("restore recreates the worktree from the preserved branch and clears archived", async () => {
    const created = await seedWorktreeSession("feat-b", "feature/b");
    // Archive first.
    {
      const { archivePOST } = await freshModules();
      const res = await archivePOST(mockReq(ADMIN, {}), {
        params: Promise.resolve({ name: "feat-b" }),
      });
      expect(res.status).toBe(200);
    }
    expect(fs.existsSync(created.worktreePath)).toBe(false);

    const { restorePOST, sessions } = await freshModules();
    const res = await restorePOST(mockReq(ADMIN, {}), {
      params: Promise.resolve({ name: "feat-b" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.archived).toBe(false);

    const meta = sessions.getMeta("feat-b");
    expect(meta?.archived).toBe(false);
    expect(meta?.archivedAt).toBeUndefined();
    expect(fs.existsSync(created.worktreePath)).toBe(true);
    expect(git(created.worktreePath, ["branch", "--show-current"])).toBe("feature/b");
  });

  it("restore 400s when the session is not archived", async () => {
    await seedWorktreeSession("feat-c", "feature/c");
    const { restorePOST } = await freshModules();
    const res = await restorePOST(mockReq(ADMIN, {}), {
      params: Promise.resolve({ name: "feat-c" }),
    });
    expect(res.status).toBe(400);
  });

  it("archive does NOT prune recordings (kept until a confirmed delete)", async () => {
    const created = await seedWorktreeSession("feat-d", "feature/d");
    // Drop a recording for the session.
    const recDir = path.join(cwd, "data", "recordings");
    fs.mkdirSync(recDir, { recursive: true });
    const recFile = path.join(recDir, "feat-d-1700000000000.jsonl");
    fs.writeFileSync(recFile, JSON.stringify({ v: 1, sessionId: "feat-d" }) + "\n");

    const { archivePOST } = await freshModules();
    const res = await archivePOST(mockReq(ADMIN, {}), {
      params: Promise.resolve({ name: "feat-d" }),
    });
    expect(res.status).toBe(200);
    expect(fs.existsSync(created.worktreePath)).toBe(false);
    // Recording survives an archive.
    expect(fs.existsSync(recFile)).toBe(true);
  });

  it("archive 403s for a session without a worktree (archive is worktree-level)", async () => {
    vi.resetModules();
    const { saveMeta } = await import("@/lib/ai-sessions");
    await saveMeta({ name: "plain", kind: "bash", createdAt: new Date().toISOString() });
    const { archivePOST } = await freshModules();
    const res = await archivePOST(mockReq(ADMIN, {}), {
      params: Promise.resolve({ name: "plain" }),
    });
    expect(res.status).toBe(400);
  });
});
