import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// Mock the session + git lookups so the route's repoRoot resolution is
// deterministic without a real session store / git repo (ESM mocking: vi.mock).
const mocks = vi.hoisted(() => ({
  getMeta: vi.fn(),
  getGitDirectoryInfo: vi.fn(),
}));

vi.mock("@/lib/ai-sessions", () => ({
  getMeta: mocks.getMeta,
}));
vi.mock("@/lib/git-worktree", () => ({
  getGitDirectoryInfo: mocks.getGitDirectoryInfo,
}));
// This suite exercises the settings-store / repo-write logic, not the admin
// gate. Treat the JWT re-verification as satisfied so the existing admin-path
// tests (which set x-user-role: admin) keep testing what they were written for.
// The defense-in-depth gate itself is covered in admin-auth-gates.test.ts.
vi.mock("@/lib/request-actor", () => ({
  requireVerifiedAdmin: vi.fn(async () => true),
}));

function mockReq(opts: { url?: string; body?: unknown; headers?: Record<string, string> }) {
  const headers = opts.headers ?? {};
  return {
    url: opts.url ?? "http://localhost/api/settings",
    headers: { get: (n: string) => headers[n.toLowerCase()] ?? null },
    json: async () => opts.body,
  } as never;
}

async function loadRoute() {
  return await import("@/app/api/settings/route");
}

describe("GET/PUT /api/settings", () => {
  let cwd: string;
  let prevCwd: string;
  let root: string;
  let repoRoot: string;

  beforeEach(() => {
    vi.resetModules();
    mocks.getMeta.mockReset();
    mocks.getGitDirectoryInfo.mockReset();

    prevCwd = process.cwd();
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-settings-route-")));
    cwd = path.join(root, "cwd");
    fs.mkdirSync(cwd, { recursive: true });
    process.chdir(cwd);
    process.env.TERMINUS_ROOT = root;
    repoRoot = path.join(root, "repo");
    fs.mkdirSync(repoRoot, { recursive: true });
  });

  afterEach(() => {
    process.chdir(prevCwd);
    delete process.env.TERMINUS_ROOT;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("GET scope=user returns resolved defaults", async () => {
    const { GET } = await loadRoute();
    const res = await GET(mockReq({ url: "http://localhost/api/settings?scope=user" }));
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.scope).toBe("user");
    expect(body.resolved.codexPersonality).toBe("pragmatic");
    expect(body.resolved.defaultModel.effort).toBe("high");
  });

  it("GET with invalid scope is 400", async () => {
    const { GET } = await loadRoute();
    const res = await GET(mockReq({ url: "http://localhost/api/settings?scope=bogus" }));
    expect(res.status).toBe(400);
  });

  it("GET scope=repo with no repo context is 404", async () => {
    mocks.getMeta.mockReturnValue(undefined);
    const { GET } = await loadRoute();
    const res = await GET(mockReq({ url: "http://localhost/api/settings?scope=repo&session=x" }));
    expect(res.status).toBe(404);
  });

  it("PUT scope=user deep-merges and persists", async () => {
    const { PUT, GET } = await loadRoute();
    const res = await PUT(
      mockReq({
        body: {
          scope: "user",
          models: { defaultModel: { modelId: "codex:gpt-5-codex", effort: "low" } },
        },
      })
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.resolved.defaultModel).toEqual({
      modelId: "codex:gpt-5-codex",
      effort: "low",
    });

    // Read back via GET
    const getRes = await GET(mockReq({ url: "http://localhost/api/settings?scope=user" }));
    const getBody = await getRes.json();
    expect(getBody.settings.models.defaultModel.modelId).toBe("codex:gpt-5-codex");
  });

  it("PUT with an unknown modelId is 400", async () => {
    const { PUT } = await loadRoute();
    const res = await PUT(
      mockReq({
        body: { scope: "user", models: { defaultModel: { modelId: "x:y", effort: "low" } } },
      })
    );
    expect(res.status).toBe(400);
  });

  it("PUT scope=repo without admin is 403", async () => {
    mocks.getMeta.mockReturnValue({ name: "s", worktree: { repoRoot } });
    const { PUT } = await loadRoute();
    const res = await PUT(
      mockReq({
        body: { scope: "repo", session: "s", models: { defaultToPlanMode: true } },
        headers: { "x-user-role": "user" },
      })
    );
    expect(res.status).toBe(403);
  });

  it("PUT scope=repo with admin + repo context writes the toml", async () => {
    mocks.getMeta.mockReturnValue({ name: "s", worktree: { repoRoot } });
    const { PUT } = await loadRoute();
    const res = await PUT(
      mockReq({
        body: {
          scope: "repo",
          session: "s",
          models: { reviewModel: { modelId: "codex:gpt-5-codex", effort: "medium" } },
        },
        headers: { "x-user-role": "admin", "x-username": "admin" },
      })
    );
    expect(res.status).toBe(200);
    const tomlPath = path.join(repoRoot, ".terminalx", "settings.toml");
    expect(fs.existsSync(tomlPath)).toBe(true);
    expect(fs.readFileSync(tomlPath, "utf-8")).toContain("codex:gpt-5-codex");
  });

  it("PUT scope=repo with admin but no repo context is 409", async () => {
    mocks.getMeta.mockReturnValue({ name: "s", cwd: "/tmp/nope" });
    mocks.getGitDirectoryInfo.mockReturnValue({ isRepo: false });
    const { PUT } = await loadRoute();
    const res = await PUT(
      mockReq({
        body: { scope: "repo", session: "s", models: { defaultToPlanMode: true } },
        headers: { "x-user-role": "admin" },
      })
    );
    expect(res.status).toBe(409);
  });
});
