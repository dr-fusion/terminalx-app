import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// patchMeta + the PATCH /api/sessions/[name] archive/collapse hook (feature #12,
// completed by #9). The store captures DATA_DIR from cwd at module load, so we
// chdir into a tmp dir and load fresh modules.

const ADMIN = { "x-username": "admin", "x-user-role": "admin" };

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
  const route = await import("@/app/api/sessions/[name]/route");
  return { sessions, PATCH: route.PATCH };
}

function writeSessionsJson(cwd: string, metas: unknown[]) {
  const dir = path.join(cwd, "data");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "ai-sessions.json"), JSON.stringify(metas, null, 2));
}

describe("patchMeta + PATCH /api/sessions/[name] (feature #12)", () => {
  let cwd: string;
  let prevCwd: string;

  beforeEach(() => {
    prevCwd = process.cwd();
    cwd = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-archive-")));
    process.chdir(cwd);
    writeSessionsJson(cwd, [{ name: "feat-x", kind: "bash", createdAt: new Date().toISOString() }]);
  });

  afterEach(() => {
    process.chdir(prevCwd);
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  it("patchMeta merges flags and leaves the name intact", async () => {
    const { sessions } = await freshModules();
    const updated = await sessions.patchMeta("feat-x", { collapsed: true });
    expect(updated?.name).toBe("feat-x");
    expect(updated?.collapsed).toBe(true);
    expect(sessions.getMeta("feat-x")?.collapsed).toBe(true);
  });

  it("patchMeta returns undefined for an unknown session", async () => {
    const { sessions } = await freshModules();
    expect(await sessions.patchMeta("nope", { archived: true })).toBeUndefined();
  });

  it("PATCH collapses a workspace row", async () => {
    const { PATCH, sessions } = await freshModules();
    const res = await PATCH(mockReq(ADMIN, { collapsed: true }), {
      params: Promise.resolve({ name: "feat-x" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.collapsed).toBe(true);
    expect(sessions.getMeta("feat-x")?.collapsed).toBe(true);
  });

  it("PATCH archives a workspace row and stamps archivedAt", async () => {
    const { PATCH, sessions } = await freshModules();
    const res = await PATCH(mockReq(ADMIN, { archived: true }), {
      params: Promise.resolve({ name: "feat-x" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.archived).toBe(true);
    const meta = sessions.getMeta("feat-x");
    expect(meta?.archived).toBe(true);
    expect(meta?.archivedAt).toBeTruthy();
  });

  it("PATCH 400s when no recognized fields are sent", async () => {
    const { PATCH } = await freshModules();
    const res = await PATCH(mockReq(ADMIN, { foo: "bar" }), {
      params: Promise.resolve({ name: "feat-x" }),
    });
    expect(res.status).toBe(400);
  });

  it("PATCH 404s for an unknown session", async () => {
    const { PATCH } = await freshModules();
    const res = await PATCH(mockReq(ADMIN, { archived: true }), {
      params: Promise.resolve({ name: "ghost" }),
    });
    expect(res.status).toBe(404);
  });
});
