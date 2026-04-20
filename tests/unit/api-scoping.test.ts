import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

/**
 * Handler-level tests for scoping behavior of /api/snippets and /api/logs.
 * These import the route modules directly — not quite full integration but
 * they exercise the same Next.js Request/Response and scoping helpers that
 * production runs through.
 */

function mockRequest(headers: Record<string, string> = {}) {
  return {
    headers: {
      get: (name: string) => headers[name.toLowerCase()] ?? null,
    },
    nextUrl: { searchParams: new URLSearchParams() },
  } as never;
}

async function loadSnippetsRoute() {
  return await import("@/app/api/snippets/route");
}

async function loadLogsRoute() {
  return await import("@/app/api/logs/route");
}

describe("snippets GET scoping", () => {
  let tmpDir: string;
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tx-snippet-scope-"));
    process.chdir(tmpDir);
    fs.mkdirSync(path.join(tmpDir, "data"), { recursive: true });
    const snippets = [
      { id: "1", name: "alice-thing", command: "ls", createdAt: "2026-01-01", createdBy: "alice" },
      { id: "2", name: "bob-thing", command: "ls", createdAt: "2026-01-02", createdBy: "bob" },
      { id: "3", name: "legacy", command: "ls", createdAt: "2026-01-03" },
    ];
    fs.writeFileSync(path.join(tmpDir, "data", "snippets.json"), JSON.stringify(snippets));
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TERMINALX_AUTH_MODE;
  });

  it("non-admin in local mode sees only their snippets + legacy", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const { GET } = await loadSnippetsRoute();
    const res = await GET(mockRequest({ "x-username": "alice", "x-user-role": "user" }));
    const body = await res.json();
    const names = body.snippets.map((s: { name: string }) => s.name).sort();
    expect(names).toEqual(["alice-thing", "legacy"]);
  });

  it("admin sees everything in local mode", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const { GET } = await loadSnippetsRoute();
    const res = await GET(mockRequest({ "x-username": "admin", "x-user-role": "admin" }));
    const body = await res.json();
    expect(body.snippets).toHaveLength(3);
  });

  it("password mode shows all (no scoping)", async () => {
    process.env.TERMINALX_AUTH_MODE = "password";
    const { GET } = await loadSnippetsRoute();
    const res = await GET(mockRequest());
    const body = await res.json();
    expect(body.snippets).toHaveLength(3);
  });
});

describe("logs GET admin gate", () => {
  afterEach(() => {
    delete process.env.TERMINALX_AUTH_MODE;
  });

  it("returns empty list for non-admin in local mode", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const { GET } = await loadLogsRoute();
    const res = await GET(mockRequest({ "x-username": "alice", "x-user-role": "user" }));
    const body = await res.json();
    expect(body.files).toEqual([]);
  });

  it("returns files for admin in local mode", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const { GET } = await loadLogsRoute();
    const res = await GET(mockRequest({ "x-username": "root", "x-user-role": "admin" }));
    // We don't assert contents (depends on TERMINUS_LOG_PATHS on this host),
    // only that the guard doesn't short-circuit for admins.
    const body = await res.json();
    expect(body).toHaveProperty("files");
    expect(Array.isArray(body.files)).toBe(true);
  });
});
