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

function mockFileRequest(pathname = "test.txt", headers: Record<string, string> = {}) {
  return {
    headers: {
      get: (name: string) => headers[name.toLowerCase()] ?? null,
    },
    nextUrl: { searchParams: new URLSearchParams({ path: pathname, action: "read" }) },
  } as never;
}

async function loadSnippetsRoute() {
  return await import("@/app/api/snippets/route");
}

async function loadLogsRoute() {
  return await import("@/app/api/logs/route");
}

async function authenticatedRequest(username: string, role: "admin" | "user") {
  const { signJwt } = await import("@/lib/auth");
  const { createUser, getLocalAuthenticationIdentity } = await import("@/lib/users");
  const user = await createUser(username, "test-password-that-is-long-enough", role);
  const provisioned = getLocalAuthenticationIdentity(user.id);
  if (!provisioned) throw new Error("Test canonical identity was not provisioned");
  const token = await signJwt({
    userId: provisioned.user.id,
    username: provisioned.user.username,
    displayName: provisioned.user.displayName,
    role: provisioned.user.legacyRole,
    authProvider: provisioned.identity.provider,
    authSubject: provisioned.identity.subject,
    userGeneration: provisioned.user.generation,
    authIdentityGeneration: provisioned.identity.generation,
  });
  return mockRequest({ cookie: `terminalx-session=${token}` });
}

async function loadFilesRoute() {
  return await import("@/app/api/files/route");
}

async function loadDirectoriesRoute() {
  return await import("@/app/api/directories/route");
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
  let authDirectory: string;

  beforeEach(() => {
    authDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "tx-logs-auth-"));
    process.env.TERMINALX_TEAM_SESSION_DB_PATH = path.join(authDirectory, "team-sessions.sqlite");
    process.env.TERMINALX_LEGACY_USERS_FILE = path.join(authDirectory, "users.json");
  });

  afterEach(() => {
    fs.rmSync(authDirectory, { recursive: true, force: true });
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
    delete process.env.TERMINALX_LEGACY_USERS_FILE;
  });

  it("returns empty list for an authenticated non-admin in local mode", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const { GET } = await loadLogsRoute();
    const res = await GET(await authenticatedRequest("alice", "user"));
    const body = await res.json();
    expect(body.files).toEqual([]);
  });

  it("returns files for a freshly verified admin in local mode", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const { GET } = await loadLogsRoute();
    const res = await GET(await authenticatedRequest("root", "admin"));
    // We don't assert contents (depends on TERMINUS_LOG_PATHS on this host),
    // only that the guard doesn't short-circuit for admins.
    const body = await res.json();
    expect(body).toHaveProperty("files");
    expect(Array.isArray(body.files)).toBe(true);
  });

  it("rejects spoofed identity headers", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    const { GET } = await loadLogsRoute();
    const res = await GET(mockRequest({ "x-username": "root", "x-user-role": "admin" }));
    expect(res.status).toBe(401);
  });
});

describe("files GET admin gate", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tx-files-gate-"));
    process.env.TERMINUS_ROOT = tmpDir;
    process.env.TERMINALX_AUTH_MODE = "local";
    fs.writeFileSync(path.join(tmpDir, "test.txt"), "ok");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TERMINUS_ROOT;
    delete process.env.TERMINALX_AUTH_MODE;
  });

  it("denies non-admin local users", async () => {
    const { GET } = await loadFilesRoute();
    const res = await GET(
      mockFileRequest("test.txt", { "x-username": "alice", "x-user-role": "user" })
    );
    expect(res.status).toBe(403);
  });

  it("allows admins to read non-sensitive files", async () => {
    const { GET } = await loadFilesRoute();
    const res = await GET(
      mockFileRequest("test.txt", { "x-username": "admin", "x-user-role": "admin" })
    );
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.content).toBe("ok");
  });
});

describe("directories GET auth gate", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tx-dirs-gate-"));
    process.env.TERMINUS_ROOT = tmpDir;
    process.env.TERMINALX_AUTH_MODE = "local";
    fs.mkdirSync(path.join(tmpDir, "project"), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, "note.txt"), "ok");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TERMINUS_ROOT;
    delete process.env.TERMINALX_AUTH_MODE;
  });

  it("allows authenticated non-admin users to list directories only", async () => {
    const { GET } = await loadDirectoriesRoute();
    const res = await GET(mockRequest({ "x-username": "alice", "x-user-role": "user" }));
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.path).toBe(tmpDir);
    expect(body.entries.map((entry: { name: string }) => entry.name)).toEqual(["project"]);
  });

  it("denies unauthenticated local requests", async () => {
    const { GET } = await loadDirectoriesRoute();
    const res = await GET(mockRequest());
    expect(res.status).toBe(403);
  });
});
