import { beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

/**
 * Route-level defense-in-depth coverage for the admin GRANT gates hardened in
 * agent/harden-admin-auth-gates: /api/users, /api/settings (repo scope) and
 * /api/telegram/settings.
 *
 * These exercise the REAL requireVerifiedAdmin -> resolveRequestActor code path;
 * only verifyJwt and getAuthMode are overridden so we can drive each auth mode
 * deterministically without a live JWT/identity store. parseCookies stays real,
 * so a request with no session cookie genuinely resolves to no actor.
 *
 * The core regression under test: a spoofed `x-user-role: admin` header with NO
 * valid session JWT must NOT grant admin at any hardened gate — not even when it
 * rides on a legitimately-authenticated NON-admin session.
 */

const mocks = vi.hoisted(() => ({
  authMode: "local" as "none" | "password" | "local" | "google",
  verifyJwt: vi.fn(),
}));

vi.mock("@/lib/auth", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/auth")>();
  return { ...actual, verifyJwt: mocks.verifyJwt };
});

vi.mock("@/lib/auth-config", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/auth-config")>();
  return { ...actual, getAuthMode: () => mocks.authMode };
});

vi.mock("@/lib/audit-log", () => ({ audit: () => {} }));

vi.mock("@/lib/users", () => ({
  getUsers: () => [
    { id: "u1", username: "root", role: "admin", passwordHash: "x", createdAt: "2026-01-01" },
  ],
  createUser: vi.fn(),
  deleteUser: vi.fn(),
  getUserById: vi.fn(),
  getUserByUsername: vi.fn(),
  updateUserRole: vi.fn(),
}));

// Keep repo resolution deterministic: no repo context so a granted settings PUT
// stops at 409 (proving the admin gate was passed rather than short-circuited).
vi.mock("@/lib/ai-sessions", () => ({ getMeta: () => undefined }));

interface ReqOpts {
  cookie?: string;
  headers?: Record<string, string>;
  body?: unknown;
  url?: string;
}

function makeReq(opts: ReqOpts = {}) {
  const store = new Map<string, string>();
  for (const [k, v] of Object.entries(opts.headers ?? {})) store.set(k.toLowerCase(), v);
  if (opts.cookie) store.set("cookie", opts.cookie);
  return {
    url: opts.url ?? "http://localhost/api/test",
    headers: { get: (name: string) => store.get(name.toLowerCase()) ?? null },
    nextUrl: { searchParams: new URLSearchParams() },
    json: async () => opts.body,
  } as never;
}

const ADMIN_JWT = { userId: "u1", username: "root", role: "admin" };
const USER_JWT = { userId: "u2", username: "alice", role: "user" };

// Simulates a middleware-authenticated admin: a valid session cookie PLUS the
// x-user-* headers the proxy projects from the verified JWT.
const verifiedAdminReq = (o: Partial<ReqOpts> = {}) =>
  makeReq({
    cookie: "terminalx-session=admin-token",
    headers: { "x-user-role": "admin", "x-username": "root" },
    ...o,
  });

// A spoofed admin header with no session cookie at all — the bypass the
// hardening must defeat.
const spoofedAdminReq = (o: Partial<ReqOpts> = {}) =>
  makeReq({ headers: { "x-user-role": "admin", "x-username": "attacker" }, ...o });

// A legitimately-authenticated NON-admin whose request also carries a spoofed
// admin header (e.g. if middleware header-stripping were bypassed).
const userSessionSpoofedHeaderReq = (o: Partial<ReqOpts> = {}) =>
  makeReq({
    cookie: "terminalx-session=user-token",
    headers: { "x-user-role": "admin", "x-username": "alice" },
    ...o,
  });

beforeEach(() => {
  vi.resetModules();
  mocks.authMode = "local";
  mocks.verifyJwt.mockReset();
  delete process.env.TERMINALX_AUTH_MODE;
  delete process.env.TERMINALX_ALLOW_AUTH_NONE;
});

describe("/api/users admin gate", () => {
  it("grants a JWT-verified admin", async () => {
    mocks.verifyJwt.mockResolvedValue(ADMIN_JWT);
    const { GET } = await import("@/app/api/users/route");
    const res = await GET(verifiedAdminReq());
    expect(res.status).toBe(200);
  });

  it("denies a spoofed admin header with no session", async () => {
    mocks.verifyJwt.mockResolvedValue(ADMIN_JWT); // never reached: no cookie present
    const { GET } = await import("@/app/api/users/route");
    const res = await GET(spoofedAdminReq());
    expect(res.status).toBe(403);
    expect(mocks.verifyJwt).not.toHaveBeenCalled();
  });

  it("denies a real non-admin session even with a spoofed admin header", async () => {
    mocks.verifyJwt.mockResolvedValue(USER_JWT);
    const { GET } = await import("@/app/api/users/route");
    const res = await GET(userSessionSpoofedHeaderReq());
    expect(res.status).toBe(403);
  });

  it("denies a JWT-verified non-admin", async () => {
    mocks.verifyJwt.mockResolvedValue(USER_JWT);
    const { GET } = await import("@/app/api/users/route");
    const res = await GET(
      makeReq({
        cookie: "terminalx-session=user-token",
        headers: { "x-user-role": "user", "x-username": "alice" },
      })
    );
    expect(res.status).toBe(403);
  });

  it("password mode: preserves the 'requires local auth mode' 400", async () => {
    mocks.authMode = "password";
    const { GET } = await import("@/app/api/users/route");
    const res = await GET(verifiedAdminReq());
    expect(res.status).toBe(400);
  });
});

describe("/api/settings repo-scope admin gate", () => {
  let tmp: string;
  const repoBody = { scope: "repo", session: "s", models: { defaultToPlanMode: true } };

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tx-admin-gate-settings-"));
    process.env.TERMINUS_ROOT = tmp;
  });

  it("passes the gate for a JWT-verified admin (stops at 409 no-repo-context)", async () => {
    mocks.verifyJwt.mockResolvedValue(ADMIN_JWT);
    const { PUT } = await import("@/app/api/settings/route");
    const res = await PUT(verifiedAdminReq({ body: repoBody }));
    expect(res.status).toBe(409);
  });

  it("denies a spoofed admin header with no session", async () => {
    const { PUT } = await import("@/app/api/settings/route");
    const res = await PUT(spoofedAdminReq({ body: repoBody }));
    expect(res.status).toBe(403);
    expect(mocks.verifyJwt).not.toHaveBeenCalled();
  });

  it("denies a real non-admin session even with a spoofed admin header", async () => {
    mocks.verifyJwt.mockResolvedValue(USER_JWT);
    const { PUT } = await import("@/app/api/settings/route");
    const res = await PUT(userSessionSpoofedHeaderReq({ body: repoBody }));
    expect(res.status).toBe(403);
  });
});

describe("/api/telegram/settings admin gate", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tx-admin-gate-telegram-"));
    process.env.TERMINALX_DATA_DIR = tmp;
  });

  it("grants a JWT-verified admin (GET)", async () => {
    mocks.verifyJwt.mockResolvedValue(ADMIN_JWT);
    const { GET } = await import("@/app/api/telegram/settings/route");
    const res = await GET(verifiedAdminReq());
    expect(res.status).toBe(200);
  });

  it("denies a spoofed admin header with no session (GET)", async () => {
    const { GET } = await import("@/app/api/telegram/settings/route");
    const res = await GET(spoofedAdminReq());
    expect(res.status).toBe(403);
    expect(mocks.verifyJwt).not.toHaveBeenCalled();
  });

  it("denies a real non-admin session even with a spoofed admin header (PATCH)", async () => {
    mocks.verifyJwt.mockResolvedValue(USER_JWT);
    const { PATCH } = await import("@/app/api/telegram/settings/route");
    const res = await PATCH(userSessionSpoofedHeaderReq({ body: { enabled: true } }));
    expect(res.status).toBe(403);
  });
});
