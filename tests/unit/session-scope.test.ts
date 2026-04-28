import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { canAccessSession, getUserScoping, scopedSessionName } from "@/lib/session-scope";

describe("canAccessSession", () => {
  beforeEach(() => {
    process.env.TERMINALX_AUTH_MODE = "local";
  });

  afterEach(() => {
    delete process.env.TERMINALX_AUTH_MODE;
  });

  it("admin can access any session", () => {
    expect(canAccessSession("admin", "admin", "any-session")).toBe(true);
    expect(canAccessSession("admin", "admin", "other-user-session")).toBe(true);
  });

  it("user can access their own sessions (username-prefixed)", () => {
    expect(canAccessSession("alice", "user", "alice-myterm")).toBe(true);
    expect(canAccessSession("alice", "user", "alice-dev")).toBe(true);
  });

  it("user cannot access other users' sessions", () => {
    expect(canAccessSession("alice", "user", "bob-myterm")).toBe(false);
    expect(canAccessSession("alice", "user", "shared-session")).toBe(false);
  });

  it("returns false for null username in local mode", () => {
    expect(canAccessSession(null, "user", "any-session")).toBe(false);
  });

  it("allows all access in none auth mode", () => {
    process.env.TERMINALX_AUTH_MODE = "none";
    expect(canAccessSession(null, null, "any-session")).toBe(true);
  });

  it("allows all access in password auth mode", () => {
    process.env.TERMINALX_AUTH_MODE = "password";
    expect(canAccessSession(null, null, "any-session")).toBe(true);
  });
});

describe("scopedSessionName", () => {
  it("prefixes with username in local mode", () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    expect(scopedSessionName("myterm", "alice")).toBe("alice-myterm");
  });

  it("returns name unchanged when no username", () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    expect(scopedSessionName("myterm", null)).toBe("myterm");
  });

  it("returns name unchanged in none mode", () => {
    process.env.TERMINALX_AUTH_MODE = "none";
    expect(scopedSessionName("myterm", "alice")).toBe("myterm");
  });

  afterEach(() => {
    delete process.env.TERMINALX_AUTH_MODE;
  });
});

describe("getUserScoping", () => {
  const headers = (values: Record<string, string> = {}) => ({
    get: (name: string) => values[name.toLowerCase()] ?? null,
  });

  afterEach(() => {
    delete process.env.TERMINALX_AUTH_MODE;
  });

  it("fails closed in local mode when trusted identity is missing", () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    expect(getUserScoping(headers())).toEqual({
      username: null,
      role: null,
      shouldScope: true,
      hasIdentity: false,
    });
  });

  it("accepts a trusted local user identity", () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    expect(getUserScoping(headers({ "x-username": "alice", "x-user-role": "user" }))).toEqual({
      username: "alice",
      role: "user",
      shouldScope: true,
      hasIdentity: true,
    });
  });

  it("treats password mode as single-admin mode", () => {
    process.env.TERMINALX_AUTH_MODE = "password";
    expect(getUserScoping(headers())).toEqual({
      username: null,
      role: "admin",
      shouldScope: false,
      hasIdentity: true,
    });
  });
});
