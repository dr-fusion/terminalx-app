import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { closeCanonicalIdentityAuthorityService } from "@/lib/identity-service";

describe("local login canonical identity", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-local-login-"));
  let users: typeof import("@/lib/users");
  let verifyJwt: typeof import("@/lib/auth").verifyJwt;
  let login: typeof import("@/app/api/auth/login/route").POST;

  beforeAll(async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    process.env.TERMINALX_JWT_SECRET = "local-login-secret-that-is-at-least-32-characters";
    process.env.TERMINALX_TEAM_SESSION_DB_PATH = path.join(directory, "team-sessions.sqlite");
    process.env.TERMINALX_LEGACY_USERS_FILE = path.join(directory, "users.json");
    users = await import("@/lib/users");
    ({ verifyJwt } = await import("@/lib/auth"));
    ({ POST: login } = await import("@/app/api/auth/login/route"));
    await users.createUser("alice", "correct-password", "user");
  });

  afterAll(() => {
    closeCanonicalIdentityAuthorityService();
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_JWT_SECRET;
    delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
    delete process.env.TERMINALX_LEGACY_USERS_FILE;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("issues the exact active local identity generation without changing the route response", async () => {
    const response = await login({
      json: async () => ({ username: "alice", password: "correct-password" }),
      headers: { get: (name: string) => (name === "host" ? "localhost:3000" : null) },
      nextUrl: { protocol: "http:", host: "localhost:3000" },
    } as never);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      success: true,
      username: "alice",
      role: "user",
    });
    const cookie = response.headers.get("set-cookie") ?? "";
    const token = /terminalx-session=([^;]+)/.exec(cookie)?.[1];
    expect(token).toBeTruthy();
    const payload = JSON.parse(Buffer.from(token!.split(".")[1]!, "base64url").toString()) as {
      authProvider?: string;
      authSubject?: string;
      userGeneration?: number;
      authIdentityGeneration?: number;
      auth_time?: number;
      iat?: number;
      jti?: string;
    };
    expect(payload).toMatchObject({
      authProvider: "local",
      authSubject: "alice",
      userGeneration: 1,
      authIdentityGeneration: 1,
      auth_time: expect.any(Number),
      iat: expect.any(Number),
      jti: expect.any(String),
    });
    expect(payload.iat! - payload.auth_time!).toBeGreaterThanOrEqual(0);
    expect(payload.iat! - payload.auth_time!).toBeLessThanOrEqual(1);
    await expect(verifyJwt(token!)).resolves.toMatchObject({ username: "alice", role: "user" });
  });
});
