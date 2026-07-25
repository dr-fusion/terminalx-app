import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { closeCanonicalIdentityAuthorityService } from "@/lib/identity-service";

describe("shared-password login canonical identity", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-password-login-"));
  let login: typeof import("@/app/api/auth/login/route").POST;

  beforeAll(async () => {
    process.env.TERMINALX_AUTH_MODE = "password";
    process.env.TERMINALX_PASSWORD = "correct-password";
    process.env.TERMINALX_JWT_SECRET = "password-login-secret-that-is-at-least-32-characters";
    process.env.TERMINALX_TEAM_SESSION_DB_PATH = path.join(directory, "team-sessions.sqlite");
    ({ POST: login } = await import("@/app/api/auth/login/route"));
  });

  afterAll(() => {
    closeCanonicalIdentityAuthorityService();
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_PASSWORD;
    delete process.env.TERMINALX_JWT_SECRET;
    delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("provisions one stable password identity without changing the login response", async () => {
    const request = () =>
      ({
        json: async () => ({ password: "correct-password" }),
        headers: { get: (name: string) => (name === "host" ? "localhost:3000" : null) },
        nextUrl: { protocol: "http:", host: "localhost:3000" },
      }) as never;

    const first = await login(request());
    const second = await login(request());

    expect(first.status).toBe(200);
    await expect(first.clone().json()).resolves.toEqual({ success: true, username: "admin" });
    const payloads = [first, second].map((response) => {
      const cookie = response.headers.get("set-cookie") ?? "";
      const token = /terminalx-session=([^;]+)/.exec(cookie)?.[1];
      expect(token).toBeTruthy();
      return JSON.parse(Buffer.from(token!.split(".")[1]!, "base64url").toString()) as {
        userId: string;
        authProvider?: string;
        authSubject?: string;
        userGeneration?: number;
        authIdentityGeneration?: number;
        auth_time?: number;
        iat?: number;
        jti?: string;
      };
    });
    expect(payloads[0]).toMatchObject({
      userId: "single-user",
      authProvider: "password",
      authSubject: "shared-password",
      userGeneration: 1,
      authIdentityGeneration: 1,
      auth_time: expect.any(Number),
      iat: expect.any(Number),
      jti: expect.any(String),
    });
    expect(payloads[0]!.iat! - payloads[0]!.auth_time!).toBeGreaterThanOrEqual(0);
    expect(payloads[0]!.iat! - payloads[0]!.auth_time!).toBeLessThanOrEqual(1);
    expect(payloads[1]!.userId).toBe(payloads[0]!.userId);
  });
});
