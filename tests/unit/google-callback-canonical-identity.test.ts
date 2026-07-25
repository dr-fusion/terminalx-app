import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NextRequest } from "next/server";

describe("Google callback canonical identity", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-google-callback-"));

  beforeAll(() => {
    process.env.TERMINALX_AUTH_MODE = "google";
    process.env.TERMINALX_JWT_SECRET = "google-login-secret-that-is-at-least-32-characters";
    process.env.TERMINALX_GOOGLE_CLIENT_ID = "google-client";
    process.env.TERMINALX_GOOGLE_CLIENT_SECRET = "google-client-secret";
    process.env.TERMINALX_ALLOWED_EMAILS = "alice@example.com";
    process.env.TERMINALX_TEAM_SESSION_DB_PATH = path.join(directory, "team-sessions.sqlite");
  });

  afterAll(() => {
    vi.restoreAllMocks();
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_JWT_SECRET;
    delete process.env.TERMINALX_GOOGLE_CLIENT_ID;
    delete process.env.TERMINALX_GOOGLE_CLIENT_SECRET;
    delete process.env.TERMINALX_ALLOWED_EMAILS;
    delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("provisions the verified provider subject before issuing a canonical JWT", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: "access-token",
            id_token: "id-token",
            token_type: "Bearer",
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            sub: "google-subject-1",
            email: "alice@example.com",
            email_verified: true,
            name: "Alice",
            picture: "https://example.invalid/alice.png",
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        )
      );
    const { GET } = await import("@/app/api/auth/google/callback/route");
    const response = await GET(
      new NextRequest(
        "http://localhost:3000/api/auth/google/callback?code=oauth-code&state=state-1",
        { headers: { cookie: "oauth-state=state-1" } }
      )
    );

    expect(response.status).toBe(307);
    const cookie = response.headers.get("set-cookie") ?? "";
    const token = /terminalx-session=([^;]+)/.exec(cookie)?.[1];
    expect(token).toBeTruthy();
    const payload = JSON.parse(Buffer.from(token!.split(".")[1]!, "base64url").toString()) as {
      userId: string;
      username: string;
      authProvider?: string;
      authSubject?: string;
      userGeneration?: number;
      authIdentityGeneration?: number;
    };
    expect(payload.userId).not.toBe("google-google-subject-1");
    expect(payload).toMatchObject({
      username: "alice@example.com",
      authProvider: "google",
      authSubject: "google-subject-1",
      userGeneration: 1,
      authIdentityGeneration: 1,
    });
  });
});
