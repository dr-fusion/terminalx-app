import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NextRequest } from "next/server";
import { createCanonicalIdentityAuthority } from "@/lib/identity-authority";
import { closeCanonicalIdentityAuthorityService } from "@/lib/identity-service";
import { openTeamSessionDatabase } from "@/lib/team-sessions/sqlite";

describe("Google callback canonical identity", () => {
  let directory: string;
  let filename: string;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-google-callback-"));
    filename = path.join(directory, "team-sessions.sqlite");
    process.env.TERMINALX_AUTH_MODE = "google";
    process.env.TERMINALX_JWT_SECRET = "google-login-secret-that-is-at-least-32-characters";
    process.env.TERMINALX_GOOGLE_CLIENT_ID = "google-client";
    process.env.TERMINALX_GOOGLE_CLIENT_SECRET = "google-client-secret";
    process.env.TERMINALX_ALLOWED_EMAILS = "alice@example.com";
    process.env.TERMINALX_TEAM_SESSION_DB_PATH = filename;
  });

  afterEach(() => {
    closeCanonicalIdentityAuthorityService();
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
    mockGoogleUserInfo("google-subject-1");
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
      auth_time?: number;
      iat?: number;
      jti?: string;
    };
    expect(payload).toMatchObject({
      userId: "google-google-subject-1",
      username: "alice@example.com",
      authProvider: "google",
      authSubject: "google-subject-1",
      userGeneration: 1,
      authIdentityGeneration: 1,
      auth_time: expect.any(Number),
      iat: expect.any(Number),
      jti: expect.any(String),
    });
    expect(payload.iat! - payload.auth_time!).toBeGreaterThanOrEqual(0);
    expect(payload.iat! - payload.auth_time!).toBeLessThanOrEqual(1);
  });

  it("keeps the pre-v11 Google User id so existing team and project access remains effective", async () => {
    const legacyUserId = "google-google-subject-legacy";
    const database = openTeamSessionDatabase({ filename });
    try {
      database.db.exec(`
        INSERT INTO teams (id, name, created_at_ms) VALUES ('team-legacy', 'Team', 100);
        INSERT INTO projects (id, team_id, name, source_ref, created_at_ms)
        VALUES ('project-legacy', 'team-legacy', 'Project', NULL, 100);
        INSERT INTO team_memberships (
          team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
        ) VALUES (
          'team-legacy', '${legacyUserId}', 'owner', 'active', 2, 100, NULL
        );
        INSERT INTO project_access (
          project_id, user_id, role, status, version, created_at_ms, revoked_at_ms
        ) VALUES (
          'project-legacy', '${legacyUserId}', 'maintainer', 'active', 2, 100, NULL
        );
      `);
    } finally {
      database.close();
    }
    mockGoogleUserInfo("google-subject-legacy");
    const { GET } = await import("@/app/api/auth/google/callback/route");

    const response = await GET(
      new NextRequest(
        "http://localhost:3000/api/auth/google/callback?code=oauth-code&state=state-legacy",
        { headers: { cookie: "oauth-state=state-legacy" } }
      )
    );

    expect(response.status).toBe(307);
    const payload = sessionPayload(response);
    expect(payload).toMatchObject({
      userId: legacyUserId,
      username: "alice@example.com",
      authProvider: "google",
      authSubject: "google-subject-legacy",
      userGeneration: 1,
      authIdentityGeneration: 1,
    });
    const persisted = openTeamSessionDatabase({ filename });
    try {
      expect(
        persisted.db
          .prepare(
            `SELECT team_id, user_id, role, status, version
             FROM team_memberships WHERE user_id = ?`
          )
          .get(legacyUserId)
      ).toEqual({
        team_id: "team-legacy",
        user_id: legacyUserId,
        role: "owner",
        status: "active",
        version: 2,
      });
      expect(
        persisted.db
          .prepare(
            `SELECT project_id, user_id, role, status, version
             FROM project_access WHERE user_id = ?`
          )
          .get(legacyUserId)
      ).toEqual({
        project_id: "project-legacy",
        user_id: legacyUserId,
        role: "maintainer",
        status: "active",
        version: 2,
      });
    } finally {
      persisted.close();
    }
  });

  it("denies OAuth when the derived legacy User id already belongs to a local identity", async () => {
    const legacyUserId = "google-google-subject-collision";
    const database = openTeamSessionDatabase({ filename });
    try {
      const authority = createCanonicalIdentityAuthority({
        db: database.db,
        idGenerator: () => "local-identity-collision",
      });
      authority.importLegacyLocalUsers({
        sourceDigest: "d".repeat(64),
        users: [
          {
            id: legacyUserId,
            username: "local-owner",
            role: "user",
            passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
            createdAt: "2023-11-14T22:13:20.000Z",
            lastLogin: null,
          },
        ],
      });
      database.db.exec(`
        INSERT INTO teams (id, name, created_at_ms) VALUES ('team-collision', 'Team', 100);
        INSERT INTO team_memberships (
          team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
        ) VALUES (
          'team-collision', '${legacyUserId}', 'owner', 'active', 1, 100, NULL
        );
      `);
    } finally {
      database.close();
    }
    mockGoogleUserInfo("google-subject-collision");
    const { GET } = await import("@/app/api/auth/google/callback/route");

    const response = await GET(
      new NextRequest(
        "http://localhost:3000/api/auth/google/callback?code=oauth-code&state=state-collision",
        { headers: { cookie: "oauth-state=state-collision" } }
      )
    );

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toContain("/login?error=oauth_failed");
    expect(response.headers.get("set-cookie") ?? "").not.toContain("terminalx-session=");
    const persisted = openTeamSessionDatabase({ filename });
    try {
      expect(
        persisted.db
          .prepare("SELECT provider, subject, user_id FROM auth_identities ORDER BY id")
          .all()
      ).toEqual([{ provider: "local", subject: "local-owner", user_id: legacyUserId }]);
      expect(persisted.db.prepare("SELECT * FROM legacy_google_identity_bridges").all()).toEqual(
        []
      );
    } finally {
      persisted.close();
    }
  });
});

function mockGoogleUserInfo(subject: string): void {
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
          sub: subject,
          email: "alice@example.com",
          email_verified: true,
          name: "Alice",
          picture: "https://example.invalid/alice.png",
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    );
}

function sessionPayload(response: Response): Record<string, unknown> {
  const cookie = response.headers.get("set-cookie") ?? "";
  const token = /terminalx-session=([^;]+)/.exec(cookie)?.[1];
  if (!token) throw new Error("Expected canonical session cookie");
  return JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()) as Record<
    string,
    unknown
  >;
}
