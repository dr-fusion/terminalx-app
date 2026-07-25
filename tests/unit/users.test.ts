import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { closeCanonicalIdentityAuthorityService } from "@/lib/identity-service";

describe("SQL-backed local Users", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-users-"));
  const dataDirectory = path.join(directory, "data");
  const legacyUsersFile = path.join(dataDirectory, "users.json");
  const databaseFile = path.join(dataDirectory, "team-sessions.sqlite");
  const legacyUser = {
    id: "stable-local-user-id",
    username: "alice",
    role: "admin" as const,
    passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
    createdAt: "2023-11-14T22:13:20.000Z",
    lastLogin: null,
  };
  let users: typeof import("@/lib/users");

  beforeAll(async () => {
    fs.mkdirSync(dataDirectory, { recursive: true });
    fs.writeFileSync(legacyUsersFile, JSON.stringify([legacyUser]), { mode: 0o600 });
    process.env.TERMINALX_TEAM_SESSION_DB_PATH = databaseFile;
    process.env.TERMINALX_LEGACY_USERS_FILE = legacyUsersFile;
    users = await import("@/lib/users");
  });

  afterAll(() => {
    closeCanonicalIdentityAuthorityService();
    delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
    delete process.env.TERMINALX_LEGACY_USERS_FILE;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("bridges legacy Users once and cannot resurrect a revoked User from the JSON source", async () => {
    expect(users.getUsers()).toEqual([legacyUser]);

    fs.writeFileSync(legacyUsersFile, "not-json", { mode: 0o600 });
    expect(users.getUsers()).toEqual([legacyUser]);

    await users.deleteUser(legacyUser.id);
    fs.writeFileSync(legacyUsersFile, JSON.stringify([legacyUser]), { mode: 0o600 });

    expect(users.getUsers()).toEqual([]);
    expect(users.getUserById(legacyUser.id)).toBeUndefined();
  });
});
