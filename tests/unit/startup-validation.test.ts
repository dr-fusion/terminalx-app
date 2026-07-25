import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

describe("startup validation", () => {
  let tmp: string;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-startup-"));
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("refuses no-auth mode", async () => {
    process.env.TERMINALX_AUTH_MODE = "none";
    process.env.TERMINALX_JWT_SECRET = "x".repeat(40);
    const { validateStartupConfiguration } = await import("@/lib/startup-validation");

    const result = validateStartupConfiguration({ host: "127.0.0.1", cwd: tmp });

    expect(result.errors.some((error) => error.includes("AUTH_MODE=none"))).toBe(true);
  });

  it("requires an admin password on first local-auth startup", async () => {
    process.env.TERMINALX_AUTH_MODE = "local";
    process.env.TERMINALX_JWT_SECRET = "x".repeat(40);
    delete process.env.TERMINALX_ADMIN_PASSWORD;
    const { validateStartupConfiguration } = await import("@/lib/startup-validation");

    const result = validateStartupConfiguration({ host: "127.0.0.1", cwd: tmp });

    expect(result.errors.some((error) => error.includes("TERMINALX_ADMIN_PASSWORD"))).toBe(true);
  });

  it("accepts local auth with an existing user file and jwt secret", async () => {
    fs.mkdirSync(path.join(tmp, "data"));
    fs.writeFileSync(path.join(tmp, "data", "users.json"), JSON.stringify([{ id: "u1" }]));
    process.env.TERMINALX_AUTH_MODE = "local";
    process.env.TERMINALX_JWT_SECRET = "x".repeat(40);
    const { validateStartupConfiguration } = await import("@/lib/startup-validation");

    const result = validateStartupConfiguration({ host: "127.0.0.1", cwd: tmp });

    expect(result.errors).toEqual([]);
  });

  it("accepts local auth with an active SQL-backed User after legacy migration", async () => {
    fs.mkdirSync(path.join(tmp, "data"));
    const filename = path.join(tmp, "data", "team-sessions.sqlite");
    const { openTeamSessionDatabase } = await import("@/lib/team-sessions/sqlite");
    const { createCanonicalIdentityAuthority } = await import("@/lib/identity-authority");
    const database = openTeamSessionDatabase({ filename });
    try {
      const ids = ["canonical-user-1", "local-identity-1"];
      createCanonicalIdentityAuthority({
        db: database.db,
        idGenerator: () => ids.shift()!,
      }).createLocalUser({
        username: "alice",
        passwordHash: "$2b$12$01234567890123456789012345678901234567890123456789012",
        legacyRole: "admin",
      });
    } finally {
      database.close();
    }
    process.env.TERMINALX_AUTH_MODE = "local";
    process.env.TERMINALX_JWT_SECRET = "x".repeat(40);
    delete process.env.TERMINALX_ADMIN_PASSWORD;
    const { validateStartupConfiguration } = await import("@/lib/startup-validation");

    const result = validateStartupConfiguration({ host: "127.0.0.1", cwd: tmp });

    expect(result.errors).toEqual([]);
  });

  it("fails explicitly when the configured database has the wrong application identity", async () => {
    fs.mkdirSync(path.join(tmp, "data"));
    fs.writeFileSync(path.join(tmp, "data", "users.json"), JSON.stringify([{ id: "legacy" }]));
    const database = new Database(path.join(tmp, "data", "team-sessions.sqlite"));
    database.pragma("application_id = 1234");
    database.pragma("user_version = 10");
    database.close();
    process.env.TERMINALX_AUTH_MODE = "local";
    process.env.TERMINALX_JWT_SECRET = "x".repeat(40);
    process.env.TERMINALX_ADMIN_PASSWORD = "valid-password";
    const { validateStartupConfiguration } = await import("@/lib/startup-validation");

    const result = validateStartupConfiguration({ host: "127.0.0.1", cwd: tmp });

    expect(result.errors).toEqual([
      "Canonical identity database failed validation; refusing local-auth startup.",
    ]);
  });

  it("allows a recognized pre-identity database to reach transactional migration", async () => {
    fs.mkdirSync(path.join(tmp, "data"));
    fs.writeFileSync(path.join(tmp, "data", "users.json"), JSON.stringify([{ id: "legacy" }]));
    const database = new Database(path.join(tmp, "data", "team-sessions.sqlite"));
    database.pragma("application_id = 0x54585331");
    database.pragma("user_version = 10");
    database.close();
    process.env.TERMINALX_AUTH_MODE = "local";
    process.env.TERMINALX_JWT_SECRET = "x".repeat(40);
    delete process.env.TERMINALX_ADMIN_PASSWORD;
    const { validateStartupConfiguration } = await import("@/lib/startup-validation");

    const result = validateStartupConfiguration({ host: "127.0.0.1", cwd: tmp });

    expect(result.errors).toEqual([]);
  });

  it("fails explicitly when a canonical identity schema cannot be queried", async () => {
    fs.mkdirSync(path.join(tmp, "data"));
    const database = new Database(path.join(tmp, "data", "team-sessions.sqlite"));
    database.pragma("application_id = 0x54585331");
    database.pragma("user_version = 11");
    database.close();
    process.env.TERMINALX_AUTH_MODE = "local";
    process.env.TERMINALX_JWT_SECRET = "x".repeat(40);
    process.env.TERMINALX_ADMIN_PASSWORD = "valid-password";
    const { validateStartupConfiguration } = await import("@/lib/startup-validation");

    const result = validateStartupConfiguration({ host: "127.0.0.1", cwd: tmp });

    expect(result.errors).toEqual([
      "Canonical identity database failed validation; refusing local-auth startup.",
    ]);
  });
});
