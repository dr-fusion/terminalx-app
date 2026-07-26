import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { evaluateReadiness } from "@/lib/ops/readiness";
import { handleReadiness } from "@/lib/ops/http";

describe("readiness evaluation", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-ready-"));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function migratedDatabase(): string {
    const filename = path.join(tmp, "team-sessions.sqlite");
    openTeamSessionDatabase({ filename }).close();
    return filename;
  }

  it("is ready when the database is migrated and no broker is configured", () => {
    const result = evaluateReadiness({
      databaseFilename: migratedDatabase(),
      secretBrokerConfigured: () => false,
    });
    expect(result.ready).toBe(true);
    expect(result.checks.every((check) => check.ok)).toBe(true);
  });

  it("fails closed when the database is missing", () => {
    const result = evaluateReadiness({
      databaseFilename: path.join(tmp, "missing.sqlite"),
      secretBrokerConfigured: () => false,
    });
    expect(result.ready).toBe(false);
    expect(result.checks.find((check) => check.name === "database")?.ok).toBe(false);
  });

  it("fails closed when the schema version is not the expected version", () => {
    const filename = migratedDatabase();
    const raw = new Database(filename);
    raw.pragma("user_version = 17");
    raw.close();
    const result = evaluateReadiness({
      databaseFilename: filename,
      secretBrokerConfigured: () => false,
    });
    expect(result.ready).toBe(false);
    expect(result.checks.find((check) => check.name === "schema")?.ok).toBe(false);
  });

  it("fails closed when a configured broker is not ready", () => {
    const result = evaluateReadiness({
      databaseFilename: migratedDatabase(),
      secretBrokerConfigured: () => true,
      secretBrokerReady: () => false,
    });
    expect(result.ready).toBe(false);
    expect(result.checks.find((check) => check.name === "secret-broker")?.ok).toBe(false);
  });
});

describe("readiness HTTP surface", () => {
  it("returns 200 with a bare non-leaking status when ready", async () => {
    const response = handleReadiness({
      evaluate: () => ({ ready: true, checks: [{ name: "database", ok: true }] }),
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({ status: "ready" });
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("returns 503 without disclosing which dependency is degraded", async () => {
    const response = handleReadiness({
      evaluate: () => ({
        ready: false,
        checks: [
          { name: "database", ok: false },
          { name: "secret-broker", ok: false },
        ],
      }),
    });
    expect(response.status).toBe(503);
    const text = await response.text();
    expect(text).toBe(JSON.stringify({ status: "not-ready" }));
    expect(text).not.toContain("database");
    expect(text).not.toContain("secret-broker");
  });

  it("fails closed to 503 if evaluation throws", async () => {
    const response = handleReadiness({
      evaluate: () => {
        throw new Error("boom");
      },
    });
    expect(response.status).toBe(503);
    const text = await response.text();
    expect(text).toBe(JSON.stringify({ status: "not-ready" }));
    expect(text).not.toContain("boom");
  });
});
