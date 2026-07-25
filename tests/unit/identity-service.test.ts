import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const sqliteHarness = vi.hoisted(() => ({ openCount: 0, failClose: false }));

vi.mock("@/lib/team-sessions/sqlite", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/team-sessions/sqlite")>();
  return {
    ...actual,
    openTeamSessionDatabase(
      options: Parameters<typeof actual.openTeamSessionDatabase>[0]
    ): ReturnType<typeof actual.openTeamSessionDatabase> {
      sqliteHarness.openCount += 1;
      const database = actual.openTeamSessionDatabase(options);
      return {
        ...database,
        close(): void {
          if (sqliteHarness.failClose) throw new Error("simulated close failure");
          database.close();
        },
      };
    },
  };
});

import {
  closeCanonicalIdentityAuthorityService,
  initializeCanonicalIdentityAuthorityService,
  initializeLegacyMobileAuthState,
  withCanonicalIdentityAuthority,
  withMobileAuthAuthority,
} from "@/lib/identity-service";
import type { CanonicalIdentityAuthority } from "@/lib/identity-authority";

describe("canonical identity database service", () => {
  let temporaryDirectory = "";
  let filename = "";

  beforeEach(() => {
    closeCanonicalIdentityAuthorityService();
    sqliteHarness.openCount = 0;
    sqliteHarness.failClose = false;
    temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-identity-service-"));
    filename = path.join(temporaryDirectory, "team-sessions.sqlite");
    process.env.TERMINALX_TEAM_SESSION_DB_PATH = filename;
  });

  afterEach(() => {
    sqliteHarness.failClose = false;
    closeCanonicalIdentityAuthorityService();
    delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
    delete process.env.TERMINALX_DEVICES_FILE;
    delete process.env.TERMINALX_DEVICE_REVOCATIONS_DIR;
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  });

  it("reuses one validated connection across repeated arbitrary identity lookups", () => {
    const authorities = new Set<CanonicalIdentityAuthority>();

    initializeCanonicalIdentityAuthorityService();

    for (let index = 0; index < 512; index += 1) {
      withCanonicalIdentityAuthority((authority) => {
        authorities.add(authority);
        expect(authority.getLocalUserByUsername(`untrusted-${index}`)).toBeNull();
      });
    }

    expect(authorities.size).toBe(1);
    expect(sqliteHarness.openCount).toBe(1);
  });

  it("defers cleanup until an asynchronous lease settles and rejects nested admission", async () => {
    let releaseLease!: () => void;
    let leasedAuthority!: CanonicalIdentityAuthority;
    const lease = withCanonicalIdentityAuthority(async (authority) => {
      leasedAuthority = authority;
      closeCanonicalIdentityAuthorityService();

      expect(() =>
        withCanonicalIdentityAuthority((nestedAuthority) => nestedAuthority.listLocalUsers())
      ).toThrow("Canonical identity service is closing");

      await new Promise<void>((resolve) => {
        releaseLease = resolve;
      });
      expect(authority.listLocalUsers()).toEqual([]);
    });

    expect(sqliteHarness.openCount).toBe(1);
    releaseLease();
    await lease;

    expect(() => leasedAuthority.listLocalUsers()).toThrow();
    const replacement = withCanonicalIdentityAuthority((authority) => authority);
    expect(replacement).not.toBe(leasedAuthority);
    expect(sqliteHarness.openCount).toBe(2);

    closeCanonicalIdentityAuthorityService();
    expect(() => closeCanonicalIdentityAuthorityService()).not.toThrow();
  });

  it("reruns schema validation after cleanup and rejects a tampered version", () => {
    withCanonicalIdentityAuthority((authority) => authority.listLocalUsers());
    expect(sqliteHarness.openCount).toBe(1);

    const tamper = new Database(filename);
    tamper.pragma("user_version = 999");
    tamper.close();

    // Reuse deliberately avoids repeating migrations and quick_check for each
    // request. A fresh lifecycle must still enforce the exact schema version.
    withCanonicalIdentityAuthority((authority) => authority.listLocalUsers());
    expect(sqliteHarness.openCount).toBe(1);

    closeCanonicalIdentityAuthorityService();
    expect(() => withCanonicalIdentityAuthority((authority) => authority.listLocalUsers())).toThrow(
      "Unsupported Team Session database schema 999"
    );
    expect(sqliteHarness.openCount).toBe(2);
  });

  it("closes the prior database before switching test isolation paths", () => {
    const firstAuthority = withCanonicalIdentityAuthority((authority) => authority);
    const secondDirectory = fs.mkdtempSync(
      path.join(os.tmpdir(), "terminalx-identity-service-next-")
    );
    try {
      process.env.TERMINALX_TEAM_SESSION_DB_PATH = path.join(
        secondDirectory,
        "team-sessions.sqlite"
      );
      const secondAuthority = withCanonicalIdentityAuthority((authority) => authority);

      expect(secondAuthority).not.toBe(firstAuthority);
      expect(sqliteHarness.openCount).toBe(2);
      expect(() => firstAuthority.listLocalUsers()).toThrow();
    } finally {
      closeCanonicalIdentityAuthorityService();
      fs.rmSync(secondDirectory, { recursive: true, force: true });
    }
  });

  it("stays fail-closed after a cleanup failure and allows an explicit retry", () => {
    const firstAuthority = withCanonicalIdentityAuthority((authority) => authority);
    sqliteHarness.failClose = true;

    expect(() => closeCanonicalIdentityAuthorityService()).toThrow("simulated close failure");
    expect(() => withCanonicalIdentityAuthority((authority) => authority.listLocalUsers())).toThrow(
      "Canonical identity service is closing"
    );
    expect(sqliteHarness.openCount).toBe(1);
    expect(firstAuthority.listLocalUsers()).toEqual([]);

    sqliteHarness.failClose = false;
    expect(() => closeCanonicalIdentityAuthorityService()).not.toThrow();
    const replacement = withCanonicalIdentityAuthority((authority) => authority);
    expect(replacement).not.toBe(firstAuthority);
    expect(sqliteHarness.openCount).toBe(2);
  });

  it("does not reread a corrupt legacy device source after its immutable import marker", () => {
    const identity = withCanonicalIdentityAuthority((authority) =>
      authority.provisionPasswordIdentity()
    );
    const devicesFile = path.join(temporaryDirectory, "devices.json");
    process.env.TERMINALX_DEVICES_FILE = devicesFile;
    fs.writeFileSync(
      devicesFile,
      JSON.stringify([
        {
          id: "legacy-device-1",
          userId: identity.user.id,
          username: identity.user.username,
          name: "Legacy phone",
          createdAt: 100,
          lastSeenAt: 200,
          revokedAt: null,
        },
      ])
    );

    initializeLegacyMobileAuthState();
    expect(
      withMobileAuthAuthority((authority) => authority.getDevice("legacy-device-1"))
    ).toMatchObject({ userId: identity.user.id });

    fs.writeFileSync(devicesFile, "corrupt-after-success");
    closeCanonicalIdentityAuthorityService();
    expect(() => initializeLegacyMobileAuthState()).not.toThrow();
    expect(
      withMobileAuthAuthority((authority) => authority.getDevice("legacy-device-1"))
    ).not.toBeNull();
  });
});
