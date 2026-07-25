import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMobileAuthAuthority } from "@/lib/mobile-auth/authority";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

const NOW = 1_700_000_000_000;
const SOURCE_AUTHENTICATION = {
  credentialJtiDigest: "a".repeat(64),
  credentialExpiresAtMs: 4_000_000_000_000,
  device: { provenance: "browser" as const },
};

describe("multi-connection mobile authentication authority", () => {
  let directory: string;
  let filename: string;
  let first: TeamSessionDatabase | undefined;
  let second: TeamSessionDatabase | undefined;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-mobile-connections-"));
    filename = path.join(directory, "team-sessions.sqlite");
    first = openTeamSessionDatabase({ filename });
    insertUser(first.db, "user-1", "alice@example.com");
    second = openTeamSessionDatabase({ filename });
  });

  afterEach(() => {
    second?.close();
    first?.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("retains codes issued by independent database owners and permits one redemption total", () => {
    const firstAuthority = createMobileAuthAuthority({ db: first!.db, clock: () => NOW });
    const secondAuthority = createMobileAuthAuthority({ db: second!.db, clock: () => NOW });
    const firstCode = firstAuthority.createPairingCode(pairingInput("subject-1"));
    const secondCode = secondAuthority.createPairingCode(pairingInput("subject-2"));

    expect(first!.db.prepare("SELECT count(*) AS count FROM mobile_pairing_codes").get()).toEqual({
      count: 2,
    });
    expect(secondAuthority.consumePairingCode(firstCode.code)).toMatchObject({
      authSubject: "subject-1",
    });
    expect(firstAuthority.consumePairingCode(firstCode.code)).toBeNull();
    expect(firstAuthority.consumePairingCode(secondCode.code)).toMatchObject({
      authSubject: "subject-2",
    });
    expect(secondAuthority.consumePairingCode(secondCode.code)).toBeNull();

    first!.db.pragma("wal_checkpoint(TRUNCATE)");
    for (const entry of fs.readdirSync(directory)) {
      const raw = fs.readFileSync(path.join(directory, entry));
      expect(raw.includes(Buffer.from(firstCode.code))).toBe(false);
      expect(raw.includes(Buffer.from(secondCode.code))).toBe(false);
    }
  });

  it("keeps unknown-code guesses read-only while another connection owns the write lock", () => {
    const secondAuthority = createMobileAuthAuthority({ db: second!.db, clock: () => NOW });
    first!.db.exec("BEGIN IMMEDIATE");
    try {
      expect(secondAuthority.consumePairingCode("Z".repeat(32))).toBeNull();
    } finally {
      first!.db.exec("ROLLBACK");
    }
  });

  it("retains independent device registrations and an irreversible revocation across reopen", () => {
    const firstAuthority = createMobileAuthAuthority({ db: first!.db, clock: () => NOW });
    const secondAuthority = createMobileAuthAuthority({ db: second!.db, clock: () => NOW + 1 });
    const firstDevice = firstAuthority.registerDevice({
      userId: "user-1",
      username: "alice@example.com",
      name: "Phone",
    });
    const secondDevice = secondAuthority.registerDevice({
      userId: "user-1",
      username: "alice@example.com",
      name: "Tablet",
    });

    expect(new Set(firstAuthority.listDevicesForUser("user-1").map(({ id }) => id))).toEqual(
      new Set([firstDevice.id, secondDevice.id])
    );
    expect(secondAuthority.revokeDevice(firstDevice.id, "user-1")).toBe(true);
    expect(firstAuthority.isDeviceActive(firstDevice.id)).toBe(false);
    expect(firstAuthority.isDeviceActive(secondDevice.id)).toBe(true);

    second!.close();
    second = undefined;
    first!.close();
    first = undefined;
    const reopened = openTeamSessionDatabase({ filename });
    try {
      const reopenedAuthority = createMobileAuthAuthority({ db: reopened.db });
      expect(reopenedAuthority.getDevice(firstDevice.id)?.revokedAt).not.toBeNull();
      expect(reopenedAuthority.isDeviceActive(secondDevice.id)).toBe(true);
    } finally {
      reopened.close();
    }
  });
});

function pairingInput(authSubject: string) {
  return {
    userId: "user-1",
    username: "alice@example.com",
    displayName: "Alice",
    role: "admin",
    authProvider: "google" as const,
    authSubject,
    userGeneration: 1,
    authIdentityGeneration: 1,
    sourceAuthentication: SOURCE_AUTHENTICATION,
  };
}

function insertUser(db: TeamSessionDatabase["db"], id: string, username: string): void {
  db.prepare(
    `INSERT INTO users (
       id, username, display_name, legacy_role, status, generation,
       created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
     ) VALUES (?, ?, ?, 'admin', 'active', 1, 1, 1, NULL, NULL)`
  ).run(id, username, username);
}
