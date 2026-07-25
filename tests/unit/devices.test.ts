import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMobileAuthAuthority } from "@/lib/mobile-auth/authority";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

describe("SQLite paired-device authority", () => {
  let database: TeamSessionDatabase;
  let now: number;

  beforeEach(() => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    now = 1_700_000_000_000;
    insertUser(database.db, "user-1", "alice@example.com");
    insertUser(database.db, "user-2", "bob@example.com");
  });

  afterEach(() => database.close());

  it("registers, lists, touches, and durably revokes one owned device", () => {
    const authority = createMobileAuthAuthority({ db: database.db, clock: () => now });
    const device = authority.registerDevice({
      userId: "user-1",
      username: "alice@example.com",
      name: "Alice's phone",
    });
    expect(authority.getDevice(device.id)).toEqual(device);
    expect(authority.listDevicesForUser("user-1")).toEqual([device]);
    expect(authority.isDeviceActive(device.id)).toBe(true);

    now += 5_000;
    authority.touchDevice(device.id);
    expect(authority.getDevice(device.id)?.lastSeenAt).toBe(now);
    expect(authority.revokeDevice(device.id, "user-2")).toBe(false);
    expect(authority.revokeDevice(device.id, "user-1")).toBe(true);
    expect(authority.revokeDevice(device.id, "user-1")).toBe(true);
    expect(authority.isDeviceActive(device.id)).toBe(false);

    now += 5_000;
    authority.touchDevice(device.id);
    expect(authority.getDevice(device.id)?.lastSeenAt).toBe(now - 5_000);
  });

  it("cannot revive or delete a revoked device through ordinary SQL", () => {
    const authority = createMobileAuthAuthority({ db: database.db, clock: () => now });
    const device = authority.registerDevice({
      userId: "user-1",
      username: "alice@example.com",
      name: "Alice's phone",
    });
    authority.revokeDevice(device.id, "user-1");

    expect(() =>
      database.db
        .prepare("UPDATE paired_devices SET revoked_at_ms = NULL WHERE id = ?")
        .run(device.id)
    ).toThrow("Paired Device revocation is irreversible");
    expect(() =>
      database.db.prepare("DELETE FROM paired_devices WHERE id = ?").run(device.id)
    ).toThrow("Paired Device history is immutable");
    expect(authority.isDeviceActive(device.id)).toBe(false);
  });

  it("imports valid legacy devices once, skips orphan Users, and counts inserts only", () => {
    const authority = createMobileAuthAuthority({ db: database.db, clock: () => now });
    const imported = authority.importLegacyDevices({
      sourceDigest: "d".repeat(64),
      devices: [
        {
          id: "legacy-valid",
          userId: "user-1",
          username: "alice@example.com",
          name: "Old phone",
          createdAt: 100,
          lastSeenAt: 200,
          revokedAt: null,
        },
        {
          id: "legacy-orphan",
          userId: "missing-user",
          username: "gone@example.com",
          name: "Orphan phone",
          createdAt: 100,
          lastSeenAt: 200,
          revokedAt: null,
        },
      ],
    });

    expect(imported).toBe(1);
    expect(authority.hasImportedLegacyDevices()).toBe(true);
    expect(authority.getDevice("legacy-valid")).toMatchObject({ userId: "user-1" });
    expect(authority.getDevice("legacy-orphan")).toBeNull();
    expect(authority.importLegacyDevices({ sourceDigest: "e".repeat(64), devices: [] })).toBe(1);
    expect(database.db.prepare("SELECT imported_count FROM mobile_auth_migrations").get()).toEqual({
      imported_count: 1,
    });
  });
});

function insertUser(db: TeamSessionDatabase["db"], id: string, username: string): void {
  db.prepare(
    `INSERT INTO users (
       id, username, display_name, legacy_role, status, generation,
       created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
     ) VALUES (?, ?, ?, 'admin', 'active', 1, 1, 1, NULL, NULL)`
  ).run(id, username, username);
}
