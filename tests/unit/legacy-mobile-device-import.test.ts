import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readLegacyDeviceImport } from "@/lib/mobile-auth/legacy-devices";

const DEVICE = {
  id: "legacy-device-1",
  userId: "user-1",
  username: "alice@example.com",
  name: "Old phone",
  createdAt: 100,
  lastSeenAt: 200,
  revokedAt: null,
};

describe("legacy mobile-device import boundary", () => {
  let directory: string;
  let devicesFile: string;
  let revocationsDirectory: string;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-legacy-mobile-"));
    devicesFile = path.join(directory, "devices.json");
    revocationsDirectory = path.join(directory, "revocations");
    process.env.TERMINALX_DEVICES_FILE = devicesFile;
    process.env.TERMINALX_DEVICE_REVOCATIONS_DIR = revocationsDirectory;
    fs.writeFileSync(devicesFile, JSON.stringify([DEVICE]));
    fs.mkdirSync(revocationsDirectory);
  });

  afterEach(() => {
    delete process.env.TERMINALX_DEVICES_FILE;
    delete process.env.TERMINALX_DEVICE_REVOCATIONS_DIR;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("applies an exact legacy revocation tombstone before returning an import", () => {
    const revokedAt = 250;
    fs.writeFileSync(
      revocationFile(),
      JSON.stringify({
        schema: 1,
        deviceIdDigest: digest(DEVICE.id),
        userIdDigest: digest(DEVICE.userId),
        revokedAt,
      })
    );

    const imported = readLegacyDeviceImport();

    expect(imported.sourceDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(imported.devices).toEqual([{ ...DEVICE, revokedAt }]);
  });

  it.each(["not-json", JSON.stringify({ schema: 1 })])(
    "preserves fail-closed revocation for malformed tombstone state",
    (contents) => {
      fs.writeFileSync(revocationFile(), contents);

      expect(readLegacyDeviceImport().devices).toEqual([
        { ...DEVICE, revokedAt: DEVICE.createdAt },
      ]);
    }
  );

  it("rejects an unavailable or malformed registry before producing a migration marker input", () => {
    fs.rmSync(devicesFile);
    fs.mkdirSync(devicesFile);
    expect(() => readLegacyDeviceImport()).toThrow(
      "Legacy Paired Device migration source is unavailable"
    );

    fs.rmSync(devicesFile, { recursive: true });
    fs.writeFileSync(devicesFile, "not-json");
    expect(() => readLegacyDeviceImport()).toThrow(
      "Legacy Paired Device migration source is invalid"
    );
  });

  function revocationFile(): string {
    return path.join(revocationsDirectory, `${digest(DEVICE.id)}.json`);
  }
});

function digest(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}
