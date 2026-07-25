import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Device, LegacyDeviceImport } from "./authority";

const SHA256_HEX = /^[0-9a-f]{64}$/;

function errorCodeIs(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === code
  );
}

function legacyDevicesFilename(): string {
  return (
    process.env.TERMINALX_DEVICES_FILE ??
    path.join(/* turbopackIgnore: true */ process.cwd(), "data", "devices.json")
  );
}

function legacyRevocationsDirectory(devicesFilename: string): string {
  return process.env.TERMINALX_DEVICE_REVOCATIONS_DIR ?? `${devicesFilename}.revocations`;
}

function parseDevice(value: unknown): Device {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.keys(value).sort().join(",") !==
      "createdAt,id,lastSeenAt,name,revokedAt,userId,username" ||
    !("id" in value) ||
    typeof value.id !== "string" ||
    value.id.length < 1 ||
    value.id.length > 300 ||
    !("userId" in value) ||
    typeof value.userId !== "string" ||
    value.userId.length < 1 ||
    value.userId.length > 300 ||
    !("username" in value) ||
    typeof value.username !== "string" ||
    value.username.length < 1 ||
    value.username.length > 1024 ||
    !("name" in value) ||
    typeof value.name !== "string" ||
    value.name.length > 120 ||
    !("createdAt" in value) ||
    !Number.isSafeInteger(value.createdAt) ||
    (value.createdAt as number) < 0 ||
    !("lastSeenAt" in value) ||
    !Number.isSafeInteger(value.lastSeenAt) ||
    (value.lastSeenAt as number) < (value.createdAt as number) ||
    !("revokedAt" in value) ||
    (value.revokedAt !== null &&
      (!Number.isSafeInteger(value.revokedAt) ||
        (value.revokedAt as number) < (value.createdAt as number)))
  ) {
    throw new Error("Legacy Paired Device migration source is invalid");
  }
  return {
    id: value.id,
    userId: value.userId,
    username: value.username,
    name: value.name,
    createdAt: value.createdAt as number,
    lastSeenAt: value.lastSeenAt as number,
    revokedAt: value.revokedAt as number | null,
  };
}

function digest(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function applyRevocationOverlay(device: Device, directory: string): Device {
  const deviceDigest = digest(device.id);
  let raw: string;
  try {
    raw = fs.readFileSync(
      /* turbopackIgnore: true */ path.join(directory, `${deviceDigest}.json`),
      "utf8"
    );
  } catch (error) {
    if (errorCodeIs(error, "ENOENT")) return device;
    throw new Error("Legacy Paired Device revocation source is unavailable", { cause: error });
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    const expectedUserDigest = digest(device.userId);
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Object.keys(parsed).sort().join(",") !== "deviceIdDigest,revokedAt,schema,userIdDigest" ||
      !("schema" in parsed) ||
      parsed.schema !== 1 ||
      !("deviceIdDigest" in parsed) ||
      parsed.deviceIdDigest !== deviceDigest ||
      typeof parsed.deviceIdDigest !== "string" ||
      !SHA256_HEX.test(parsed.deviceIdDigest) ||
      !("userIdDigest" in parsed) ||
      parsed.userIdDigest !== expectedUserDigest ||
      typeof parsed.userIdDigest !== "string" ||
      !SHA256_HEX.test(parsed.userIdDigest) ||
      !("revokedAt" in parsed) ||
      !Number.isSafeInteger(parsed.revokedAt) ||
      (parsed.revokedAt as number) < device.createdAt
    ) {
      return { ...device, revokedAt: device.revokedAt ?? device.createdAt };
    }
    return {
      ...device,
      revokedAt: Math.max(device.revokedAt ?? device.createdAt, parsed.revokedAt as number),
    };
  } catch {
    // A malformed existing tombstone was fail-closed before SQLite migration;
    // preserve that denial rather than reviving the device.
    return { ...device, revokedAt: device.revokedAt ?? device.createdAt };
  }
}

/**
 * Read the legacy device projection for a one-time SQLite import. Pairing-code
 * JSON is intentionally never read or imported: all outstanding legacy QR
 * codes are invalidated at cutover so plaintext secrets cannot enter SQLite.
 */
export function readLegacyDeviceImport(): LegacyDeviceImport {
  const filename = legacyDevicesFilename();
  const revocationsDirectory = legacyRevocationsDirectory(filename);
  let raw = "[]";
  try {
    raw = fs.readFileSync(/* turbopackIgnore: true */ filename, "utf8");
  } catch (error) {
    if (!errorCodeIs(error, "ENOENT")) {
      throw new Error("Legacy Paired Device migration source is unavailable", { cause: error });
    }
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Legacy Paired Device migration source is invalid");
  }
  if (!Array.isArray(parsed)) throw new Error("Legacy Paired Device migration source is invalid");
  const devices = parsed
    .map(parseDevice)
    .map((device) => applyRevocationOverlay(device, revocationsDirectory));
  const sourceDigest = digest(
    JSON.stringify(
      devices.map((device) => ({
        idDigest: digest(device.id),
        userIdDigest: digest(device.userId),
        usernameDigest: digest(device.username),
        nameDigest: digest(device.name),
        createdAt: device.createdAt,
        lastSeenAt: device.lastSeenAt,
        revokedAt: device.revokedAt,
      }))
    )
  );
  return { sourceDigest, devices };
}
