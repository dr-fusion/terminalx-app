import crypto from "node:crypto";
import type Database from "better-sqlite3";

export const PAIRING_CODE_TTL_MS = 2 * 60 * 1000;
export const PAIRING_ISSUANCE_WINDOW_MS = 60 * 60 * 1000;
export const PAIRING_MAX_ACTIVE_PER_USER = 3;
export const PAIRING_MAX_ACTIVE_GLOBAL = 1024;
export const PAIRING_MAX_ISSUED_PER_USER_WINDOW = 12;
export const PAIRING_MAX_ISSUED_GLOBAL_WINDOW = 4096;

const LEGACY_DEVICE_MIGRATION_KEY = "legacy-mobile-devices-json-v1";
const SHA256_HEX = /^[0-9a-f]{64}$/;
const PAIRING_CODE = /^[A-Za-z0-9_-]{32}$/;

export type AuthenticationCredentialProvenance =
  | { provenance: "browser" }
  | { provenance: "paired-device"; id: string };

export interface PairingSourceAuthentication {
  credentialJtiDigest: string;
  credentialExpiresAtMs: number;
  device: AuthenticationCredentialProvenance;
}

export type CreatePairingCodeInput = {
  userId: string;
  username: string;
  displayName?: string;
  role: string;
  authProvider?: "local" | "google" | "password";
  authSubject?: string;
  userGeneration?: number;
  authIdentityGeneration?: number;
  authTime?: number;
  sourceAuthentication?: PairingSourceAuthentication;
};

export type CreatedPairingCode = { code: string; expiresAt: number };

export type ConsumedPairingCode = {
  userId: string;
  username: string;
  displayName?: string;
  role: string;
  authProvider?: "local" | "google" | "password";
  authSubject?: string;
  userGeneration?: number;
  authIdentityGeneration?: number;
  authTime?: number;
  sourceAuthentication?: PairingSourceAuthentication;
};

export interface Device {
  id: string;
  userId: string;
  username: string;
  name: string;
  createdAt: number;
  lastSeenAt: number;
  revokedAt: number | null;
}

export type RegisterDeviceInput = { userId: string; username: string; name: string };

export type PairingIssuanceLimitScope =
  | "user-active"
  | "global-active"
  | "user-window"
  | "global-window";

export class PairingIssuanceLimitError extends Error {
  override readonly name = "PairingIssuanceLimitError";
  readonly code = "PAIRING_ISSUANCE_LIMIT" as const;

  constructor(
    readonly retryAfterSeconds: number,
    readonly scope: PairingIssuanceLimitScope
  ) {
    super("Pairing Code issuance limit exceeded");
    if (!Number.isSafeInteger(retryAfterSeconds) || retryAfterSeconds < 1) {
      throw new TypeError("Pairing issuance retry interval is invalid");
    }
  }
}

export interface PairingIssuanceLimits {
  activePerUser: number;
  activeGlobal: number;
  issuedPerUserWindow: number;
  issuedGlobalWindow: number;
  windowMs: number;
}

export interface LegacyDeviceImport {
  sourceDigest: string;
  devices: readonly Device[];
}

export interface MobileAuthAuthority {
  createPairingCode(input: CreatePairingCodeInput): CreatedPairingCode;
  consumePairingCode(code: string): ConsumedPairingCode | null;
  registerDevice(input: RegisterDeviceInput): Device;
  listDevicesForUser(userId: string): Device[];
  getDevice(deviceId: string): Device | null;
  isDeviceActive(deviceId: string): boolean;
  revokeDevice(deviceId: string, userId: string): boolean;
  touchDevice(deviceId: string): void;
  hasImportedLegacyDevices(): boolean;
  importLegacyDevices(input: LegacyDeviceImport): number;
}

interface CreateMobileAuthAuthorityOptions {
  db: Database.Database;
  clock?: () => number;
  randomBytes?: (size: number) => Buffer;
  limits?: Partial<PairingIssuanceLimits>;
}

interface PairingRow {
  user_id: string;
  username: string;
  display_name: string | null;
  legacy_role: string;
  auth_provider: "local" | "google" | "password";
  auth_subject: string;
  user_generation: number;
  auth_identity_generation: number;
  auth_time_seconds: number | null;
  source_credential_jti_digest: string;
  source_credential_expires_at_ms: number;
  source_device_provenance: "browser" | "paired-device";
  source_device_id: string | null;
}

interface DeviceRow {
  id: string;
  user_id: string;
  username: string;
  name: string;
  created_at_ms: number;
  last_seen_at_ms: number;
  revoked_at_ms: number | null;
}

const DEFAULT_LIMITS: PairingIssuanceLimits = Object.freeze({
  activePerUser: PAIRING_MAX_ACTIVE_PER_USER,
  activeGlobal: PAIRING_MAX_ACTIVE_GLOBAL,
  issuedPerUserWindow: PAIRING_MAX_ISSUED_PER_USER_WINDOW,
  issuedGlobalWindow: PAIRING_MAX_ISSUED_GLOBAL_WINDOW,
  windowMs: PAIRING_ISSUANCE_WINDOW_MS,
});

export function createMobileAuthAuthority(
  options: CreateMobileAuthAuthorityOptions
): MobileAuthAuthority {
  const clock = options.clock ?? Date.now;
  const randomBytes = options.randomBytes ?? crypto.randomBytes;
  const limits = normalizeLimits(options.limits);

  const deleteOldPairingCodes = options.db.prepare(
    "DELETE FROM mobile_pairing_codes WHERE created_at_ms <= ?"
  );
  const countUserWindow = options.db.prepare(
    `SELECT count(*) AS count, min(created_at_ms) AS earliest
     FROM mobile_pairing_codes WHERE user_id = ? AND created_at_ms > ?`
  );
  const countGlobalWindow = options.db.prepare(
    `SELECT count(*) AS count, min(created_at_ms) AS earliest
     FROM mobile_pairing_codes WHERE created_at_ms > ?`
  );
  const countUserActive = options.db.prepare(
    `SELECT count(*) AS count, min(expires_at_ms) AS earliest
     FROM mobile_pairing_codes
     WHERE user_id = ? AND consumed_at_ms IS NULL AND expires_at_ms > ?`
  );
  const countGlobalActive = options.db.prepare(
    `SELECT count(*) AS count, min(expires_at_ms) AS earliest
     FROM mobile_pairing_codes WHERE consumed_at_ms IS NULL AND expires_at_ms > ?`
  );
  const insertPairingCode = options.db.prepare(
    `INSERT INTO mobile_pairing_codes (
       code_digest, user_id, username, display_name, legacy_role,
       auth_provider, auth_subject, user_generation, auth_identity_generation,
       auth_time_seconds, source_credential_jti_digest,
       source_credential_expires_at_ms, source_device_provenance, source_device_id,
       created_at_ms, expires_at_ms, consumed_at_ms
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`
  );
  const findConsumablePairingCode = options.db.prepare(
    `SELECT 1 FROM mobile_pairing_codes
     WHERE code_digest = ? AND consumed_at_ms IS NULL
       AND expires_at_ms > ? AND source_credential_expires_at_ms > ?`
  );
  const consumePairingCodeRow = options.db.prepare(
    `UPDATE mobile_pairing_codes
     SET consumed_at_ms = ?
     WHERE code_digest = ? AND consumed_at_ms IS NULL
       AND expires_at_ms > ? AND source_credential_expires_at_ms > ?
     RETURNING user_id, username, display_name, legacy_role, auth_provider, auth_subject,
       user_generation, auth_identity_generation, auth_time_seconds,
       source_credential_jti_digest, source_credential_expires_at_ms,
       source_device_provenance, source_device_id`
  );
  const insertDevice = options.db.prepare(
    `INSERT INTO paired_devices (
       id, user_id, username, name, created_at_ms, last_seen_at_ms, revoked_at_ms
     ) VALUES (?, ?, ?, ?, ?, ?, ?)`
  );
  const findDevice = options.db.prepare(
    `SELECT id, user_id, username, name, created_at_ms, last_seen_at_ms, revoked_at_ms
     FROM paired_devices WHERE id = ?`
  );
  const listDevices = options.db.prepare(
    `SELECT id, user_id, username, name, created_at_ms, last_seen_at_ms, revoked_at_ms
     FROM paired_devices WHERE user_id = ? ORDER BY created_at_ms, id`
  );
  const revokeDeviceRow = options.db.prepare(
    `UPDATE paired_devices
     SET revoked_at_ms = COALESCE(revoked_at_ms, max(?, created_at_ms))
     WHERE id = ? AND user_id = ? RETURNING id`
  );
  const touchDeviceRow = options.db.prepare(
    `UPDATE paired_devices SET last_seen_at_ms = max(?, last_seen_at_ms)
     WHERE id = ? AND revoked_at_ms IS NULL`
  );
  const findMigration = options.db.prepare(
    "SELECT imported_count FROM mobile_auth_migrations WHERE migration_key = ?"
  );
  const findCanonicalUser = options.db.prepare("SELECT 1 FROM users WHERE id = ?");
  const insertMigration = options.db.prepare(
    `INSERT INTO mobile_auth_migrations (
       migration_key, source_digest, imported_count, completed_at_ms
     ) VALUES (?, ?, ?, ?)`
  );

  const issue = options.db.transaction((input: CreatePairingCodeInput): CreatedPairingCode => {
    const normalized = normalizePairingInput(input, currentTime(clock));
    const now = normalized.now;
    const windowStart = Math.max(0, now - limits.windowMs);
    deleteOldPairingCodes.run(windowStart);

    enforceLimit(
      countUserWindow.get(normalized.userId, windowStart),
      limits.issuedPerUserWindow,
      now,
      limits.windowMs,
      "user-window"
    );
    enforceLimit(
      countGlobalWindow.get(windowStart),
      limits.issuedGlobalWindow,
      now,
      limits.windowMs,
      "global-window"
    );
    enforceLimit(
      countUserActive.get(normalized.userId, now),
      limits.activePerUser,
      now,
      0,
      "user-active"
    );
    enforceLimit(countGlobalActive.get(now), limits.activeGlobal, now, 0, "global-active");

    const expiresAt = Math.min(now + PAIRING_CODE_TTL_MS, normalized.credentialExpiresAtMs);
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const code = randomBytes(24).toString("base64url");
      if (!PAIRING_CODE.test(code)) throw new Error("Pairing Code generator returned invalid data");
      try {
        insertPairingCode.run(
          pairingCodeDigest(code),
          normalized.userId,
          normalized.username,
          normalized.displayName,
          normalized.role,
          normalized.authProvider,
          normalized.authSubject,
          normalized.userGeneration,
          normalized.authIdentityGeneration,
          normalized.authTime,
          normalized.credentialJtiDigest,
          normalized.credentialExpiresAtMs,
          normalized.device.provenance,
          normalized.device.provenance === "paired-device" ? normalized.device.id : null,
          now,
          expiresAt
        );
        return { code, expiresAt };
      } catch (error) {
        if (!isPairingDigestCollision(error) || attempt === 3) throw error;
      }
    }
    throw new Error("Pairing Code generator exhausted collision retries");
  });

  const consume = options.db.transaction((codeDigest: string): ConsumedPairingCode | null => {
    const now = currentTime(clock);
    const row = consumePairingCodeRow.get(now, codeDigest, now, now) as PairingRow | undefined;
    if (!row) return null;
    return pairingView(row);
  });

  const register = options.db.transaction((input: RegisterDeviceInput): Device => {
    const normalized = normalizeDeviceInput(input);
    const now = currentTime(clock);
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const id = `dvc_${randomBytes(12).toString("base64url")}`;
      try {
        insertDevice.run(
          id,
          normalized.userId,
          normalized.username,
          normalized.name,
          now,
          now,
          null
        );
        return { id, ...normalized, createdAt: now, lastSeenAt: now, revokedAt: null };
      } catch (error) {
        if (!isDeviceIdCollision(error) || attempt === 3) throw error;
      }
    }
    throw new Error("Paired Device generator exhausted collision retries");
  });

  const revoke = options.db.transaction((deviceId: string, userId: string): boolean => {
    boundedString(deviceId, "Paired Device ID", 300);
    boundedString(userId, "Paired Device User ID", 300);
    return Boolean(revokeDeviceRow.get(currentTime(clock), deviceId, userId));
  });

  const importLegacy = options.db.transaction((input: LegacyDeviceImport): number => {
    if (!SHA256_HEX.test(input.sourceDigest)) {
      throw new TypeError("Legacy Paired Device migration digest is invalid");
    }
    const existing = findMigration.get(LEGACY_DEVICE_MIGRATION_KEY) as
      | { imported_count: number }
      | undefined;
    if (existing) return existing.imported_count;
    // Validate the complete source before writing any row. The surrounding
    // transaction also rolls back all inserts and the marker on any failure.
    const devices = input.devices.map(normalizeLegacyDevice);
    let imported = 0;
    for (const device of devices) {
      // Orphaned legacy rows cannot authenticate because their canonical User
      // no longer exists. Skipping them preserves that denial without blocking
      // every valid user's startup migration.
      if (!findCanonicalUser.get(device.userId)) continue;
      insertDevice.run(
        device.id,
        device.userId,
        device.username,
        device.name,
        device.createdAt,
        device.lastSeenAt,
        device.revokedAt
      );
      imported += 1;
    }
    insertMigration.run(
      LEGACY_DEVICE_MIGRATION_KEY,
      input.sourceDigest,
      imported,
      currentTime(clock)
    );
    return imported;
  });

  const authority: MobileAuthAuthority = {
    createPairingCode: (input) => issue.immediate(input),
    consumePairingCode: (code) => {
      if (typeof code !== "string" || !PAIRING_CODE.test(code)) return null;
      const digest = pairingCodeDigest(code);
      const now = currentTime(clock);
      // Invalid random guesses are a read-only indexed lookup and never take
      // SQLite's global write reservation. A code that passed this preflight
      // still competes through the atomic UPDATE below, which rechecks expiry
      // with a fresh clock value and permits only one committed consumer.
      if (!findConsumablePairingCode.get(digest, now, now)) return null;
      return consume.immediate(digest);
    },
    registerDevice: (input) => register.immediate(input),
    listDevicesForUser: (userId) => {
      boundedString(userId, "Paired Device User ID", 300);
      return (listDevices.all(userId) as DeviceRow[]).map(deviceView);
    },
    getDevice: (deviceId) => {
      boundedString(deviceId, "Paired Device ID", 300);
      const row = findDevice.get(deviceId) as DeviceRow | undefined;
      return row ? deviceView(row) : null;
    },
    isDeviceActive: (deviceId) => {
      boundedString(deviceId, "Paired Device ID", 300);
      const row = findDevice.get(deviceId) as DeviceRow | undefined;
      return Boolean(row && row.revoked_at_ms === null);
    },
    revokeDevice: (deviceId, userId) => revoke.immediate(deviceId, userId),
    touchDevice: (deviceId) => {
      boundedString(deviceId, "Paired Device ID", 300);
      touchDeviceRow.run(currentTime(clock), deviceId);
    },
    hasImportedLegacyDevices: () => Boolean(findMigration.get(LEGACY_DEVICE_MIGRATION_KEY)),
    importLegacyDevices: (input) => importLegacy.immediate(input),
  };
  return Object.freeze(authority);
}

function pairingCodeDigest(code: string): string {
  return crypto
    .createHash("sha256")
    .update("terminalx:mobile-pairing:v1\0", "utf8")
    .update(code, "utf8")
    .digest("hex");
}

function currentTime(clock: () => number): number {
  const now = clock();
  if (!Number.isSafeInteger(now) || now < 0)
    throw new TypeError("Mobile authority time is invalid");
  return now;
}

function normalizeLimits(input: Partial<PairingIssuanceLimits> | undefined): PairingIssuanceLimits {
  const value = { ...DEFAULT_LIMITS, ...input };
  for (const [name, limit] of Object.entries(value)) {
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new TypeError(`Pairing issuance limit ${name} is invalid`);
    }
  }
  return value;
}

function enforceLimit(
  result: unknown,
  maximum: number,
  now: number,
  windowMs: number,
  scope: PairingIssuanceLimitScope
): void {
  const row = result as { count: number; earliest: number | null };
  if (row.count < maximum) return;
  const retryAt = Math.max(now + 1, (row.earliest ?? now) + windowMs);
  throw new PairingIssuanceLimitError(Math.max(1, Math.ceil((retryAt - now) / 1000)), scope);
}

function normalizePairingInput(input: CreatePairingCodeInput, now: number) {
  const userId = boundedString(input.userId, "Pairing User ID", 300);
  const username = boundedString(input.username, "Pairing username", 1024);
  const displayName =
    input.displayName === undefined
      ? null
      : boundedString(input.displayName, "Pairing display name", 1024);
  const role = boundedString(input.role, "Pairing role", 100);
  if (
    (input.authProvider !== "local" &&
      input.authProvider !== "google" &&
      input.authProvider !== "password") ||
    typeof input.authSubject !== "string" ||
    !Number.isSafeInteger(input.userGeneration) ||
    input.userGeneration! < 1 ||
    !Number.isSafeInteger(input.authIdentityGeneration) ||
    input.authIdentityGeneration! < 1
  ) {
    throw new TypeError("Pairing authentication identity snapshot is invalid");
  }
  const authSubject = boundedString(input.authSubject, "Pairing authentication subject", 1024);
  if (
    input.authTime !== undefined &&
    (!Number.isSafeInteger(input.authTime) ||
      input.authTime < 0 ||
      input.authTime > Math.floor(now / 1000))
  ) {
    throw new TypeError("Pairing authentication time is invalid");
  }
  const source = normalizeSourceAuthentication(input.sourceAuthentication);
  if (!source) throw new TypeError("Pairing source authentication snapshot is required");
  if (source.credentialExpiresAtMs <= now) {
    throw new TypeError("Pairing source authentication credential is expired");
  }
  return {
    now,
    userId,
    username,
    displayName,
    role,
    authProvider: input.authProvider,
    authSubject,
    userGeneration: input.userGeneration,
    authIdentityGeneration: input.authIdentityGeneration,
    authTime: input.authTime ?? null,
    credentialJtiDigest: source.credentialJtiDigest,
    credentialExpiresAtMs: source.credentialExpiresAtMs,
    device: source.device,
  };
}

function normalizeSourceAuthentication(
  input: PairingSourceAuthentication | undefined
): PairingSourceAuthentication | null {
  if (!input || typeof input !== "object" || !SHA256_HEX.test(input.credentialJtiDigest)) {
    if (input === undefined) return null;
    throw new TypeError("Pairing source authentication snapshot is invalid");
  }
  if (!Number.isSafeInteger(input.credentialExpiresAtMs) || input.credentialExpiresAtMs < 0) {
    throw new TypeError("Pairing source authentication snapshot is invalid");
  }
  const device = input.device;
  if (device?.provenance === "browser" && Object.keys(device).length === 1) return input;
  if (
    device?.provenance === "paired-device" &&
    Object.keys(device).sort().join(",") === "id,provenance" &&
    typeof device.id === "string" &&
    device.id.length >= 1 &&
    device.id.length <= 300
  ) {
    return input;
  }
  throw new TypeError("Pairing source authentication snapshot is invalid");
}

function normalizeDeviceInput(input: RegisterDeviceInput) {
  return {
    userId: boundedString(input.userId, "Device registration User ID", 300),
    username: boundedString(input.username, "Device registration username", 1024),
    name:
      typeof input.name === "string"
        ? input.name.slice(0, 120)
        : (() => {
            throw new TypeError("Device registration identity is invalid");
          })(),
  };
}

function normalizeLegacyDevice(input: Device): Device {
  const normalized = normalizeDeviceInput(input);
  const id = boundedString(input.id, "Legacy Paired Device ID", 300);
  if (
    !Number.isSafeInteger(input.createdAt) ||
    input.createdAt < 0 ||
    !Number.isSafeInteger(input.lastSeenAt) ||
    input.lastSeenAt < input.createdAt ||
    (input.revokedAt !== null &&
      (!Number.isSafeInteger(input.revokedAt) || input.revokedAt < input.createdAt))
  ) {
    throw new TypeError("Legacy Paired Device is invalid");
  }
  return {
    id,
    ...normalized,
    createdAt: input.createdAt,
    lastSeenAt: input.lastSeenAt,
    revokedAt: input.revokedAt,
  };
}

function boundedString(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function pairingView(row: PairingRow): ConsumedPairingCode {
  const device: AuthenticationCredentialProvenance =
    row.source_device_provenance === "browser"
      ? { provenance: "browser" }
      : { provenance: "paired-device", id: row.source_device_id! };
  return {
    userId: row.user_id,
    username: row.username,
    ...(row.display_name === null ? {} : { displayName: row.display_name }),
    role: row.legacy_role,
    authProvider: row.auth_provider,
    authSubject: row.auth_subject,
    userGeneration: row.user_generation,
    authIdentityGeneration: row.auth_identity_generation,
    ...(row.auth_time_seconds === null ? {} : { authTime: row.auth_time_seconds }),
    sourceAuthentication: {
      credentialJtiDigest: row.source_credential_jti_digest,
      credentialExpiresAtMs: row.source_credential_expires_at_ms,
      device,
    },
  };
}

function deviceView(row: DeviceRow): Device {
  return {
    id: row.id,
    userId: row.user_id,
    username: row.username,
    name: row.name,
    createdAt: row.created_at_ms,
    lastSeenAt: row.last_seen_at_ms,
    revokedAt: row.revoked_at_ms,
  };
}

function isPairingDigestCollision(error: unknown): boolean {
  return (
    error instanceof Error &&
    /UNIQUE constraint failed: mobile_pairing_codes\.code_digest/.test(error.message)
  );
}

function isDeviceIdCollision(error: unknown): boolean {
  return (
    error instanceof Error && /UNIQUE constraint failed: paired_devices\.id/.test(error.message)
  );
}
