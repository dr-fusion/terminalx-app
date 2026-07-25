import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { ensureSecureDir } from "./secure-dir";

// Short-lived, single-use codes that let a logged-in web user pair a mobile
// device. The web app calls POST /api/auth/pairing-codes (cookie-authenticated),
// renders the returned `code` in a QR, and the mobile app posts it to
// /api/auth/pair within the TTL to receive a 24h device-scoped JWT.

const CODE_TTL_MS = 120 * 1000; // 2 minutes
const DATA_DIR = path.join(process.cwd(), "data");
const PAIRING_FILE = path.join(DATA_DIR, "pairing-codes.json");

interface PairingCode {
  code: string;
  userId: string;
  username: string;
  displayName?: string;
  role: string;
  authProvider?: "local" | "google" | "password";
  authSubject?: string;
  userGeneration?: number;
  authIdentityGeneration?: number;
  createdAt: number;
  expiresAt: number;
  consumedAt: number | null;
}

let writeLock: Promise<void> = Promise.resolve();
function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = writeLock.then(fn, fn);
  writeLock = next.then(
    () => {},
    () => {}
  );
  return next;
}

function readAll(): PairingCode[] {
  try {
    const raw = fs.readFileSync(PAIRING_FILE, "utf-8");
    const parsed = JSON.parse(raw) as PairingCode[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeAll(entries: PairingCode[]): void {
  ensureSecureDir(DATA_DIR);
  const tmp = PAIRING_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(entries), { mode: 0o600 });
  fs.renameSync(tmp, PAIRING_FILE);
}

function prune(entries: PairingCode[], now: number): PairingCode[] {
  // Drop expired or consumed-more-than-an-hour-ago codes
  return entries.filter((e) => {
    if (e.consumedAt !== null) return now - e.consumedAt < 3600_000;
    return e.expiresAt > now;
  });
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
};

export type CreatedPairingCode = {
  code: string;
  expiresAt: number;
};

export function createPairingCode(input: CreatePairingCodeInput): Promise<CreatedPairingCode> {
  return withLock(async () => {
    const now = Date.now();
    const code = crypto.randomBytes(24).toString("base64url");
    const entry: PairingCode = {
      code,
      userId: input.userId,
      username: input.username,
      ...(input.displayName ? { displayName: input.displayName } : {}),
      role: input.role,
      ...(input.authProvider ? { authProvider: input.authProvider } : {}),
      ...(input.authSubject ? { authSubject: input.authSubject } : {}),
      ...(input.userGeneration !== undefined ? { userGeneration: input.userGeneration } : {}),
      ...(input.authIdentityGeneration !== undefined
        ? { authIdentityGeneration: input.authIdentityGeneration }
        : {}),
      createdAt: now,
      expiresAt: now + CODE_TTL_MS,
      consumedAt: null,
    };
    const next = prune(readAll(), now);
    next.push(entry);
    writeAll(next);
    return { code, expiresAt: entry.expiresAt };
  });
}

export type ConsumedPairingCode = {
  userId: string;
  username: string;
  displayName?: string;
  role: string;
  authProvider?: "local" | "google" | "password";
  authSubject?: string;
  userGeneration?: number;
  authIdentityGeneration?: number;
};

/**
 * Atomically validate and mark a code as consumed. Returns the bound user info
 * if the code was unexpired and unused; null otherwise.
 */
export function consumePairingCode(code: string): Promise<ConsumedPairingCode | null> {
  return withLock(async () => {
    const now = Date.now();
    const entries = readAll();
    const idx = entries.findIndex((e) => e.code === code);
    if (idx === -1) return null;
    const entry = entries[idx]!;
    if (entry.consumedAt !== null) return null;
    if (entry.expiresAt <= now) return null;
    entry.consumedAt = now;
    entries[idx] = entry;
    writeAll(prune(entries, now));
    return {
      userId: entry.userId,
      username: entry.username,
      ...(entry.displayName ? { displayName: entry.displayName } : {}),
      role: entry.role,
      ...(entry.authProvider ? { authProvider: entry.authProvider } : {}),
      ...(entry.authSubject ? { authSubject: entry.authSubject } : {}),
      ...(entry.userGeneration !== undefined ? { userGeneration: entry.userGeneration } : {}),
      ...(entry.authIdentityGeneration !== undefined
        ? { authIdentityGeneration: entry.authIdentityGeneration }
        : {}),
    };
  });
}
