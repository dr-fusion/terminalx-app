import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { hashPassword } from "./auth";
import { getAdminPassword, getAdminUsername, getAuthMode } from "./auth-config";
import {
  type CanonicalIdentityAuthority,
  type LegacyLocalUserRecord,
  type ProvisionedIdentity,
} from "./identity-authority";
import { withCanonicalIdentityAuthority } from "./identity-service";

export interface User {
  id: string;
  username: string;
  role: "admin" | "user";
  passwordHash: string;
  createdAt: string;
  lastLogin: string | null;
}

export type SafeUser = Omit<User, "passwordHash">;

const LEGACY_USERS_FILE_ENV = "TERMINALX_LEGACY_USERS_FILE";

function legacyUsersFilename(): string {
  return (
    process.env[LEGACY_USERS_FILE_ENV] ??
    path.join(/* turbopackIgnore: true */ process.cwd(), "data", "users.json")
  );
}

function readLegacyUsers(): { sourceDigest: string; users: LegacyLocalUserRecord[] } {
  const filename = legacyUsersFilename();
  let raw = "[]";
  if (fs.existsSync(/* turbopackIgnore: true */ filename)) {
    raw = fs.readFileSync(/* turbopackIgnore: true */ filename, "utf8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Legacy User migration source is invalid");
  }
  if (!Array.isArray(parsed)) throw new Error("Legacy User migration source is invalid");
  return {
    sourceDigest: crypto.createHash("sha256").update(raw).digest("hex"),
    users: parsed as LegacyLocalUserRecord[],
  };
}

function withIdentityAuthority<T>(operation: (authority: CanonicalIdentityAuthority) => T): T {
  return withCanonicalIdentityAuthority((authority) => {
    if (!authority.hasImportedLegacyLocalUsers()) {
      authority.importLegacyLocalUsers(readLegacyUsers());
    }
    return operation(authority);
  });
}

function asUser(record: LegacyLocalUserRecord): User {
  return { ...record };
}

function stripHash(user: User): SafeUser {
  const { passwordHash: _hash, ...safe } = user;
  return safe;
}

export function getUsers(): User[] {
  return withIdentityAuthority((authority) => authority.listLocalUsers().map(asUser));
}

export function getUserByUsername(username: string): User | undefined {
  return withIdentityAuthority((authority) => {
    const user = authority.getLocalUserByUsername(username);
    return user ? asUser(user) : undefined;
  });
}

export function getUserById(id: string): User | undefined {
  return withIdentityAuthority((authority) => {
    const user = authority.getLocalUserById(id);
    return user ? asUser(user) : undefined;
  });
}

export function getLocalAuthenticationIdentity(userId: string): ProvisionedIdentity | null {
  return withIdentityAuthority((authority) => authority.getLocalAuthenticationIdentity(userId));
}

export async function createUser(
  username: string,
  password: string,
  role: "admin" | "user"
): Promise<SafeUser> {
  const passwordHash = await hashPassword(password);
  const user = withIdentityAuthority((authority) =>
    authority.createLocalUser({ username, passwordHash, legacyRole: role })
  );
  return stripHash(asUser(user));
}

/** Soft-revoke the canonical User and every authentication identity it owns. */
export async function deleteUser(id: string): Promise<void> {
  withIdentityAuthority((authority) => authority.revokeUser(id));
}

export async function updateUserRole(id: string, role: "admin" | "user"): Promise<SafeUser> {
  const user = withIdentityAuthority((authority) => authority.updateLocalUserRole(id, role));
  return stripHash(asUser(user));
}

export async function updateLastLogin(id: string): Promise<void> {
  withIdentityAuthority((authority) => authority.recordLocalLogin(id));
}

let initialized = false;

export async function ensureDefaultAdmin(): Promise<void> {
  if (initialized) return;
  initialized = true;

  if (getAuthMode() !== "local") return;
  if (getUsers().length > 0) return;

  const username = getAdminUsername();
  const password = getAdminPassword();
  if (!password) {
    console.warn("[auth] Local mode: set TERMINALX_ADMIN_PASSWORD to auto-create admin user");
    return;
  }

  await createUser(username, password, "admin");
  console.log(`[auth] Created default admin user: ${username}`);
}
