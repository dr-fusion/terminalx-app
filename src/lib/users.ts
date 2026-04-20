import * as fs from "fs";
import * as path from "path";
import { hashPassword } from "./auth";
import { getAuthMode, getAdminUsername, getAdminPassword } from "./auth-config";
import { ensureSecureDir } from "./secure-dir";

// ── Types ───────────────────────────────────────────────────────────────────

export interface User {
  id: string;
  username: string;
  role: "admin" | "user";
  passwordHash: string;
  createdAt: string;
  lastLogin: string | null;
}

export type SafeUser = Omit<User, "passwordHash">;

// ── File Path ───────────────────────────────────────────────────────────────

const DATA_DIR = path.join(process.cwd(), "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

function ensureDataDir(): void {
  ensureSecureDir(DATA_DIR);
}

// ── In-process Write Lock ───────────────────────────────────────────────────

let writeLock: Promise<void> = Promise.resolve();

function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = writeLock.then(fn, fn);
  writeLock = next.then(
    () => {},
    () => {}
  );
  return next;
}

// ── Atomic File Write ───────────────────────────────────────────────────────

function atomicWriteUsers(users: User[]): void {
  ensureDataDir();
  const tmpFile = USERS_FILE + ".tmp";
  fs.writeFileSync(tmpFile, JSON.stringify(users, null, 2), { encoding: "utf-8", mode: 0o600 });
  fs.renameSync(tmpFile, USERS_FILE);
  invalidateCache();
}

// ── User Cache (mtime-based to avoid disk reads on every auth check) ────────

let cachedUsers: User[] | null = null;
let cachedMtime: number = 0;

function invalidateCache(): void {
  cachedUsers = null;
  cachedMtime = 0;
}

// ── CRUD ────────────────────────────────────────────────────────────────────

export function getUsers(): User[] {
  ensureDataDir();
  if (!fs.existsSync(USERS_FILE)) {
    cachedUsers = [];
    return [];
  }
  try {
    const stat = fs.statSync(USERS_FILE);
    const mtime = stat.mtimeMs;
    if (cachedUsers && mtime === cachedMtime) {
      return cachedUsers;
    }
    const raw = fs.readFileSync(USERS_FILE, "utf-8");
    cachedUsers = JSON.parse(raw) as User[];
    cachedMtime = mtime;
    return cachedUsers;
  } catch {
    return [];
  }
}

export function getUserByUsername(username: string): User | undefined {
  return getUsers().find((u) => u.username === username);
}

export function getUserById(id: string): User | undefined {
  return getUsers().find((u) => u.id === id);
}

function stripHash(user: User): SafeUser {
  const { passwordHash: _hash, ...safe } = user;
  return safe;
}

export async function createUser(
  username: string,
  password: string,
  role: "admin" | "user"
): Promise<SafeUser> {
  return withLock(async () => {
    const users = getUsers();
    if (users.find((u) => u.username === username)) {
      throw new Error("Username already exists");
    }

    const passwordHash = await hashPassword(password);
    const user: User = {
      id: crypto.randomUUID(),
      username,
      role,
      passwordHash,
      createdAt: new Date().toISOString(),
      lastLogin: null,
    };
    users.push(user);
    atomicWriteUsers(users);
    return stripHash(user);
  });
}

// NOTE: Deleting a user does not revoke their active JWT tokens since we don't
// track which tokens belong to which user. Tokens will remain valid until they
// expire (7 days). The in-memory blacklist only covers explicit logout. A future
// improvement would be to track token-to-user mappings for forced revocation.
export async function deleteUser(id: string): Promise<void> {
  return withLock(async () => {
    const users = getUsers();
    const idx = users.findIndex((u) => u.id === id);
    if (idx === -1) throw new Error("User not found");
    users.splice(idx, 1);
    atomicWriteUsers(users);
  });
}

export async function updateUserRole(id: string, role: "admin" | "user"): Promise<SafeUser> {
  return withLock(async () => {
    const users = getUsers();
    const user = users.find((u) => u.id === id);
    if (!user) throw new Error("User not found");
    user.role = role;
    atomicWriteUsers(users);
    return stripHash(user);
  });
}

export async function updateLastLogin(id: string): Promise<void> {
  return withLock(async () => {
    const users = getUsers();
    const user = users.find((u) => u.id === id);
    if (!user) return;
    user.lastLogin = new Date().toISOString();
    atomicWriteUsers(users);
  });
}

// ── Auto-create Admin on First Startup ──────────────────────────────────────

let initialized = false;

export async function ensureDefaultAdmin(): Promise<void> {
  if (initialized) return;
  initialized = true;

  const mode = getAuthMode();
  if (mode !== "local") return;

  const users = getUsers();
  if (users.length > 0) return;

  const username = getAdminUsername();
  const password = getAdminPassword();
  if (!password) {
    console.warn("[auth] Local mode: set TERMINALX_ADMIN_PASSWORD to auto-create admin user");
    return;
  }

  await createUser(username, password, "admin");
  console.log(`[auth] Created default admin user: ${username}`);
}
