import crypto from "node:crypto";
import type Database from "better-sqlite3";

export type CanonicalUserStatus = "active" | "revoked";
export type AuthIdentityStatus = "active" | "revoked";
export type AuthIdentityProvider = "local" | "google" | "password";
export type LegacyUserRole = "admin" | "user";

export interface CanonicalUser {
  id: string;
  username: string;
  displayName: string;
  legacyRole: LegacyUserRole;
  status: CanonicalUserStatus;
  generation: number;
  createdAtMs: number;
  updatedAtMs: number;
  lastLoginAtMs: number | null;
  revokedAtMs: number | null;
}

export interface AuthIdentity {
  id: string;
  userId: string;
  provider: AuthIdentityProvider;
  subject: string;
  status: AuthIdentityStatus;
  generation: number;
  createdAtMs: number;
  updatedAtMs: number;
  lastAuthenticatedAtMs: number | null;
  revokedAtMs: number | null;
}

export interface ProvisionedIdentity {
  user: CanonicalUser;
  identity: AuthIdentity;
}

export interface ProvisionGoogleIdentityInput {
  subject: string;
  email: string;
  displayName: string;
  legacyRole: LegacyUserRole;
}

export interface AuthenticationIdentitySnapshot {
  userId: string;
  userGeneration: number;
  provider: AuthIdentityProvider;
  subject: string;
  identityGeneration: number;
}

export interface RevokeAuthenticationIdentityInput {
  provider: AuthIdentityProvider;
  subject: string;
  expectedGeneration: number;
}

export interface LegacyLocalUserRecord {
  id: string;
  username: string;
  role: LegacyUserRole;
  passwordHash: string;
  createdAt: string;
  lastLogin: string | null;
}

export interface ImportLegacyLocalUsersInput {
  sourceDigest: string;
  users: readonly LegacyLocalUserRecord[];
}

export interface LegacyLocalUsersImportResult {
  status: "imported" | "already-imported";
  sourceDigest: string;
  importedCount: number;
}

export interface CreateLocalUserInput {
  username: string;
  passwordHash: string;
  legacyRole: LegacyUserRole;
}

export interface CanonicalIdentityAuthority {
  provisionGoogleIdentity(input: ProvisionGoogleIdentityInput): ProvisionedIdentity;
  provisionPasswordIdentity(): ProvisionedIdentity;
  resolveAuthenticationIdentity(
    snapshot: AuthenticationIdentitySnapshot
  ): ProvisionedIdentity | null;
  revokeAuthenticationIdentity(input: RevokeAuthenticationIdentityInput): AuthIdentity;
  hasImportedLegacyLocalUsers(): boolean;
  importLegacyLocalUsers(input: ImportLegacyLocalUsersInput): LegacyLocalUsersImportResult;
  listLocalUsers(): readonly LegacyLocalUserRecord[];
  getLocalUserByUsername(username: string): LegacyLocalUserRecord | null;
  getLocalUserById(userId: string): LegacyLocalUserRecord | null;
  createLocalUser(input: CreateLocalUserInput): LegacyLocalUserRecord;
  updateLocalUserRole(userId: string, role: LegacyUserRole): LegacyLocalUserRecord;
  recordLocalLogin(userId: string): void;
  revokeUser(userId: string): void;
  getLocalAuthenticationIdentity(userId: string): ProvisionedIdentity | null;
}

export interface CreateCanonicalIdentityAuthorityOptions {
  db: Database.Database;
  clock?: () => number;
  idGenerator?: () => string;
}

interface UserRow {
  id: string;
  username: string;
  display_name: string;
  legacy_role: LegacyUserRole;
  status: CanonicalUserStatus;
  generation: number;
  created_at_ms: number;
  updated_at_ms: number;
  last_login_at_ms: number | null;
  revoked_at_ms: number | null;
}

interface IdentityRow {
  id: string;
  user_id: string;
  provider: AuthIdentityProvider;
  subject: string;
  status: AuthIdentityStatus;
  generation: number;
  created_at_ms: number;
  updated_at_ms: number;
  last_authenticated_at_ms: number | null;
  revoked_at_ms: number | null;
}

interface LegacyMigrationRow {
  source_digest: string;
  imported_count: number;
}

interface LocalUserRow {
  id: string;
  username: string;
  legacy_role: LegacyUserRole;
  password_hash: string;
  created_at_ms: number;
  last_login_at_ms: number | null;
}

const LEGACY_LOCAL_USERS_MIGRATION_KEY = "legacy-local-users-json-v1";

export function createCanonicalIdentityAuthority(
  options: CreateCanonicalIdentityAuthorityOptions
): CanonicalIdentityAuthority {
  const clock = options.clock ?? Date.now;
  const idGenerator = options.idGenerator ?? crypto.randomUUID;
  const findIdentity = options.db.prepare(
    `SELECT id, user_id, provider, subject, status, generation,
            created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
     FROM auth_identities
     WHERE provider = ? AND subject = ?`
  );
  const findUser = options.db.prepare(
    `SELECT id, username, display_name, legacy_role, status, generation,
            created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
     FROM users
     WHERE id = ?`
  );
  const insertUser = options.db.prepare(
    `INSERT INTO users (
       id, username, display_name, legacy_role, status, generation,
       created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
     ) VALUES (?, ?, ?, ?, 'active', 1, ?, ?, ?, NULL)`
  );
  const insertIdentity = options.db.prepare(
    `INSERT INTO auth_identities (
       id, user_id, provider, subject, status, generation,
       created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
     ) VALUES (?, ?, 'google', ?, 'active', 1, ?, ?, ?, NULL)`
  );
  const insertLocalIdentity = options.db.prepare(
    `INSERT INTO auth_identities (
       id, user_id, provider, subject, status, generation,
       created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
     ) VALUES (?, ?, 'local', ?, 'active', 1, ?, ?, ?, NULL)`
  );
  const insertPasswordIdentity = options.db.prepare(
    `INSERT INTO auth_identities (
       id, user_id, provider, subject, status, generation,
       created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
     ) VALUES (?, ?, 'password', 'shared-password', 'active', 1, ?, ?, ?, NULL)`
  );
  const insertLocalCredential = options.db.prepare(
    `INSERT INTO local_auth_credentials (
       auth_identity_id, user_id, password_hash, updated_at_ms
     ) VALUES (?, ?, ?, ?)`
  );
  const updateProfile = options.db.prepare(
    `UPDATE users
     SET username = ?, display_name = ?, legacy_role = ?,
         generation = generation + 1, updated_at_ms = ?
     WHERE id = ? AND status = 'active'`
  );
  const updateAuthentication = options.db.prepare(
    `UPDATE auth_identities
     SET last_authenticated_at_ms = ?, updated_at_ms = ?
     WHERE id = ? AND status = 'active'`
  );
  const resolveIdentity = options.db.prepare(
    `SELECT identity.id AS identity_id, identity.user_id, identity.provider, identity.subject,
            identity.status AS identity_status,
            identity.generation AS identity_generation,
            identity.created_at_ms AS identity_created_at_ms,
            identity.updated_at_ms AS identity_updated_at_ms,
            identity.last_authenticated_at_ms, identity.revoked_at_ms AS identity_revoked_at_ms,
            user.id AS canonical_user_id, user.username, user.display_name, user.legacy_role,
            user.status AS user_status, user.generation AS user_generation,
            user.created_at_ms AS user_created_at_ms,
            user.updated_at_ms AS user_updated_at_ms,
            user.last_login_at_ms, user.revoked_at_ms AS user_revoked_at_ms
     FROM auth_identities identity
     JOIN users user ON user.id = identity.user_id
     WHERE identity.provider = ? AND identity.subject = ? AND identity.user_id = ?
       AND identity.generation = ? AND user.generation = ?
       AND identity.status = 'active' AND user.status = 'active'`
  );
  const revokeIdentity = options.db.prepare(
    `UPDATE auth_identities
     SET status = 'revoked', generation = generation + 1,
         updated_at_ms = ?, revoked_at_ms = ?
     WHERE provider = ? AND subject = ? AND status = 'active' AND generation = ?`
  );
  const findLegacyMigration = options.db.prepare(
    `SELECT source_digest, imported_count
     FROM identity_migrations
     WHERE migration_key = ?`
  );
  const insertLegacyMigration = options.db.prepare(
    `INSERT INTO identity_migrations (
       migration_key, source_digest, imported_count, completed_at_ms
     ) VALUES (?, ?, ?, ?)`
  );
  const findLocalUserByUsername = options.db.prepare(
    `SELECT user.id, user.username, user.legacy_role, credential.password_hash,
            user.created_at_ms, user.last_login_at_ms
     FROM auth_identities identity
     JOIN users user ON user.id = identity.user_id
     JOIN local_auth_credentials credential
       ON credential.auth_identity_id = identity.id AND credential.user_id = user.id
     WHERE identity.provider = 'local' AND identity.subject = ?
       AND identity.status = 'active' AND user.status = 'active'`
  );
  const findLocalUserById = options.db.prepare(
    `SELECT user.id, user.username, user.legacy_role, credential.password_hash,
            user.created_at_ms, user.last_login_at_ms
     FROM auth_identities identity
     JOIN users user ON user.id = identity.user_id
     JOIN local_auth_credentials credential
       ON credential.auth_identity_id = identity.id AND credential.user_id = user.id
     WHERE identity.provider = 'local' AND user.id = ?
       AND identity.status = 'active' AND user.status = 'active'`
  );
  const listLocalUsers = options.db.prepare(
    `SELECT user.id, user.username, user.legacy_role, credential.password_hash,
            user.created_at_ms, user.last_login_at_ms
     FROM auth_identities identity
     JOIN users user ON user.id = identity.user_id
     JOIN local_auth_credentials credential
       ON credential.auth_identity_id = identity.id AND credential.user_id = user.id
     WHERE identity.provider = 'local'
       AND identity.status = 'active' AND user.status = 'active'
     ORDER BY user.created_at_ms, user.id`
  );
  const updateLocalRole = options.db.prepare(
    `UPDATE users
     SET legacy_role = ?, generation = generation + 1, updated_at_ms = ?
     WHERE id = ? AND status = 'active'`
  );
  const updateLocalLastLogin = options.db.prepare(
    `UPDATE users
     SET last_login_at_ms = ?, updated_at_ms = ?
     WHERE id = ? AND status = 'active'`
  );
  const updateLocalIdentityLogin = options.db.prepare(
    `UPDATE auth_identities
     SET last_authenticated_at_ms = ?, updated_at_ms = ?
     WHERE user_id = ? AND provider = 'local' AND status = 'active'`
  );
  const revokeUserRow = options.db.prepare(
    `UPDATE users
     SET status = 'revoked', generation = generation + 1,
         updated_at_ms = ?, revoked_at_ms = ?
     WHERE id = ? AND status = 'active'`
  );
  const revokeUserIdentities = options.db.prepare(
    `UPDATE auth_identities
     SET status = 'revoked', generation = generation + 1,
         updated_at_ms = ?, revoked_at_ms = ?
     WHERE user_id = ? AND status = 'active'`
  );
  const findAnyUserIdentity = options.db.prepare(
    `SELECT 1
     FROM auth_identities
     WHERE user_id = ?
     LIMIT 1`
  );
  const findActiveLocalIdentityForUser = options.db.prepare(
    `SELECT identity.id AS identity_id, identity.user_id, identity.provider, identity.subject,
            identity.status AS identity_status,
            identity.generation AS identity_generation,
            identity.created_at_ms AS identity_created_at_ms,
            identity.updated_at_ms AS identity_updated_at_ms,
            identity.last_authenticated_at_ms, identity.revoked_at_ms AS identity_revoked_at_ms,
            user.id AS canonical_user_id, user.username, user.display_name, user.legacy_role,
            user.status AS user_status, user.generation AS user_generation,
            user.created_at_ms AS user_created_at_ms,
            user.updated_at_ms AS user_updated_at_ms,
            user.last_login_at_ms, user.revoked_at_ms AS user_revoked_at_ms
     FROM auth_identities identity
     JOIN users user ON user.id = identity.user_id
     WHERE identity.user_id = ? AND identity.provider = 'local'
       AND identity.status = 'active' AND user.status = 'active'`
  );

  const provisionGoogleIdentity = options.db.transaction(
    (input: ProvisionGoogleIdentityInput): ProvisionedIdentity => {
      const subject = requiredString(input.subject, "Google subject", 1024);
      const email = requiredString(input.email, "Google email", 320).toLowerCase();
      const displayName = requiredString(input.displayName, "Google display name", 320);
      assertLegacyRole(input.legacyRole);
      const now = safeTimestamp(clock());

      const existingIdentity = findIdentity.get("google", subject) as IdentityRow | undefined;
      if (existingIdentity) {
        if (existingIdentity.status !== "active") {
          throw new Error("Google authentication identity is revoked");
        }
        const existingUser = findUser.get(existingIdentity.user_id) as UserRow | undefined;
        if (!existingUser || existingUser.status !== "active") {
          throw new Error("Canonical User is unavailable");
        }
        if (
          existingUser.username !== email ||
          existingUser.display_name !== displayName ||
          existingUser.legacy_role !== input.legacyRole
        ) {
          const updated = updateProfile.run(
            email,
            displayName,
            input.legacyRole,
            now,
            existingUser.id
          );
          if (updated.changes !== 1) throw new Error("Canonical User update was fenced");
        }
        const authenticated = updateAuthentication.run(now, now, existingIdentity.id);
        if (authenticated.changes !== 1) {
          throw new Error("Google authentication identity update was fenced");
        }
        return requireProvisionedIdentity(options.db, existingIdentity.id, existingUser.id);
      }

      const userId = requiredString(idGenerator(), "generated User ID", 300);
      const identityId = requiredString(idGenerator(), "generated authentication identity ID", 300);
      insertUser.run(userId, email, displayName, input.legacyRole, now, now, null);
      insertIdentity.run(identityId, userId, subject, now, now, now);
      return requireProvisionedIdentity(options.db, identityId, userId);
    }
  );
  const provisionPasswordIdentity = options.db.transaction((): ProvisionedIdentity => {
    const now = safeTimestamp(clock());
    const existingIdentity = findIdentity.get("password", "shared-password") as
      | IdentityRow
      | undefined;
    if (existingIdentity) {
      if (existingIdentity.status !== "active") {
        throw new Error("Password authentication identity is revoked");
      }
      const existingUser = findUser.get(existingIdentity.user_id) as UserRow | undefined;
      if (!existingUser || existingUser.status !== "active") {
        throw new Error("Canonical User is unavailable");
      }
      const authenticated = updateAuthentication.run(now, now, existingIdentity.id);
      if (authenticated.changes !== 1) {
        throw new Error("Password authentication identity update was fenced");
      }
      return requireProvisionedIdentity(options.db, existingIdentity.id, existingUser.id);
    }

    const identityId = requiredString(idGenerator(), "generated authentication identity ID", 300);
    insertUser.run("single-user", "admin", "admin", "admin", now, now, null);
    insertPasswordIdentity.run(identityId, "single-user", now, now, now);
    return requireProvisionedIdentity(options.db, identityId, "single-user");
  });

  const revokeAuthenticationIdentity = options.db.transaction(
    (input: RevokeAuthenticationIdentityInput): AuthIdentity => {
      const provider = authProvider(input.provider);
      const subject = requiredString(input.subject, "authentication subject", 1024);
      const expectedGeneration = positiveGeneration(input.expectedGeneration);
      const now = safeTimestamp(clock());
      const result = revokeIdentity.run(now, now, provider, subject, expectedGeneration);
      if (result.changes !== 1) {
        throw new Error("Authentication identity revocation was fenced");
      }
      const row = findIdentity.get(provider, subject) as IdentityRow | undefined;
      if (!row) throw new Error("Authentication identity revocation did not settle");
      return identityView(row);
    }
  );
  const importLegacyLocalUsers = options.db.transaction(
    (input: ImportLegacyLocalUsersInput): LegacyLocalUsersImportResult => {
      const sourceDigest = sha256Digest(input.sourceDigest);
      const completed = findLegacyMigration.get(LEGACY_LOCAL_USERS_MIGRATION_KEY) as
        | LegacyMigrationRow
        | undefined;
      if (completed) {
        return Object.freeze({
          status: "already-imported" as const,
          sourceDigest: completed.source_digest,
          importedCount: completed.imported_count,
        });
      }
      if (!Array.isArray(input.users)) throw new TypeError("Legacy local Users are invalid");
      for (const inputUser of input.users) {
        const user = legacyLocalUser(inputUser);
        const identityId = requiredString(
          idGenerator(),
          "generated authentication identity ID",
          300
        );
        const createdAtMs = isoTimestamp(user.createdAt, "Legacy User creation time");
        const lastLoginAtMs =
          user.lastLogin === null ? null : isoTimestamp(user.lastLogin, "Legacy User last login");
        const updatedAtMs = lastLoginAtMs ?? createdAtMs;
        insertUser.run(
          user.id,
          user.username,
          user.username,
          user.role,
          createdAtMs,
          updatedAtMs,
          lastLoginAtMs
        );
        insertLocalIdentity.run(
          identityId,
          user.id,
          user.username,
          createdAtMs,
          updatedAtMs,
          lastLoginAtMs
        );
        insertLocalCredential.run(identityId, user.id, user.passwordHash, updatedAtMs);
      }
      const now = safeTimestamp(clock());
      insertLegacyMigration.run(
        LEGACY_LOCAL_USERS_MIGRATION_KEY,
        sourceDigest,
        input.users.length,
        now
      );
      return Object.freeze({
        status: "imported" as const,
        sourceDigest,
        importedCount: input.users.length,
      });
    }
  );
  const createLocalUser = options.db.transaction(
    (input: CreateLocalUserInput): LegacyLocalUserRecord => {
      const username = requiredString(input.username, "local username", 320);
      assertLegacyRole(input.legacyRole);
      const passwordHash = requiredString(input.passwordHash, "local password hash", 4096);
      if (passwordHash.length < 20) throw new TypeError("Local password hash is invalid");
      // Provider subjects are permanent attribution keys. A revoked local
      // identity must not be silently replaced by a new User with the same
      // username.
      if (findIdentity.get("local", username)) throw new Error("Username already exists");
      const now = safeTimestamp(clock());
      const userId = requiredString(idGenerator(), "generated User ID", 300);
      const identityId = requiredString(idGenerator(), "generated authentication identity ID", 300);
      insertUser.run(userId, username, username, input.legacyRole, now, now, null);
      insertLocalIdentity.run(identityId, userId, username, now, now, null);
      insertLocalCredential.run(identityId, userId, passwordHash, now);
      const row = findLocalUserById.get(userId) as LocalUserRow | undefined;
      if (!row) throw new Error("Local User creation did not settle");
      return localUserView(row);
    }
  );
  const updateLocalUserRole = options.db.transaction(
    (userIdInput: string, role: LegacyUserRole): LegacyLocalUserRecord => {
      const userId = requiredString(userIdInput, "User ID", 300);
      assertLegacyRole(role);
      const now = safeTimestamp(clock());
      const updated = updateLocalRole.run(role, now, userId);
      if (updated.changes !== 1) throw new Error("User not found");
      const row = findLocalUserById.get(userId) as LocalUserRow | undefined;
      if (!row) throw new Error("Local User role update did not settle");
      return localUserView(row);
    }
  );
  const recordLocalLogin = options.db.transaction((userIdInput: string): void => {
    const userId = requiredString(userIdInput, "User ID", 300);
    const now = safeTimestamp(clock());
    const userUpdated = updateLocalLastLogin.run(now, now, userId);
    const identityUpdated = updateLocalIdentityLogin.run(now, now, userId);
    if (userUpdated.changes !== 1 || identityUpdated.changes !== 1) {
      throw new Error("Local User login was fenced");
    }
  });
  const revokeUser = options.db.transaction((userIdInput: string): void => {
    const userId = requiredString(userIdInput, "User ID", 300);
    if (!findAnyUserIdentity.get(userId)) {
      throw new Error("Canonical User has no authentication identity");
    }
    const now = safeTimestamp(clock());
    const userRevoked = revokeUserRow.run(now, now, userId);
    if (userRevoked.changes !== 1) throw new Error("User not found");
    revokeUserIdentities.run(now, now, userId);
  });

  const authority: CanonicalIdentityAuthority = {
    provisionGoogleIdentity: (input) => provisionGoogleIdentity.immediate(input),
    provisionPasswordIdentity: () => provisionPasswordIdentity.immediate(),
    resolveAuthenticationIdentity(snapshot) {
      const userId = requiredString(snapshot.userId, "User ID", 300);
      const provider = authProvider(snapshot.provider);
      const subject = requiredString(snapshot.subject, "authentication subject", 1024);
      const identityGeneration = positiveGeneration(snapshot.identityGeneration);
      const userGeneration = positiveGeneration(snapshot.userGeneration);
      const row = resolveIdentity.get(
        provider,
        subject,
        userId,
        identityGeneration,
        userGeneration
      ) as ResolvedIdentityRow | undefined;
      return row ? resolvedIdentityView(row) : null;
    },
    revokeAuthenticationIdentity: (input) => revokeAuthenticationIdentity.immediate(input),
    hasImportedLegacyLocalUsers: () =>
      Boolean(findLegacyMigration.get(LEGACY_LOCAL_USERS_MIGRATION_KEY)),
    importLegacyLocalUsers: (input) => importLegacyLocalUsers.immediate(input),
    listLocalUsers() {
      return Object.freeze(
        (listLocalUsers.all() as LocalUserRow[]).map((row) => localUserView(row))
      );
    },
    getLocalUserByUsername(username) {
      const subject = requiredString(username, "local username", 320);
      const row = findLocalUserByUsername.get(subject) as LocalUserRow | undefined;
      return row ? localUserView(row) : null;
    },
    getLocalUserById(userId) {
      const id = requiredString(userId, "User ID", 300);
      const row = findLocalUserById.get(id) as LocalUserRow | undefined;
      return row ? localUserView(row) : null;
    },
    createLocalUser: (input) => createLocalUser.immediate(input),
    updateLocalUserRole: (userId, role) => updateLocalUserRole.immediate(userId, role),
    recordLocalLogin: (userId) => recordLocalLogin.immediate(userId),
    revokeUser: (userId) => revokeUser.immediate(userId),
    getLocalAuthenticationIdentity(userId) {
      const id = requiredString(userId, "User ID", 300);
      const row = findActiveLocalIdentityForUser.get(id) as ResolvedIdentityRow | undefined;
      return row ? resolvedIdentityView(row) : null;
    },
  };
  return Object.freeze(authority);
}

interface ResolvedIdentityRow {
  identity_id: string;
  user_id: string;
  provider: AuthIdentityProvider;
  subject: string;
  identity_status: AuthIdentityStatus;
  identity_generation: number;
  identity_created_at_ms: number;
  identity_updated_at_ms: number;
  last_authenticated_at_ms: number | null;
  identity_revoked_at_ms: number | null;
  canonical_user_id: string;
  username: string;
  display_name: string;
  legacy_role: LegacyUserRole;
  user_status: CanonicalUserStatus;
  user_generation: number;
  user_created_at_ms: number;
  user_updated_at_ms: number;
  last_login_at_ms: number | null;
  user_revoked_at_ms: number | null;
}

function resolvedIdentityView(row: ResolvedIdentityRow): ProvisionedIdentity {
  return Object.freeze({
    user: userView({
      id: row.canonical_user_id,
      username: row.username,
      display_name: row.display_name,
      legacy_role: row.legacy_role,
      status: row.user_status,
      generation: row.user_generation,
      created_at_ms: row.user_created_at_ms,
      updated_at_ms: row.user_updated_at_ms,
      last_login_at_ms: row.last_login_at_ms,
      revoked_at_ms: row.user_revoked_at_ms,
    }),
    identity: identityView({
      id: row.identity_id,
      user_id: row.user_id,
      provider: row.provider,
      subject: row.subject,
      status: row.identity_status,
      generation: row.identity_generation,
      created_at_ms: row.identity_created_at_ms,
      updated_at_ms: row.identity_updated_at_ms,
      last_authenticated_at_ms: row.last_authenticated_at_ms,
      revoked_at_ms: row.identity_revoked_at_ms,
    }),
  });
}

function requireProvisionedIdentity(
  db: Database.Database,
  identityId: string,
  userId: string
): ProvisionedIdentity {
  const identity = db
    .prepare(
      `SELECT id, user_id, provider, subject, status, generation,
              created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
       FROM auth_identities WHERE id = ?`
    )
    .get(identityId) as IdentityRow | undefined;
  const user = db
    .prepare(
      `SELECT id, username, display_name, legacy_role, status, generation,
              created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
       FROM users WHERE id = ?`
    )
    .get(userId) as UserRow | undefined;
  if (!identity || !user) throw new Error("Canonical identity provisioning did not settle");
  return Object.freeze({ user: userView(user), identity: identityView(identity) });
}

function userView(row: UserRow): CanonicalUser {
  return Object.freeze({
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    legacyRole: row.legacy_role,
    status: row.status,
    generation: row.generation,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
    lastLoginAtMs: row.last_login_at_ms,
    revokedAtMs: row.revoked_at_ms,
  });
}

function identityView(row: IdentityRow): AuthIdentity {
  return Object.freeze({
    id: row.id,
    userId: row.user_id,
    provider: row.provider,
    subject: row.subject,
    status: row.status,
    generation: row.generation,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
    lastAuthenticatedAtMs: row.last_authenticated_at_ms,
    revokedAtMs: row.revoked_at_ms,
  });
}

function localUserView(row: LocalUserRow): LegacyLocalUserRecord {
  return Object.freeze({
    id: row.id,
    username: row.username,
    role: row.legacy_role,
    passwordHash: row.password_hash,
    createdAt: new Date(row.created_at_ms).toISOString(),
    lastLogin: row.last_login_at_ms === null ? null : new Date(row.last_login_at_ms).toISOString(),
  });
}

function requiredString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new TypeError(`${label} is invalid`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength) throw new TypeError(`${label} is invalid`);
  return normalized;
}

function safeTimestamp(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("Identity clock is invalid");
  return value;
}

function assertLegacyRole(value: unknown): asserts value is LegacyUserRole {
  if (value !== "admin" && value !== "user") throw new TypeError("Legacy User role is invalid");
}

function authProvider(value: unknown): AuthIdentityProvider {
  if (value !== "local" && value !== "google" && value !== "password") {
    throw new TypeError("Authentication identity provider is invalid");
  }
  return value;
}

function positiveGeneration(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new TypeError("Identity generation is invalid");
  }
  return value as number;
}

function sha256Digest(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("Legacy User source digest is invalid");
  }
  return value;
}

function isoTimestamp(value: unknown, label: string): number {
  if (typeof value !== "string") throw new TypeError(`${label} is invalid`);
  const timestamp = Date.parse(value);
  if (
    !Number.isSafeInteger(timestamp) ||
    timestamp < 0 ||
    new Date(timestamp).toISOString() !== value
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return timestamp;
}

function legacyLocalUser(value: unknown): LegacyLocalUserRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Legacy local User is invalid");
  }
  const candidate = value as Partial<LegacyLocalUserRecord>;
  const id = requiredString(candidate.id, "Legacy User ID", 300);
  const username = requiredString(candidate.username, "Legacy local username", 320);
  assertLegacyRole(candidate.role);
  const passwordHash = requiredString(candidate.passwordHash, "Legacy password hash", 4096);
  if (passwordHash.length < 20) throw new TypeError("Legacy password hash is invalid");
  const createdAtMs = isoTimestamp(candidate.createdAt, "Legacy User creation time");
  const createdAt = new Date(createdAtMs).toISOString();
  let lastLogin: string | null = null;
  if (candidate.lastLogin !== null) {
    const lastLoginAtMs = isoTimestamp(candidate.lastLogin, "Legacy User last login");
    if (lastLoginAtMs < createdAtMs) throw new TypeError("Legacy User last login is invalid");
    lastLogin = new Date(lastLoginAtMs).toISOString();
  }
  return Object.freeze({ id, username, role: candidate.role, passwordHash, createdAt, lastLogin });
}
