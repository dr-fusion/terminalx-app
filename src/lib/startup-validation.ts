import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";
import { getAllowedEmails, getAuthMode } from "./auth-config";

export interface StartupValidationOptions {
  host: string;
  cwd?: string;
}

export interface StartupValidationResult {
  errors: string[];
  warnings: string[];
}

const MIN_SECRET_LENGTH = 32;
const MIN_PASSWORD_LENGTH = 8;
const TERMINALX_DATABASE_APPLICATION_ID = 0x54585331;
const CANONICAL_IDENTITY_SCHEMA_VERSION = 11;
const CANONICAL_IDENTITY_DATABASE_ERROR =
  "Canonical identity database failed validation; refusing local-auth startup.";

function dataPath(cwd = process.cwd(), file: string): string {
  return path.join(cwd, "data", file);
}

function hasLegacyLocalUser(cwd = process.cwd()): boolean {
  const usersFile = dataPath(cwd, "users.json");
  try {
    const raw = fs.readFileSync(usersFile, "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) && parsed.length > 0;
  } catch {
    return false;
  }
}

function hasCanonicalLocalUser(cwd = process.cwd()): boolean {
  const configured = process.env.TERMINALX_TEAM_SESSION_DB_PATH;
  const filename = configured
    ? path.resolve(cwd, configured)
    : dataPath(cwd, "team-sessions.sqlite");
  try {
    fs.lstatSync(filename);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  let database: Database.Database | undefined;
  try {
    database = new Database(filename, { readonly: true, fileMustExist: true });
    const applicationId = database.pragma("application_id", { simple: true }) as number;
    if (applicationId !== TERMINALX_DATABASE_APPLICATION_ID) {
      throw new Error("Unexpected TerminalX database application ID.");
    }
    const schemaVersion = database.pragma("user_version", { simple: true }) as number;
    if (
      !Number.isSafeInteger(schemaVersion) ||
      schemaVersion < 1 ||
      schemaVersion > CANONICAL_IDENTITY_SCHEMA_VERSION
    ) {
      throw new Error("Unsupported TerminalX database schema version.");
    }
    // Startup validation runs before openTeamSessionDatabase performs its
    // transactional migration. A recognized v1-v10 database legitimately has
    // no canonical identity tables yet, so defer to the legacy source here;
    // the database opener remains responsible for validating and migrating it.
    if (schemaVersion < CANONICAL_IDENTITY_SCHEMA_VERSION) return false;
    return Boolean(
      database
        .prepare(
          `SELECT 1
           FROM users user
           JOIN auth_identities identity ON identity.user_id = user.id
           JOIN local_auth_credentials credential
             ON credential.user_id = user.id AND credential.auth_identity_id = identity.id
           WHERE user.status = 'active'
             AND identity.status = 'active'
             AND identity.provider = 'local'
           LIMIT 1`
        )
        .get()
    );
  } finally {
    database?.close();
  }
}

function hasLongEnoughSecret(raw: string | undefined): boolean {
  return Boolean(raw && raw.trim().length >= MIN_SECRET_LENGTH);
}

function hasLongEnoughPassword(raw: string | undefined): boolean {
  return Boolean(raw && raw.length >= MIN_PASSWORD_LENGTH);
}

export function validateStartupConfiguration(
  opts: StartupValidationOptions
): StartupValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const cwd = opts.cwd ?? process.cwd();
  const authMode = getAuthMode();

  // `none` mode disables auth entirely and is forbidden in normal operation.
  // It can be explicitly opted into for local development and automated tests
  // (e.g. Playwright) via TERMINALX_ALLOW_AUTH_NONE=true. In that mode the JWT
  // secret is unused (middleware bypasses token verification), so it is not
  // required either.
  const allowAuthNone = process.env.TERMINALX_ALLOW_AUTH_NONE === "true";

  if (authMode === "none" && !allowAuthNone) {
    errors.push(
      "TERMINALX_AUTH_MODE=none is not allowed. Configure local, password, or google auth."
    );
  }

  if (authMode !== "none" && !hasLongEnoughSecret(process.env.TERMINALX_JWT_SECRET)) {
    errors.push(`TERMINALX_JWT_SECRET must be set and at least ${MIN_SECRET_LENGTH} characters.`);
  }

  if (authMode === "password" && !hasLongEnoughPassword(process.env.TERMINALX_PASSWORD)) {
    errors.push(
      `TERMINALX_PASSWORD must be set and at least ${MIN_PASSWORD_LENGTH} characters in password auth mode.`
    );
  }

  if (authMode === "local") {
    let canonicalIdentityDatabaseValid = true;
    let hasCanonicalUsers = false;
    try {
      hasCanonicalUsers = hasCanonicalLocalUser(cwd);
    } catch {
      canonicalIdentityDatabaseValid = false;
      errors.push(CANONICAL_IDENTITY_DATABASE_ERROR);
    }
    if (canonicalIdentityDatabaseValid) {
      const hasUsers = hasCanonicalUsers || hasLegacyLocalUser(cwd);
      if (!hasUsers && !hasLongEnoughPassword(process.env.TERMINALX_ADMIN_PASSWORD)) {
        errors.push(
          `TERMINALX_ADMIN_PASSWORD must be set and at least ${MIN_PASSWORD_LENGTH} characters for first local-auth startup.`
        );
      }
    }
  }

  if (authMode === "google") {
    if (!process.env.TERMINALX_GOOGLE_CLIENT_ID?.trim()) {
      errors.push("TERMINALX_GOOGLE_CLIENT_ID is required in google auth mode.");
    }
    if (!process.env.TERMINALX_GOOGLE_CLIENT_SECRET?.trim()) {
      errors.push("TERMINALX_GOOGLE_CLIENT_SECRET is required in google auth mode.");
    }
    if (getAllowedEmails().length === 0) {
      errors.push("TERMINALX_ALLOWED_EMAILS must contain at least one email in google auth mode.");
    }
  }

  if (opts.host === "0.0.0.0" && !process.env.TERMINALX_PUBLIC_URL?.trim()) {
    warnings.push(
      "TERMINUS_HOST=0.0.0.0 without TERMINALX_PUBLIC_URL can produce incorrect external URLs behind proxies."
    );
  }

  return { errors, warnings };
}

export function assertValidStartupConfiguration(opts: StartupValidationOptions): void {
  const result = validateStartupConfiguration(opts);
  for (const warning of result.warnings) {
    console.warn(`[security] ${warning}`);
  }
  if (result.errors.length === 0) return;
  for (const error of result.errors) {
    console.error(`[security] ${error}`);
  }
  process.exit(1);
}
