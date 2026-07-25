import path from "node:path";
import {
  createCanonicalIdentityAuthority,
  type CanonicalIdentityAuthority,
} from "./identity-authority";
import { createStoredAuthenticationSessionValidator } from "./auth-session-validator";
import { createConnectionAuthority, type ConnectionAuthority } from "./connections/authority";
import { createMobileAuthAuthority, type MobileAuthAuthority } from "./mobile-auth/authority";
import { readLegacyDeviceImport } from "./mobile-auth/legacy-devices";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "./team-sessions/sqlite";

interface CanonicalIdentityService {
  readonly filename: string;
  readonly database: TeamSessionDatabase;
  readonly authority: CanonicalIdentityAuthority;
  readonly connectionAuthority: ConnectionAuthority;
  readonly mobileAuthAuthority: MobileAuthAuthority;
  activeOperations: number;
  closeRequested: boolean;
  closed: boolean;
}

interface CanonicalIdentityServiceRegistry {
  active: CanonicalIdentityService | null;
}

// The custom server and Next route bundles can load separate module instances
// in the same process. A global symbol gives them one database owner while
// remaining invisible to ordinary string-key enumeration.
const REGISTRY_KEY = Symbol.for("terminalx.canonical-identity-service.v1");

function serviceRegistry(): CanonicalIdentityServiceRegistry {
  const shared = globalThis as typeof globalThis & Record<symbol, unknown>;
  const existing = shared[REGISTRY_KEY];
  if (existing) return existing as CanonicalIdentityServiceRegistry;
  const created: CanonicalIdentityServiceRegistry = { active: null };
  shared[REGISTRY_KEY] = created;
  return created;
}

export function canonicalIdentityDatabaseFilename(): string {
  return (
    process.env.TERMINALX_TEAM_SESSION_DB_PATH ??
    path.join(/* turbopackIgnore: true */ process.cwd(), "data", "team-sessions.sqlite")
  );
}

function normalizedDatabaseFilename(): string {
  const filename = canonicalIdentityDatabaseFilename();
  return filename === ":memory:" ? filename : path.resolve(/* turbopackIgnore: true */ filename);
}

function closeService(service: CanonicalIdentityService): void {
  if (service.closed) return;
  service.database.close();
  service.closed = true;
  const registry = serviceRegistry();
  if (registry.active === service) registry.active = null;
}

function createService(filename: string): CanonicalIdentityService {
  const database = openTeamSessionDatabase({ filename });
  try {
    const mobileAuthAuthority = createMobileAuthAuthority({ db: database.db });
    const validateAuthenticationSnapshot = createStoredAuthenticationSessionValidator({
      getDevice: (deviceId) => mobileAuthAuthority.getDevice(deviceId),
    });
    return {
      filename,
      database,
      authority: createCanonicalIdentityAuthority({ db: database.db }),
      connectionAuthority: createConnectionAuthority({
        db: database.db,
        validateAuthenticationSnapshot: (snapshot) =>
          validateAuthenticationSnapshot({
            canonicalUserId: snapshot.userId,
            canonicalUsername: snapshot.username,
            provider: snapshot.authProvider,
            credentialJtiDigest: snapshot.credentialJtiDigest,
            credentialExpiresAtMs: snapshot.credentialExpiresAtMs,
            device: snapshot.device,
          }),
      }),
      mobileAuthAuthority,
      activeOperations: 0,
      closeRequested: false,
      closed: false,
    };
  } catch (error) {
    database.close();
    throw error;
  }
}

function acquireService(): CanonicalIdentityService {
  const registry = serviceRegistry();
  const filename = normalizedDatabaseFilename();
  const current = registry.active;
  if (current && current.filename === filename) {
    if (current.closeRequested || current.closed) {
      throw new Error("Canonical identity service is closing");
    }
    return current;
  }
  if (current) {
    if (current.activeOperations > 0) {
      throw new Error("Canonical identity database cannot change during an active operation");
    }
    closeService(current);
  }
  const created = createService(filename);
  registry.active = created;
  return created;
}

function releaseService(service: CanonicalIdentityService): void {
  if (service.activeOperations < 1) {
    throw new Error("Canonical identity service operation accounting failed");
  }
  service.activeOperations -= 1;
  if (service.activeOperations === 0 && service.closeRequested) closeService(service);
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    ((typeof value === "object" && value !== null) || typeof value === "function") &&
    typeof (value as { then?: unknown }).then === "function"
  );
}

export function withCanonicalIdentityAuthority<T>(
  operation: (authority: CanonicalIdentityAuthority) => T
): T {
  const service = acquireService();
  service.activeOperations += 1;
  try {
    const result = operation(service.authority);
    if (isPromiseLike(result)) {
      return Promise.resolve(result).finally(() => releaseService(service)) as T;
    }
    releaseService(service);
    return result;
  } catch (error) {
    releaseService(service);
    throw error;
  }
}

/**
 * Run a connection-authority operation against the same migrated, validated,
 * process-owned SQLite connection as canonical authentication. This avoids a
 * second in-process database owner and lets each authority method validate
 * identity, Team, Session, and connection fences in its own transaction. A
 * returned routing/attribution snapshot does not make a later Team command or
 * provider effect atomic; those consumers must revalidate at their effect
 * boundary.
 */
export function withConnectionAuthority<T>(operation: (authority: ConnectionAuthority) => T): T {
  const service = acquireService();
  service.activeOperations += 1;
  try {
    const result = operation(service.connectionAuthority);
    if (isPromiseLike(result)) {
      return Promise.resolve(result).finally(() => releaseService(service)) as T;
    }
    releaseService(service);
    return result;
  } catch (error) {
    releaseService(service);
    throw error;
  }
}

/** Run a mobile pairing/device operation on the process-owned SQLite connection. */
export function withMobileAuthAuthority<T>(operation: (authority: MobileAuthAuthority) => T): T {
  const service = acquireService();
  service.activeOperations += 1;
  try {
    const result = operation(service.mobileAuthAuthority);
    if (isPromiseLike(result)) {
      return Promise.resolve(result).finally(() => releaseService(service)) as T;
    }
    releaseService(service);
    return result;
  } catch (error) {
    releaseService(service);
    throw error;
  }
}

/**
 * Import the legacy devices.json projection exactly once after canonical User
 * provisioning. Plaintext legacy pairing codes are intentionally not read.
 */
export function initializeLegacyMobileAuthState(): void {
  if (withMobileAuthAuthority((authority) => authority.hasImportedLegacyDevices())) return;
  const legacy = readLegacyDeviceImport();
  withMobileAuthAuthority((authority) => authority.importLegacyDevices(legacy));
}

/**
 * Open, migrate, integrity-check, and retain the canonical identity database.
 * Authenticated server profiles call this before constructing request ingress.
 */
export function initializeCanonicalIdentityAuthorityService(): void {
  withCanonicalIdentityAuthority(() => undefined);
}

/**
 * Stop the process-wide canonical identity database owner. The call is
 * idempotent. If an operation is active, its lease remains valid and the
 * database closes as soon as that operation settles; new operations fail
 * closed in the meantime.
 */
export function closeCanonicalIdentityAuthorityService(): void {
  const service = serviceRegistry().active;
  if (!service || service.closed) return;
  service.closeRequested = true;
  if (service.activeOperations === 0) closeService(service);
}
