import * as path from "path";
import Database from "better-sqlite3";
import { TEAM_SESSION_SCHEMA_VERSION } from "../team-sessions/sqlite";
import { configuredSecretBrokerRoot } from "../connections/secret-broker-composition";
import { readBrokerVerificationKey } from "../connections/secret-broker-verifier";

/**
 * Readiness evaluation for the load-balancer readiness probe. Unlike the
 * liveness probe (which only proves the process is up), readiness proves the
 * real dependencies are usable: the SQLite database is reachable, migrated to
 * the exact schema version this binary expects, and integrity-clean; and, when a
 * Secret Broker is configured, that it has published its verification key. It
 * fails closed — any unmet dependency yields `ready: false` so traffic is held.
 *
 * The structured `checks` detail exists for telemetry and tests. The HTTP
 * surface must collapse it to a single non-leaking status so a probe never
 * discloses which dependency is degraded.
 */

const TERMINALX_DATABASE_APPLICATION_ID = 0x54585331; // "TXS1"

export type ReadinessCheckName = "database" | "schema" | "integrity" | "secret-broker";

export interface ReadinessCheck {
  readonly name: ReadinessCheckName;
  readonly ok: boolean;
}

export interface ReadinessResult {
  readonly ready: boolean;
  readonly checks: readonly ReadinessCheck[];
}

export interface ReadinessOptions {
  /** Override the database path (defaults to the canonical Team Session DB). */
  readonly databaseFilename?: string;
  /** Override broker configuration detection (defaults to env). */
  readonly secretBrokerConfigured?: () => boolean;
  /** Override broker readiness detection (defaults to published verification key). */
  readonly secretBrokerReady?: () => boolean;
}

function resolveDatabaseFilename(options: ReadinessOptions): string {
  if (options.databaseFilename) return options.databaseFilename;
  return (
    process.env.TERMINALX_TEAM_SESSION_DB_PATH ??
    path.join(process.cwd(), "data", "team-sessions.sqlite")
  );
}

function evaluateDatabase(filename: string): {
  database: boolean;
  schema: boolean;
  integrity: boolean;
} {
  if (filename === ":memory:") {
    // An in-memory database is never the production readiness target.
    return { database: false, schema: false, integrity: false };
  }
  let db: Database.Database | undefined;
  try {
    db = new Database(filename, { readonly: true, fileMustExist: true });
    const applicationId = db.pragma("application_id", { simple: true }) as number;
    if (applicationId !== TERMINALX_DATABASE_APPLICATION_ID) {
      return { database: true, schema: false, integrity: false };
    }
    const schemaVersion = db.pragma("user_version", { simple: true }) as number;
    const schema = schemaVersion === TEAM_SESSION_SCHEMA_VERSION;
    const quickCheck = db.pragma("quick_check", { simple: true }) as string;
    const integrity = quickCheck === "ok";
    return { database: true, schema, integrity };
  } catch {
    return { database: false, schema: false, integrity: false };
  } finally {
    db?.close();
  }
}

function defaultSecretBrokerConfigured(): boolean {
  return configuredSecretBrokerRoot() !== null;
}

function defaultSecretBrokerReady(): boolean {
  const root = configuredSecretBrokerRoot();
  if (!root) return true;
  return readBrokerVerificationKey(root) !== null;
}

export function evaluateReadiness(options: ReadinessOptions = {}): ReadinessResult {
  const filename = resolveDatabaseFilename(options);
  const db = evaluateDatabase(filename);
  const brokerConfigured = (options.secretBrokerConfigured ?? defaultSecretBrokerConfigured)();
  const brokerReady = brokerConfigured
    ? (options.secretBrokerReady ?? defaultSecretBrokerReady)()
    : true;

  const checks: ReadinessCheck[] = [
    { name: "database", ok: db.database },
    { name: "schema", ok: db.schema },
    { name: "integrity", ok: db.integrity },
    { name: "secret-broker", ok: brokerReady },
  ];
  const ready = checks.every((check) => check.ok);
  return { ready, checks };
}
