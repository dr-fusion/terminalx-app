import { chmodSync } from "node:fs";
import Database from "better-sqlite3";
import { sealAtRest, openAtRest } from "../at-rest";
import { SecretBrokerProtocolError } from "../protocol";

/**
 * Broker-private, at-rest-sealed store for provider webhook-verification secrets
 * (currently the Slack signing secret). Each secret is bound to one installation
 * via its `expectationDigest`, encrypted with the broker-root at-rest key, and is
 * only ever revealed inside the broker process to compute an HMAC. The plaintext
 * never crosses the socket; `webhook.verify-slack` returns only a boolean.
 */
export interface WebhookSecretStore {
  /** Store (or idempotently re-store) a sealed secret bound to an installation. */
  put(provider: string, expectationDigest: string, secret: Buffer): void;
  /** Reveal the plaintext secret for in-broker use. Caller must zero the result. */
  reveal(provider: string, expectationDigest: string): Buffer | null;
  close(): void;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS webhook_secrets (
  provider TEXT NOT NULL,
  expectation_digest TEXT NOT NULL,
  sealed_secret BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (provider, expectation_digest)
);
`;

export interface OpenWebhookSecretStoreOptions {
  readonly databasePath: string;
  readonly atRestKey: Buffer;
  readonly clock?: () => number;
}

export function openWebhookSecretStore(options: OpenWebhookSecretStoreOptions): WebhookSecretStore {
  if (typeof options !== "object" || options === null) throw new TypeError();
  const clock = options.clock ?? Date.now;
  const atRestKey = Buffer.from(options.atRestKey);
  const db = new Database(options.databasePath);
  if (options.databasePath !== ":memory:") restrictDatabaseFiles(options.databasePath);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  db.exec(SCHEMA);
  if (options.databasePath !== ":memory:") restrictDatabaseFiles(options.databasePath);

  const upsert = db.prepare(
    `INSERT INTO webhook_secrets (provider, expectation_digest, sealed_secret, created_at_ms)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (provider, expectation_digest)
     DO UPDATE SET sealed_secret = excluded.sealed_secret, created_at_ms = excluded.created_at_ms`
  );
  const select = db.prepare<[string, string]>(
    "SELECT sealed_secret FROM webhook_secrets WHERE provider = ? AND expectation_digest = ?"
  );

  return Object.freeze({
    put(provider: string, expectationDigest: string, secret: Buffer): void {
      const now = clock();
      if (!Number.isSafeInteger(now) || now < 0) throw new SecretBrokerProtocolError("internal");
      // sealAtRest zeroes the plaintext secret buffer on return.
      const sealed = sealAtRest(secret, atRestKey);
      try {
        upsert.run(provider, expectationDigest, sealed, now);
      } finally {
        sealed.fill(0);
      }
    },
    reveal(provider: string, expectationDigest: string): Buffer | null {
      const row = select.get(provider, expectationDigest) as { sealed_secret: Buffer } | undefined;
      if (!row) return null;
      try {
        return openAtRest(Buffer.from(row.sealed_secret), atRestKey);
      } catch {
        return null;
      }
    },
    close(): void {
      atRestKey.fill(0);
      db.close();
    },
  });
}

function restrictDatabaseFiles(databasePath: string): void {
  for (const suffix of ["", "-wal", "-shm", "-journal"]) {
    try {
      chmodSync(`${databasePath}${suffix}`, 0o600);
    } catch {
      // Sidecars may not exist yet; re-restricted on the next call.
    }
  }
}
