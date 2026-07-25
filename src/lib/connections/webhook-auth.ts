import type Database from "better-sqlite3";

/**
 * Digest-only persistence for the per-installation Telegram webhook secret token
 * (schema v15). The broker generates the raw `secret_token`, sets it on Telegram,
 * and returns only its SHA-256 (`webhookAuthDigest`); the main process appends
 * that digest here and authenticates inbound deliveries by constant-time digest
 * comparison. Rows are write-once; a credential rotation appends a new row and
 * `latestWebhookAuthDigest` returns the most recent one.
 */
export interface WebhookAuthStore {
  recordWebhookAuthDigest(input: {
    installationId: string;
    provider: "telegram";
    authDigest: string;
    createdAtMs: number;
  }): void;
  latestWebhookAuthDigest(installationId: string, provider: "telegram"): string | null;
}

export function createWebhookAuthStore(db: Database.Database): WebhookAuthStore {
  const insert = db.prepare(
    `INSERT INTO installation_webhook_auth_digests
       (installation_id, provider, auth_digest, created_at_ms)
     VALUES (?, ?, ?, ?)`
  );
  const selectLatest = db.prepare(
    `SELECT auth_digest FROM installation_webhook_auth_digests
     WHERE installation_id = ? AND provider = ?
     ORDER BY sequence DESC LIMIT 1`
  );
  const impl: WebhookAuthStore = {
    recordWebhookAuthDigest({ installationId, provider, authDigest, createdAtMs }) {
      if (!/^[0-9a-f]{64}$/.test(authDigest)) {
        throw new TypeError("Webhook authentication digest is invalid");
      }
      insert.run(installationId, provider, authDigest, createdAtMs);
    },
    latestWebhookAuthDigest(installationId, provider) {
      const row = selectLatest.get(installationId, provider) as { auth_digest: string } | undefined;
      return row?.auth_digest ?? null;
    },
  };
  return Object.freeze(impl);
}
