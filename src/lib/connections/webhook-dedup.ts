import type Database from "better-sqlite3";
import type { ConnectionProvider } from "./contracts";
import { sha256 } from "./contracts";

const DEDUP_DIGEST_DOMAIN = "terminalx/provider-webhook-delivery/v1\0";

/**
 * Durable, bounded, digest-only replay dedup for provider webhook deliveries
 * (schema v14), scoped per Channel Installation. Rows are write-once and carry
 * only a digest of the provider replay id, never message content.
 *
 * This is an optimization: the authoritative "never processed twice" guarantee is
 * the idempotent Team Session kernel command. A delivery is recorded only after
 * it has been processed (or dropped), so a crash between processing and recording
 * is at-least-once acknowledged, and a re-delivery idempotent-replays the kernel
 * command rather than producing a second Session event.
 */
export interface WebhookDeliveryDedup {
  /** True if this exact (installation, replay id) delivery was already recorded. */
  hasDelivery(input: {
    installationId: string;
    provider: ConnectionProvider;
    replayId: string;
  }): boolean;
  /**
   * Record a delivery. Idempotent: a duplicate (installation, digest) is a no-op
   * that returns `{ recorded: false }`. `monotonicOrdinal` is the Telegram
   * `update_id` for monotonic tolerance (undefined for Slack).
   */
  recordDelivery(input: {
    installationId: string;
    provider: ConnectionProvider;
    replayId: string;
    monotonicOrdinal?: number;
    receivedAtMs: number;
  }): { recorded: boolean };
  /** The greatest recorded Telegram `update_id` for an installation, or null. */
  latestOrdinal(installationId: string, provider: ConnectionProvider): number | null;
}

export function deliveryDigest(
  provider: ConnectionProvider,
  installationId: string,
  replayId: string
): string {
  return sha256(`${DEDUP_DIGEST_DOMAIN}${provider}\0${installationId}\0${replayId}`);
}

export function createWebhookDeliveryDedup(db: Database.Database): WebhookDeliveryDedup {
  const selectByDigest = db.prepare(
    "SELECT 1 AS present FROM provider_webhook_deliveries WHERE installation_id = ? AND delivery_digest = ?"
  );
  const insert = db.prepare(
    `INSERT INTO provider_webhook_deliveries
       (installation_id, provider, delivery_digest, monotonic_ordinal, received_at_ms)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (installation_id, delivery_digest) DO NOTHING`
  );
  const selectLatest = db.prepare(
    `SELECT MAX(monotonic_ordinal) AS ordinal FROM provider_webhook_deliveries
     WHERE installation_id = ? AND provider = ? AND monotonic_ordinal IS NOT NULL`
  );

  return Object.freeze({
    hasDelivery({ installationId, provider, replayId }): boolean {
      const digest = deliveryDigest(provider, installationId, replayId);
      return selectByDigest.get(installationId, digest) !== undefined;
    },
    recordDelivery({ installationId, provider, replayId, monotonicOrdinal, receivedAtMs }): {
      recorded: boolean;
    } {
      const digest = deliveryDigest(provider, installationId, replayId);
      const result = insert.run(
        installationId,
        provider,
        digest,
        monotonicOrdinal === undefined ? null : monotonicOrdinal,
        receivedAtMs
      );
      return { recorded: result.changes === 1 };
    },
    latestOrdinal(installationId, provider): number | null {
      const row = selectLatest.get(installationId, provider) as { ordinal: number | null };
      return row.ordinal ?? null;
    },
  });
}
