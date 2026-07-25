import type { SecretBrokerClient } from "./secret-broker-client";

export interface PreparedRegistrationRecord {
  readonly handleId: string;
  readonly receiptId: string;
  readonly expiresAtMs: number;
  readonly rotation: boolean;
}

export type ReconcileAction = "finalized" | "aborted" | "deferred";

export interface ReconcileOutcome {
  readonly handleId: string;
  readonly action: ReconcileAction;
}

export interface CreateSecretBrokerReconcilerOptions {
  readonly client: SecretBrokerClient;
  /**
   * True iff the authority SQLite transaction committed a Credential Handle row
   * with this id. Read-only, synchronous, and never inside a broker IPC.
   */
  readonly authorityHandleCommitted: (handleId: string) => boolean;
  readonly clock?: () => number;
}

export interface SecretBrokerReconciler {
  reconcile(record: PreparedRegistrationRecord): Promise<ReconcileOutcome>;
  reconcileAll(
    records: readonly PreparedRegistrationRecord[]
  ): Promise<readonly ReconcileOutcome[]>;
}

/**
 * Resolve the outcome of any prepared registration whose finalize/abort was not
 * observed to complete.
 *
 * - If the authority committed the handle row, the broker is finalized. This is
 *   the only actor that knows the authority transaction committed, so it is the
 *   only actor that can finalize a committed-but-pending handle.
 * - If the authority did not commit and the receipt has expired, the broker is
 *   aborted. Aborting only after expiry avoids racing an in-flight authority
 *   transaction, whose verifier already rejects expired receipts.
 * - Otherwise the outcome is deferred to a later sweep. The broker's own TTL
 *   reap independently aborts expired pending rows, so no externally active
 *   orphan handle can persist regardless of main-side liveness.
 *
 * Every branch is idempotent, so repeated sweeps and duplicate records converge.
 */
export function createSecretBrokerReconciler(
  options: CreateSecretBrokerReconcilerOptions
): SecretBrokerReconciler {
  const clock = options.clock ?? Date.now;

  async function reconcile(record: PreparedRegistrationRecord): Promise<ReconcileOutcome> {
    if (options.authorityHandleCommitted(record.handleId)) {
      if (record.rotation) {
        await options.client.finalizeRotation(record.handleId, record.receiptId);
      } else {
        await options.client.finalizeRegistration(record.handleId, record.receiptId);
      }
      return { handleId: record.handleId, action: "finalized" };
    }
    if (clock() >= record.expiresAtMs) {
      if (record.rotation) {
        await options.client.abortRotation(record.receiptId);
      } else {
        await options.client.abortRegistration(record.receiptId);
      }
      return { handleId: record.handleId, action: "aborted" };
    }
    return { handleId: record.handleId, action: "deferred" };
  }

  return Object.freeze({
    reconcile,
    async reconcileAll(
      records: readonly PreparedRegistrationRecord[]
    ): Promise<readonly ReconcileOutcome[]> {
      const outcomes: ReconcileOutcome[] = [];
      for (const record of records) outcomes.push(await reconcile(record));
      return Object.freeze(outcomes);
    },
  });
}
