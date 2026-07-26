import type {
  AttentionDeliveryDeps,
  AttentionOutboundDecision,
  SessionOutboundBindingRef,
} from "../attention/contracts";
import { deliverOutboundMessage } from "../connections/outbound-worker";
import type { CredentialProxyClient } from "../connections/credential-proxy-client";
import type { ConnectionAuthority } from "../connections/authority";
import type Database from "better-sqlite3";
import { resolveConfiguredCredentialProxyClient } from "../connections/secret-broker-composition";
import { withConnectionAuthority, withConnectionDatabase } from "../identity-service";

/**
 * The concrete production wiring for Phase 11A attention notification delivery.
 * It bridges the attention subsystem's injected seams onto the EXISTING Slice 8E
 * connection egress:
 *
 * - `resolveSessionBinding` → the active Channel Binding for a Team Session
 *   (revisions read from the connection authority's database).
 * - `deliverOutbound` → `deliverOutboundMessage`, which re-fences the Binding via
 *   the authority's `resolveOutboundBinding` and sends through the 8D Credential
 *   Proxy.
 *
 * It fails closed: without a configured Secret Broker / Credential Proxy there is
 * no egress, so `resolveSessionBinding` returns null and nothing is ever sent.
 * The in-app inbox and escalation log are unaffected either way.
 */

export interface ProductionAttentionDeliveryOptions {
  /** Override the Credential Proxy client (defaults to the configured broker's). */
  readonly proxyClient?: CredentialProxyClient | null;
  /** Override the session→binding lookup (defaults to the connection database). */
  readonly resolveSessionBinding?: (sessionId: string) => SessionOutboundBindingRef | null;
  /** Override the outbound Binding re-fence (defaults to the connection authority). */
  readonly withAuthority?: <T>(operation: (authority: ConnectionAuthority) => T) => T;
  /** Override the connection database accessor (defaults to the identity service). */
  readonly withDatabase?: <T>(operation: (db: Database.Database) => T) => T;
}

interface BindingRow {
  readonly id: string;
  readonly revision: number;
  readonly installation_revision: number;
}

function defaultResolveSessionBinding(
  withDatabase: <T>(operation: (db: Database.Database) => T) => T
): (sessionId: string) => SessionOutboundBindingRef | null {
  return (sessionId: string) => {
    try {
      return withDatabase((db) => {
        const row = db
          .prepare(
            `SELECT id, revision, installation_revision
               FROM channel_bindings
              WHERE session_id = ? AND status = 'active'
              ORDER BY id ASC
              LIMIT 1`
          )
          .get(sessionId) as BindingRow | undefined;
        if (!row) return null;
        return {
          bindingId: row.id,
          expectedBindingRevision: row.revision,
          expectedInstallationRevision: row.installation_revision,
        };
      });
    } catch {
      // Fail closed: an unavailable authority means no external delivery.
      return null;
    }
  };
}

const FAIL_CLOSED_DEPS: AttentionDeliveryDeps = Object.freeze({
  resolveSessionBinding: () => null,
  deliverOutbound: async (): Promise<AttentionOutboundDecision> => ({
    delivered: false,
    shouldRetry: false,
    reason: "not-routed",
  }),
});

/**
 * Build the production {@link AttentionDeliveryDeps}. Returns a fully fail-closed
 * set when no Credential Proxy is configured.
 */
export function createProductionAttentionDeliveryDeps(
  options: ProductionAttentionDeliveryOptions = {}
): AttentionDeliveryDeps {
  const proxyClient =
    options.proxyClient === undefined
      ? resolveConfiguredCredentialProxyClient()
      : options.proxyClient;
  if (proxyClient === null) return FAIL_CLOSED_DEPS;

  const withDatabase = options.withDatabase ?? withConnectionDatabase;
  const withAuthority = options.withAuthority ?? withConnectionAuthority;
  const resolveSessionBinding =
    options.resolveSessionBinding ?? defaultResolveSessionBinding(withDatabase);

  return Object.freeze({
    resolveSessionBinding,
    deliverOutbound: async (
      input: Parameters<AttentionDeliveryDeps["deliverOutbound"]>[0]
    ): Promise<AttentionOutboundDecision> => {
      const decision = await deliverOutboundMessage(
        {
          proxyClient,
          resolveOutboundBinding: (bindingInput) =>
            withAuthority((authority) => authority.resolveOutboundBinding(bindingInput)),
        },
        {
          bindingId: input.bindingId,
          expectedBindingRevision: input.expectedBindingRevision,
          expectedInstallationRevision: input.expectedInstallationRevision,
          messageKind: input.messageKind,
          includesArtifacts: input.includesArtifacts,
          text: input.text,
          attempt: input.attempt,
        }
      );
      return {
        delivered: decision.delivered,
        shouldRetry: decision.shouldRetry,
        reason: decision.reason,
      };
    },
  });
}
