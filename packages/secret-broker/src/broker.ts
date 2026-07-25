import { randomBytes } from "node:crypto";
import type { BrokerRootContext } from "./broker-root";
import type { SecretManagerAdapterRegistry, CredentialBrokerKind } from "./adapters";
import { signSecretBrokerReceipt, type SecretBrokerReceipt } from "./receipt-schema";
import {
  boundedIdentifier,
  digestField,
  exactRecord,
  field,
  SecretBrokerProtocolError,
} from "./protocol";
import type { SecretBrokerRequest, SecretBrokerRequestHandler } from "./ndjson";
import type { RegistrationRow, SecretBrokerStateStore } from "./state-store";
import { createProviderExchange, type ProviderExchange } from "./exchange/exchange";
import type { ProviderExchangeClient } from "./exchange/provider-exchange-client";
import type { WebhookSecretStore } from "./exchange/webhook-secret-store";

const MIN_TTL_MS = 60 * 1000;
const MAX_TTL_MS = 30 * 60 * 1000;
const DEFAULT_TTL_MS = 5 * 60 * 1000;
const MAX_SECRET_BYTES = 128 * 1024;
const BROKER_KINDS: readonly CredentialBrokerKind[] = ["oauth-envelope", "onepassword-connect"];

export interface SecretBrokerAuditEvent {
  readonly action:
    | "reconcile.reap"
    | "registration.prepare"
    | "registration.finalize"
    | "registration.abort"
    | "rotation.finalize"
    | "handle.revoke";
  readonly handleId: string;
  readonly status?: string;
}

export interface CreateSecretBrokerOptions {
  readonly root: BrokerRootContext;
  readonly store: SecretBrokerStateStore;
  readonly adapters: SecretManagerAdapterRegistry;
  readonly clock?: () => number;
  readonly receiptTtlMs?: number;
  readonly audit?: (event: SecretBrokerAuditEvent) => void;
  /**
   * Slice 8E provider credential-acquisition (optional and additive). When both
   * are present the broker serves `exchange.slack-oauth`,
   * `exchange.telegram-bot-token`, and `webhook.verify-slack`; otherwise those
   * methods fail closed with `not-ready`.
   */
  readonly providerExchangeClient?: ProviderExchangeClient;
  readonly webhookSecretStore?: WebhookSecretStore;
  readonly exchangeRandomBytes?: (size: number) => Buffer;
}

export interface SecretBroker {
  readonly handle: SecretBrokerRequestHandler;
  reconcile(now?: number): { readonly reaped: number };
}

/**
 * The Secret Broker service: resolves prepare/finalize/abort/rotation/revoke/
 * status/health requests against broker-private state. Non-exporting by
 * construction — no handler returns credential material, only opaque handles,
 * statuses, and a signed receipt.
 */
export function createSecretBroker(options: CreateSecretBrokerOptions): SecretBroker {
  const clock = options.clock ?? Date.now;
  const receiptTtlMs = options.receiptTtlMs ?? DEFAULT_TTL_MS;
  if (
    !Number.isSafeInteger(receiptTtlMs) ||
    receiptTtlMs < MIN_TTL_MS ||
    receiptTtlMs > MAX_TTL_MS
  ) {
    throw new TypeError();
  }
  const { root, store, adapters } = options;
  const audit = options.audit ?? ((): void => undefined);

  const now = (): number => {
    const value = clock();
    if (!Number.isSafeInteger(value) || value < 0) throw new SecretBrokerProtocolError("internal");
    return value;
  };

  async function prepare(
    params: unknown,
    rotation: boolean
  ): Promise<{ receipt: SecretBrokerReceipt }> {
    const request = snapshotPrepareParams(params, rotation);
    const existing = store.getByOperationId(request.operationId);
    if (existing) {
      if (
        existing.status !== "pending" ||
        existing.expectationDigest !== request.expectationDigest ||
        existing.brokerKind !== request.brokerKind ||
        (existing.replacesHandleId ?? null) !== request.replacesHandleId
      ) {
        request.secretMaterial.fill(0);
        throw new SecretBrokerProtocolError("conflict");
      }
      request.secretMaterial.fill(0);
      return { receipt: signRow(existing) };
    }
    const adapter = adapters[request.brokerKind];
    if (!adapter) {
      request.secretMaterial.fill(0);
      throw new SecretBrokerProtocolError("not-ready");
    }
    // adapter.prepare zeroes the plaintext; it returns broker-persistable bytes.
    const prepared = await adapter.prepare(request.secretMaterial);
    const issuedAtMs = now();
    const row = store.prepare({
      operationId: request.operationId,
      handleId: newHandleId(),
      receiptId: newReceiptId(),
      provider: request.provider,
      brokerKind: request.brokerKind,
      usage: request.usage,
      expectationDigest: request.expectationDigest,
      replacesHandleId: request.replacesHandleId,
      issuedAtMs,
      expiresAtMs: issuedAtMs + receiptTtlMs,
      secretMaterial: prepared.material,
    });
    audit({ action: "registration.prepare", handleId: row.handleId, status: row.status });
    return { receipt: signRow(row) };
  }

  function signRow(row: RegistrationRow): SecretBrokerReceipt {
    return signSecretBrokerReceipt(
      {
        schema: 1,
        kind: "terminalx.secret-broker-registration-receipt",
        brokerInstanceId: root.brokerInstanceId,
        brokerEpoch: root.brokerEpoch,
        signingKeyId: root.signingKeyId,
        operationId: row.operationId,
        handleId: row.handleId,
        receiptId: row.receiptId,
        provider: row.provider,
        brokerKind: row.brokerKind,
        usage: row.usage,
        expectationDigest: row.expectationDigest,
        hasReplacement: row.replacesHandleId !== null,
        issuedAtMs: row.issuedAtMs,
        expiresAtMs: row.expiresAtMs,
      },
      root.signingKey
    );
  }

  const exchange: ProviderExchange | null =
    options.providerExchangeClient && options.webhookSecretStore
      ? createProviderExchange({
          client: options.providerExchangeClient,
          webhookSecrets: options.webhookSecretStore,
          clock,
          // The exchange client also serves Slack's OIDC JWKS for in-broker
          // id_token verification (Sign in with Slack identity linking).
          slackOidcJwks: options.providerExchangeClient,
          ...(options.exchangeRandomBytes ? { randomBytes: options.exchangeRandomBytes } : {}),
          // Seal the acquired token through the exact two-phase prepare path so the
          // returned receipt is an ordinary Registration Receipt the main process
          // verifies and finalizes; the token never crosses the socket.
          prepareInstallationCredential: async ({
            operationId,
            provider,
            expectationDigest,
            tokenUtf8,
            replaces,
          }) => {
            const base64 = tokenUtf8.toString("base64");
            tokenUtf8.fill(0);
            const rotation = replaces !== null;
            const { receipt } = await prepare(
              {
                operationId,
                provider,
                brokerKind: "oauth-envelope",
                usage: "installation",
                expectationDigest,
                replaces: rotation ? { handleId: replaces.handleId } : null,
                secretMaterial: base64,
              },
              rotation
            );
            return receipt;
          },
        })
      : null;

  function requireExchange(): ProviderExchange {
    if (!exchange) throw new SecretBrokerProtocolError("not-ready");
    return exchange;
  }

  const handle: SecretBrokerRequestHandler = async (request: SecretBrokerRequest) => {
    switch (request.method) {
      case "registration.prepare":
        return prepare(request.params, false);
      case "rotation.prepare":
        return prepare(request.params, true);
      case "exchange.slack-oauth":
        return requireExchange().slackOauth(request.params);
      case "exchange.telegram-bot-token":
        return requireExchange().telegramBotToken(request.params);
      case "webhook.verify-slack":
        return requireExchange().verifySlackWebhook(request.params);
      case "exchange.slack-oidc":
        return requireExchange().slackOidc(request.params);
      case "registration.finalize": {
        const { handleId, receiptId } = snapshotHandleReceipt(request.params);
        const row = store.finalize(handleId, receiptId);
        audit({ action: "registration.finalize", handleId: row.handleId, status: row.status });
        return { handleId: row.handleId, status: row.status };
      }
      case "rotation.finalize": {
        const { handleId, receiptId } = snapshotHandleReceipt(request.params);
        const row = store.finalizeRotation(handleId, receiptId);
        const replaced = row.replacesHandleId ? store.getByHandleId(row.replacesHandleId) : null;
        audit({ action: "rotation.finalize", handleId: row.handleId, status: row.status });
        return {
          handleId: row.handleId,
          status: row.status,
          replacedHandleId: row.replacesHandleId,
          replacedStatus: replaced ? replaced.status : "revoked",
        };
      }
      case "registration.abort":
      case "rotation.abort": {
        const receiptId = snapshotReceiptId(request.params);
        const row = store.abort(receiptId);
        audit({ action: "registration.abort", handleId: row.handleId, status: row.status });
        return { receiptId: row.receiptId, status: row.status };
      }
      case "handle.revoke": {
        const handleId = snapshotHandleId(request.params);
        const row = store.revoke(handleId);
        audit({ action: "handle.revoke", handleId: row.handleId, status: row.status });
        return { handleId: row.handleId, status: row.status };
      }
      case "handle.status": {
        const handleId = snapshotHandleId(request.params);
        const row = store.getByHandleId(handleId);
        if (!row) throw new SecretBrokerProtocolError("not-found");
        return {
          handleId: row.handleId,
          status: row.status,
          brokerKind: row.brokerKind,
          provider: row.provider,
          usage: row.usage,
          expiresAtMs: row.expiresAtMs,
        };
      }
      case "broker.health":
        exactRecord(request.params, []);
        return {
          brokerInstanceId: root.brokerInstanceId,
          brokerEpoch: root.brokerEpoch,
          signingKeyId: root.signingKeyId,
          pendingRegistrations: store.countPending(),
        };
      default:
        throw new SecretBrokerProtocolError("invalid-request");
    }
  };

  return Object.freeze({
    handle,
    reconcile(nowMs?: number): { readonly reaped: number } {
      const timestamp = nowMs ?? now();
      const reaped = store.reapExpiredPending(timestamp);
      for (const row of reaped) {
        audit({ action: "reconcile.reap", handleId: row.handleId, status: row.status });
      }
      return { reaped: reaped.length };
    },
  });
}

interface PrepareRequest {
  readonly operationId: string;
  readonly provider: string;
  readonly brokerKind: CredentialBrokerKind;
  readonly usage: string;
  readonly expectationDigest: string;
  readonly replacesHandleId: string | null;
  readonly secretMaterial: Buffer;
}

function snapshotPrepareParams(params: unknown, rotation: boolean): PrepareRequest {
  const record = exactRecord(params, [
    "operationId",
    "provider",
    "brokerKind",
    "usage",
    "expectationDigest",
    "replaces",
    "secretMaterial",
  ]);
  const brokerKind = field(record, "brokerKind");
  if (
    typeof brokerKind !== "string" ||
    !BROKER_KINDS.includes(brokerKind as CredentialBrokerKind)
  ) {
    throw new SecretBrokerProtocolError("invalid-request");
  }
  const replaces = field(record, "replaces");
  let replacesHandleId: string | null = null;
  if (rotation) {
    const replacesRecord = exactRecord(replaces, ["handleId"]);
    replacesHandleId = boundedIdentifier(field(replacesRecord, "handleId"));
  } else if (replaces !== null) {
    throw new SecretBrokerProtocolError("invalid-request");
  }
  const secretMaterialBase64 = field(record, "secretMaterial");
  if (typeof secretMaterialBase64 !== "string") {
    throw new SecretBrokerProtocolError("invalid-request");
  }
  const secretMaterial = Buffer.from(secretMaterialBase64, "base64");
  if (secretMaterial.byteLength < 1 || secretMaterial.byteLength > MAX_SECRET_BYTES) {
    secretMaterial.fill(0);
    throw new SecretBrokerProtocolError("invalid-request");
  }
  try {
    return Object.freeze({
      operationId: boundedIdentifier(field(record, "operationId")),
      provider: boundedIdentifier(field(record, "provider")),
      brokerKind: brokerKind as CredentialBrokerKind,
      usage: boundedIdentifier(field(record, "usage")),
      expectationDigest: digestField(field(record, "expectationDigest")),
      replacesHandleId,
      secretMaterial,
    });
  } catch (error) {
    secretMaterial.fill(0);
    if (error instanceof SecretBrokerProtocolError) throw error;
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

function snapshotHandleReceipt(params: unknown): { handleId: string; receiptId: string } {
  try {
    const record = exactRecord(params, ["handleId", "receiptId"]);
    return {
      handleId: boundedIdentifier(field(record, "handleId")),
      receiptId: boundedIdentifier(field(record, "receiptId"), 2048),
    };
  } catch {
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

function snapshotHandleId(params: unknown): string {
  try {
    return boundedIdentifier(field(exactRecord(params, ["handleId"]), "handleId"));
  } catch {
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

function snapshotReceiptId(params: unknown): string {
  try {
    return boundedIdentifier(field(exactRecord(params, ["receiptId"]), "receiptId"), 2048);
  } catch {
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

function newHandleId(): string {
  // The 8B connection authority pins Credential Handle ids to `txch_v1_` + 64 hex
  // (enforced by both its validator and the SQLite CHECK), so the broker mints
  // handle ids in that exact shape for the receipt it returns.
  return `txch_v1_${randomBytes(32).toString("hex")}`;
}

function newReceiptId(): string {
  return `rcp_${randomBytes(32).toString("base64url")}`;
}
