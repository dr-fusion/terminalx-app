import { boundedIdentifier, exactRecord, field, SecretBrokerProtocolError } from "../protocol";
import type { PreparedSecret, SecretManagerAdapter } from "./index";

export interface OnePasswordItemRef {
  readonly vaultId: string;
  readonly itemId: string;
}

/**
 * The narrow, non-exporting client the adapter is allowed to use. It confirms an
 * item is resolvable and never returns the item's secret fields. Network I/O
 * happens only here, inside the broker process.
 */
export interface OnePasswordConnectClient {
  resolves(ref: OnePasswordItemRef, signal: AbortSignal): Promise<boolean>;
}

export interface CreateOnePasswordConnectAdapterOptions {
  readonly client: OnePasswordConnectClient;
  readonly requestTimeoutMs?: number;
}

const REFERENCE_SCHEMA = 1 as const;

/**
 * References items in an external 1Password Connect server. TerminalX persists
 * only the opaque {vaultId, itemId} reference; the secret itself stays in
 * 1Password. If the reference cannot be resolved because of a network fault, the
 * adapter fails closed with a retryable `unavailable` error rather than
 * registering an unverifiable handle.
 */
export function createOnePasswordConnectAdapter(
  options: CreateOnePasswordConnectAdapterOptions
): SecretManagerAdapter {
  if (
    typeof options !== "object" ||
    options === null ||
    typeof options.client !== "object" ||
    options.client === null ||
    typeof options.client.resolves !== "function"
  ) {
    throw new TypeError();
  }
  const timeoutMs = options.requestTimeoutMs ?? 5000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new TypeError();
  }
  return Object.freeze({
    kind: "onepassword-connect" as const,
    async prepare(secretMaterial: Buffer): Promise<PreparedSecret> {
      const ref = decodeItemRef(secretMaterial);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      timeout.unref?.();
      let resolved: boolean;
      try {
        resolved = await options.client.resolves(ref, controller.signal);
      } catch {
        // A transport fault is retryable; do not register an unverifiable handle.
        throw new SecretBrokerProtocolError("unavailable");
      } finally {
        clearTimeout(timeout);
      }
      if (resolved !== true) throw new SecretBrokerProtocolError("invalid-request");
      const material = Buffer.from(
        JSON.stringify({ schema: REFERENCE_SCHEMA, vaultId: ref.vaultId, itemId: ref.itemId }),
        "utf8"
      );
      return Object.freeze({ material });
    },
    async destroy(material: Buffer): Promise<void> {
      // TerminalX does not own the external 1Password item lifecycle; only the
      // local reference row is removed. Zero any copy handed to us.
      if (Buffer.isBuffer(material)) material.fill(0);
    },
  });
}

function decodeItemRef(secretMaterial: Buffer): OnePasswordItemRef {
  if (!Buffer.isBuffer(secretMaterial) || secretMaterial.byteLength > 8192) {
    if (Buffer.isBuffer(secretMaterial)) secretMaterial.fill(0);
    throw new SecretBrokerProtocolError("invalid-request");
  }
  try {
    const record = exactRecord(JSON.parse(secretMaterial.toString("utf8")), [
      "schema",
      "vaultId",
      "itemId",
    ]);
    if (field(record, "schema") !== REFERENCE_SCHEMA) throw new TypeError();
    return Object.freeze({
      vaultId: boundedIdentifier(field(record, "vaultId")),
      itemId: boundedIdentifier(field(record, "itemId")),
    });
  } catch {
    throw new SecretBrokerProtocolError("invalid-request");
  } finally {
    secretMaterial.fill(0);
  }
}

export interface CreateOnePasswordConnectHttpClientOptions {
  /** e.g. https://connect.example.internal */
  readonly connectHost: string;
  /** Connect API token; held only in the broker process, never logged. */
  readonly token: string;
  readonly fetchImpl?: typeof fetch;
}

/**
 * The shipped real client. It performs a single authenticated existence check
 * and discards the response body so no secret field is ever read into the
 * adapter. Tests inject a fake `OnePasswordConnectClient` instead.
 */
export function createOnePasswordConnectHttpClient(
  options: CreateOnePasswordConnectHttpClientOptions
): OnePasswordConnectClient {
  if (
    typeof options !== "object" ||
    options === null ||
    typeof options.token !== "string" ||
    options.token.length < 1
  ) {
    throw new TypeError();
  }
  const base = new URL(options.connectHost);
  if (base.protocol !== "https:" && base.protocol !== "http:") throw new TypeError();
  const doFetch = options.fetchImpl ?? fetch;
  const token = options.token;
  return Object.freeze({
    async resolves(ref: OnePasswordItemRef, signal: AbortSignal): Promise<boolean> {
      const url = new URL(
        `/v1/vaults/${encodeURIComponent(ref.vaultId)}/items/${encodeURIComponent(ref.itemId)}`,
        base
      );
      const response = await doFetch(url, {
        method: "GET",
        headers: { authorization: `Bearer ${token}`, accept: "application/json" },
        signal,
      });
      // Drain and discard the body without parsing secret fields.
      await response.arrayBuffer().catch(() => undefined);
      return response.status === 200;
    },
  });
}
