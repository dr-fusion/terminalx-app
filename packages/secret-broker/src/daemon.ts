import { readFileSync } from "node:fs";
import { createSecretBroker, type SecretBrokerAuditEvent } from "./broker";
import { establishBrokerRoot } from "./broker-root";
import { openSecretBrokerStateStore } from "./state-store";
import { createOauthEnvelopeAdapter } from "./adapters/oauth-envelope";
import {
  createOnePasswordConnectAdapter,
  createOnePasswordConnectHttpClient,
} from "./adapters/onepassword-connect";
import type { SecretManagerAdapter } from "./adapters";
import { createPinnedPeerCredentialVerifier } from "./peer-credentials";
import { startSecretBrokerUnixServer } from "./unix-socket-transport";
import { exactRecord, field, SecretBrokerProtocolError } from "./protocol";
import { openAtRest } from "./at-rest";
import { openProxyAccountingStore } from "./proxy/accounting-store";
import { createFetchProxyNetworkClient } from "./proxy/network-client";
import { createCredentialProxy, type CredentialProxyAuditEvent } from "./proxy/credential-proxy";
import { runCredentialProxyConnection } from "./proxy/proxy-transport";
import { openWebhookSecretStore, type WebhookSecretStore } from "./exchange/webhook-secret-store";
import { createFetchProviderExchangeClient } from "./exchange/provider-exchange-client";

interface ProxyBootstrapConfig {
  readonly enabled: boolean;
  /**
   * Optional per-host request-origin overrides. Used to point a hermetic test or
   * a private egress gateway at a loopback origin without weakening the operation
   * host allowlist (the operation still declares `api.telegram.org`/`slack.com`).
   */
  readonly originOverrides?: Readonly<Record<string, string>>;
  readonly requestTimeoutMs?: number;
}

interface ExchangeBootstrapConfig {
  readonly enabled: boolean;
  /** Per-host request-origin overrides for hermetic tests (slack.com/api.telegram.org). */
  readonly originOverrides?: Readonly<Record<string, string>>;
  /** Reviewed Slack app OAuth client id/secret env var names. */
  readonly slackClientIdEnv?: string;
  readonly slackClientSecretEnv?: string;
  readonly requestTimeoutMs?: number;
}

interface BootstrapConfig {
  readonly rootDir: string;
  readonly expectedOwnerUid?: number;
  readonly expectedParentPid?: number;
  readonly peercred: { readonly executableFile: string; readonly executableSha256: string };
  readonly adapters: {
    readonly oauthEnvelope?: boolean;
    readonly onePasswordConnect?: {
      readonly connectHost: string;
      readonly tokenEnv: string;
    };
  };
  readonly receiptTtlMs?: number;
  readonly reconcileIntervalMs?: number;
  readonly proxy?: ProxyBootstrapConfig;
  readonly exchange?: ExchangeBootstrapConfig;
}

/** Structured, secret-free stderr audit line. Never logs receipts or keys. */
function log(
  level: "info" | "warn" | "error",
  event: string,
  detail?: Record<string, unknown>
): void {
  process.stderr.write(`${JSON.stringify({ level, event, ...detail })}\n`);
}

export async function runSecretBrokerDaemon(configPath: string): Promise<() => Promise<void>> {
  const config = readBootstrapConfig(configPath);
  const root = establishBrokerRoot({
    rootDir: config.rootDir,
    expectedOwnerUid: config.expectedOwnerUid,
  });
  const store = openSecretBrokerStateStore({ databasePath: root.databasePath });
  const adapters = buildAdapters(config, root.atRestKey);
  const audit = (event: SecretBrokerAuditEvent): void =>
    log("info", "broker.audit", {
      action: event.action,
      handleId: event.handleId,
      status: event.status,
    });

  // Slice 8E provider credential-acquisition, composed only when enabled. It
  // requires the oauth-envelope adapter (the acquired token is sealed as one).
  let webhookSecretStore: WebhookSecretStore | null = null;
  let providerExchangeClient: ReturnType<typeof createFetchProviderExchangeClient> | undefined;
  if (config.exchange && config.exchange.enabled) {
    if (!config.adapters.oauthEnvelope) throw new SecretBrokerProtocolError("not-ready");
    webhookSecretStore = openWebhookSecretStore({
      databasePath: root.webhookSecretsPath,
      atRestKey: root.atRestKey,
    });
    const originOverrides = config.exchange.originOverrides ?? {};
    providerExchangeClient = createFetchProviderExchangeClient({
      resolveOrigin: (host: string) => originOverrides[host] ?? `https://${host}`,
      ...(config.exchange.slackClientIdEnv
        ? { slackClientId: process.env[config.exchange.slackClientIdEnv] }
        : {}),
      ...(config.exchange.slackClientSecretEnv
        ? { slackClientSecret: process.env[config.exchange.slackClientSecretEnv] }
        : {}),
      ...(config.exchange.requestTimeoutMs
        ? { requestTimeoutMs: config.exchange.requestTimeoutMs }
        : {}),
    });
  }

  const broker = createSecretBroker({
    root,
    store,
    adapters,
    receiptTtlMs: config.receiptTtlMs,
    audit,
    ...(providerExchangeClient && webhookSecretStore
      ? { providerExchangeClient, webhookSecretStore }
      : {}),
  });

  const verifyPeerCredentials = createPinnedPeerCredentialVerifier({
    executableFile: config.peercred.executableFile,
    executableSha256: config.peercred.executableSha256,
    expectedOwnerUid: config.expectedOwnerUid,
  });

  const server = await startSecretBrokerUnixServer({
    socketPath: root.socketPath,
    expectedOwnerUid: config.expectedOwnerUid,
    expectedParentPid: config.expectedParentPid,
    verifyPeerCredentials,
    handler: broker.handle,
    onDenial: (denial) =>
      log("warn", "broker.denial", { reason: denial.reason, code: denial.code }),
  });

  const proxyRuntime =
    config.proxy && config.proxy.enabled
      ? await startCredentialProxy(config.proxy, root, store, verifyPeerCredentials, config)
      : null;

  broker.reconcile();
  const reconcileIntervalMs = config.reconcileIntervalMs ?? 30_000;
  const timer = setInterval(() => {
    try {
      const { reaped } = broker.reconcile();
      if (reaped > 0) log("info", "broker.reconcile", { reaped });
    } catch {
      log("error", "broker.reconcile-failed");
    }
  }, reconcileIntervalMs);
  timer.unref();

  log("info", "broker.ready", {
    brokerInstanceId: root.brokerInstanceId,
    brokerEpoch: root.brokerEpoch,
    signingKeyId: root.signingKeyId,
    socketPath: root.socketPath,
    proxySocketPath: proxyRuntime ? root.proxySocketPath : undefined,
  });

  let closed = false;
  return async (): Promise<void> => {
    if (closed) return;
    closed = true;
    clearInterval(timer);
    await server.close();
    if (proxyRuntime) await proxyRuntime.close();
    if (webhookSecretStore) webhookSecretStore.close();
    store.close();
  };
}

/**
 * Compose the Credential Proxy (Slice 8D) inside this same non-exporting broker
 * process and serve it on a sibling socket in the 0700 broker root under the
 * same peer-credential admission. The credential value never leaves this
 * process: the proxy reads broker-private sealed material and reveals it here to
 * attach an outbound Authorization header.
 */
async function startCredentialProxy(
  proxyConfig: ProxyBootstrapConfig,
  root: Awaited<ReturnType<typeof establishBrokerRoot>>,
  store: ReturnType<typeof openSecretBrokerStateStore>,
  verifyPeerCredentials: ReturnType<typeof createPinnedPeerCredentialVerifier>,
  config: BootstrapConfig
): Promise<{ close(): Promise<void> }> {
  const accounting = openProxyAccountingStore({ databasePath: root.proxyAccountingPath });
  const network = createFetchProxyNetworkClient();
  const originOverrides = proxyConfig.originOverrides ?? {};
  const proxy = createCredentialProxy({
    store,
    accounting,
    network,
    requestTimeoutMs: proxyConfig.requestTimeoutMs,
    resolveOrigin: (host: string) => originOverrides[host] ?? `https://${host}`,
    resolveCredential: (brokerKind: string, storedMaterial: Buffer): Buffer | null => {
      // Only broker-locally sealed OAuth material is usable for a request; an
      // external reference (onepassword-connect) is not resolvable for use in 8D.
      if (brokerKind !== "oauth-envelope") return null;
      return openAtRest(storedMaterial, root.atRestKey);
    },
    audit: (event: CredentialProxyAuditEvent): void =>
      log("info", "proxy.audit", {
        operation: event.operation,
        resultClass: event.resultClass,
        errorCode: event.errorCode,
        ambiguous: event.ambiguous,
        authoritySnapshotDigest: event.authoritySnapshotDigest,
      }),
  });

  const proxyServer = await startSecretBrokerUnixServer({
    socketPath: root.proxySocketPath,
    expectedOwnerUid: config.expectedOwnerUid,
    expectedParentPid: config.expectedParentPid,
    verifyPeerCredentials,
    runConnection: ({ input, output, signal }) =>
      runCredentialProxyConnection({ input, output, signal, handler: proxy.handle }),
    onDenial: (denial) => log("warn", "proxy.denial", { reason: denial.reason, code: denial.code }),
  });

  return {
    async close(): Promise<void> {
      await proxyServer.close();
      accounting.close();
    },
  };
}

function buildAdapters(
  config: BootstrapConfig,
  atRestKey: Buffer
): Readonly<Record<string, SecretManagerAdapter>> {
  const adapters: Record<string, SecretManagerAdapter> = {};
  if (config.adapters.oauthEnvelope) {
    adapters["oauth-envelope"] = createOauthEnvelopeAdapter(atRestKey);
  }
  if (config.adapters.onePasswordConnect) {
    const token = process.env[config.adapters.onePasswordConnect.tokenEnv];
    if (typeof token !== "string" || token.length < 1) {
      throw new SecretBrokerProtocolError("not-ready");
    }
    adapters["onepassword-connect"] = createOnePasswordConnectAdapter({
      client: createOnePasswordConnectHttpClient({
        connectHost: config.adapters.onePasswordConnect.connectHost,
        token,
      }),
    });
  }
  if (Object.keys(adapters).length === 0) throw new SecretBrokerProtocolError("not-ready");
  return Object.freeze(adapters);
}

function readBootstrapConfig(configPath: string): BootstrapConfig {
  if (typeof configPath !== "string" || configPath.length < 1) {
    throw new SecretBrokerProtocolError("not-ready");
  }
  const parsed = JSON.parse(readFileSync(configPath, "utf8")) as unknown;
  // The Credential Proxy section is optional and additive: an 8C config without
  // it stays valid and simply leaves the proxy closed. Unknown keys are still
  // rejected below.
  const record = requireBootstrapKeys(parsed, [
    "rootDir",
    "expectedOwnerUid",
    "expectedParentPid",
    "peercred",
    "adapters",
    "receiptTtlMs",
    "reconcileIntervalMs",
  ]);
  const peercred = exactRecord(field(record, "peercred"), ["executableFile", "executableSha256"]);
  const adapters = field(record, "adapters");
  if (typeof adapters !== "object" || adapters === null) throw new TypeError();
  const rootDir = field(record, "rootDir");
  const executableFile = field(peercred, "executableFile");
  const executableSha256 = field(peercred, "executableSha256");
  if (
    typeof rootDir !== "string" ||
    typeof executableFile !== "string" ||
    typeof executableSha256 !== "string"
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    rootDir,
    expectedOwnerUid: optionalUid(field(record, "expectedOwnerUid")),
    expectedParentPid: optionalPositive(field(record, "expectedParentPid")),
    peercred: Object.freeze({ executableFile, executableSha256 }),
    adapters: adapters as BootstrapConfig["adapters"],
    receiptTtlMs: optionalPositive(field(record, "receiptTtlMs")),
    reconcileIntervalMs: optionalPositive(field(record, "reconcileIntervalMs")),
    proxy: parseProxyConfig(record["proxy"]),
    exchange: parseExchangeConfig(record["exchange"]),
  });
}

function parseExchangeConfig(value: unknown): ExchangeBootstrapConfig | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) throw new TypeError();
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new TypeError();
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "enabled",
    "originOverrides",
    "slackClientIdEnv",
    "slackClientSecretEnv",
    "requestTimeoutMs",
  ]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new TypeError();
  }
  const enabled = record.enabled;
  if (typeof enabled !== "boolean") throw new TypeError();
  const overridesRaw = record.originOverrides;
  let originOverrides: Record<string, string> | undefined;
  if (overridesRaw !== undefined && overridesRaw !== null) {
    if (
      typeof overridesRaw !== "object" ||
      Array.isArray(overridesRaw) ||
      Object.getPrototypeOf(overridesRaw) !== Object.prototype
    ) {
      throw new TypeError();
    }
    originOverrides = {};
    for (const [key, origin] of Object.entries(overridesRaw as Record<string, unknown>)) {
      if (typeof origin !== "string" || origin.length < 1) throw new TypeError();
      originOverrides[key] = origin;
    }
  }
  return Object.freeze({
    enabled,
    originOverrides: originOverrides ? Object.freeze(originOverrides) : undefined,
    slackClientIdEnv: optionalString(record.slackClientIdEnv),
    slackClientSecretEnv: optionalString(record.slackClientSecretEnv),
    requestTimeoutMs: optionalPositive(record.requestTimeoutMs),
  });
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || value.length < 1) throw new TypeError();
  return value;
}

/**
 * Accept a plain object that contains every required key and, optionally, the
 * additive `proxy` key. Any other key is rejected, preserving strictness.
 */
function requireBootstrapKeys(
  value: unknown,
  required: readonly string[]
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError();
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new TypeError();
  }
  const allowed = new Set([...required, "proxy", "exchange"]);
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new TypeError();
  }
  for (const key of required) {
    if (!(key in record)) throw new TypeError();
  }
  return record;
}

function parseProxyConfig(value: unknown): ProxyBootstrapConfig | undefined {
  if (value === undefined || value === null) return undefined;
  const record = exactRecord(value, ["enabled", "originOverrides", "requestTimeoutMs"]);
  const enabled = field(record, "enabled");
  if (typeof enabled !== "boolean") throw new TypeError();
  const overridesRaw = field(record, "originOverrides");
  let originOverrides: Record<string, string> | undefined;
  if (overridesRaw !== undefined && overridesRaw !== null) {
    if (
      typeof overridesRaw !== "object" ||
      Array.isArray(overridesRaw) ||
      Object.getPrototypeOf(overridesRaw) !== Object.prototype
    ) {
      throw new TypeError();
    }
    originOverrides = {};
    for (const [key, origin] of Object.entries(overridesRaw as Record<string, unknown>)) {
      if (typeof origin !== "string" || origin.length < 1) throw new TypeError();
      originOverrides[key] = origin;
    }
  }
  return Object.freeze({
    enabled,
    originOverrides: originOverrides ? Object.freeze(originOverrides) : undefined,
    requestTimeoutMs: optionalPositive(field(record, "requestTimeoutMs")),
  });
}

function optionalUid(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError();
  return value as number;
}

function optionalPositive(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TypeError();
  return value as number;
}

if (require.main === module) {
  const configPath = process.argv[2];
  runSecretBrokerDaemon(configPath ?? "")
    .then((close) => {
      const shutdown = (): void => {
        void close().then(
          () => process.exit(0),
          () => process.exit(1)
        );
      };
      process.once("SIGTERM", shutdown);
      process.once("SIGINT", shutdown);
    })
    .catch((error) => {
      const code = error instanceof SecretBrokerProtocolError ? error.code : "internal";
      log("error", "broker.start-failed", { code });
      process.exit(1);
    });
}
