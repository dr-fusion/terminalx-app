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
  const broker = createSecretBroker({
    root,
    store,
    adapters,
    receiptTtlMs: config.receiptTtlMs,
    audit,
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
  });

  let closed = false;
  return async (): Promise<void> => {
    if (closed) return;
    closed = true;
    clearInterval(timer);
    await server.close();
    store.close();
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
  const record = exactRecord(parsed, [
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
