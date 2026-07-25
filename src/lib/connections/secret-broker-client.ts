import { randomBytes } from "node:crypto";
import { connect, type Socket } from "node:net";
import {
  canonicalJson,
  SECRET_BROKER_PROTOCOL_VERSION,
  type SecretBrokerMethod,
} from "../../../packages/secret-broker/src/protocol";
import {
  snapshotReceipt,
  type SecretBrokerReceipt,
} from "../../../packages/secret-broker/src/receipt-schema";
import { secretBrokerExpectationDigest } from "./secret-broker-shared";
import type { CredentialHandleRegistrationExpectation } from "./authority";

const MAX_RESPONSE_BYTES = 256 * 1024;

export class SecretBrokerClientError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`Secret Broker request failed: ${code}`);
    this.code = code;
    this.name = "SecretBrokerClientError";
  }
}

export interface SecretBrokerClient {
  prepareRegistration(
    expectation: Readonly<CredentialHandleRegistrationExpectation>,
    secretMaterial: Buffer
  ): Promise<SecretBrokerReceipt>;
  finalizeRegistration(handleId: string, receiptId: string): Promise<void>;
  abortRegistration(receiptId: string): Promise<void>;
  prepareRotation(
    expectation: Readonly<CredentialHandleRegistrationExpectation>,
    secretMaterial: Buffer
  ): Promise<SecretBrokerReceipt>;
  finalizeRotation(handleId: string, receiptId: string): Promise<void>;
  abortRotation(receiptId: string): Promise<void>;
  revokeHandle(handleId: string): Promise<void>;
  handleStatus(handleId: string): Promise<{ handleId: string; status: string }>;
  health(): Promise<{ pendingRegistrations: number }>;
}

export interface CreateSecretBrokerClientOptions {
  readonly socketPath: string;
  readonly requestTimeoutMs?: number;
}

/**
 * Main-process NDJSON client for the Secret Broker socket. It never receives or
 * handles credential material back from the broker — `prepare` sends secret
 * material one way and receives only a signed receipt.
 */
export function createSecretBrokerClient(
  options: CreateSecretBrokerClientOptions
): SecretBrokerClient {
  const socketPath = options.socketPath;
  const timeoutMs = options.requestTimeoutMs ?? 10_000;
  if (typeof socketPath !== "string" || socketPath.length < 1) throw new TypeError();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new TypeError();
  }

  async function call(method: SecretBrokerMethod, params: unknown): Promise<unknown> {
    return request(socketPath, timeoutMs, method, params);
  }

  async function prepare(
    method: "registration.prepare" | "rotation.prepare",
    expectation: Readonly<CredentialHandleRegistrationExpectation>,
    secretMaterial: Buffer
  ): Promise<SecretBrokerReceipt> {
    if (!Buffer.isBuffer(secretMaterial)) throw new TypeError();
    const expectationDigest = secretBrokerExpectationDigest(expectation);
    const params = {
      operationId: `op_${randomBytes(24).toString("base64url")}`,
      provider: expectation.provider,
      brokerKind: expectation.brokerKind,
      usage: expectation.usage,
      expectationDigest,
      replaces: expectation.replaces === null ? null : { handleId: expectation.replaces.handleId },
      secretMaterial: secretMaterial.toString("base64"),
    };
    secretMaterial.fill(0);
    const result = await call(method, params);
    if (typeof result !== "object" || result === null || !("receipt" in result)) {
      throw new SecretBrokerClientError("internal");
    }
    return snapshotReceipt((result as { receipt: unknown }).receipt);
  }

  const client: SecretBrokerClient = {
    prepareRegistration: (expectation, secretMaterial) =>
      prepare("registration.prepare", expectation, secretMaterial),
    prepareRotation: (expectation, secretMaterial) =>
      prepare("rotation.prepare", expectation, secretMaterial),
    async finalizeRegistration(handleId, receiptId) {
      await call("registration.finalize", { handleId, receiptId });
    },
    async abortRegistration(receiptId) {
      await call("registration.abort", { receiptId });
    },
    async finalizeRotation(handleId, receiptId) {
      await call("rotation.finalize", { handleId, receiptId });
    },
    async abortRotation(receiptId) {
      await call("rotation.abort", { receiptId });
    },
    async revokeHandle(handleId) {
      await call("handle.revoke", { handleId });
    },
    async handleStatus(handleId) {
      const result = (await call("handle.status", { handleId })) as {
        handleId: string;
        status: string;
      };
      return { handleId: result.handleId, status: result.status };
    },
    async health() {
      const result = (await call("broker.health", {})) as { pendingRegistrations: number };
      return { pendingRegistrations: result.pendingRegistrations };
    },
  };
  return Object.freeze(client);
}

async function request(
  socketPath: string,
  timeoutMs: number,
  method: SecretBrokerMethod,
  params: unknown
): Promise<unknown> {
  const frame = `${canonicalJson({
    version: SECRET_BROKER_PROTOCOL_VERSION,
    sequence: 1,
    method,
    params,
  })}\n`;
  return new Promise<unknown>((resolve, reject) => {
    const socket: Socket = connect(socketPath);
    let settled = false;
    let received = Buffer.alloc(0);
    const timer = setTimeout(() => finish(new SecretBrokerClientError("unavailable")), timeoutMs);
    timer.unref();

    const finish = (error: Error | null, value?: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };

    socket.once("connect", () => {
      socket.write(frame, "utf8");
    });
    socket.on("data", (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      if (received.byteLength > MAX_RESPONSE_BYTES) {
        finish(new SecretBrokerClientError("unavailable"));
        return;
      }
      const newline = received.indexOf(0x0a);
      if (newline < 0) return;
      try {
        finish(null, parseResponse(received.subarray(0, newline).toString("utf8")));
      } catch (error) {
        finish(error instanceof Error ? error : new SecretBrokerClientError("internal"));
      }
    });
    socket.once("error", () => finish(new SecretBrokerClientError("unavailable")));
    socket.once("close", () => finish(new SecretBrokerClientError("unavailable")));
  });
}

function parseResponse(line: string): unknown {
  const parsed = JSON.parse(line) as unknown;
  if (typeof parsed !== "object" || parsed === null) throw new SecretBrokerClientError("internal");
  const record = parsed as Record<string, unknown>;
  if (record.version !== SECRET_BROKER_PROTOCOL_VERSION) {
    throw new SecretBrokerClientError("internal");
  }
  if (record.ok === true) return record.result;
  const error = record.error as { code?: unknown } | undefined;
  throw new SecretBrokerClientError(
    error && typeof error.code === "string" ? error.code : "internal"
  );
}
