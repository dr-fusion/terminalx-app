import { randomBytes } from "node:crypto";
import { connect, type Socket } from "node:net";
import { canonicalJson } from "../../../packages/secret-broker/src/protocol";
import {
  CREDENTIAL_PROXY_PROTOCOL_VERSION,
  snapshotProxyResult,
  type CredentialProxyMethod,
  type ProxyAuthoritySnapshot,
  type ProxyCallerFence,
  type ProxyResult,
} from "../../../packages/secret-broker/src/proxy/proxy-protocol";

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export class CredentialProxyClientError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`Credential Proxy request failed: ${code}`);
    this.code = code;
    this.name = "CredentialProxyClientError";
  }
}

export interface CredentialProxyExecuteInput {
  readonly operation: string;
  readonly authority: ProxyAuthoritySnapshot;
  /** Slice 8F caller fence. Hosted Runs pass a `hosted-assignment` fence. */
  readonly caller?: ProxyCallerFence;
  readonly params: unknown;
}

export interface CredentialProxyClient {
  execute(input: CredentialProxyExecuteInput): Promise<ProxyResult>;
}

export interface CreateCredentialProxyClientOptions {
  readonly socketPath: string;
  readonly requestTimeoutMs?: number;
}

/**
 * Main-process NDJSON client for the Credential Proxy socket. It sends a typed,
 * destination-scoped operation request and receives only a closed, schema-validated
 * result. No credential material is ever sent to or received from this seam — the
 * credential lives solely inside the broker process, and the result cannot carry
 * it by construction.
 */
export function createCredentialProxyClient(
  options: CreateCredentialProxyClientOptions
): CredentialProxyClient {
  const socketPath = options.socketPath;
  const timeoutMs = options.requestTimeoutMs ?? 30_000;
  if (typeof socketPath !== "string" || socketPath.length < 1) throw new TypeError();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    throw new TypeError();
  }

  return Object.freeze({
    async execute(input: CredentialProxyExecuteInput): Promise<ProxyResult> {
      const params = {
        operationId: `pxy_${randomBytes(24).toString("base64url")}`,
        operation: input.operation,
        authority: {
          provider: input.authority.provider,
          handleId: input.authority.handleId,
          handleGeneration: input.authority.handleGeneration,
          expectationDigest: input.authority.expectationDigest,
          installationId: input.authority.installationId,
          installationRevision: input.authority.installationRevision,
          bindingId: input.authority.bindingId,
          bindingRevision: input.authority.bindingRevision,
        },
        ...(input.caller ? { caller: input.caller } : {}),
        params: input.params,
      };
      const result = await request(socketPath, timeoutMs, "proxy.execute", params);
      return snapshotProxyResult(result);
    },
  });
}

async function request(
  socketPath: string,
  timeoutMs: number,
  method: CredentialProxyMethod,
  params: unknown
): Promise<unknown> {
  const frame = `${canonicalJson({
    version: CREDENTIAL_PROXY_PROTOCOL_VERSION,
    sequence: 1,
    method,
    params,
  })}\n`;
  return new Promise<unknown>((resolve, reject) => {
    const socket: Socket = connect(socketPath);
    let settled = false;
    let received = Buffer.alloc(0);
    const timer = setTimeout(
      () => finish(new CredentialProxyClientError("unavailable")),
      timeoutMs
    );
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
        finish(new CredentialProxyClientError("unavailable"));
        return;
      }
      const newline = received.indexOf(0x0a);
      if (newline < 0) return;
      try {
        finish(null, parseResponse(received.subarray(0, newline).toString("utf8")));
      } catch (error) {
        finish(error instanceof Error ? error : new CredentialProxyClientError("internal"));
      }
    });
    socket.once("error", () => finish(new CredentialProxyClientError("unavailable")));
    socket.once("close", () => finish(new CredentialProxyClientError("unavailable")));
  });
}

function parseResponse(line: string): unknown {
  const parsed = JSON.parse(line) as unknown;
  if (typeof parsed !== "object" || parsed === null) {
    throw new CredentialProxyClientError("internal");
  }
  const record = parsed as Record<string, unknown>;
  if (record.version !== CREDENTIAL_PROXY_PROTOCOL_VERSION) {
    throw new CredentialProxyClientError("internal");
  }
  if (record.ok === true) return record.result;
  const error = record.error as { code?: unknown } | undefined;
  throw new CredentialProxyClientError(
    error && typeof error.code === "string" ? error.code : "internal"
  );
}
