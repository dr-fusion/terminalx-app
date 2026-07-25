import { createHash, timingSafeEqual } from "node:crypto";
import { Agent, request as httpsRequest, type RequestOptions } from "node:https";
import { isIP } from "node:net";
import { checkServerIdentity, type DetailedPeerCertificate } from "node:tls";
import { TextDecoder, types as nodeTypes } from "node:util";
import {
  DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_REQUEST_BYTES,
  DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_RESPONSE_BYTES,
  DAYTONA_ASSIGNMENT_BOOTSTRAP_REQUEST_MEDIA_TYPE,
  DAYTONA_ASSIGNMENT_BOOTSTRAP_RESPONSE_MEDIA_TYPE,
} from "../../../packages/daytona-supervisor/src/assignment-bootstrap";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MAX_CREDENTIAL_BYTES = 4096;
const MAX_CA_BYTES = 1024 * 1024;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 10 * 60_000;

export type DaytonaAssignmentBootstrapTransportErrorCode =
  | "invalid-request"
  | "conflict"
  | "permission-denied"
  | "unavailable";

export class DaytonaAssignmentBootstrapTransportError extends Error {
  constructor(readonly code: DaytonaAssignmentBootstrapTransportErrorCode) {
    super("Daytona assignment bootstrap transport failed closed");
    this.name = "DaytonaAssignmentBootstrapTransportError";
  }
}

export interface DaytonaAssignmentBootstrapTransport {
  /** Takes ownership of `envelope` and always zeroes it. */
  install(providerSandboxId: string, envelope: Buffer, signal: AbortSignal): Promise<unknown>;
  close(): Promise<void>;
}

export interface CreateDaytonaAssignmentBootstrapTransportOptions {
  readonly runnerOrigin: string;
  readonly runnerCaPem: string;
  readonly runnerTlsSpkiSha256: string;
  /** Ownership transfers to this transport and is zeroed on close. */
  readonly runnerCredential: Uint8Array;
  readonly connectTimeoutMs?: number;
  readonly requestTimeoutMs?: number;
}

export function createDaytonaAssignmentBootstrapTransport(
  unsafeOptions: CreateDaytonaAssignmentBootstrapTransportOptions
): DaytonaAssignmentBootstrapTransport {
  return new HttpsDaytonaAssignmentBootstrapTransport(unsafeOptions);
}

class HttpsDaytonaAssignmentBootstrapTransport implements DaytonaAssignmentBootstrapTransport {
  private readonly options: CapturedOptions;
  private readonly agent: Agent;
  private closed = false;

  constructor(options: CreateDaytonaAssignmentBootstrapTransportOptions) {
    this.options = captureOptions(options);
    try {
      this.agent = new Agent({
        keepAlive: false,
        maxSockets: 16,
        maxFreeSockets: 0,
        timeout: this.options.connectTimeoutMs,
      });
    } catch (error) {
      this.options.credential.fill(0);
      throw error;
    }
  }

  async install(
    unsafeProviderSandboxId: string,
    envelope: Buffer,
    signal: AbortSignal
  ): Promise<unknown> {
    if (!Buffer.isBuffer(envelope) || nodeTypes.isProxy(envelope)) {
      transportFailure("invalid-request");
    }
    try {
      if (this.closed) transportFailure("unavailable");
      if (!(signal instanceof AbortSignal) || nodeTypes.isProxy(signal) || signal.aborted) {
        transportFailure("unavailable");
      }
      const providerSandboxId = sandboxId(unsafeProviderSandboxId);
      if (
        envelope.byteLength < 1 ||
        envelope.byteLength > DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_REQUEST_BYTES
      ) {
        transportFailure("invalid-request");
      }
      const controller = new AbortController();
      const abort = (): void => controller.abort();
      signal.addEventListener("abort", abort, { once: true });
      const timer = setTimeout(abort, this.options.requestTimeoutMs);
      timer.unref();
      try {
        const credential = decodeCredential(this.options.credential);
        const response = await sendRequest(
          this.options,
          this.agent,
          providerSandboxId,
          credential,
          envelope,
          controller.signal
        );
        if (
          response.statusCode !== 200 ||
          response.headers["content-type"] !== DAYTONA_ASSIGNMENT_BOOTSTRAP_RESPONSE_MEDIA_TYPE ||
          response.headers["content-encoding"] !== undefined ||
          response.headers.location !== undefined
        ) {
          const status = response.statusCode;
          response.destroy();
          if (status === 400) transportFailure("invalid-request");
          if (status === 409) transportFailure("conflict");
          if (status === 401 || status === 403) transportFailure("permission-denied");
          transportFailure("unavailable");
        }
        return await readExactInstalledJson(response, controller.signal);
      } catch (error) {
        if (error instanceof DaytonaAssignmentBootstrapTransportError) throw error;
        transportFailure("unavailable");
      } finally {
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        controller.abort();
      }
    } finally {
      envelope.fill(0);
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.options.credential.fill(0);
    this.agent.destroy();
  }
}

interface CapturedOptions {
  readonly origin: URL;
  readonly runnerCaPem: string;
  readonly runnerTlsSpkiSha256: string;
  readonly credential: Uint8Array;
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
}

function captureOptions(value: CreateDaytonaAssignmentBootstrapTransportOptions): CapturedOptions {
  let unsafeCredential: unknown;
  if (typeof value === "object" && value !== null && !nodeTypes.isProxy(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, "runnerCredential");
    if (descriptor && "value" in descriptor) unsafeCredential = descriptor.value;
  }
  let sourceCredential: Uint8Array | null = ownedCredential(unsafeCredential);
  let credential: Uint8Array | undefined;
  try {
    const record = optionRecord(value);
    unsafeCredential = optionField(record, "runnerCredential");
    sourceCredential = ownedCredential(unsafeCredential);
    const runnerOrigin = optionField(record, "runnerOrigin");
    let origin: URL;
    try {
      origin = new URL(typeof runnerOrigin === "string" ? runnerOrigin : "");
    } catch {
      throw new TypeError();
    }
    if (
      typeof runnerOrigin !== "string" ||
      origin.protocol !== "https:" ||
      origin.username !== "" ||
      origin.password !== "" ||
      origin.pathname !== "/" ||
      origin.search !== "" ||
      origin.hash !== "" ||
      origin.hostname.length === 0 ||
      origin.origin !== runnerOrigin.replace(/\/$/u, "")
    ) {
      throw new TypeError();
    }
    const runnerCaPem = optionField(record, "runnerCaPem");
    const runnerTlsSpkiSha256 = optionField(record, "runnerTlsSpkiSha256");
    if (
      typeof runnerCaPem !== "string" ||
      !runnerCaPem.startsWith("-----BEGIN CERTIFICATE-----\n") ||
      !runnerCaPem.endsWith("-----END CERTIFICATE-----\n") ||
      Buffer.byteLength(runnerCaPem, "utf8") > MAX_CA_BYTES ||
      typeof runnerTlsSpkiSha256 !== "string" ||
      !SHA256.test(runnerTlsSpkiSha256) ||
      sourceCredential === null ||
      sourceCredential.byteLength < 1 ||
      sourceCredential.byteLength > MAX_CREDENTIAL_BYTES
    ) {
      throw new TypeError();
    }
    credential = new Uint8Array(sourceCredential);
    decodeCredential(credential);
    return Object.freeze({
      origin,
      runnerCaPem,
      runnerTlsSpkiSha256,
      credential,
      connectTimeoutMs: boundedTimeout(optionField(record, "connectTimeoutMs") ?? 5_000),
      requestTimeoutMs: boundedTimeout(optionField(record, "requestTimeoutMs") ?? 30_000),
    });
  } catch (error) {
    credential?.fill(0);
    throw error;
  } finally {
    zeroCredential(sourceCredential);
  }
}

function optionRecord(value: unknown): Record<string, unknown> {
  const required = [
    "runnerOrigin",
    "runnerCaPem",
    "runnerTlsSpkiSha256",
    "runnerCredential",
  ] as const;
  const allowed = new Set([...required, "connectTimeoutMs", "requestTimeoutMs"]);
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new TypeError();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    required.some((name) => !keys.includes(name))
  ) {
    throw new TypeError();
  }
  for (const key of keys) optionField(value as Record<string, unknown>, key as string);
  return value as Record<string, unknown>;
}

function optionField(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (descriptor === undefined) return undefined;
  if (!descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function ownedCredential(value: unknown): Uint8Array | null {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return null;
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) return null;
  return value;
}

function zeroCredential(value: Uint8Array | null): void {
  if (value === null) return;
  try {
    Uint8Array.prototype.fill.call(value, 0);
  } catch {
    // A concurrently detached caller-owned view is already unusable.
  }
}

function sendRequest(
  options: CapturedOptions,
  agent: Agent,
  providerSandboxId: string,
  credential: string,
  envelope: Buffer,
  signal: AbortSignal
): Promise<import("node:http").IncomingMessage> {
  return new Promise((resolve, reject) => {
    const requestOptions: RequestOptions = {
      protocol: "https:",
      hostname: options.origin.hostname,
      port: options.origin.port || 443,
      method: "POST",
      path: `/sandboxes/${providerSandboxId}/terminalx-assignment-bootstrap`,
      agent,
      ca: options.runnerCaPem,
      ...(isIP(options.origin.hostname) === 0 ? { servername: options.origin.hostname } : {}),
      rejectUnauthorized: true,
      checkServerIdentity: (hostname, certificate) =>
        verifyServerIdentity(hostname, certificate, options.runnerTlsSpkiSha256),
      headers: {
        accept: DAYTONA_ASSIGNMENT_BOOTSTRAP_RESPONSE_MEDIA_TYPE,
        authorization: `Bearer ${credential}`,
        "cache-control": "no-store",
        "content-length": String(envelope.byteLength),
        "content-type": DAYTONA_ASSIGNMENT_BOOTSTRAP_REQUEST_MEDIA_TYPE,
      },
      signal,
    };
    let responseReceived = false;
    let writeComplete = false;
    let response: import("node:http").IncomingMessage | undefined;
    const finish = (): void => {
      if (responseReceived && writeComplete && response) resolve(response);
    };
    try {
      const outgoing = httpsRequest(requestOptions, (incoming) => {
        response = incoming;
        responseReceived = true;
        finish();
      });
      outgoing.once("error", () =>
        reject(new DaytonaAssignmentBootstrapTransportError("unavailable"))
      );
      outgoing.end(envelope, () => {
        writeComplete = true;
        finish();
      });
    } catch {
      reject(new DaytonaAssignmentBootstrapTransportError("unavailable"));
    }
  });
}

async function readExactInstalledJson(
  response: import("node:http").IncomingMessage,
  signal: AbortSignal
): Promise<unknown> {
  const declaredLength = response.headers["content-length"];
  if (
    declaredLength !== undefined &&
    (!/^[0-9]+$/u.test(declaredLength) ||
      Number(declaredLength) < 2 ||
      Number(declaredLength) > DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_RESPONSE_BYTES)
  ) {
    response.destroy();
    transportFailure("unavailable");
  }
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    for await (const unsafeChunk of response) {
      if (signal.aborted) transportFailure("unavailable");
      const chunk = Buffer.isBuffer(unsafeChunk) ? unsafeChunk : Buffer.from(unsafeChunk);
      length += chunk.byteLength;
      if (length > DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_RESPONSE_BYTES) {
        transportFailure("unavailable");
      }
      chunks.push(Buffer.from(chunk));
    }
    const body = Buffer.concat(chunks, length);
    try {
      if (body.byteLength < 2 || body[0] !== 0x7b || body[body.byteLength - 1] !== 0x7d) {
        transportFailure("unavailable");
      }
      const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
      const parsed = snapshotRuntimeSupervisorPortableData(JSON.parse(text));
      if (canonicalRuntimeJson(parsed) !== text) transportFailure("unavailable");
      return parsed;
    } finally {
      body.fill(0);
    }
  } catch (error) {
    response.destroy();
    if (error instanceof DaytonaAssignmentBootstrapTransportError) throw error;
    transportFailure("unavailable");
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function verifyServerIdentity(
  hostname: string,
  certificate: DetailedPeerCertificate,
  expectedSpkiSha256: string
): Error | undefined {
  const standard = checkServerIdentity(hostname, certificate);
  if (standard) return standard;
  try {
    if (!Buffer.isBuffer(certificate.pubkey) || certificate.pubkey.byteLength < 1) {
      return new Error("TLS peer key unavailable");
    }
    const actual = createHash("sha256").update(certificate.pubkey).digest();
    const expected = Buffer.from(expectedSpkiSha256, "hex");
    if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) {
      return new Error("TLS peer key mismatch");
    }
    return undefined;
  } catch {
    return new Error("TLS peer verification failed");
  }
}

function decodeCredential(value: Uint8Array): string {
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(value);
  if (decoded.length < 1 || decoded.trim() !== decoded || /[\u0000-\u0020\u007f]/u.test(decoded)) {
    throw new TypeError();
  }
  return decoded;
}

function sandboxId(value: unknown): string {
  if (typeof value !== "string" || !UUID_V4.test(value)) transportFailure("invalid-request");
  return value;
}

function boundedTimeout(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < MIN_TIMEOUT_MS ||
    (value as number) > MAX_TIMEOUT_MS
  ) {
    throw new TypeError();
  }
  return value as number;
}

function transportFailure(code: DaytonaAssignmentBootstrapTransportErrorCode): never {
  throw new DaytonaAssignmentBootstrapTransportError(code);
}
