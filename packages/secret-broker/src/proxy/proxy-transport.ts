import type { Readable, Writable } from "node:stream";
import {
  canonicalJson,
  exactRecord,
  field,
  SecretBrokerProtocolError,
  type SecretBrokerProtocolErrorCode,
} from "../protocol";
import {
  assertClosedProxyResponse,
  CREDENTIAL_PROXY_PROTOCOL_VERSION,
  isCredentialProxyMethod,
  type CredentialProxyMethod,
} from "./proxy-protocol";

const MAX_LINE_BYTES = 512 * 1024;
const MAX_BUFFERED_LINES = 16;

export interface CredentialProxyRequest {
  readonly version: typeof CREDENTIAL_PROXY_PROTOCOL_VERSION;
  readonly sequence: number;
  readonly method: CredentialProxyMethod;
  readonly params: unknown;
}

export type CredentialProxyRequestHandler = (request: CredentialProxyRequest) => Promise<unknown>;

export interface RunCredentialProxyConnectionOptions {
  readonly input: Readable;
  readonly output: Writable;
  readonly handler: CredentialProxyRequestHandler;
  readonly signal: AbortSignal;
}

/**
 * Serve one accepted Credential Proxy connection over NDJSON. Mirrors the
 * registration transport discipline: monotonic sequence, bounded lines, no
 * bearer token, and every outbound frame passes {@link assertClosedProxyResponse}
 * so a non-schema (potentially credential-bearing) field can never reach the
 * wire.
 */
export async function runCredentialProxyConnection(
  options: RunCredentialProxyConnectionOptions
): Promise<void> {
  let previousSequence = 0;
  for await (const line of boundedLines(options.input, options.signal)) {
    if (options.signal.aborted) break;
    let request: CredentialProxyRequest;
    try {
      request = snapshotRequest(JSON.parse(line));
      if (request.sequence <= previousSequence) throw new SecretBrokerProtocolError("conflict");
      previousSequence = request.sequence;
    } catch (error) {
      const code = error instanceof SecretBrokerProtocolError ? error.code : "invalid-request";
      await writeFailure(options.output, previousSequence + 1, code);
      continue;
    }
    await dispatch(options, request);
  }
}

async function dispatch(
  options: RunCredentialProxyConnectionOptions,
  request: CredentialProxyRequest
): Promise<void> {
  try {
    const result = await options.handler(request);
    assertClosedProxyResponse(result);
    await writeFrame(options.output, {
      version: CREDENTIAL_PROXY_PROTOCOL_VERSION,
      sequence: request.sequence,
      ok: true,
      result,
    });
  } catch (error) {
    const code = error instanceof SecretBrokerProtocolError ? error.code : "internal";
    await writeFailure(options.output, request.sequence, code);
  }
}

function snapshotRequest(value: unknown): CredentialProxyRequest {
  const record = exactRecord(value, ["version", "sequence", "method", "params"]);
  const sequence = field(record, "sequence");
  const method = field(record, "method");
  if (
    field(record, "version") !== CREDENTIAL_PROXY_PROTOCOL_VERSION ||
    !Number.isSafeInteger(sequence) ||
    (sequence as number) < 1 ||
    !isCredentialProxyMethod(method)
  ) {
    throw new SecretBrokerProtocolError("invalid-request");
  }
  return Object.freeze({
    version: CREDENTIAL_PROXY_PROTOCOL_VERSION,
    sequence: sequence as number,
    method,
    params: field(record, "params"),
  });
}

async function* boundedLines(input: Readable, signal: AbortSignal): AsyncGenerator<string> {
  let pending = Buffer.alloc(0);
  let bufferedLines = 0;
  try {
    for await (const unsafeChunk of input) {
      if (signal.aborted) return;
      const chunk = Buffer.isBuffer(unsafeChunk)
        ? unsafeChunk
        : Buffer.from(String(unsafeChunk), "utf8");
      pending = Buffer.concat([pending, chunk], pending.byteLength + chunk.byteLength);
      if (pending.byteLength > MAX_LINE_BYTES * MAX_BUFFERED_LINES) {
        throw new SecretBrokerProtocolError("invalid-request");
      }
      while (true) {
        const newline = pending.indexOf(0x0a);
        if (newline < 0) break;
        if (newline > MAX_LINE_BYTES) throw new SecretBrokerProtocolError("invalid-request");
        const lineBytes = pending.subarray(0, newline);
        pending = Buffer.from(pending.subarray(newline + 1));
        bufferedLines += 1;
        if (bufferedLines > MAX_BUFFERED_LINES) {
          throw new SecretBrokerProtocolError("invalid-request");
        }
        const line = lineBytes.toString("utf8");
        lineBytes.fill(0);
        if (line.length === 0) throw new SecretBrokerProtocolError("invalid-request");
        yield line;
        bufferedLines -= 1;
      }
      if (pending.byteLength > MAX_LINE_BYTES) {
        throw new SecretBrokerProtocolError("invalid-request");
      }
    }
  } finally {
    pending.fill(0);
  }
}

async function writeFailure(
  output: Writable,
  sequence: number,
  code: SecretBrokerProtocolErrorCode
): Promise<void> {
  await writeFrame(output, {
    version: CREDENTIAL_PROXY_PROTOCOL_VERSION,
    sequence,
    ok: false,
    error: Object.freeze({ code, message: new SecretBrokerProtocolError(code).message }),
  });
}

async function writeFrame(output: Writable, frame: object): Promise<void> {
  let line: string;
  try {
    line = `${canonicalJson(frame)}\n`;
  } catch {
    throw new SecretBrokerProtocolError("internal");
  }
  if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) {
    throw new SecretBrokerProtocolError("internal");
  }
  await new Promise<void>((resolve, reject) => {
    const accepted = output.write(line, "utf8", (error?: Error | null) => {
      if (error) reject(new SecretBrokerProtocolError("unavailable"));
      else if (accepted) resolve();
    });
    if (!accepted) output.once("drain", resolve);
  });
}
