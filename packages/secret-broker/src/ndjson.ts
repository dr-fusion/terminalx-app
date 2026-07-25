import type { Readable, Writable } from "node:stream";
import {
  assertClosedResponse,
  canonicalJson,
  exactRecord,
  field,
  isSecretBrokerMethod,
  SECRET_BROKER_PROTOCOL_VERSION,
  SecretBrokerProtocolError,
  type SecretBrokerMethod,
  type SecretBrokerProtocolErrorCode,
} from "./protocol";

const MAX_LINE_BYTES = 256 * 1024;
const MAX_BUFFERED_LINES = 16;

export interface SecretBrokerRequest {
  readonly version: typeof SECRET_BROKER_PROTOCOL_VERSION;
  readonly sequence: number;
  readonly method: SecretBrokerMethod;
  readonly params: unknown;
}

/** Handles one validated request and returns a closed-schema result object. */
export type SecretBrokerRequestHandler = (request: SecretBrokerRequest) => Promise<unknown>;

export interface RunSecretBrokerConnectionOptions {
  readonly input: Readable;
  readonly output: Writable;
  readonly handler: SecretBrokerRequestHandler;
  readonly signal: AbortSignal;
}

/**
 * Serve one accepted connection over NDJSON. There is deliberately no bearer
 * token, no request logging, and no shutdown method reachable from the peer.
 * Every outbound frame passes {@link assertClosedResponse} so a non-schema
 * (potentially secret-bearing) field can never reach the wire.
 */
export async function runSecretBrokerConnection(
  options: RunSecretBrokerConnectionOptions
): Promise<void> {
  let previousSequence = 0;
  for await (const line of boundedLines(options.input, options.signal)) {
    if (options.signal.aborted) break;
    let request: SecretBrokerRequest;
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
  options: RunSecretBrokerConnectionOptions,
  request: SecretBrokerRequest
): Promise<void> {
  try {
    const result = await options.handler(request);
    assertClosedResponse(request.method, result);
    await writeFrame(options.output, {
      version: SECRET_BROKER_PROTOCOL_VERSION,
      sequence: request.sequence,
      ok: true,
      result,
    });
  } catch (error) {
    const code = error instanceof SecretBrokerProtocolError ? error.code : "internal";
    await writeFailure(options.output, request.sequence, code);
  }
}

function snapshotRequest(value: unknown): SecretBrokerRequest {
  const record = exactRecord(value, ["version", "sequence", "method", "params"]);
  const sequence = field(record, "sequence");
  const method = field(record, "method");
  if (
    field(record, "version") !== SECRET_BROKER_PROTOCOL_VERSION ||
    !Number.isSafeInteger(sequence) ||
    (sequence as number) < 1 ||
    !isSecretBrokerMethod(method)
  ) {
    throw new SecretBrokerProtocolError("invalid-request");
  }
  return Object.freeze({
    version: SECRET_BROKER_PROTOCOL_VERSION,
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
    version: SECRET_BROKER_PROTOCOL_VERSION,
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
