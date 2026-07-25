import type { Readable, Writable } from "node:stream";
import { types as nodeTypes } from "node:util";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import type {
  DaytonaSupervisorCommandRequest,
  DaytonaSupervisorFollowRequest,
  DaytonaSupervisorIsolationRequest,
  PinnedDaytonaSupervisorTransport,
} from "../../../src/lib/runtime/daytona-hosted-control-plane";
import {
  DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
  DaytonaSupervisorProtocolError,
  type DaytonaSupervisorProtocolErrorCode,
} from "./supervisor";

const MAX_LINE_BYTES = 1024 * 1024;
const MAX_BUFFERED_LINES = 32;

type Method = "isolation.attest" | "command.execute" | "observations.follow";

interface ProtocolRequest {
  readonly version: typeof DAYTONA_SUPERVISOR_PROTOCOL_VERSION;
  readonly sequence: number;
  readonly method: Method;
  readonly params: unknown;
}

export interface RunDaytonaSupervisorNdjsonOptions {
  readonly supervisor: PinnedDaytonaSupervisorTransport;
  readonly input: Readable;
  readonly output: Writable;
  readonly signal: AbortSignal;
}

/**
 * Serve the private inherited stdio channel. There is deliberately no network
 * listener, bearer token, logging of requests, or shutdown method available to
 * the agent-facing peer.
 */
export async function runDaytonaSupervisorNdjson(
  unsafeOptions: RunDaytonaSupervisorNdjsonOptions
): Promise<void> {
  const options = captureOptions(unsafeOptions);
  let previousSequence = 0;
  try {
    for await (const line of boundedLines(options.input, options.signal)) {
      if (options.signal.aborted) break;
      let request: ProtocolRequest;
      try {
        request = snapshotRequest(JSON.parse(line));
        if (request.sequence <= previousSequence) {
          throw new DaytonaSupervisorProtocolError("conflict");
        }
        previousSequence = request.sequence;
      } catch (error) {
        if (error instanceof DaytonaSupervisorProtocolError) {
          await writeFailure(options.output, previousSequence + 1, error);
          continue;
        }
        await writeFailure(
          options.output,
          previousSequence + 1,
          new DaytonaSupervisorProtocolError("invalid-request")
        );
        continue;
      }
      await dispatch(options, request);
    }
  } finally {
    await options.supervisor.close().catch(() => undefined);
  }
}

async function dispatch(options: CapturedOptions, request: ProtocolRequest): Promise<void> {
  try {
    if (request.method === "isolation.attest") {
      const result = await options.supervisor.attestIsolation(
        request.params as DaytonaSupervisorIsolationRequest,
        options.signal
      );
      await writeSuccess(options.output, request.sequence, result);
      return;
    }
    if (request.method === "command.execute") {
      const result = await options.supervisor.executeAuthenticated(
        request.params as DaytonaSupervisorCommandRequest,
        options.signal
      );
      await writeSuccess(options.output, request.sequence, result);
      return;
    }
    const stream = options.supervisor.followSigned(
      request.params as DaytonaSupervisorFollowRequest,
      options.signal
    );
    for await (const item of stream) {
      await writeFrame(options.output, {
        version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
        sequence: request.sequence,
        ok: true,
        stream: "item",
        item: snapshotRuntimeSupervisorPortableData(item),
      });
    }
    await writeFrame(options.output, {
      version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
      sequence: request.sequence,
      ok: true,
      stream: "end",
    });
  } catch (error) {
    const safeError =
      error instanceof DaytonaSupervisorProtocolError
        ? error
        : new DaytonaSupervisorProtocolError("internal");
    await writeFailure(options.output, request.sequence, safeError);
  }
}

interface CapturedOptions {
  readonly supervisor: PinnedDaytonaSupervisorTransport;
  readonly input: Readable;
  readonly output: Writable;
  readonly signal: AbortSignal;
}

function captureOptions(value: RunDaytonaSupervisorNdjsonOptions): CapturedOptions {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value))
    throw new TypeError();
  if (
    typeof value.supervisor !== "object" ||
    value.supervisor === null ||
    typeof value.supervisor.attestIsolation !== "function" ||
    typeof value.supervisor.executeAuthenticated !== "function" ||
    typeof value.supervisor.followSigned !== "function" ||
    typeof value.supervisor.close !== "function" ||
    typeof value.input?.[Symbol.asyncIterator] !== "function" ||
    typeof value.output?.write !== "function" ||
    !(value.signal instanceof AbortSignal)
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    supervisor: value.supervisor,
    input: value.input,
    output: value.output,
    signal: value.signal,
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
        throw new DaytonaSupervisorProtocolError("invalid-request");
      }
      while (true) {
        const newline = pending.indexOf(0x0a);
        if (newline < 0) break;
        if (newline > MAX_LINE_BYTES) {
          throw new DaytonaSupervisorProtocolError("invalid-request");
        }
        const lineBytes = pending.subarray(0, newline);
        pending = Buffer.from(pending.subarray(newline + 1));
        bufferedLines += 1;
        if (bufferedLines > MAX_BUFFERED_LINES) {
          throw new DaytonaSupervisorProtocolError("invalid-request");
        }
        const line = lineBytes.toString("utf8");
        lineBytes.fill(0);
        if (line.length === 0) throw new DaytonaSupervisorProtocolError("invalid-request");
        yield line;
        bufferedLines -= 1;
      }
      if (pending.byteLength > MAX_LINE_BYTES) {
        throw new DaytonaSupervisorProtocolError("invalid-request");
      }
    }
    if (pending.byteLength !== 0) throw new DaytonaSupervisorProtocolError("invalid-request");
  } finally {
    pending.fill(0);
  }
}

function snapshotRequest(value: unknown): ProtocolRequest {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, ["version", "sequence", "method", "params"]);
  const sequence = field(record, "sequence");
  const method = field(record, "method");
  if (
    field(record, "version") !== DAYTONA_SUPERVISOR_PROTOCOL_VERSION ||
    !Number.isSafeInteger(sequence) ||
    (sequence as number) < 1 ||
    (method !== "isolation.attest" &&
      method !== "command.execute" &&
      method !== "observations.follow")
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return Object.freeze({
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    sequence: sequence as number,
    method,
    params: field(record, "params"),
  });
}

async function writeSuccess(output: Writable, sequence: number, result: unknown): Promise<void> {
  await writeFrame(output, {
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    sequence,
    ok: true,
    result: snapshotRuntimeSupervisorPortableData(result),
  });
}

async function writeFailure(
  output: Writable,
  sequence: number,
  error: DaytonaSupervisorProtocolError
): Promise<void> {
  await writeFrame(output, {
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    sequence,
    ok: false,
    error: Object.freeze({ code: error.code, message: safeMessage(error.code) }),
  });
}

function safeMessage(code: DaytonaSupervisorProtocolErrorCode): string {
  return new DaytonaSupervisorProtocolError(code).message;
}

async function writeFrame(output: Writable, frame: object): Promise<void> {
  let line: string;
  try {
    line = `${canonicalRuntimeJson(frame)}\n`;
  } catch {
    throw new DaytonaSupervisorProtocolError("internal");
  }
  if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) {
    throw new DaytonaSupervisorProtocolError("internal");
  }
  await new Promise<void>((resolve, reject) => {
    const accepted = output.write(line, "utf8", (error?: Error | null) => {
      if (error) reject(new DaytonaSupervisorProtocolError("unavailable"));
      else if (accepted) resolve();
    });
    if (!accepted) output.once("drain", resolve);
  });
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}
