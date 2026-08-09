import { TextDecoder, types as nodeTypes } from "node:util";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import {
  DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
  DaytonaSupervisorProtocolError,
  type DaytonaSupervisorProtocolErrorCode,
} from "./supervisor";

export const DAYTONA_SUPERVISOR_SOCKET_PROTOCOL = "terminalx.daytona-supervisor.socket/v1" as const;
export const DAYTONA_SUPERVISOR_SOCKET_MAX_FRAME_BYTES = 1024 * 1024;
const MAX_BUFFERED_FRAMES = 32;
const SAFE_REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export type DaytonaSupervisorSocketMethod =
  | "isolation.attest"
  | "command.execute"
  | "observations.follow"
  | "terminal.open"
  | "terminal.input"
  | "terminal.resize"
  | "terminal.interrupt"
  | "terminal.destroy";

export type DaytonaSupervisorSocketRequestFrame = Readonly<{
  protocol: typeof DAYTONA_SUPERVISOR_SOCKET_PROTOCOL;
  version: typeof DAYTONA_SUPERVISOR_PROTOCOL_VERSION;
  type: "request";
  requestId: string;
  method: DaytonaSupervisorSocketMethod;
  params: unknown;
}>;

export type DaytonaSupervisorSocketCancelFrame = Readonly<{
  protocol: typeof DAYTONA_SUPERVISOR_SOCKET_PROTOCOL;
  version: typeof DAYTONA_SUPERVISOR_PROTOCOL_VERSION;
  type: "cancel";
  requestId: string;
}>;

export type DaytonaSupervisorSocketSuccessFrame = Readonly<{
  protocol: typeof DAYTONA_SUPERVISOR_SOCKET_PROTOCOL;
  version: typeof DAYTONA_SUPERVISOR_PROTOCOL_VERSION;
  type: "response";
  requestId: string;
  ok: true;
  result: unknown;
}>;

export type DaytonaSupervisorSocketFailureFrame = Readonly<{
  protocol: typeof DAYTONA_SUPERVISOR_SOCKET_PROTOCOL;
  version: typeof DAYTONA_SUPERVISOR_PROTOCOL_VERSION;
  type: "response";
  requestId: string;
  ok: false;
  error: Readonly<{
    code: DaytonaSupervisorProtocolErrorCode;
    message: string;
  }>;
}>;

export type DaytonaSupervisorSocketStreamFrame = Readonly<{
  protocol: typeof DAYTONA_SUPERVISOR_SOCKET_PROTOCOL;
  version: typeof DAYTONA_SUPERVISOR_PROTOCOL_VERSION;
  type: "stream";
  requestId: string;
  item: unknown;
}>;

export type DaytonaSupervisorSocketEndFrame = Readonly<{
  protocol: typeof DAYTONA_SUPERVISOR_SOCKET_PROTOCOL;
  version: typeof DAYTONA_SUPERVISOR_PROTOCOL_VERSION;
  type: "end";
  requestId: string;
}>;

export type DaytonaSupervisorSocketInboundFrame =
  | DaytonaSupervisorSocketRequestFrame
  | DaytonaSupervisorSocketCancelFrame;

export type DaytonaSupervisorSocketOutboundFrame =
  | DaytonaSupervisorSocketSuccessFrame
  | DaytonaSupervisorSocketFailureFrame
  | DaytonaSupervisorSocketStreamFrame
  | DaytonaSupervisorSocketEndFrame;

export type DaytonaSupervisorSocketFrame =
  | DaytonaSupervisorSocketInboundFrame
  | DaytonaSupervisorSocketOutboundFrame;

/**
 * Four-byte big-endian length prefix followed by strict canonical JSON. The
 * prefix removes newline ambiguity and lets one connection multiplex bounded
 * unary and streaming requests without a follow stream blocking commands.
 */
export function encodeDaytonaSupervisorSocketFrame(
  unsafeFrame: DaytonaSupervisorSocketFrame,
  maximumFrameBytes = DAYTONA_SUPERVISOR_SOCKET_MAX_FRAME_BYTES
): Buffer {
  const frame = snapshotSocketFrame(unsafeFrame);
  let payload: Buffer;
  try {
    payload = Buffer.from(canonicalRuntimeJson(frame), "utf8");
  } catch {
    throw new DaytonaSupervisorProtocolError("internal");
  }
  if (payload.byteLength < 2 || payload.byteLength > boundedMaximum(maximumFrameBytes)) {
    payload.fill(0);
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  const result = Buffer.allocUnsafe(4 + payload.byteLength);
  result.writeUInt32BE(payload.byteLength, 0);
  payload.copy(result, 4);
  payload.fill(0);
  return result;
}

/** Stateful bounded decoder. Any malformed frame poisons the decoder. */
export class DaytonaSupervisorSocketFrameDecoder {
  private pending = Buffer.alloc(0);
  private failed = false;
  private readonly maximumFrameBytes: number;

  constructor(maximumFrameBytes = DAYTONA_SUPERVISOR_SOCKET_MAX_FRAME_BYTES) {
    this.maximumFrameBytes = boundedMaximum(maximumFrameBytes);
  }

  push(unsafeChunk: Uint8Array): readonly DaytonaSupervisorSocketFrame[] {
    if (this.failed || !(unsafeChunk instanceof Uint8Array)) return this.fail();
    const chunk = Buffer.from(unsafeChunk);
    if (
      this.pending.byteLength + chunk.byteLength >
      (this.maximumFrameBytes + 4) * MAX_BUFFERED_FRAMES
    ) {
      chunk.fill(0);
      return this.fail();
    }
    const combined = Buffer.concat(
      [this.pending, chunk],
      this.pending.byteLength + chunk.byteLength
    );
    this.pending.fill(0);
    chunk.fill(0);
    this.pending = combined;

    const frames: DaytonaSupervisorSocketFrame[] = [];
    try {
      while (this.pending.byteLength >= 4) {
        const length = this.pending.readUInt32BE(0);
        if (length < 2 || length > this.maximumFrameBytes) return this.fail();
        if (this.pending.byteLength < length + 4) break;
        const payload = Buffer.from(this.pending.subarray(4, length + 4));
        const remainder = Buffer.from(this.pending.subarray(length + 4));
        this.pending.fill(0);
        this.pending = remainder;
        let parsed: unknown;
        let text: string;
        try {
          text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
          parsed = JSON.parse(text);
        } finally {
          payload.fill(0);
        }
        const frame = snapshotSocketFrame(parsed);
        if (canonicalRuntimeJson(frame) !== text) return this.fail();
        frames.push(frame);
        if (frames.length > MAX_BUFFERED_FRAMES) return this.fail();
      }
      return Object.freeze(frames);
    } catch {
      return this.fail();
    }
  }

  finish(): void {
    if (this.failed || this.pending.byteLength !== 0) this.fail();
    this.destroy();
  }

  destroy(): void {
    this.pending.fill(0);
    this.pending = Buffer.alloc(0);
    this.failed = true;
  }

  private fail(): never {
    this.destroy();
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
}

export function snapshotDaytonaSupervisorSocketInboundFrame(
  value: unknown
): DaytonaSupervisorSocketInboundFrame {
  const frame = snapshotSocketFrame(value);
  if (frame.type !== "request" && frame.type !== "cancel") {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return frame;
}

export function snapshotDaytonaSupervisorSocketOutboundFrame(
  value: unknown
): DaytonaSupervisorSocketOutboundFrame {
  const frame = snapshotSocketFrame(value);
  if (frame.type === "request" || frame.type === "cancel") {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return frame;
}

function snapshotSocketFrame(value: unknown): DaytonaSupervisorSocketFrame {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const base = exactRecordWithVariableFields(snapshot);
  if (
    field(base, "protocol") !== DAYTONA_SUPERVISOR_SOCKET_PROTOCOL ||
    field(base, "version") !== DAYTONA_SUPERVISOR_PROTOCOL_VERSION
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  const type = field(base, "type");
  const requestId = safeRequestId(field(base, "requestId"));
  if (type === "cancel") {
    exactNames(base, ["protocol", "version", "type", "requestId"]);
    return Object.freeze({
      protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
      version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
      type: "cancel",
      requestId,
    });
  }
  if (type === "request") {
    exactNames(base, ["protocol", "version", "type", "requestId", "method", "params"]);
    const method = field(base, "method");
    if (
      method !== "isolation.attest" &&
      method !== "command.execute" &&
      method !== "observations.follow" &&
      method !== "terminal.open" &&
      method !== "terminal.input" &&
      method !== "terminal.resize" &&
      method !== "terminal.interrupt" &&
      method !== "terminal.destroy"
    ) {
      throw new DaytonaSupervisorProtocolError("invalid-request");
    }
    return Object.freeze({
      protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
      version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
      type: "request",
      requestId,
      method: method as DaytonaSupervisorSocketMethod,
      params: field(base, "params"),
    });
  }
  if (type === "stream") {
    exactNames(base, ["protocol", "version", "type", "requestId", "item"]);
    return Object.freeze({
      protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
      version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
      type: "stream",
      requestId,
      item: field(base, "item"),
    });
  }
  if (type === "end") {
    exactNames(base, ["protocol", "version", "type", "requestId"]);
    return Object.freeze({
      protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
      version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
      type: "end",
      requestId,
    });
  }
  if (type !== "response") throw new DaytonaSupervisorProtocolError("invalid-request");
  const ok = field(base, "ok");
  if (ok === true) {
    exactNames(base, ["protocol", "version", "type", "requestId", "ok", "result"]);
    return Object.freeze({
      protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
      version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
      type: "response",
      requestId,
      ok: true as const,
      result: field(base, "result"),
    });
  }
  if (ok !== false) throw new DaytonaSupervisorProtocolError("invalid-request");
  exactNames(base, ["protocol", "version", "type", "requestId", "ok", "error"]);
  const error = exactRecord(field(base, "error"), ["code", "message"]);
  const code = protocolErrorCode(field(error, "code"));
  const expected = new DaytonaSupervisorProtocolError(code).message;
  if (field(error, "message") !== expected) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return Object.freeze({
    protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    type: "response",
    requestId,
    ok: false,
    error: Object.freeze({ code, message: expected }),
  });
}

function exactRecordWithVariableFields(value: unknown): Record<string, unknown> {
  const record = plainRecord(value);
  for (const name of ["protocol", "version", "type", "requestId"]) field(record, name);
  return record;
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return value as Record<string, unknown>;
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  const record = plainRecord(value);
  exactNames(record, names);
  return record;
}

function exactNames(record: Record<string, unknown>, names: readonly string[]): void {
  const keys = Reflect.ownKeys(record);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  for (const name of names) field(record, name);
}

function field(record: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return descriptor.value;
}

function safeRequestId(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REQUEST_ID.test(value)) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return value;
}

function protocolErrorCode(value: unknown): DaytonaSupervisorProtocolErrorCode {
  if (
    value !== "invalid-request" &&
    value !== "permission-denied" &&
    value !== "conflict" &&
    value !== "not-ready" &&
    value !== "unavailable" &&
    value !== "internal"
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return value;
}

function boundedMaximum(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1024 || value > 16 * 1024 * 1024) {
    throw new TypeError();
  }
  return value;
}
