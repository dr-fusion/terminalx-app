import { randomUUID } from "node:crypto";
import { redactFields } from "./redaction";

/**
 * Structured (JSON) telemetry for TerminalX operations. Every record carries a
 * timestamp, a level, an event name, and an optional request/trace correlation
 * id, and every field is passed through the redaction guard before serialization
 * so no secret material, token, credential value, or raw provider body can reach
 * stdout. It augments — it does not replace — the durable Session Event Chain and
 * the security audit log; it is diagnostic telemetry, not authority.
 */

export type TelemetryLevel = "debug" | "info" | "warn" | "error";

const LEVEL_RANK: Record<TelemetryLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export interface TelemetryRecord {
  readonly ts: string;
  readonly level: TelemetryLevel;
  readonly event: string;
  readonly traceId?: string;
  readonly fields: Record<string, unknown>;
}

export type TelemetrySink = (line: string, level: TelemetryLevel) => void;

const defaultSink: TelemetrySink = (line, level) => {
  if (level === "error" || level === "warn") {
    console.error(line);
  } else {
    console.log(line);
  }
};

let activeSink: TelemetrySink = defaultSink;

/** Replace the telemetry sink (tests capture emitted lines; returns a restorer). */
export function setTelemetrySink(sink: TelemetrySink): () => void {
  const previous = activeSink;
  activeSink = sink;
  return () => {
    activeSink = previous;
  };
}

function configuredMinLevel(): number {
  const raw = process.env.TERMINALX_LOG_LEVEL?.trim().toLowerCase();
  if (raw === "debug" || raw === "info" || raw === "warn" || raw === "error") {
    return LEVEL_RANK[raw];
  }
  return LEVEL_RANK.info;
}

const TRACE_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/** A fresh correlation id for a request/trace with no inbound id. */
export function newTraceId(): string {
  return randomUUID();
}

/**
 * Derive a correlation id from inbound headers, honoring a caller-supplied
 * `x-request-id`/`x-correlation-id` when it is well-formed, else minting one.
 */
export function correlationIdFromHeaders(headers: { get(name: string): string | null }): string {
  for (const name of ["x-request-id", "x-correlation-id"]) {
    const value = headers.get(name);
    if (value && TRACE_ID_PATTERN.test(value)) return value;
  }
  return newTraceId();
}

export interface EmitOptions {
  readonly traceId?: string;
}

/** Emit one redacted, structured telemetry record. Never throws to its caller. */
export function emitTelemetry(
  level: TelemetryLevel,
  event: string,
  fields: Record<string, unknown> = {},
  options: EmitOptions = {}
): void {
  if (LEVEL_RANK[level] < configuredMinLevel()) return;
  const record: TelemetryRecord = {
    ts: new Date().toISOString(),
    level,
    event,
    ...(options.traceId ? { traceId: options.traceId } : {}),
    fields: redactFields(fields),
  };
  let line: string;
  try {
    line = JSON.stringify(record);
  } catch {
    line = JSON.stringify({
      ts: record.ts,
      level: "error",
      event: "telemetry.serialize-failed",
      fields: {},
    });
  }
  try {
    activeSink(line, level);
  } catch {
    // Telemetry must never destabilize the caller's control flow.
  }
}

export const telemetry = {
  debug: (event: string, fields?: Record<string, unknown>, options?: EmitOptions) =>
    emitTelemetry("debug", event, fields, options),
  info: (event: string, fields?: Record<string, unknown>, options?: EmitOptions) =>
    emitTelemetry("info", event, fields, options),
  warn: (event: string, fields?: Record<string, unknown>, options?: EmitOptions) =>
    emitTelemetry("warn", event, fields, options),
  error: (event: string, fields?: Record<string, unknown>, options?: EmitOptions) =>
    emitTelemetry("error", event, fields, options),
} as const;
