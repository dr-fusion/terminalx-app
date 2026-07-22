import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

export type TelegramMessageDirection = "inbound" | "outbound";
export type TelegramMessageOperation = "receive" | "send" | "edit";
export type TelegramMessageDeliveryStatus = "received" | "pending" | "sent" | "failed";
export type TelegramMessageRoutingStatus = "matched" | "mismatch" | "unbound" | "unknown";
export type TelegramMessageProcessingStatus = "pending" | "processing" | "processed" | "failed";

export interface NewTelegramMessageAuditEvent {
  dedupeKey?: string;
  direction: TelegramMessageDirection;
  operation: TelegramMessageOperation;
  deliveryStatus: TelegramMessageDeliveryStatus;
  routingStatus: TelegramMessageRoutingStatus;
  source: string;
  sourceRef?: string;
  correlationId?: string;
  apiMethod?: string;
  telegramBotId?: number;
  telegramUpdateId?: number;
  telegramMessageId?: number;
  telegramMessageIds?: number[];
  telegramChatId?: number;
  telegramTopicId?: number;
  telegramUserId?: number;
  telegramUsername?: string;
  sessionId?: string;
  boundSessionId?: string;
  boundSessionCreatedAtMs?: number;
  expectedChatId?: number;
  expectedTopicId?: number;
  sessionCreatedAtMs?: number;
  sessionKind?: string;
  sessionCwd?: string;
  transcriptSessionId?: string;
  transcriptPath?: string;
  replyToMessageId?: number;
  messageType: string;
  content?: string;
  payload?: unknown;
  result?: unknown;
  errorCode?: string;
  errorMessage?: string;
  processingStatus?: TelegramMessageProcessingStatus;
  processingAttempts?: number;
  processingStartedAtMs?: number;
  processingCompletedAtMs?: number;
  receivedCount?: number;
  lastReceivedAtMs?: number;
  occurredAtMs?: number;
  completedAtMs?: number;
  durationMs?: number;
}

export interface TelegramMessageAuditEvent extends Omit<
  NewTelegramMessageAuditEvent,
  "payload" | "result"
> {
  id: number;
  recordedAtMs: number;
  contentHash?: string;
  contentPreview?: string;
  payload?: unknown;
  result?: unknown;
}

export interface TelegramMessageAuditQuery {
  includeContent?: boolean;
  limit?: number;
  cursor?: string;
  direction?: TelegramMessageDirection;
  operation?: TelegramMessageOperation;
  deliveryStatus?: TelegramMessageDeliveryStatus;
  routingStatus?: TelegramMessageRoutingStatus;
  processingStatus?: TelegramMessageProcessingStatus;
  source?: string;
  messageType?: string;
  sessionId?: string;
  telegramBotId?: number;
  telegramUpdateId?: number;
  telegramMessageId?: number;
  telegramChatId?: number;
  telegramTopicId?: number;
  telegramUserId?: number;
  fromMs?: number;
  toMs?: number;
}

export interface TelegramMessageAuditPage {
  messages: TelegramMessageAuditEvent[];
  page: {
    limit: number;
    hasMore: boolean;
    nextCursor: string | null;
  };
}

export type TelegramInboundDispatchClaim =
  | { status: "claimed"; event: TelegramMessageAuditEvent }
  | { status: "processed" | "busy"; event: TelegramMessageAuditEvent };

export const DEFAULT_INBOUND_PROCESSING_LEASE_MS = 15 * 60 * 1000;

export interface CompleteTelegramOutboundInput {
  telegramBotId?: number;
  telegramMessageId?: number;
  telegramMessageIds?: number[];
  telegramChatId?: number;
  telegramTopicId?: number;
  telegramUserId?: number;
  telegramUsername?: string;
  completedAtMs?: number;
  result?: unknown;
}

export interface FailTelegramOutboundInput {
  errorCode?: string;
  errorMessage: string;
  completedAtMs?: number;
  result?: unknown;
}

export interface TelegramMessageAuditSummary {
  total: number;
  byDirection: Record<string, number>;
  byDeliveryStatus: Record<string, number>;
  byRoutingStatus: Record<string, number>;
  byProcessingStatus: Record<string, number>;
  routePairs: Array<{
    telegramChatId?: number;
    telegramTopicId?: number;
    sessionId?: string;
    sessionCreatedAtMs?: number;
    count: number;
  }>;
  anomalies: {
    topicsWithMultipleSessions: Array<{
      telegramChatId?: number;
      telegramTopicId: number;
      sessionIds: string[];
      sessions: Array<{ sessionId: string; sessionCreatedAtMs?: number }>;
      count: number;
    }>;
    sessionsWithMultipleTopics: Array<{
      sessionId: string;
      sessionCreatedAtMs?: number;
      topicIds: number[];
      topics: Array<{ telegramChatId?: number; telegramTopicId: number }>;
      count: number;
    }>;
    sourcesDeliveredToMultipleTopics: Array<{
      sourceRef: string;
      topicIds: number[];
      topics: Array<{ telegramChatId?: number; telegramTopicId: number }>;
      sessionIds: string[];
      count: number;
    }>;
    contentDeliveredToMultipleTopics: Array<{
      contentHash: string;
      contentPreview: string;
      topicIds: number[];
      topics: Array<{ telegramChatId?: number; telegramTopicId: number }>;
      sessionIds: string[];
      count: number;
    }>;
  };
}

type SqlRow = Record<string, string | number | null>;
type SqlValue = string | number;

interface QueryWhere {
  sql: string;
  values: SqlValue[];
}

interface SummaryTopicIdentity {
  telegramChatId?: number;
  telegramTopicId: number;
}

interface SummarySessionIdentity {
  sessionId: string;
  sessionCreatedAtMs?: number;
}

function topicIdentityKey(topic: SummaryTopicIdentity): string {
  return `${topic.telegramChatId ?? "unknown"}:${topic.telegramTopicId}`;
}

function sessionIdentityKey(session: SummarySessionIdentity): string {
  return `${session.sessionId}:${session.sessionCreatedAtMs ?? "unknown"}`;
}

function sortTopics(topics: SummaryTopicIdentity[]): SummaryTopicIdentity[] {
  return topics.sort(
    (a, b) =>
      (a.telegramChatId ?? Number.MIN_SAFE_INTEGER) -
        (b.telegramChatId ?? Number.MIN_SAFE_INTEGER) || a.telegramTopicId - b.telegramTopicId
  );
}

function sortSessions(sessions: SummarySessionIdentity[]): SummarySessionIdentity[] {
  return sessions.sort(
    (a, b) =>
      a.sessionId.localeCompare(b.sessionId) ||
      (a.sessionCreatedAtMs ?? Number.MIN_SAFE_INTEGER) -
        (b.sessionCreatedAtMs ?? Number.MIN_SAFE_INTEGER)
  );
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS telegram_message_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key TEXT UNIQUE,
    recorded_at_ms INTEGER NOT NULL,
    occurred_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    duration_ms INTEGER,
    direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    operation TEXT NOT NULL CHECK (operation IN ('receive', 'send', 'edit')),
    delivery_status TEXT NOT NULL CHECK (delivery_status IN ('received', 'pending', 'sent', 'failed')),
    routing_status TEXT NOT NULL CHECK (routing_status IN ('matched', 'mismatch', 'unbound', 'unknown')),
    source TEXT NOT NULL,
    source_ref TEXT,
    correlation_id TEXT,
    api_method TEXT,
    telegram_bot_id INTEGER,
    telegram_update_id INTEGER,
    telegram_message_id INTEGER,
    telegram_message_ids_json TEXT,
    telegram_chat_id INTEGER,
    telegram_topic_id INTEGER,
    telegram_user_id INTEGER,
    telegram_username TEXT,
    session_id TEXT,
    bound_session_id TEXT,
    bound_session_created_at_ms INTEGER,
    expected_chat_id INTEGER,
    expected_topic_id INTEGER,
    session_created_at_ms INTEGER,
    session_kind TEXT,
    session_cwd TEXT,
    transcript_session_id TEXT,
    transcript_path TEXT,
    reply_to_message_id INTEGER,
    message_type TEXT NOT NULL,
    content TEXT,
    content_hash TEXT,
    payload_json TEXT,
    result_json TEXT,
    error_code TEXT,
    error_message TEXT,
    processing_status TEXT CHECK (
      processing_status IS NULL OR
      processing_status IN ('pending', 'processing', 'processed', 'failed')
    ),
    processing_attempts INTEGER NOT NULL DEFAULT 0,
    processing_started_at_ms INTEGER,
    processing_completed_at_ms INTEGER,
    processing_owner TEXT,
    received_count INTEGER NOT NULL DEFAULT 1,
    last_received_at_ms INTEGER
  );

  CREATE INDEX IF NOT EXISTS telegram_message_events_topic_time_idx
    ON telegram_message_events (telegram_chat_id, telegram_topic_id, occurred_at_ms DESC, id DESC);
  CREATE INDEX IF NOT EXISTS telegram_message_events_session_time_idx
    ON telegram_message_events (session_id, session_created_at_ms, occurred_at_ms DESC, id DESC);
  CREATE INDEX IF NOT EXISTS telegram_message_events_message_idx
    ON telegram_message_events (telegram_chat_id, telegram_message_id);
  CREATE INDEX IF NOT EXISTS telegram_message_events_update_idx
    ON telegram_message_events (telegram_update_id);
  CREATE INDEX IF NOT EXISTS telegram_message_events_source_idx
    ON telegram_message_events (source_ref, telegram_topic_id);
  CREATE INDEX IF NOT EXISTS telegram_message_events_content_idx
    ON telegram_message_events (content_hash, telegram_topic_id);
  CREATE INDEX IF NOT EXISTS telegram_message_events_time_idx
    ON telegram_message_events (occurred_at_ms DESC, id DESC);
`;

function hashContent(content: string | undefined): string | undefined {
  if (content === undefined) return undefined;
  return crypto.createHash("sha256").update(content).digest("hex");
}

const SENSITIVE_JSON_KEY = /token|secret|password|authorization|cookie|api[_-]?key/i;

function objectType(value: object): string {
  try {
    return value.constructor?.name || "Object";
  } catch {
    return "Object";
  }
}

function normalizeForAudit(value: unknown, ancestors: WeakSet<object>, depth = 0): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : String(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "undefined") return "[undefined]";
  if (typeof value === "function" || typeof value === "symbol") return `[${typeof value}]`;
  if (typeof value !== "object") return String(value);

  const type = objectType(value);
  if (type === "InputFile") {
    const rawFilename = (value as { filename?: unknown }).filename;
    const filename = typeof rawFilename === "string" ? rawFilename : undefined;
    return { type: "InputFile", ...(filename ? { filename } : {}) };
  }
  if (Buffer.isBuffer(value)) return { type: "Buffer", byteLength: value.byteLength };
  if (value instanceof ArrayBuffer) return { type: "ArrayBuffer", byteLength: value.byteLength };
  if (ArrayBuffer.isView(value)) {
    return { type, byteLength: value.byteLength };
  }
  if (value instanceof Date) return value.toISOString();
  if (value instanceof URL) return value.toString();
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (depth >= 20) return "[max-depth]";
  if (ancestors.has(value)) return "[circular]";

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => normalizeForAudit(item, ancestors, depth + 1));
    }
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      if (SENSITIVE_JSON_KEY.test(key)) {
        normalized[key] = "[redacted]";
        continue;
      }
      try {
        normalized[key] = normalizeForAudit(
          (value as Record<string, unknown>)[key],
          ancestors,
          depth + 1
        );
      } catch {
        normalized[key] = "[unavailable]";
      }
    }
    return normalized;
  } finally {
    ancestors.delete(value);
  }
}

function stringify(value: unknown): string | null {
  if (value === undefined) return null;
  try {
    return JSON.stringify(normalizeForAudit(value, new WeakSet()));
  } catch {
    return JSON.stringify({ serializationError: "payload unavailable" });
  }
}

function parseJson(value: string | number | null | undefined): unknown {
  if (typeof value !== "string") return undefined;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return { auditCorruption: "stored JSON is invalid" };
  }
}

function optionalString(value: string | number | null | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function optionalNumber(value: string | number | null | undefined): number | undefined {
  return typeof value === "number" ? value : undefined;
}

function optionalNumberArray(value: string | number | null | undefined): number[] | undefined {
  const parsed = parseJson(value);
  if (!Array.isArray(parsed)) return undefined;
  const numbers = parsed.filter(
    (item): item is number => typeof item === "number" && Number.isSafeInteger(item)
  );
  return numbers.length ? numbers : undefined;
}

function mapRow(row: SqlRow, includeContent: boolean): TelegramMessageAuditEvent {
  const content = optionalString(row.content);
  return {
    id: Number(row.id),
    dedupeKey: optionalString(row.dedupe_key),
    recordedAtMs: Number(row.recorded_at_ms),
    occurredAtMs: Number(row.occurred_at_ms),
    completedAtMs: optionalNumber(row.completed_at_ms),
    durationMs: optionalNumber(row.duration_ms),
    direction: row.direction as TelegramMessageDirection,
    operation: row.operation as TelegramMessageOperation,
    deliveryStatus: row.delivery_status as TelegramMessageDeliveryStatus,
    routingStatus: row.routing_status as TelegramMessageRoutingStatus,
    source: String(row.source),
    sourceRef: optionalString(row.source_ref),
    correlationId: optionalString(row.correlation_id),
    apiMethod: optionalString(row.api_method),
    telegramBotId: optionalNumber(row.telegram_bot_id),
    telegramUpdateId: optionalNumber(row.telegram_update_id),
    telegramMessageId: optionalNumber(row.telegram_message_id),
    telegramMessageIds: optionalNumberArray(row.telegram_message_ids_json),
    telegramChatId: optionalNumber(row.telegram_chat_id),
    telegramTopicId: optionalNumber(row.telegram_topic_id),
    telegramUserId: optionalNumber(row.telegram_user_id),
    telegramUsername: optionalString(row.telegram_username),
    sessionId: optionalString(row.session_id),
    boundSessionId: optionalString(row.bound_session_id),
    boundSessionCreatedAtMs: optionalNumber(row.bound_session_created_at_ms),
    expectedChatId: optionalNumber(row.expected_chat_id),
    expectedTopicId: optionalNumber(row.expected_topic_id),
    sessionCreatedAtMs: optionalNumber(row.session_created_at_ms),
    sessionKind: optionalString(row.session_kind),
    sessionCwd: optionalString(row.session_cwd),
    transcriptSessionId: optionalString(row.transcript_session_id),
    transcriptPath: optionalString(row.transcript_path),
    replyToMessageId: optionalNumber(row.reply_to_message_id),
    messageType: String(row.message_type),
    contentHash: optionalString(row.content_hash),
    contentPreview: content === undefined ? undefined : content.slice(0, 240),
    errorCode: optionalString(row.error_code),
    errorMessage: optionalString(row.error_message),
    processingStatus: optionalString(row.processing_status) as
      | TelegramMessageProcessingStatus
      | undefined,
    processingAttempts: optionalNumber(row.processing_attempts),
    processingStartedAtMs: optionalNumber(row.processing_started_at_ms),
    processingCompletedAtMs: optionalNumber(row.processing_completed_at_ms),
    receivedCount: optionalNumber(row.received_count),
    lastReceivedAtMs: optionalNumber(row.last_received_at_ms),
    ...(includeContent
      ? {
          content,
          payload: parseJson(row.payload_json),
          result: parseJson(row.result_json),
        }
      : {}),
  };
}

function decodeCursor(cursor: string): { occurredAtMs: number; id: number } {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf-8")) as unknown;
    if (
      !Array.isArray(parsed) ||
      parsed.length !== 2 ||
      !Number.isSafeInteger(parsed[0]) ||
      !Number.isSafeInteger(parsed[1])
    ) {
      throw new Error("invalid cursor");
    }
    return { occurredAtMs: parsed[0] as number, id: parsed[1] as number };
  } catch {
    throw new Error("invalid cursor");
  }
}

function encodeCursor(row: SqlRow): string {
  return Buffer.from(JSON.stringify([Number(row.occurred_at_ms), Number(row.id)])).toString(
    "base64url"
  );
}

function queryWhere(query: TelegramMessageAuditQuery, includeCursor: boolean): QueryWhere {
  const clauses: string[] = [];
  const values: SqlValue[] = [];
  const exact: Array<[keyof TelegramMessageAuditQuery, string]> = [
    ["direction", "direction"],
    ["operation", "operation"],
    ["deliveryStatus", "delivery_status"],
    ["routingStatus", "routing_status"],
    ["processingStatus", "processing_status"],
    ["source", "source"],
    ["messageType", "message_type"],
    ["sessionId", "session_id"],
    ["telegramBotId", "telegram_bot_id"],
    ["telegramUpdateId", "telegram_update_id"],
    ["telegramChatId", "telegram_chat_id"],
    ["telegramTopicId", "telegram_topic_id"],
    ["telegramUserId", "telegram_user_id"],
  ];
  for (const [key, column] of exact) {
    const value = query[key];
    if (typeof value !== "string" && typeof value !== "number") continue;
    clauses.push(`${column} = ?`);
    values.push(value);
  }
  if (query.telegramMessageId !== undefined) {
    clauses.push(`(
      telegram_message_id = ? OR EXISTS (
        SELECT 1 FROM json_each(telegram_message_ids_json)
        WHERE json_each.value = ?
      )
    )`);
    values.push(query.telegramMessageId, query.telegramMessageId);
  }
  if (query.fromMs !== undefined) {
    clauses.push("occurred_at_ms >= ?");
    values.push(query.fromMs);
  }
  if (query.toMs !== undefined) {
    clauses.push("occurred_at_ms <= ?");
    values.push(query.toMs);
  }
  if (includeCursor && query.cursor) {
    const cursor = decodeCursor(query.cursor);
    clauses.push("(occurred_at_ms < ? OR (occurred_at_ms = ? AND id < ?))");
    values.push(cursor.occurredAtMs, cursor.occurredAtMs, cursor.id);
  }
  return { sql: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", values };
}

export class TelegramMessageAuditStore {
  private readonly db: Database.Database;
  private readonly filename?: string;
  private readonly processingOwner = crypto.randomUUID();
  private closed = false;

  constructor(filename: string) {
    const resolved = filename === ":memory:" ? filename : path.resolve(filename);
    if (resolved !== ":memory:") {
      const parent = path.dirname(resolved);
      // Create missing directories privately, but never chmod an existing
      // operator-selected parent because it may be shared by other services.
      fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
      this.filename = resolved;
    }
    this.db = new Database(resolved);
    // Secure the main file before enabling WAL so its sidecars inherit a
    // private mode rather than the process's potentially permissive umask.
    this.secureDatabaseFiles();
    this.db.pragma("busy_timeout = 5000");
    this.db.pragma("foreign_keys = ON");
    this.db.pragma("trusted_schema = OFF");
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL");
    this.db.exec(SCHEMA);
    this.db.pragma("user_version = 1");
    this.secureDatabaseFiles();
  }

  private secureDatabaseFiles(): void {
    if (!this.filename || process.platform === "win32") return;
    for (const filename of [
      this.filename,
      `${this.filename}-wal`,
      `${this.filename}-shm`,
      `${this.filename}-journal`,
    ]) {
      if (fs.existsSync(filename)) fs.chmodSync(filename, 0o600);
    }
  }

  record(input: NewTelegramMessageAuditEvent): TelegramMessageAuditEvent {
    return this.recordOnce(input).event;
  }

  recordOnce(input: NewTelegramMessageAuditEvent): {
    event: TelegramMessageAuditEvent;
    inserted: boolean;
  } {
    const recordedAtMs = Date.now();
    const occurredAtMs = input.occurredAtMs ?? recordedAtMs;
    const statement = this.db.prepare(`
      INSERT OR IGNORE INTO telegram_message_events (
        dedupe_key, recorded_at_ms, occurred_at_ms, completed_at_ms, duration_ms,
        direction, operation, delivery_status, routing_status, source, source_ref,
        correlation_id, api_method, telegram_bot_id, telegram_update_id, telegram_message_id,
        telegram_message_ids_json, telegram_chat_id, telegram_topic_id, telegram_user_id,
        telegram_username,
        session_id, bound_session_id, bound_session_created_at_ms, expected_chat_id,
        expected_topic_id, session_created_at_ms,
        session_kind, session_cwd, transcript_session_id, transcript_path,
        reply_to_message_id, message_type, content, content_hash, payload_json,
        result_json, error_code, error_message, processing_status, processing_attempts,
        processing_started_at_ms, processing_completed_at_ms, received_count,
        last_received_at_ms
      ) VALUES (
        @dedupeKey, @recordedAtMs, @occurredAtMs, @completedAtMs, @durationMs,
        @direction, @operation, @deliveryStatus, @routingStatus, @source, @sourceRef,
        @correlationId, @apiMethod, @telegramBotId, @telegramUpdateId, @telegramMessageId,
        @telegramMessageIdsJson, @telegramChatId, @telegramTopicId, @telegramUserId,
        @telegramUsername,
        @sessionId, @boundSessionId, @boundSessionCreatedAtMs, @expectedChatId,
        @expectedTopicId, @sessionCreatedAtMs,
        @sessionKind, @sessionCwd, @transcriptSessionId, @transcriptPath,
        @replyToMessageId, @messageType, @content, @contentHash, @payloadJson,
        @resultJson, @errorCode, @errorMessage, @processingStatus, @processingAttempts,
        @processingStartedAtMs, @processingCompletedAtMs, @receivedCount,
        @lastReceivedAtMs
      )
    `);
    const values = {
      dedupeKey: input.dedupeKey ?? null,
      recordedAtMs,
      occurredAtMs,
      completedAtMs: input.completedAtMs ?? null,
      durationMs: input.durationMs ?? null,
      direction: input.direction,
      operation: input.operation,
      deliveryStatus: input.deliveryStatus,
      routingStatus: input.routingStatus,
      source: input.source,
      sourceRef: input.sourceRef ?? null,
      correlationId: input.correlationId ?? null,
      apiMethod: input.apiMethod ?? null,
      telegramBotId: input.telegramBotId ?? null,
      telegramUpdateId: input.telegramUpdateId ?? null,
      telegramMessageId: input.telegramMessageId ?? null,
      telegramMessageIdsJson: stringify(input.telegramMessageIds),
      telegramChatId: input.telegramChatId ?? null,
      telegramTopicId: input.telegramTopicId ?? null,
      telegramUserId: input.telegramUserId ?? null,
      telegramUsername: input.telegramUsername ?? null,
      sessionId: input.sessionId ?? null,
      boundSessionId: input.boundSessionId ?? null,
      boundSessionCreatedAtMs: input.boundSessionCreatedAtMs ?? null,
      expectedChatId: input.expectedChatId ?? null,
      expectedTopicId: input.expectedTopicId ?? null,
      sessionCreatedAtMs: input.sessionCreatedAtMs ?? null,
      sessionKind: input.sessionKind ?? null,
      sessionCwd: input.sessionCwd ?? null,
      transcriptSessionId: input.transcriptSessionId ?? null,
      transcriptPath: input.transcriptPath ?? null,
      replyToMessageId: input.replyToMessageId ?? null,
      messageType: input.messageType,
      content: input.content ?? null,
      contentHash: hashContent(input.content) ?? null,
      payloadJson: stringify(input.payload),
      resultJson: stringify(input.result),
      errorCode: input.errorCode ?? null,
      errorMessage: input.errorMessage ?? null,
      processingStatus:
        input.processingStatus ?? (input.direction === "inbound" ? "pending" : null),
      processingAttempts: input.processingAttempts ?? 0,
      processingStartedAtMs: input.processingStartedAtMs ?? null,
      processingCompletedAtMs: input.processingCompletedAtMs ?? null,
      receivedCount: input.receivedCount ?? (input.direction === "inbound" ? 1 : 0),
      lastReceivedAtMs:
        input.lastReceivedAtMs ?? (input.direction === "inbound" ? recordedAtMs : null),
    };
    const inserted = statement.run(values);
    if (inserted.changes === 0 && input.dedupeKey) {
      this.db
        .prepare(
          `
          UPDATE telegram_message_events
          SET received_count = received_count + 1,
              last_received_at_ms = ?
          WHERE dedupe_key = ? AND direction = 'inbound'
        `
        )
        .run(recordedAtMs, input.dedupeKey);
    }
    const row =
      inserted.changes > 0
        ? this.db
            .prepare("SELECT * FROM telegram_message_events WHERE id = ?")
            .get(inserted.lastInsertRowid)
        : this.db
            .prepare("SELECT * FROM telegram_message_events WHERE dedupe_key = ?")
            .get(input.dedupeKey);
    if (!row) throw new Error("failed to read recorded Telegram message event");
    return { event: mapRow(row as SqlRow, true), inserted: inserted.changes > 0 };
  }

  claimInboundDispatch(
    id: number,
    leaseMs = DEFAULT_INBOUND_PROCESSING_LEASE_MS
  ): TelegramInboundDispatchClaim {
    const startedAtMs = Date.now();
    const leaseExpiredBeforeMs = startedAtMs - Math.max(0, leaseMs);
    const claimed = this.db
      .prepare(
        `
        UPDATE telegram_message_events SET
          processing_status = 'processing',
          processing_attempts = processing_attempts + 1,
          processing_started_at_ms = @startedAtMs,
          processing_completed_at_ms = NULL,
          processing_owner = @processingOwner,
          error_code = NULL,
          error_message = NULL
        WHERE id = @id
          AND direction = 'inbound'
          AND (
            processing_status IS NULL OR
            processing_status IN ('pending', 'failed') OR
            (
              processing_status = 'processing' AND
              (
                processing_started_at_ms IS NULL OR
                processing_started_at_ms <= @leaseExpiredBeforeMs
              )
            )
          )
      `
      )
      .run({ id, startedAtMs, leaseExpiredBeforeMs, processingOwner: this.processingOwner });
    const event = mapRow(this.rowById(id), true);
    if (claimed.changes > 0) return { status: "claimed", event };
    return {
      status: event.processingStatus === "processed" ? "processed" : "busy",
      event,
    };
  }

  completeInboundDispatch(id: number, completedAtMs = Date.now()): TelegramMessageAuditEvent {
    this.db
      .prepare(
        `
        UPDATE telegram_message_events SET
          processing_status = 'processed',
          processing_completed_at_ms = @completedAtMs,
          processing_owner = NULL,
          error_code = NULL,
          error_message = NULL
        WHERE id = @id
          AND direction = 'inbound'
          AND processing_status = 'processing'
          AND processing_owner = @processingOwner
      `
      )
      .run({ id, completedAtMs, processingOwner: this.processingOwner });
    return mapRow(this.rowById(id), true);
  }

  failInboundDispatch(
    id: number,
    failure: { errorCode?: string; errorMessage: string; completedAtMs?: number }
  ): TelegramMessageAuditEvent {
    const completedAtMs = failure.completedAtMs ?? Date.now();
    this.db
      .prepare(
        `
        UPDATE telegram_message_events SET
          processing_status = 'failed',
          processing_completed_at_ms = @completedAtMs,
          processing_owner = NULL,
          error_code = @errorCode,
          error_message = @errorMessage
        WHERE id = @id
          AND direction = 'inbound'
          AND processing_status = 'processing'
          AND processing_owner = @processingOwner
      `
      )
      .run({
        id,
        completedAtMs,
        processingOwner: this.processingOwner,
        errorCode: failure.errorCode ?? null,
        errorMessage: failure.errorMessage,
      });
    return mapRow(this.rowById(id), true);
  }

  completeOutbound(
    id: number,
    completion: CompleteTelegramOutboundInput
  ): TelegramMessageAuditEvent {
    const existing = this.rowById(id);
    const completedAtMs = completion.completedAtMs ?? Date.now();
    this.db
      .prepare(
        `
        UPDATE telegram_message_events SET
          delivery_status = 'sent',
          completed_at_ms = @completedAtMs,
          duration_ms = @durationMs,
          telegram_bot_id = COALESCE(@telegramBotId, telegram_bot_id),
          telegram_message_id = COALESCE(@telegramMessageId, telegram_message_id),
          telegram_message_ids_json = COALESCE(@telegramMessageIdsJson, telegram_message_ids_json),
          telegram_chat_id = COALESCE(@telegramChatId, telegram_chat_id),
          telegram_topic_id = COALESCE(@telegramTopicId, telegram_topic_id),
          telegram_user_id = COALESCE(@telegramUserId, telegram_user_id),
          telegram_username = COALESCE(@telegramUsername, telegram_username),
          result_json = @resultJson,
          error_code = NULL,
          error_message = NULL
        WHERE id = @id AND direction = 'outbound'
      `
      )
      .run({
        id,
        completedAtMs,
        durationMs: Math.max(0, completedAtMs - Number(existing.occurred_at_ms)),
        telegramBotId: completion.telegramBotId ?? null,
        telegramMessageId: completion.telegramMessageId ?? null,
        telegramMessageIdsJson: stringify(completion.telegramMessageIds),
        telegramChatId: completion.telegramChatId ?? null,
        telegramTopicId: completion.telegramTopicId ?? null,
        telegramUserId: completion.telegramUserId ?? null,
        telegramUsername: completion.telegramUsername ?? null,
        resultJson: stringify(completion.result),
      });
    return mapRow(this.rowById(id), true);
  }

  failOutbound(id: number, failure: FailTelegramOutboundInput): TelegramMessageAuditEvent {
    const existing = this.rowById(id);
    const completedAtMs = failure.completedAtMs ?? Date.now();
    this.db
      .prepare(
        `
        UPDATE telegram_message_events SET
          delivery_status = 'failed',
          completed_at_ms = @completedAtMs,
          duration_ms = @durationMs,
          result_json = @resultJson,
          error_code = @errorCode,
          error_message = @errorMessage
        WHERE id = @id AND direction = 'outbound'
      `
      )
      .run({
        id,
        completedAtMs,
        durationMs: Math.max(0, completedAtMs - Number(existing.occurred_at_ms)),
        resultJson: stringify(failure.result),
        errorCode: failure.errorCode ?? null,
        errorMessage: failure.errorMessage,
      });
    return mapRow(this.rowById(id), true);
  }

  query(query: TelegramMessageAuditQuery = {}): TelegramMessageAuditPage {
    const limit = Math.max(1, Math.min(query.limit ?? 100, 200));
    const where = queryWhere(query, true);
    const rows = this.db
      .prepare(
        `
        SELECT * FROM telegram_message_events
        ${where.sql}
        ORDER BY occurred_at_ms DESC, id DESC
        LIMIT ?
      `
      )
      .all(...where.values, limit + 1) as SqlRow[];
    const hasMore = rows.length > limit;
    const visible = rows.slice(0, limit);
    return {
      messages: visible.map((row) => mapRow(row, query.includeContent === true)),
      page: {
        limit,
        hasMore,
        nextCursor: hasMore && visible.length ? encodeCursor(visible[visible.length - 1]!) : null,
      },
    };
  }

  summarize(query: TelegramMessageAuditQuery = {}): TelegramMessageAuditSummary {
    const where = queryWhere(query, false);
    const countBy = (
      column: "direction" | "delivery_status" | "routing_status" | "processing_status"
    ) => {
      const rows = this.db
        .prepare(
          `
          SELECT ${column} AS value, COUNT(*) AS count
          FROM telegram_message_events
          ${where.sql}
          GROUP BY ${column}
        `
        )
        .all(...where.values) as SqlRow[];
      return Object.fromEntries(
        rows
          .filter((row) => row.value !== null && row.value !== undefined)
          .map((row) => [String(row.value), Number(row.count)])
      );
    };
    const totalRow = this.db
      .prepare(`SELECT COUNT(*) AS count FROM telegram_message_events ${where.sql}`)
      .get(...where.values) as SqlRow;
    const routeRows = this.db
      .prepare(
        `
        SELECT telegram_chat_id, telegram_topic_id, session_id, session_created_at_ms,
               COUNT(*) AS count
        FROM telegram_message_events
        ${where.sql}
        GROUP BY telegram_chat_id, telegram_topic_id, session_id, session_created_at_ms
        ORDER BY telegram_chat_id, telegram_topic_id, session_id, session_created_at_ms
      `
      )
      .all(...where.values) as SqlRow[];
    const routePairs = routeRows.map((row) => ({
      telegramChatId: optionalNumber(row.telegram_chat_id),
      telegramTopicId: optionalNumber(row.telegram_topic_id),
      sessionId: optionalString(row.session_id),
      sessionCreatedAtMs: optionalNumber(row.session_created_at_ms),
      count: Number(row.count),
    }));

    const topicGroups = new Map<
      string,
      { topic: SummaryTopicIdentity; sessions: Map<string, SummarySessionIdentity>; count: number }
    >();
    const sessionGroups = new Map<
      string,
      { session: SummarySessionIdentity; topics: Map<string, SummaryTopicIdentity>; count: number }
    >();
    for (const pair of routePairs) {
      if (pair.telegramTopicId !== undefined && pair.sessionId !== undefined) {
        const topicIdentity = {
          telegramChatId: pair.telegramChatId,
          telegramTopicId: pair.telegramTopicId,
        };
        const sessionIdentity = {
          sessionId: pair.sessionId,
          sessionCreatedAtMs: pair.sessionCreatedAtMs,
        };
        const topicKey = topicIdentityKey(topicIdentity);
        const sessionKey = sessionIdentityKey(sessionIdentity);
        const topicGroup = topicGroups.get(topicKey) ?? {
          topic: topicIdentity,
          sessions: new Map<string, SummarySessionIdentity>(),
          count: 0,
        };
        topicGroup.sessions.set(sessionKey, sessionIdentity);
        topicGroup.count += pair.count;
        topicGroups.set(topicKey, topicGroup);
        const sessionGroup = sessionGroups.get(sessionKey) ?? {
          session: sessionIdentity,
          topics: new Map<string, SummaryTopicIdentity>(),
          count: 0,
        };
        sessionGroup.topics.set(topicKey, topicIdentity);
        sessionGroup.count += pair.count;
        sessionGroups.set(sessionKey, sessionGroup);
      }
    }

    const deliveredWhere = where.sql
      ? `${where.sql} AND delivery_status = 'sent' AND telegram_topic_id IS NOT NULL`
      : "WHERE delivery_status = 'sent' AND telegram_topic_id IS NOT NULL";
    const deliveredRows = this.db
      .prepare(
        `
        SELECT source_ref, content_hash, substr(content, 1, 240) AS content_preview,
               telegram_chat_id, telegram_topic_id, session_id, session_created_at_ms,
               COUNT(*) AS count
        FROM telegram_message_events
        ${deliveredWhere}
        GROUP BY source_ref, content_hash, content_preview, telegram_chat_id,
                 telegram_topic_id, session_id, session_created_at_ms
      `
      )
      .all(...where.values) as SqlRow[];
    const sourceGroups = new Map<
      string,
      {
        topics: Map<string, SummaryTopicIdentity>;
        sessions: Map<string, SummarySessionIdentity>;
        count: number;
      }
    >();
    const contentGroups = new Map<
      string,
      {
        preview: string;
        topics: Map<string, SummaryTopicIdentity>;
        sessions: Map<string, SummarySessionIdentity>;
        count: number;
      }
    >();
    for (const row of deliveredRows) {
      const chatId = optionalNumber(row.telegram_chat_id);
      const topicId = optionalNumber(row.telegram_topic_id);
      const sessionId = optionalString(row.session_id);
      const sessionCreatedAtMs = optionalNumber(row.session_created_at_ms);
      const sourceRef = optionalString(row.source_ref);
      const contentHash = optionalString(row.content_hash);
      const count = Number(row.count);
      const topicIdentity =
        topicId === undefined ? undefined : { telegramChatId: chatId, telegramTopicId: topicId };
      const sessionIdentity =
        sessionId === undefined ? undefined : { sessionId, sessionCreatedAtMs };
      if (topicId !== undefined && sourceRef !== undefined) {
        const group = sourceGroups.get(sourceRef) ?? {
          topics: new Map<string, SummaryTopicIdentity>(),
          sessions: new Map<string, SummarySessionIdentity>(),
          count: 0,
        };
        group.topics.set(topicIdentityKey(topicIdentity!), topicIdentity!);
        if (sessionIdentity) {
          group.sessions.set(sessionIdentityKey(sessionIdentity), sessionIdentity);
        }
        group.count += count;
        sourceGroups.set(sourceRef, group);
      }
      if (topicId !== undefined && contentHash !== undefined) {
        const group = contentGroups.get(contentHash) ?? {
          preview: optionalString(row.content_preview) ?? "",
          topics: new Map<string, SummaryTopicIdentity>(),
          sessions: new Map<string, SummarySessionIdentity>(),
          count: 0,
        };
        group.topics.set(topicIdentityKey(topicIdentity!), topicIdentity!);
        if (sessionIdentity) {
          group.sessions.set(sessionIdentityKey(sessionIdentity), sessionIdentity);
        }
        group.count += count;
        contentGroups.set(contentHash, group);
      }
    }

    return {
      total: Number(totalRow.count),
      byDirection: countBy("direction"),
      byDeliveryStatus: countBy("delivery_status"),
      byRoutingStatus: countBy("routing_status"),
      byProcessingStatus: countBy("processing_status"),
      routePairs,
      anomalies: {
        topicsWithMultipleSessions: [...topicGroups]
          .filter(([, group]) => group.sessions.size > 1)
          .map(([, group]) => {
            const sessions = sortSessions([...group.sessions.values()]);
            return {
              ...group.topic,
              sessionIds: [...new Set(sessions.map((session) => session.sessionId))].sort(),
              sessions,
              count: group.count,
            };
          }),
        sessionsWithMultipleTopics: [...sessionGroups]
          .filter(([, group]) => group.topics.size > 1)
          .map(([, group]) => {
            const topics = sortTopics([...group.topics.values()]);
            return {
              ...group.session,
              topicIds: [...new Set(topics.map((topic) => topic.telegramTopicId))].sort(
                (a, b) => a - b
              ),
              topics,
              count: group.count,
            };
          }),
        sourcesDeliveredToMultipleTopics: [...sourceGroups]
          .filter(([, group]) => group.topics.size > 1)
          .map(([sourceRef, group]) => {
            const topics = sortTopics([...group.topics.values()]);
            return {
              sourceRef,
              topicIds: [...new Set(topics.map((topic) => topic.telegramTopicId))].sort(
                (a, b) => a - b
              ),
              topics,
              sessionIds: [
                ...new Set([...group.sessions.values()].map((session) => session.sessionId)),
              ].sort(),
              count: group.count,
            };
          }),
        contentDeliveredToMultipleTopics: [...contentGroups]
          .filter(([, group]) => group.topics.size > 1)
          .map(([contentHash, group]) => {
            const topics = sortTopics([...group.topics.values()]);
            return {
              contentHash,
              contentPreview: group.preview,
              topicIds: [...new Set(topics.map((topic) => topic.telegramTopicId))].sort(
                (a, b) => a - b
              ),
              topics,
              sessionIds: [
                ...new Set([...group.sessions.values()].map((session) => session.sessionId)),
              ].sort(),
              count: group.count,
            };
          }),
      },
    };
  }

  private rowById(id: number): SqlRow {
    const row = this.db.prepare("SELECT * FROM telegram_message_events WHERE id = ?").get(id);
    if (!row) throw new Error(`Telegram message event ${id} not found`);
    return row as SqlRow;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.db.close();
  }
}

export function createTelegramMessageAuditStore(filename: string): TelegramMessageAuditStore {
  return new TelegramMessageAuditStore(filename);
}

let defaultStore: TelegramMessageAuditStore | null = null;

export function getTelegramMessageAuditStore(): TelegramMessageAuditStore {
  if (defaultStore) return defaultStore;
  const dataDir = process.env.TERMINALX_DATA_DIR
    ? path.resolve(process.env.TERMINALX_DATA_DIR)
    : path.join(process.cwd(), "data");
  // This is a trusted operator-controlled persistence path, not a path from an
  // HTTP/Telegram user. It is intentionally allowed outside TERMINUS_ROOT so
  // Docker volumes and dedicated data disks can hold the audit database.
  const filename = process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH
    ? path.resolve(process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH)
    : path.join(dataDir, "telegram-messages.sqlite");
  defaultStore = createTelegramMessageAuditStore(filename);
  return defaultStore;
}

export function closeTelegramMessageAuditStore(): void {
  defaultStore?.close();
  defaultStore = null;
}
