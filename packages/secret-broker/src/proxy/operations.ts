import type { ProxyErrorCode, ProxyResultClass } from "./proxy-protocol";

/**
 * The typed operation registry. Each entry is a named, destination-scoped
 * provider operation with a fixed host, method, credential placement, a bounded
 * and validated parameter schema, and a bounded response projection. There is
 * deliberately no generic "HTTP request with credential" operation: a caller can
 * only ask for one of these named operations, and the response is projected to
 * the operation's allowlisted fields — a raw provider response is never
 * forwarded verbatim.
 */
export type ProxyProvider = "telegram" | "slack";

/** How the proxy attaches the credential to the built request. */
export type CredentialPlacement = "telegram-bot-path" | "telegram-file-path" | "slack-bearer";

export interface ProxyRequestPlan {
  readonly method: "GET" | "POST";
  /** Path segments appended after the credential prefix; each is fixed or validated. */
  readonly pathSegments: readonly string[];
  readonly query: Readonly<Record<string, string>>;
  readonly jsonBody: unknown | null;
  readonly maxResponseBytes: number;
}

export interface ProjectionOutcome {
  readonly resultClass: ProxyResultClass;
  readonly errorCode: ProxyErrorCode | null;
  readonly projection: Record<string, unknown> | null;
}

export interface ProjectionInput {
  readonly status: number;
  readonly body: Buffer;
}

export interface TypedProviderOperation {
  readonly id: string;
  readonly provider: ProxyProvider;
  readonly destinationHost: string;
  readonly credentialPlacement: CredentialPlacement;
  /** The exact set of fields the projection is allowed to carry. */
  readonly projectionFields: readonly string[];
  plan(params: unknown): ProxyRequestPlan;
  project(input: ProjectionInput): ProjectionOutcome;
}

/** Thrown by an operation's `plan` when its input is malformed or oversized. */
export class OperationInputError extends Error {
  readonly code: Extract<ProxyErrorCode, "invalid-params" | "params-too-large">;
  constructor(code: "invalid-params" | "params-too-large") {
    super(`operation input error: ${code}`);
    this.code = code;
    this.name = "OperationInputError";
  }
}

const JSON_RESPONSE_CAP = 64 * 1024;
const FILE_DOWNLOAD_CAP = 4 * 1024 * 1024;
const TELEGRAM_TEXT_MAX = 4096;
const SLACK_TEXT_MAX = 40_000;
const FILE_PATH = /^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,511})$/;

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new OperationInputError("invalid-params");
  }
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new OperationInputError("invalid-params");
  }
  return value as Record<string, unknown>;
}

function requireKeys(source: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(source)) {
    if (!allowed.includes(key)) throw new OperationInputError("invalid-params");
  }
}

function boundedText(value: unknown, max: number): string {
  if (typeof value !== "string" || value.length < 1)
    throw new OperationInputError("invalid-params");
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) {
    throw new OperationInputError("invalid-params");
  }
  if (value.length > max) throw new OperationInputError("params-too-large");
  return value;
}

function chatId(value: unknown): string {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new OperationInputError("invalid-params");
    return String(value);
  }
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 128 ||
    !/^[@a-zA-Z0-9_-]+$/.test(value)
  ) {
    throw new OperationInputError("invalid-params");
  }
  return value;
}

function slackChannel(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Z0-9]{1,64}$/.test(value)) {
    throw new OperationInputError("invalid-params");
  }
  return value;
}

function slackTs(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9]{1,20}\.[0-9]{1,20}$/.test(value)) {
    throw new OperationInputError("invalid-params");
  }
  return value;
}

function safeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new OperationInputError("invalid-params");
  }
  return value as number;
}

function optionalInteger(value: unknown): number | undefined {
  return value === undefined ? undefined : safeInteger(value);
}

function fileId(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new OperationInputError("invalid-params");
  }
  return value;
}

/**
 * Validate a Telegram `file_path`. This value is embedded in the request path
 * after `/file/bot<token>/`, so it is validated strictly to prevent traversal
 * (`..`), absolute escapes, backslashes, or control characters that could break
 * out of the credential-scoped prefix.
 */
function filePath(value: unknown): string {
  if (typeof value !== "string" || !FILE_PATH.test(value)) {
    throw new OperationInputError("invalid-params");
  }
  if (value.includes("..") || value.includes("//") || value.endsWith("/")) {
    throw new OperationInputError("invalid-params");
  }
  return value;
}

function parseJson(body: Buffer): Record<string, unknown> | null {
  try {
    const value = JSON.parse(body.toString("utf8")) as unknown;
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

function classifyHttp(status: number): ProjectionOutcome | null {
  if (status === 429) {
    return { resultClass: "retryable", errorCode: "rate-limited", projection: null };
  }
  if (status >= 500) {
    return { resultClass: "retryable", errorCode: "provider-error", projection: null };
  }
  return null;
}

function providerDeclined(): ProjectionOutcome {
  return { resultClass: "provider-error", errorCode: "provider-declined", projection: null };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function projectTelegramMessage(body: Buffer, fields: readonly string[]): ProjectionOutcome {
  const json = parseJson(body);
  if (!json || json.ok !== true) return providerDeclined();
  const result = asRecord(json.result);
  const projection: Record<string, unknown> = {};
  const messageId =
    result && Number.isSafeInteger(result.message_id) ? (result.message_id as number) : null;
  if (fields.includes("messageId")) projection.messageId = messageId;
  if (fields.includes("date")) {
    projection.date = result && Number.isSafeInteger(result.date) ? (result.date as number) : null;
  }
  if (fields.includes("edited")) projection.edited = true;
  return { resultClass: "ok", errorCode: null, projection };
}

export const TELEGRAM_SEND_MESSAGE: TypedProviderOperation = Object.freeze({
  id: "telegram.sendMessage",
  provider: "telegram",
  destinationHost: "api.telegram.org",
  credentialPlacement: "telegram-bot-path",
  projectionFields: Object.freeze(["messageId", "date"]),
  plan(params: unknown): ProxyRequestPlan {
    const source = record(params);
    requireKeys(source, ["chatId", "text", "replyToMessageId", "messageThreadId"]);
    const jsonBody: Record<string, unknown> = {
      chat_id: chatId(source.chatId),
      text: boundedText(source.text, TELEGRAM_TEXT_MAX),
    };
    const reply = optionalInteger(source.replyToMessageId);
    if (reply !== undefined) jsonBody.reply_to_message_id = reply;
    const thread = optionalInteger(source.messageThreadId);
    if (thread !== undefined) jsonBody.message_thread_id = thread;
    return {
      method: "POST",
      pathSegments: ["sendMessage"],
      query: {},
      jsonBody,
      maxResponseBytes: JSON_RESPONSE_CAP,
    };
  },
  project(input: ProjectionInput): ProjectionOutcome {
    return classifyHttp(input.status) ?? projectTelegramMessage(input.body, this.projectionFields);
  },
});

export const TELEGRAM_EDIT_MESSAGE_TEXT: TypedProviderOperation = Object.freeze({
  id: "telegram.editMessageText",
  provider: "telegram",
  destinationHost: "api.telegram.org",
  credentialPlacement: "telegram-bot-path",
  projectionFields: Object.freeze(["messageId", "edited"]),
  plan(params: unknown): ProxyRequestPlan {
    const source = record(params);
    requireKeys(source, ["chatId", "messageId", "text", "messageThreadId"]);
    const jsonBody: Record<string, unknown> = {
      chat_id: chatId(source.chatId),
      message_id: safeInteger(source.messageId),
      text: boundedText(source.text, TELEGRAM_TEXT_MAX),
    };
    const thread = optionalInteger(source.messageThreadId);
    if (thread !== undefined) jsonBody.message_thread_id = thread;
    return {
      method: "POST",
      pathSegments: ["editMessageText"],
      query: {},
      jsonBody,
      maxResponseBytes: JSON_RESPONSE_CAP,
    };
  },
  project(input: ProjectionInput): ProjectionOutcome {
    return classifyHttp(input.status) ?? projectTelegramMessage(input.body, this.projectionFields);
  },
});

export const TELEGRAM_GET_FILE: TypedProviderOperation = Object.freeze({
  id: "telegram.getFile",
  provider: "telegram",
  destinationHost: "api.telegram.org",
  credentialPlacement: "telegram-bot-path",
  projectionFields: Object.freeze(["fileUniqueId", "fileSize", "filePath"]),
  plan(params: unknown): ProxyRequestPlan {
    const source = record(params);
    requireKeys(source, ["fileId"]);
    return {
      method: "GET",
      pathSegments: ["getFile"],
      query: { file_id: fileId(source.fileId) },
      jsonBody: null,
      maxResponseBytes: JSON_RESPONSE_CAP,
    };
  },
  project(input: ProjectionInput): ProjectionOutcome {
    const http = classifyHttp(input.status);
    if (http) return http;
    const json = parseJson(input.body);
    if (!json || json.ok !== true) return providerDeclined();
    const result = asRecord(json.result);
    if (!result) return providerDeclined();
    // file_path is a provider-internal path, NOT the bot token; the download URL
    // that embeds the token is built inside the proxy and never returned.
    const path = typeof result.file_path === "string" ? result.file_path : null;
    return {
      resultClass: "ok",
      errorCode: null,
      projection: {
        fileUniqueId: typeof result.file_unique_id === "string" ? result.file_unique_id : null,
        fileSize: Number.isSafeInteger(result.file_size) ? (result.file_size as number) : null,
        filePath: path,
      },
    };
  },
});

export const TELEGRAM_DOWNLOAD_FILE: TypedProviderOperation = Object.freeze({
  id: "telegram.downloadFile",
  provider: "telegram",
  destinationHost: "api.telegram.org",
  credentialPlacement: "telegram-file-path",
  projectionFields: Object.freeze(["contentBase64", "byteLength"]),
  plan(params: unknown): ProxyRequestPlan {
    const source = record(params);
    requireKeys(source, ["filePath"]);
    return {
      method: "GET",
      pathSegments: [filePath(source.filePath)],
      query: {},
      jsonBody: null,
      maxResponseBytes: FILE_DOWNLOAD_CAP,
    };
  },
  project(input: ProjectionInput): ProjectionOutcome {
    const http = classifyHttp(input.status);
    if (http) return http;
    if (input.status !== 200) return providerDeclined();
    // File content is not credential material; it is safe to return to the
    // caller. The token-bearing download URL is never surfaced.
    return {
      resultClass: "ok",
      errorCode: null,
      projection: {
        contentBase64: input.body.toString("base64"),
        byteLength: input.body.byteLength,
      },
    };
  },
});

function projectSlackOk(
  body: Buffer,
  build: (result: Record<string, unknown>, json: Record<string, unknown>) => Record<string, unknown>
): ProjectionOutcome {
  const json = parseJson(body);
  if (!json) return providerDeclined();
  if (json.ok !== true) return providerDeclined();
  return { resultClass: "ok", errorCode: null, projection: build(json, json) };
}

export const SLACK_CHAT_POST_MESSAGE: TypedProviderOperation = Object.freeze({
  id: "slack.chat.postMessage",
  provider: "slack",
  destinationHost: "slack.com",
  credentialPlacement: "slack-bearer",
  projectionFields: Object.freeze(["ts", "channel"]),
  plan(params: unknown): ProxyRequestPlan {
    const source = record(params);
    requireKeys(source, ["channel", "text", "threadTs"]);
    const jsonBody: Record<string, unknown> = {
      channel: slackChannel(source.channel),
      text: boundedText(source.text, SLACK_TEXT_MAX),
    };
    if (source.threadTs !== undefined) jsonBody.thread_ts = slackTs(source.threadTs);
    return {
      method: "POST",
      pathSegments: ["api", "chat.postMessage"],
      query: {},
      jsonBody,
      maxResponseBytes: JSON_RESPONSE_CAP,
    };
  },
  project(input: ProjectionInput): ProjectionOutcome {
    return (
      classifyHttp(input.status) ??
      projectSlackOk(input.body, (json) => ({
        ts: typeof json.ts === "string" ? json.ts : null,
        channel: typeof json.channel === "string" ? json.channel : null,
      }))
    );
  },
});

export const SLACK_CHAT_UPDATE: TypedProviderOperation = Object.freeze({
  id: "slack.chat.update",
  provider: "slack",
  destinationHost: "slack.com",
  credentialPlacement: "slack-bearer",
  projectionFields: Object.freeze(["ts", "channel"]),
  plan(params: unknown): ProxyRequestPlan {
    const source = record(params);
    requireKeys(source, ["channel", "ts", "text"]);
    return {
      method: "POST",
      pathSegments: ["api", "chat.update"],
      query: {},
      jsonBody: {
        channel: slackChannel(source.channel),
        ts: slackTs(source.ts),
        text: boundedText(source.text, SLACK_TEXT_MAX),
      },
      maxResponseBytes: JSON_RESPONSE_CAP,
    };
  },
  project(input: ProjectionInput): ProjectionOutcome {
    return (
      classifyHttp(input.status) ??
      projectSlackOk(input.body, (json) => ({
        ts: typeof json.ts === "string" ? json.ts : null,
        channel: typeof json.channel === "string" ? json.channel : null,
      }))
    );
  },
});

export const SLACK_CONVERSATIONS_INFO: TypedProviderOperation = Object.freeze({
  id: "slack.conversations.info",
  provider: "slack",
  destinationHost: "slack.com",
  credentialPlacement: "slack-bearer",
  projectionFields: Object.freeze(["channelId", "name", "isPrivate"]),
  plan(params: unknown): ProxyRequestPlan {
    const source = record(params);
    requireKeys(source, ["channel"]);
    return {
      method: "GET",
      pathSegments: ["api", "conversations.info"],
      query: { channel: slackChannel(source.channel) },
      jsonBody: null,
      maxResponseBytes: JSON_RESPONSE_CAP,
    };
  },
  project(input: ProjectionInput): ProjectionOutcome {
    return (
      classifyHttp(input.status) ??
      projectSlackOk(input.body, (json) => {
        const channel = asRecord(json.channel);
        return {
          channelId: channel && typeof channel.id === "string" ? channel.id : null,
          name: channel && typeof channel.name === "string" ? channel.name : null,
          isPrivate: channel && typeof channel.is_private === "boolean" ? channel.is_private : null,
        };
      })
    );
  },
});

const ALL_OPERATIONS: readonly TypedProviderOperation[] = Object.freeze([
  TELEGRAM_SEND_MESSAGE,
  TELEGRAM_EDIT_MESSAGE_TEXT,
  TELEGRAM_GET_FILE,
  TELEGRAM_DOWNLOAD_FILE,
  SLACK_CHAT_POST_MESSAGE,
  SLACK_CHAT_UPDATE,
  SLACK_CONVERSATIONS_INFO,
]);

/** The immutable, closed registry keyed by operation id. */
export const CREDENTIAL_PROXY_OPERATIONS: ReadonlyMap<string, TypedProviderOperation> = new Map(
  ALL_OPERATIONS.map((operation) => [operation.id, operation])
);

/** The exact set of destination hosts any operation may target. */
export const CREDENTIAL_PROXY_ALLOWED_HOSTS: ReadonlySet<string> = new Set(
  ALL_OPERATIONS.map((operation) => operation.destinationHost)
);
