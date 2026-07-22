import { NextRequest, NextResponse } from "next/server";
import { getUserScoping } from "@/lib/session-scope";
import {
  getTelegramMessageAuditStore,
  type TelegramMessageAuditQuery,
  type TelegramMessageDeliveryStatus,
  type TelegramMessageDirection,
  type TelegramMessageOperation,
  type TelegramMessageProcessingStatus,
  type TelegramMessageRoutingStatus,
} from "@/lib/telegram/message-audit-store";

export const runtime = "nodejs";

class InvalidQuery extends Error {}

const RESPONSE_HEADERS = { "Cache-Control": "private, no-store" };

function json(body: unknown, status = 200): NextResponse {
  return NextResponse.json(body, { status, headers: RESPONSE_HEADERS });
}

const DIRECTIONS = new Set<TelegramMessageDirection>(["inbound", "outbound"]);
const OPERATIONS = new Set<TelegramMessageOperation>(["receive", "send", "edit"]);
const DELIVERY_STATUSES = new Set<TelegramMessageDeliveryStatus>([
  "received",
  "pending",
  "sent",
  "failed",
]);
const ROUTING_STATUSES = new Set<TelegramMessageRoutingStatus>([
  "matched",
  "mismatch",
  "unbound",
  "unknown",
]);
const PROCESSING_STATUSES = new Set<TelegramMessageProcessingStatus>([
  "pending",
  "processing",
  "processed",
  "failed",
]);

function enumParam<T extends string>(
  params: URLSearchParams,
  name: string,
  allowed: Set<T>
): T | undefined {
  const value = params.get(name);
  if (value === null) return undefined;
  if (!allowed.has(value as T)) {
    throw new InvalidQuery(`${name} must be one of: ${[...allowed].join(", ")}`);
  }
  return value as T;
}

function integerParam(
  params: URLSearchParams,
  name: string,
  opts: { positive?: boolean } = {}
): number | undefined {
  const raw = params.get(name);
  if (raw === null) return undefined;
  if (!/^-?\d+$/.test(raw)) {
    throw new InvalidQuery(`${name} must be a ${opts.positive ? "positive " : ""}integer`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || (opts.positive && value <= 0)) {
    throw new InvalidQuery(`${name} must be a ${opts.positive ? "positive " : ""}integer`);
  }
  return value;
}

function textParam(
  params: URLSearchParams,
  name: string,
  opts: { pattern?: RegExp; maxLength?: number } = {}
): string | undefined {
  const raw = params.get(name);
  if (raw === null) return undefined;
  if (!raw || raw.length > (opts.maxLength ?? 200) || (opts.pattern && !opts.pattern.test(raw))) {
    throw new InvalidQuery(`${name} is invalid`);
  }
  return raw;
}

function dateParam(params: URLSearchParams, name: string): number | undefined {
  const raw = params.get(name);
  if (raw === null) return undefined;
  const value = Date.parse(raw);
  if (!Number.isFinite(value)) throw new InvalidQuery(`${name} must be an ISO timestamp`);
  return value;
}

function parseQuery(url: string): {
  query: TelegramMessageAuditQuery;
  includeSummary: boolean;
} {
  const params = new URL(url).searchParams;
  const rawLimit = params.get("limit");
  let limit = 100;
  if (rawLimit !== null) {
    if (!/^\d+$/.test(rawLimit)) throw new InvalidQuery("limit must be an integer from 1 to 200");
    limit = Number(rawLimit);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new InvalidQuery("limit must be an integer from 1 to 200");
    }
  }
  const rawIncludeContent = params.get("includeContent");
  if (rawIncludeContent !== null && rawIncludeContent !== "true" && rawIncludeContent !== "false") {
    throw new InvalidQuery("includeContent must be true or false");
  }
  const rawIncludeSummary = params.get("includeSummary");
  if (rawIncludeSummary !== null && rawIncludeSummary !== "true" && rawIncludeSummary !== "false") {
    throw new InvalidQuery("includeSummary must be true or false");
  }
  const fromMs = dateParam(params, "from");
  const toMs = dateParam(params, "to");
  if (fromMs !== undefined && toMs !== undefined && fromMs > toMs) {
    throw new InvalidQuery("from must not be after to");
  }
  return {
    includeSummary: rawIncludeSummary === "true",
    query: {
      limit,
      includeContent: rawIncludeContent === "true",
      cursor: textParam(params, "cursor", { maxLength: 500 }),
      direction: enumParam(params, "direction", DIRECTIONS),
      operation: enumParam(params, "operation", OPERATIONS),
      deliveryStatus: enumParam(params, "deliveryStatus", DELIVERY_STATUSES),
      routingStatus: enumParam(params, "routingStatus", ROUTING_STATUSES),
      processingStatus: enumParam(params, "processingStatus", PROCESSING_STATUSES),
      source: textParam(params, "source"),
      messageType: textParam(params, "messageType"),
      sessionId: textParam(params, "sessionId", {
        pattern: /^[a-zA-Z0-9_.-]+$/,
        maxLength: 128,
      }),
      telegramBotId: integerParam(params, "botId", { positive: true }),
      telegramUpdateId: integerParam(params, "updateId", { positive: true }),
      telegramMessageId: integerParam(params, "messageId", { positive: true }),
      telegramChatId: integerParam(params, "chatId"),
      telegramTopicId: integerParam(params, "topicId", { positive: true }),
      telegramUserId: integerParam(params, "telegramUserId", { positive: true }),
      fromMs,
      toMs,
    },
  };
}

export async function GET(req: NextRequest) {
  const identity = getUserScoping(req.headers);
  if (!identity.hasIdentity || identity.role !== "admin") {
    return json({ error: "admin required" }, 403);
  }

  let parsed: ReturnType<typeof parseQuery>;
  try {
    parsed = parseQuery(req.url);
  } catch (error) {
    if (error instanceof InvalidQuery) {
      return json({ error: error.message }, 400);
    }
    return json({ error: "invalid query" }, 400);
  }

  try {
    const store = getTelegramMessageAuditStore();
    const result = store.query(parsed.query);
    return json({
      messages: result.messages,
      page: result.page,
      ...(parsed.includeSummary ? { summary: store.summarize(parsed.query) } : {}),
    });
  } catch (error) {
    if (error instanceof Error && error.message === "invalid cursor") {
      return json({ error: "invalid cursor" }, 400);
    }
    console.error(
      "[telegram/audit] query failed:",
      error instanceof Error ? error.message : String(error)
    );
    return json({ error: "failed to query Telegram messages" }, 500);
  }
}
