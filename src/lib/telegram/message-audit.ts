import { AsyncLocalStorage } from "async_hooks";
import * as crypto from "crypto";
import * as path from "path";
import type { Bot, Context, Transformer } from "grammy";
import { getSessionCreatedMs } from "@/lib/tmux";
import { getTelegramConfig } from "./config";
import {
  getTelegramMessageAuditStore,
  type TelegramMessageAuditStore,
  type TelegramMessageOperation,
} from "./message-audit-store";
import { getForumChatId, getTopic, listTopics, type TopicBinding } from "./state";

export interface TelegramMessageAuditSource {
  source: string;
  sourceRef?: string;
  correlationId?: string;
  sessionId?: string;
  sessionCreatedAtMs?: number;
  expectedChatId?: number;
  expectedTopicId?: number;
  transcriptSessionId?: string;
  transcriptPath?: string;
}

interface ActiveAuditSource extends TelegramMessageAuditSource {
  active: boolean;
}

interface TelegramMessageAuditorOptions {
  store: TelegramMessageAuditStore;
  telegramBotId?: number;
  resolveForumChatId?: () => number | undefined;
  resolveTopic?: (topicId: number, chatId?: number) => TopicBinding | undefined;
  resolveMessageTopic?: (messageId: number, chatId?: number) => TopicBinding | undefined;
  resolveSessionCreatedAtMs?: (sessionId: string) => number | null;
}

type JsonObject = Record<string, unknown>;

const sourceStorage = new AsyncLocalStorage<ActiveAuditSource>();

const SEND_METHODS = new Set([
  "sendMessage",
  "sendPhoto",
  "sendAudio",
  "sendDocument",
  "sendVideo",
  "sendAnimation",
  "sendVoice",
  "sendVideoNote",
  "sendMediaGroup",
  "sendPaidMedia",
  "sendLocation",
  "sendVenue",
  "sendContact",
  "sendPoll",
  "sendChecklist",
  "sendDice",
  "sendSticker",
  "sendInvoice",
  "sendGame",
  "copyMessage",
  "forwardMessage",
  "copyMessages",
  "forwardMessages",
]);

const EDIT_METHODS = new Set([
  "editMessageText",
  "editMessageCaption",
  "editMessageMedia",
  "editMessageReplyMarkup",
  "editMessageLiveLocation",
  "stopMessageLiveLocation",
  "stopPoll",
  "editMessageChecklist",
]);

function asObject(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function apiOperation(method: string): TelegramMessageOperation | null {
  if (SEND_METHODS.has(method)) return "send";
  if (EDIT_METHODS.has(method)) return "edit";
  return null;
}

function outboundMessageType(method: string): string {
  if (method === "sendMessage" || method === "editMessageText") return "text";
  return (
    method
      .replace(/^(send|editMessage|copyMessage|forwardMessage)/, "")
      .replace(/^[A-Z]/, (value) => value.toLowerCase()) || "message"
  );
}

function inboundMessageType(message: JsonObject | undefined, updateType: string): string {
  if (!message) return updateType;
  const known = [
    "text",
    "photo",
    "document",
    "voice",
    "audio",
    "video",
    "animation",
    "video_note",
    "sticker",
    "location",
    "venue",
    "contact",
    "poll",
    "dice",
    "new_chat_members",
    "left_chat_member",
    "forum_topic_created",
    "forum_topic_closed",
    "forum_topic_reopened",
    "forum_topic_edited",
  ];
  return known.find((key) => message[key] !== undefined) ?? updateType;
}

function contentFromPayload(payload: JsonObject): string | undefined {
  return (
    asString(payload.text) ??
    asString(payload.caption) ??
    asString(payload.question) ??
    asString(payload.explanation)
  );
}

function transcriptId(transcriptPath: string | undefined): string | undefined {
  return transcriptPath ? path.basename(transcriptPath, path.extname(transcriptPath)) : undefined;
}

function replyToMessageId(payload: JsonObject): number | undefined {
  const replyParameters = asObject(payload.reply_parameters);
  return asNumber(replyParameters?.message_id) ?? asNumber(payload.reply_to_message_id);
}

function routingStatus(
  chatId: number | undefined,
  topicId: number | undefined,
  binding: TopicBinding | undefined,
  source: ActiveAuditSource | undefined,
  expectedChatId: number | undefined
): "matched" | "mismatch" | "unbound" | "unknown" {
  if (expectedChatId !== undefined && chatId !== expectedChatId) return "mismatch";
  if (topicId === undefined) return "unknown";
  if (source?.expectedTopicId !== undefined && topicId !== source.expectedTopicId)
    return "mismatch";
  if (source?.sessionId && binding && source.sessionId !== binding.sessionName) return "mismatch";
  if (
    source?.sessionCreatedAtMs !== undefined &&
    binding?.sessionCreatedAtMs !== undefined &&
    source.sessionCreatedAtMs !== binding.sessionCreatedAtMs
  )
    return "mismatch";
  return binding ? "matched" : "unbound";
}

function responseMessages(response: JsonObject): JsonObject[] {
  if (response.ok !== true) return [];
  const result = response.result;
  if (Array.isArray(result)) {
    return result.map(asObject).filter((item): item is JsonObject => item !== undefined);
  }
  const message = asObject(result);
  return message ? [message] : [];
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const FINALIZATION_RETRY_DELAYS_MS = [0, 25, 100] as const;

async function retryAuditFinalization(
  failureMessage: string,
  action: () => void
): Promise<boolean> {
  let lastError: unknown;
  for (const delayMs of FINALIZATION_RETRY_DELAYS_MS) {
    if (delayMs > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
    }
    try {
      action();
      return true;
    } catch (error) {
      lastError = error;
    }
  }
  console.error(`[telegram/audit] ${failureMessage}:`, errorMessage(lastError));
  return false;
}

export async function withTelegramMessageAuditSource<T>(
  source: TelegramMessageAuditSource,
  callback: () => T | Promise<T>
): Promise<T> {
  const active: ActiveAuditSource = { ...source, active: true };
  return sourceStorage.run(active, async () => {
    try {
      return await callback();
    } finally {
      active.active = false;
    }
  });
}

export function createTelegramMessageAuditor(options: TelegramMessageAuditorOptions) {
  const configuredForumChatId =
    options.resolveForumChatId ??
    (() => getTelegramConfig().forumChatId || getForumChatId() || undefined);
  const chatMatches = (chatId: number | undefined) => {
    const expectedChatId = configuredForumChatId();
    return chatId === undefined || expectedChatId === undefined || chatId === expectedChatId;
  };
  const resolveTopic =
    options.resolveTopic ??
    ((topicId: number, chatId?: number) => (chatMatches(chatId) ? getTopic(topicId) : undefined));
  const resolveMessageTopic =
    options.resolveMessageTopic ??
    ((messageId: number, chatId?: number) =>
      chatMatches(chatId)
        ? listTopics().find((binding) => binding.pinnedMsgId === messageId)
        : undefined);
  const resolveSessionCreatedAtMs = options.resolveSessionCreatedAtMs ?? getSessionCreatedMs;
  let telegramBotId = options.telegramBotId;

  const recordInboundUpdate = (updateValue: object, botIdOverride?: number) => {
    const update = updateValue as JsonObject;
    const updateId = asNumber(update.update_id);
    const messageKeys = [
      "message",
      "edited_message",
      "channel_post",
      "edited_channel_post",
      "business_message",
      "edited_business_message",
    ];
    const updateType =
      messageKeys.find((key) => asObject(update[key])) ??
      (asObject(update.callback_query) ? "callback_query" : "unknown");
    const callback = asObject(update.callback_query);
    const message =
      messageKeys.map((key) => asObject(update[key])).find(Boolean) ?? asObject(callback?.message);
    const chat = asObject(message?.chat);
    const from = asObject(callback?.from) ?? asObject(message?.from);
    const chatId = asNumber(chat?.id);
    const topicId = asNumber(message?.message_thread_id);
    const binding = topicId === undefined ? undefined : resolveTopic(topicId, chatId);
    const sessionId = binding?.sessionName;
    const transcriptPath = binding?.jsonlPath;
    const messageDate = asNumber(message?.date);
    const reply = asObject(message?.reply_to_message);
    const content =
      asString(message?.text) ?? asString(message?.caption) ?? asString(callback?.data);
    const sourceRef = updateId === undefined ? undefined : `update:${updateId}`;
    const botId = botIdOverride ?? telegramBotId;
    const dedupeIdentity = botId ?? "unknown";
    const expectedChatId = configuredForumChatId();
    return options.store.recordOnce({
      dedupeKey:
        updateId === undefined
          ? `inbound:unknown:${crypto.randomUUID()}`
          : `inbound:${dedupeIdentity}:${updateId}`,
      direction: "inbound",
      operation: "receive",
      deliveryStatus: "received",
      routingStatus:
        expectedChatId !== undefined && chatId !== expectedChatId
          ? "mismatch"
          : topicId === undefined
            ? "unknown"
            : binding
              ? "matched"
              : "unbound",
      source: "telegram-webhook",
      sourceRef,
      correlationId: sourceRef,
      telegramBotId: botId,
      telegramUpdateId: updateId,
      telegramMessageId: asNumber(message?.message_id),
      telegramChatId: chatId,
      telegramTopicId: topicId,
      telegramUserId: asNumber(from?.id),
      telegramUsername: asString(from?.username),
      sessionId,
      boundSessionId: sessionId,
      boundSessionCreatedAtMs: binding?.sessionCreatedAtMs,
      expectedChatId,
      expectedTopicId: binding?.topicId,
      sessionCreatedAtMs:
        binding?.sessionCreatedAtMs ??
        (sessionId ? (resolveSessionCreatedAtMs(sessionId) ?? undefined) : undefined),
      sessionKind: binding?.kind,
      sessionCwd: binding?.cwd,
      transcriptSessionId: binding?.transcriptSessionId ?? transcriptId(transcriptPath),
      transcriptPath,
      replyToMessageId: asNumber(reply?.message_id),
      messageType: inboundMessageType(message, updateType),
      content,
      payload: updateValue,
      occurredAtMs: messageDate === undefined ? Date.now() : messageDate * 1000,
    });
  };

  const transformer: Transformer = async (prev, method, payload, signal) => {
    const operation = apiOperation(method);
    if (!operation) return prev(method, payload, signal);

    const rawPayload = payload as JsonObject;
    const chatId = asNumber(rawPayload.chat_id);
    const payloadTopicId = asNumber(rawPayload.message_thread_id);
    const messageId = asNumber(rawPayload.message_id);
    const binding =
      payloadTopicId !== undefined
        ? resolveTopic(payloadTopicId, chatId)
        : operation === "edit" && messageId !== undefined
          ? resolveMessageTopic(messageId, chatId)
          : undefined;
    const topicId = payloadTopicId ?? binding?.topicId;
    const activeSource = sourceStorage.getStore();
    const source = activeSource?.active ? activeSource : undefined;
    const sessionId = source?.sessionId ?? binding?.sessionName;
    const boundSessionId = binding?.sessionName;
    const expectedTopicId = source?.expectedTopicId ?? binding?.topicId;
    const expectedChatId = source?.expectedChatId ?? configuredForumChatId();
    const transcriptPath = source?.transcriptPath ?? binding?.jsonlPath;
    const apiCallId = crypto.randomUUID();
    const correlationId = source?.correlationId ?? apiCallId;
    const startedAtMs = Date.now();
    // Fail closed before contacting Telegram: a message that cannot get a
    // durable pending row must not become an untraceable delivery.
    const auditId = options.store.record({
      dedupeKey: `outbound:${apiCallId}`,
      direction: "outbound",
      operation,
      deliveryStatus: "pending",
      routingStatus: routingStatus(chatId, topicId, binding, source, expectedChatId),
      source: source?.source ?? "telegram-api",
      sourceRef: source?.sourceRef ?? transcriptPath,
      correlationId,
      apiMethod: method,
      telegramBotId,
      telegramMessageId: messageId,
      telegramChatId: chatId,
      telegramTopicId: topicId,
      sessionId,
      boundSessionId,
      boundSessionCreatedAtMs: binding?.sessionCreatedAtMs,
      expectedChatId,
      expectedTopicId,
      sessionCreatedAtMs:
        source?.sessionCreatedAtMs ??
        binding?.sessionCreatedAtMs ??
        (sessionId ? (resolveSessionCreatedAtMs(sessionId) ?? undefined) : undefined),
      sessionKind: binding?.kind,
      sessionCwd: binding?.cwd,
      transcriptSessionId:
        source?.transcriptSessionId ?? binding?.transcriptSessionId ?? transcriptId(transcriptPath),
      transcriptPath,
      replyToMessageId: replyToMessageId(rawPayload),
      messageType: outboundMessageType(method),
      content: contentFromPayload(rawPayload),
      payload: rawPayload,
      occurredAtMs: startedAtMs,
    }).id;

    try {
      const response = await prev(method, payload, signal);
      const rawResponse = response as unknown as JsonObject;
      if (auditId !== undefined) {
        if (rawResponse.ok === true) {
          const sentMessages = responseMessages(rawResponse);
          const sent = sentMessages[0];
          const telegramMessageIds = sentMessages
            .map((message) => asNumber(message.message_id))
            .filter((messageId): messageId is number => messageId !== undefined);
          const chat = asObject(sent?.chat);
          const from = asObject(sent?.from);
          const completion = {
            telegramBotId: asNumber(from?.id) ?? telegramBotId,
            telegramMessageId: telegramMessageIds[0],
            telegramMessageIds,
            telegramChatId: asNumber(chat?.id),
            telegramTopicId: asNumber(sent?.message_thread_id),
            telegramUserId: asNumber(from?.id),
            telegramUsername: asString(from?.username),
            completedAtMs: Date.now(),
            result: rawResponse,
          };
          await retryAuditFinalization("failed to finalize outbound attempt", () => {
            options.store.completeOutbound(auditId, {
              ...completion,
            });
          });
        } else {
          const failure = {
            errorCode:
              rawResponse.error_code === undefined ? undefined : String(rawResponse.error_code),
            errorMessage: asString(rawResponse.description) ?? "Telegram API call failed",
            completedAtMs: Date.now(),
            result: rawResponse,
          };
          await retryAuditFinalization("failed to finalize outbound attempt", () => {
            options.store.failOutbound(auditId, {
              ...failure,
            });
          });
        }
      }
      return response;
    } catch (error) {
      if (auditId !== undefined) {
        const failure = {
          errorCode: error instanceof Error ? error.name : "transport_error",
          errorMessage: errorMessage(error),
          completedAtMs: Date.now(),
        };
        await retryAuditFinalization("failed to record outbound failure", () => {
          options.store.failOutbound(auditId, {
            ...failure,
          });
        });
      }
      throw error;
    }
  };

  const setTelegramBotId = (botId: number | undefined) => {
    telegramBotId = botId;
  };

  return {
    recordInboundUpdate,
    claimInboundDispatch: (id: number) => options.store.claimInboundDispatch(id),
    completeInboundDispatch: (id: number) =>
      retryAuditFinalization("failed to record inbound handler completion", () => {
        options.store.completeInboundDispatch(id);
      }),
    failInboundDispatch: (id: number, error: unknown) => {
      const failure = {
        errorCode: error instanceof Error ? error.name : "handler_error",
        errorMessage: errorMessage(error),
      };
      return retryAuditFinalization("failed to record inbound handler failure", () => {
        options.store.failInboundDispatch(id, failure);
      });
    },
    transformer,
    setTelegramBotId,
  };
}

let defaultAuditor: ReturnType<typeof createTelegramMessageAuditor> | null = null;

export function getTelegramMessageAuditor() {
  defaultAuditor ??= createTelegramMessageAuditor({ store: getTelegramMessageAuditStore() });
  return defaultAuditor;
}

const auditedBots = new WeakSet<object>();

export function installTelegramMessageAudit<C extends Context>(
  bot: Bot<C>,
  auditor = getTelegramMessageAuditor()
): void {
  if (auditedBots.has(bot)) return;
  auditedBots.add(bot);
  try {
    auditor.setTelegramBotId(bot.botInfo.id);
  } catch {
    // botInfo is unavailable until bot.init(); successful send results still
    // carry the bot's Telegram id and will fill it during finalization.
  }
  bot.api.config.use(auditor.transformer);
}
