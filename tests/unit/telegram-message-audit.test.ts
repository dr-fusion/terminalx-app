import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Bot, InputFile, type Context } from "grammy";
import type { ApiResponse } from "grammy/types";
import {
  createTelegramMessageAuditStore,
  type TelegramMessageAuditStore,
} from "@/lib/telegram/message-audit-store";
import {
  createTelegramMessageAuditor,
  installTelegramMessageAudit,
  withTelegramMessageAuditSource,
} from "@/lib/telegram/message-audit";

describe("Telegram message auditing boundaries", () => {
  let store: TelegramMessageAuditStore;

  beforeEach(() => {
    store = createTelegramMessageAuditStore(":memory:");
  });

  afterEach(() => {
    store.close();
  });

  it("stores a topic message before dispatch and deduplicates webhook retries", () => {
    const auditor = createTelegramMessageAuditor({
      store,
      resolveForumChatId: () => -1001234567890,
      resolveTopic: (topicId) =>
        topicId === 77
          ? {
              topicId: 77,
              sessionName: "admin-alpha",
              sessionCreatedAtMs: 1_784_600_000_000,
              kind: "codex",
              cwd: "/srv/alpha",
              jsonlPath: "/srv/transcripts/alpha.jsonl",
            }
          : undefined,
      resolveSessionCreatedAtMs: () => 1_784_700_000_000,
    });
    const update = {
      update_id: 9001,
      message: {
        message_id: 501,
        message_thread_id: 77,
        date: 1_784_760_000,
        chat: { id: -1001234567890, type: "supergroup" },
        from: { id: 42, username: "alice" },
        reply_to_message: { message_id: 499 },
        text: "deploy alpha",
      },
    };

    const first = auditor.recordInboundUpdate(update, 777);
    const retry = auditor.recordInboundUpdate(update, 777);

    expect(first.inserted).toBe(true);
    expect(retry.inserted).toBe(false);
    expect(retry.event.id).toBe(first.event.id);
    expect(store.query({ includeContent: true }).messages).toEqual([
      expect.objectContaining({
        direction: "inbound",
        operation: "receive",
        deliveryStatus: "received",
        processingStatus: "pending",
        processingAttempts: 0,
        receivedCount: 2,
        routingStatus: "matched",
        source: "telegram-webhook",
        sourceRef: "update:9001",
        correlationId: "update:9001",
        telegramBotId: 777,
        telegramUpdateId: 9001,
        telegramMessageId: 501,
        telegramChatId: -1001234567890,
        telegramTopicId: 77,
        telegramUserId: 42,
        telegramUsername: "alice",
        sessionId: "admin-alpha",
        boundSessionId: "admin-alpha",
        boundSessionCreatedAtMs: 1_784_600_000_000,
        expectedTopicId: 77,
        sessionCreatedAtMs: 1_784_600_000_000,
        sessionKind: "codex",
        sessionCwd: "/srv/alpha",
        transcriptPath: "/srv/transcripts/alpha.jsonl",
        replyToMessageId: 499,
        messageType: "text",
        content: "deploy alpha",
        occurredAtMs: 1_784_760_000_000,
        payload: update,
      }),
    ]);
  });

  it("attributes callback queries to the human who clicked the button", () => {
    const auditor = createTelegramMessageAuditor({ store });

    auditor.recordInboundUpdate({
      update_id: 9002,
      callback_query: {
        id: "callback-1",
        from: { id: 42, username: "alice" },
        data: "approve",
        message: {
          message_id: 502,
          message_thread_id: 77,
          date: 1_784_760_001,
          chat: { id: -1001234567890, type: "supergroup" },
          from: { id: 777, username: "terminalx_bot", is_bot: true },
        },
      },
    });

    expect(store.query({ includeContent: true }).messages[0]).toMatchObject({
      messageType: "callback_query",
      telegramUserId: 42,
      telegramUsername: "alice",
      content: "approve",
    });
  });

  it("captures Telegram's outbound message id and an explicit cross-topic source mismatch", async () => {
    const auditor = createTelegramMessageAuditor({
      store,
      resolveForumChatId: () => -1001234567890,
      resolveTopic: (topicId) =>
        topicId === 88
          ? {
              topicId: 88,
              sessionName: "admin-beta",
              kind: "codex",
              cwd: "/srv/beta",
              jsonlPath: "/srv/transcripts/beta.jsonl",
            }
          : undefined,
      resolveSessionCreatedAtMs: () => 1_784_700_000_000,
    });
    const response: ApiResponse<unknown> = {
      ok: true,
      result: {
        message_id: 602,
        message_thread_id: 88,
        date: 1_784_760_010,
        chat: { id: -1001234567890, type: "supergroup" },
        from: { id: 777, username: "terminalx_bot", is_bot: true, first_name: "TerminalX" },
        text: "finished deployment",
      },
    };

    const returned = await withTelegramMessageAuditSource(
      {
        source: "codex-transcript",
        sourceRef: "/srv/transcripts/alpha.jsonl:8192",
        sessionId: "admin-alpha",
        expectedTopicId: 77,
        transcriptPath: "/srv/transcripts/alpha.jsonl",
      },
      () =>
        auditor.transformer(
          async () => response as never,
          "sendMessage",
          {
            chat_id: -1001234567890,
            message_thread_id: 88,
            text: "finished deployment",
          },
          undefined
        )
    );

    expect(returned).toBe(response);
    expect(store.query({ includeContent: true }).messages[0]).toMatchObject({
      direction: "outbound",
      operation: "send",
      deliveryStatus: "sent",
      routingStatus: "mismatch",
      source: "codex-transcript",
      sourceRef: "/srv/transcripts/alpha.jsonl:8192",
      apiMethod: "sendMessage",
      telegramMessageId: 602,
      telegramChatId: -1001234567890,
      telegramTopicId: 88,
      telegramUserId: 777,
      telegramUsername: "terminalx_bot",
      sessionId: "admin-alpha",
      boundSessionId: "admin-beta",
      expectedTopicId: 77,
      transcriptPath: "/srv/transcripts/alpha.jsonl",
      messageType: "text",
      content: "finished deployment",
      payload: {
        chat_id: -1001234567890,
        message_thread_id: 88,
        text: "finished deployment",
      },
      result: response,
    });
  });

  it("marks a reused tmux session name from an older incarnation as a mismatch", async () => {
    const auditor = createTelegramMessageAuditor({
      store,
      resolveForumChatId: () => -1001234567890,
      resolveTopic: () => ({
        topicId: 77,
        sessionName: "admin-alpha",
        sessionCreatedAtMs: 2_000,
        kind: "codex",
        cwd: "/srv/alpha",
      }),
    });
    const response: ApiResponse<unknown> = {
      ok: true,
      result: {
        message_id: 603,
        message_thread_id: 77,
        date: 1_784_760_010,
        chat: { id: -1001234567890, type: "supergroup" },
      },
    };

    await withTelegramMessageAuditSource(
      {
        source: "codex-transcript",
        sessionId: "admin-alpha",
        sessionCreatedAtMs: 1_000,
        expectedTopicId: 77,
      },
      () =>
        auditor.transformer(
          async () => response as never,
          "sendMessage",
          { chat_id: -1001234567890, message_thread_id: 77, text: "stale reply" },
          undefined
        )
    );

    expect(store.query({ includeContent: true }).messages[0]).toMatchObject({
      routingStatus: "mismatch",
      sessionId: "admin-alpha",
      sessionCreatedAtMs: 1_000,
      boundSessionId: "admin-alpha",
      boundSessionCreatedAtMs: 2_000,
    });
  });

  it("captures both direct bot API sends and context replies through one installed transformer", async () => {
    let nextMessageId = 700;
    const fetch = vi.fn(async () => {
      nextMessageId += 1;
      return new Response(
        JSON.stringify({
          ok: true,
          result: {
            message_id: nextMessageId,
            message_thread_id: 77,
            date: 1_784_760_020,
            chat: { id: -1001234567890, type: "supergroup" },
            from: {
              id: 777,
              username: "terminalx_bot",
              is_bot: true,
              first_name: "TerminalX",
            },
            text: "sent",
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    });
    const bot = new Bot<Context>("777:test-token", {
      botInfo: {
        id: 777,
        is_bot: true,
        first_name: "TerminalX",
        username: "terminalx_bot",
        can_join_groups: true,
        can_read_all_group_messages: true,
        supports_inline_queries: false,
        can_connect_to_business: false,
        has_main_web_app: false,
        can_manage_bots: false,
        has_topics_enabled: false,
        allows_users_to_create_topics: false,
      },
      client: { fetch: fetch as never },
    });
    const auditor = createTelegramMessageAuditor({
      store,
      resolveForumChatId: () => -1001234567890,
      resolveTopic: () => ({
        topicId: 77,
        sessionName: "admin-alpha",
        kind: "codex",
        cwd: "/srv/alpha",
      }),
    });
    installTelegramMessageAudit(bot, auditor);
    bot.on("message:text", (ctx) => ctx.reply("ack"));

    await bot.api.sendMessage(-1001234567890, "direct", { message_thread_id: 77 });
    await bot.api.sendDocument(
      -1001234567890,
      new InputFile(Buffer.from("private report bytes"), "report.txt"),
      { message_thread_id: 77, caption: "report" }
    );
    await bot.handleUpdate({
      update_id: 9002,
      message: {
        message_id: 502,
        message_thread_id: 77,
        is_topic_message: true,
        date: 1_784_760_019,
        chat: { id: -1001234567890, type: "supergroup", title: "TerminalX" },
        from: { id: 42, is_bot: false, first_name: "Alice" },
        text: "hello",
      },
    });

    const messages = store.query({ includeContent: true }).messages;
    expect(messages).toHaveLength(3);
    expect(messages.map((message) => message.telegramMessageId).sort()).toEqual([701, 702, 703]);
    expect(messages.map((message) => message.content).sort()).toEqual(["ack", "direct", "report"]);
    expect(messages.every((message) => message.telegramTopicId === 77)).toBe(true);
    expect(messages.find((message) => message.messageType === "document")?.payload).toMatchObject({
      document: { type: "InputFile", filename: "report.txt" },
    });
    expect(JSON.stringify(messages)).not.toContain("private report bytes");
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("resolves a pinned screen edit back to its topic and session", async () => {
    const auditor = createTelegramMessageAuditor({
      store,
      resolveForumChatId: () => -1001234567890,
      resolveMessageTopic: (messageId, chatId) =>
        messageId === 700 && chatId === -1001234567890
          ? {
              topicId: 77,
              sessionName: "admin-alpha",
              kind: "shell",
              cwd: "/srv/alpha",
              pinnedMsgId: 700,
            }
          : undefined,
      resolveSessionCreatedAtMs: () => 1_784_700_000_000,
    });
    const response: ApiResponse<unknown> = {
      ok: true,
      result: {
        message_id: 700,
        message_thread_id: 77,
        date: 1_784_760_020,
        chat: { id: -1001234567890, type: "supergroup", title: "TerminalX" },
        text: "updated screen",
      },
    };

    await auditor.transformer(
      async () => response as never,
      "editMessageText",
      { chat_id: -1001234567890, message_id: 700, text: "updated screen" },
      undefined
    );

    expect(store.query({ includeContent: true }).messages[0]).toMatchObject({
      operation: "edit",
      routingStatus: "matched",
      telegramChatId: -1001234567890,
      telegramTopicId: 77,
      telegramMessageId: 700,
      sessionId: "admin-alpha",
      boundSessionId: "admin-alpha",
      expectedTopicId: 77,
      sessionCreatedAtMs: 1_784_700_000_000,
      sessionKind: "shell",
      sessionCwd: "/srv/alpha",
    });
  });

  it("keeps every Telegram message id returned by a multi-message API call", async () => {
    const auditor = createTelegramMessageAuditor({ store });
    const response: ApiResponse<unknown> = {
      ok: true,
      result: [
        {
          message_id: 901,
          message_thread_id: 77,
          date: 1_784_760_020,
          chat: { id: -1001234567890, type: "supergroup", title: "TerminalX" },
        },
        {
          message_id: 902,
          message_thread_id: 77,
          date: 1_784_760_020,
          chat: { id: -1001234567890, type: "supergroup", title: "TerminalX" },
        },
      ],
    };

    await auditor.transformer(
      async () => response as never,
      "sendMediaGroup",
      { chat_id: -1001234567890, message_thread_id: 77, media: [] },
      undefined
    );

    expect(store.query({ telegramMessageId: 902 }).messages).toEqual([
      expect.objectContaining({
        telegramMessageId: 901,
        telegramMessageIds: [901, 902],
      }),
    ]);
  });

  it("records every send from one correlation context as a distinct API call", async () => {
    const auditor = createTelegramMessageAuditor({ store });
    const response = (messageId: number): ApiResponse<unknown> => ({
      ok: true,
      result: {
        message_id: messageId,
        date: 1_784_760_020,
        chat: { id: -1001234567890, type: "supergroup", title: "TerminalX" },
        text: "sent",
      },
    });

    await withTelegramMessageAuditSource(
      { source: "telegram-handler", correlationId: "update:9003", expectedTopicId: 77 },
      async () => {
        await auditor.transformer(
          async () => response(801) as never,
          "sendMessage",
          { chat_id: -1001234567890, message_thread_id: 77, text: "first" },
          undefined
        );
        await auditor.transformer(
          async () => response(802) as never,
          "sendMessage",
          { chat_id: -1001234567890, message_thread_id: 77, text: "second" },
          undefined
        );
      }
    );

    const messages = store.query({ includeContent: true }).messages;
    expect(messages).toHaveLength(2);
    expect(messages.map((message) => message.correlationId)).toEqual([
      "update:9003",
      "update:9003",
    ]);
    expect(messages.map((message) => message.telegramMessageId).sort()).toEqual([801, 802]);
  });

  it("records Telegram API envelopes and transport errors without changing behavior", async () => {
    const auditor = createTelegramMessageAuditor({ store });
    const rejected: ApiResponse<unknown> = {
      ok: false,
      error_code: 429,
      description: "Too Many Requests",
      parameters: { retry_after: 30 },
    };
    const networkError = new Error("socket closed");

    const returned = await auditor.transformer(
      async () => rejected as never,
      "sendMessage",
      { chat_id: -1001234567890, message_thread_id: 77, text: "rate limited" },
      undefined
    );
    await expect(
      auditor.transformer(
        async () => {
          throw networkError;
        },
        "sendMessage",
        { chat_id: -1001234567890, message_thread_id: 77, text: "transport" },
        undefined
      )
    ).rejects.toBe(networkError);

    expect(returned).toBe(rejected);
    const messages = store.query({ includeContent: true }).messages;
    expect(messages).toHaveLength(2);
    expect(messages.map((message) => message.deliveryStatus)).toEqual(["failed", "failed"]);
    expect(messages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          errorCode: "429",
          errorMessage: "Too Many Requests",
          result: rejected,
        }),
        expect.objectContaining({
          errorCode: "Error",
          errorMessage: "socket closed",
        }),
      ])
    );
  });

  it("retries transient post-send and post-handler database finalization failures", async () => {
    const auditor = createTelegramMessageAuditor({ store });
    const originalCompleteOutbound = store.completeOutbound.bind(store);
    const completeOutbound = vi
      .spyOn(store, "completeOutbound")
      .mockImplementationOnce(() => {
        throw new Error("temporary database failure");
      })
      .mockImplementation(originalCompleteOutbound);
    const response: ApiResponse<unknown> = {
      ok: true,
      result: {
        message_id: 990,
        date: 1_784_760_020,
        chat: { id: -1001234567890, type: "supergroup" },
      },
    };

    await auditor.transformer(
      async () => response as never,
      "sendMessage",
      { chat_id: -1001234567890, message_thread_id: 77, text: "retry me" },
      undefined
    );

    const inbound = store.record({
      direction: "inbound",
      operation: "receive",
      deliveryStatus: "received",
      routingStatus: "matched",
      source: "telegram-webhook",
      messageType: "text",
    });
    store.claimInboundDispatch(inbound.id);
    const originalCompleteInbound = store.completeInboundDispatch.bind(store);
    const completeInbound = vi
      .spyOn(store, "completeInboundDispatch")
      .mockImplementationOnce(() => {
        throw new Error("temporary database failure");
      })
      .mockImplementation(originalCompleteInbound);
    await auditor.completeInboundDispatch(inbound.id);

    expect(completeOutbound).toHaveBeenCalledTimes(2);
    expect(completeInbound).toHaveBeenCalledTimes(2);
    expect(store.query({ telegramMessageId: 990 }).messages[0]).toMatchObject({
      deliveryStatus: "sent",
      telegramMessageId: 990,
    });
    expect(store.query({ processingStatus: "processed" }).messages).toEqual([
      expect.objectContaining({ id: inbound.id }),
    ]);
  });

  it("does not send an outbound message when its pending audit row cannot be stored", async () => {
    const auditor = createTelegramMessageAuditor({ store });
    const next = vi.fn();
    vi.spyOn(store, "record").mockImplementationOnce(() => {
      throw new Error("database unavailable");
    });

    await expect(
      auditor.transformer(
        next,
        "sendMessage",
        { chat_id: -1001234567890, message_thread_id: 77, text: "must be audited" },
        undefined
      )
    ).rejects.toThrow("database unavailable");
    expect(next).not.toHaveBeenCalled();
  });
});
