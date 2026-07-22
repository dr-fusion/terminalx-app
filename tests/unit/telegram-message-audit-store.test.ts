import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { InputFile } from "grammy";
import {
  createTelegramMessageAuditStore,
  type TelegramMessageAuditStore,
} from "@/lib/telegram/message-audit-store";

describe("Telegram message audit store", () => {
  let dir: string;
  let dbPath: string;
  let store: TelegramMessageAuditStore | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-telegram-audit-"));
    dbPath = path.join(dir, "messages.sqlite");
  });

  afterEach(() => {
    store?.close();
    store = undefined;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("durably records one complete inbound envelope when Telegram retries an update", () => {
    store = createTelegramMessageAuditStore(dbPath);
    const event = {
      dedupeKey: "inbound:update:9001:message",
      direction: "inbound" as const,
      operation: "receive" as const,
      deliveryStatus: "received" as const,
      routingStatus: "matched" as const,
      source: "telegram-webhook",
      sourceRef: "update:9001",
      correlationId: "update:9001",
      telegramUpdateId: 9001,
      telegramMessageId: 501,
      telegramChatId: -1001234567890,
      telegramTopicId: 77,
      telegramUserId: 42,
      telegramUsername: "alice",
      sessionId: "admin-alpha",
      sessionCreatedAtMs: 1_784_700_000_000,
      boundSessionId: "admin-alpha",
      boundSessionCreatedAtMs: 1_784_700_000_000,
      expectedTopicId: 77,
      sessionKind: "codex",
      sessionCwd: "/srv/alpha",
      transcriptPath: "/srv/transcripts/alpha.jsonl",
      replyToMessageId: 499,
      messageType: "text",
      content: "deploy alpha",
      payload: { update_id: 9001, message: { message_id: 501, text: "deploy alpha" } },
      occurredAtMs: 1_784_760_000_000,
    };

    const first = store.record(event);
    const retried = store.record(event);
    expect(retried.id).toBe(first.id);
    if (process.platform !== "win32") {
      expect(fs.statSync(dbPath).mode & 0o777).toBe(0o600);
      for (const sidecar of [`${dbPath}-wal`, `${dbPath}-shm`]) {
        if (fs.existsSync(sidecar)) expect(fs.statSync(sidecar).mode & 0o777).toBe(0o600);
      }
    }

    store.close();
    store = createTelegramMessageAuditStore(dbPath);
    const page = store.query({ includeContent: true, limit: 10 });

    expect(page.messages).toHaveLength(1);
    expect(page.messages[0]).toMatchObject({
      id: first.id,
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
      telegramUpdateId: 9001,
      telegramMessageId: 501,
      telegramChatId: -1001234567890,
      telegramTopicId: 77,
      telegramUserId: 42,
      telegramUsername: "alice",
      sessionId: "admin-alpha",
      sessionCreatedAtMs: 1_784_700_000_000,
      boundSessionId: "admin-alpha",
      boundSessionCreatedAtMs: 1_784_700_000_000,
      expectedTopicId: 77,
      sessionKind: "codex",
      sessionCwd: "/srv/alpha",
      transcriptPath: "/srv/transcripts/alpha.jsonl",
      replyToMessageId: 499,
      messageType: "text",
      content: "deploy alpha",
      contentHash: "e585711039a347dbf28ab3c8db6628a7d79032e5b3771f023a0a5fd371eb41d4",
      payload: { update_id: 9001, message: { message_id: 501, text: "deploy alpha" } },
      occurredAtMs: 1_784_760_000_000,
    });
    expect(page.page).toEqual({ limit: 10, hasMore: false, nextCursor: null });

    const claimed = store.claimInboundDispatch(first.id);
    expect(claimed).toMatchObject({
      status: "claimed",
      event: {
        processingStatus: "processing",
        processingAttempts: 1,
        receivedCount: 2,
      },
    });
    expect(store.claimInboundDispatch(first.id)).toMatchObject({
      status: "busy",
      event: { processingAttempts: 1 },
    });
    store.close();
    store = createTelegramMessageAuditStore(dbPath);
    expect(store.claimInboundDispatch(first.id)).toMatchObject({
      status: "busy",
      event: { processingAttempts: 1 },
    });
    expect(store.claimInboundDispatch(first.id, 0)).toMatchObject({
      status: "claimed",
      event: { processingStatus: "processing", processingAttempts: 2 },
    });
    expect(
      store.failInboundDispatch(first.id, {
        errorCode: "Error",
        errorMessage: "handler failed",
      })
    ).toMatchObject({ processingStatus: "failed", errorMessage: "handler failed" });
    expect(store.claimInboundDispatch(first.id)).toMatchObject({
      status: "claimed",
      event: { processingStatus: "processing", processingAttempts: 3 },
    });
    expect(store.completeInboundDispatch(first.id)).toMatchObject({
      processingStatus: "processed",
      processingAttempts: 3,
      errorMessage: undefined,
    });
    expect(store.claimInboundDispatch(first.id)).toMatchObject({
      status: "processed",
      event: { processingAttempts: 3 },
    });
  });

  it.runIf(process.platform !== "win32")(
    "secures SQLite files without changing an existing parent directory",
    () => {
      fs.chmodSync(dir, 0o755);
      store = createTelegramMessageAuditStore(dbPath);
      store.record({
        direction: "inbound",
        operation: "receive",
        deliveryStatus: "received",
        routingStatus: "unknown",
        source: "telegram-webhook",
        messageType: "unknown",
      });

      expect(fs.statSync(dir).mode & 0o777).toBe(0o755);
      for (const filename of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
        if (fs.existsSync(filename)) expect(fs.statSync(filename).mode & 0o777).toBe(0o600);
      }
    }
  );

  it("tracks outbound delivery results and flags one source delivered to multiple topics", () => {
    store = createTelegramMessageAuditStore(dbPath);
    const first = store.record({
      dedupeKey: "outbound:call-1",
      direction: "outbound",
      operation: "send",
      deliveryStatus: "pending",
      routingStatus: "matched",
      source: "codex-transcript",
      sourceRef: "/srv/transcripts/alpha.jsonl:8192",
      correlationId: "call-1",
      apiMethod: "sendMessage",
      telegramChatId: -1001234567890,
      telegramTopicId: 77,
      sessionId: "admin-alpha",
      sessionCreatedAtMs: 1_784_700_000_000,
      boundSessionId: "admin-alpha",
      expectedTopicId: 77,
      messageType: "text",
      content: "finished deployment",
      payload: { chat_id: -1001234567890, message_thread_id: 77 },
      occurredAtMs: 1_784_760_001_000,
    });
    const sentFirst = store.completeOutbound(first.id, {
      telegramMessageId: 601,
      telegramUserId: 777,
      telegramUsername: "terminalx_bot",
      completedAtMs: 1_784_760_001_050,
      result: { message_id: 601, chat: { id: -1001234567890 } },
    });

    const second = store.record({
      dedupeKey: "outbound:call-2",
      direction: "outbound",
      operation: "send",
      deliveryStatus: "pending",
      routingStatus: "mismatch",
      source: "codex-transcript",
      sourceRef: "/srv/transcripts/alpha.jsonl:8192",
      correlationId: "call-2",
      apiMethod: "sendMessage",
      telegramChatId: -1001234567890,
      telegramTopicId: 88,
      sessionId: "admin-alpha",
      sessionCreatedAtMs: 1_784_700_000_000,
      boundSessionId: "admin-beta",
      expectedTopicId: 77,
      messageType: "text",
      content: "finished deployment",
      occurredAtMs: 1_784_760_002_000,
    });
    store.completeOutbound(second.id, {
      telegramMessageId: 602,
      completedAtMs: 1_784_760_002_025,
      result: { message_id: 602, chat: { id: -1001234567890 } },
    });

    const failed = store.record({
      dedupeKey: "outbound:call-3",
      direction: "outbound",
      operation: "send",
      deliveryStatus: "pending",
      routingStatus: "matched",
      source: "telegram-files",
      correlationId: "call-3",
      apiMethod: "sendDocument",
      telegramChatId: -1001234567890,
      telegramTopicId: 77,
      sessionId: "admin-alpha",
      sessionCreatedAtMs: 1_784_700_000_000,
      messageType: "document",
      occurredAtMs: 1_784_760_003_000,
    });
    const failedResult = store.failOutbound(failed.id, {
      errorCode: "429",
      errorMessage: "Too Many Requests: retry after 30",
      completedAtMs: 1_784_760_003_010,
      result: { ok: false, error_code: 429, parameters: { retry_after: 30 } },
    });

    expect(sentFirst).toMatchObject({
      deliveryStatus: "sent",
      telegramMessageId: 601,
      telegramUserId: 777,
      telegramUsername: "terminalx_bot",
      durationMs: 50,
    });
    expect(failedResult).toMatchObject({
      deliveryStatus: "failed",
      errorCode: "429",
      errorMessage: "Too Many Requests: retry after 30",
      durationMs: 10,
    });
    expect(store.summarize()).toEqual({
      total: 3,
      byDirection: { outbound: 3 },
      byDeliveryStatus: { failed: 1, sent: 2 },
      byRoutingStatus: { matched: 2, mismatch: 1 },
      byProcessingStatus: {},
      routePairs: [
        {
          telegramChatId: -1001234567890,
          telegramTopicId: 77,
          sessionId: "admin-alpha",
          sessionCreatedAtMs: 1_784_700_000_000,
          count: 2,
        },
        {
          telegramChatId: -1001234567890,
          telegramTopicId: 88,
          sessionId: "admin-alpha",
          sessionCreatedAtMs: 1_784_700_000_000,
          count: 1,
        },
      ],
      anomalies: {
        topicsWithMultipleSessions: [],
        sessionsWithMultipleTopics: [
          {
            sessionId: "admin-alpha",
            sessionCreatedAtMs: 1_784_700_000_000,
            topicIds: [77, 88],
            topics: [
              { telegramChatId: -1001234567890, telegramTopicId: 77 },
              { telegramChatId: -1001234567890, telegramTopicId: 88 },
            ],
            count: 3,
          },
        ],
        sourcesDeliveredToMultipleTopics: [
          {
            sourceRef: "/srv/transcripts/alpha.jsonl:8192",
            topicIds: [77, 88],
            topics: [
              { telegramChatId: -1001234567890, telegramTopicId: 77 },
              { telegramChatId: -1001234567890, telegramTopicId: 88 },
            ],
            sessionIds: ["admin-alpha"],
            count: 2,
          },
        ],
        contentDeliveredToMultipleTopics: [
          {
            contentHash: "2c15ebcc8172d3fee91309a5537b8a9bce15bccdfb36c0a237437d1315f2b83d",
            contentPreview: "finished deployment",
            topicIds: [77, 88],
            topics: [
              { telegramChatId: -1001234567890, telegramTopicId: 77 },
              { telegramChatId: -1001234567890, telegramTopicId: 88 },
            ],
            sessionIds: ["admin-alpha"],
            count: 2,
          },
        ],
      },
    });
  });

  it("redacts secrets and stores file metadata without serializing file bytes", () => {
    store = createTelegramMessageAuditStore(dbPath);
    const payload: Record<string, unknown> = {
      text: "send this file",
      secret_token: "webhook-secret",
      botToken: "bot-secret",
      authorization: "Bearer private",
      document: new InputFile(Buffer.from("private file contents"), "report.txt"),
      rawBytes: Buffer.from("other private bytes"),
      count: BigInt(12),
    };
    payload.circular = payload;

    store.record({
      direction: "outbound",
      operation: "send",
      deliveryStatus: "pending",
      routingStatus: "matched",
      source: "telegram-files",
      messageType: "document",
      content: "send this file",
      payload,
    });

    expect(store.query({ includeContent: true }).messages[0]?.payload).toEqual({
      text: "send this file",
      secret_token: "[redacted]",
      botToken: "[redacted]",
      authorization: "[redacted]",
      document: { type: "InputFile", filename: "report.txt" },
      rawBytes: { type: "Buffer", byteLength: 19 },
      count: "12",
      circular: "[circular]",
    });
  });

  it("treats chat-scoped topics and reused session names as distinct identities", () => {
    store = createTelegramMessageAuditStore(dbPath);
    const record = (
      chatId: number,
      topicId: number,
      sessionCreatedAtMs: number,
      occurredAtMs: number
    ) =>
      store?.record({
        direction: "outbound",
        operation: "send",
        deliveryStatus: "sent",
        routingStatus: "matched",
        source: "terminal-streamer",
        telegramChatId: chatId,
        telegramTopicId: topicId,
        sessionId: "admin-alpha",
        sessionCreatedAtMs,
        messageType: "text",
        content: `${chatId}:${topicId}:${sessionCreatedAtMs}`,
        occurredAtMs,
      });

    record(-1001, 77, 1_000, 10_000);
    record(-1002, 77, 1_000, 11_000);
    record(-1001, 77, 2_000, 12_000);

    const anomalies = store.summarize().anomalies;
    expect(anomalies.sessionsWithMultipleTopics).toEqual([
      expect.objectContaining({
        sessionId: "admin-alpha",
        sessionCreatedAtMs: 1_000,
        topicIds: [77],
        topics: [
          { telegramChatId: -1002, telegramTopicId: 77 },
          { telegramChatId: -1001, telegramTopicId: 77 },
        ],
      }),
    ]);
    expect(anomalies.topicsWithMultipleSessions).toEqual([
      expect.objectContaining({
        telegramChatId: -1001,
        telegramTopicId: 77,
        sessionIds: ["admin-alpha"],
        sessions: [
          { sessionId: "admin-alpha", sessionCreatedAtMs: 1_000 },
          { sessionId: "admin-alpha", sessionCreatedAtMs: 2_000 },
        ],
      }),
    ]);
  });

  it("paginates deterministically with an opaque keyset cursor", () => {
    store = createTelegramMessageAuditStore(dbPath);
    for (const [messageId, occurredAtMs] of [
      [10, 1_784_760_000_000],
      [11, 1_784_760_001_000],
      [12, 1_784_760_001_000],
    ] as const) {
      store.record({
        direction: "inbound",
        operation: "receive",
        deliveryStatus: "received",
        routingStatus: "matched",
        source: "telegram-webhook",
        telegramMessageId: messageId,
        telegramTopicId: 77,
        sessionId: "admin-alpha",
        messageType: "text",
        occurredAtMs,
      });
    }

    const first = store.query({ sessionId: "admin-alpha", limit: 2 });
    const second = store.query({
      sessionId: "admin-alpha",
      limit: 2,
      cursor: first.page.nextCursor ?? undefined,
    });

    expect(first.messages.map((event) => event.telegramMessageId)).toEqual([12, 11]);
    expect(first.page.hasMore).toBe(true);
    expect(first.page.nextCursor).toEqual(expect.any(String));
    expect(second.messages.map((event) => event.telegramMessageId)).toEqual([10]);
    expect(second.page).toEqual({ limit: 2, hasMore: false, nextCursor: null });
    expect(() => store?.query({ cursor: "not-a-cursor" })).toThrow("invalid cursor");
  });
});
