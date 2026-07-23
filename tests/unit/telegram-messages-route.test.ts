import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  createTelegramMessageAuditStore,
  type TelegramMessageAuditStore,
} from "@/lib/telegram/message-audit-store";

function request(url: string, headers: Record<string, string> = {}) {
  return {
    url,
    headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
  } as never;
}

describe("GET /api/telegram/messages", () => {
  let dir: string;
  let store: TelegramMessageAuditStore;

  beforeEach(() => {
    vi.resetModules();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-telegram-route-"));
    process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH = path.join(dir, "messages.sqlite");
    process.env.TERMINALX_AUTH_MODE = "local";
    store = createTelegramMessageAuditStore(process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH);
    store.record({
      direction: "inbound",
      operation: "receive",
      deliveryStatus: "received",
      routingStatus: "matched",
      source: "telegram-webhook",
      telegramUpdateId: 100,
      telegramMessageId: 10,
      telegramChatId: -100123,
      telegramTopicId: 77,
      telegramUserId: 42,
      sessionId: "admin-alpha",
      messageType: "text",
      content: "private inbound prompt",
      occurredAtMs: 1_784_760_000_000,
    });
    store.record({
      direction: "outbound",
      operation: "send",
      deliveryStatus: "sent",
      routingStatus: "matched",
      source: "codex-transcript",
      telegramMessageId: 11,
      telegramChatId: -100123,
      telegramTopicId: 88,
      sessionId: "admin-beta",
      messageType: "text",
      content: "private outbound answer",
      occurredAtMs: 1_784_760_001_000,
    });
  });

  afterEach(async () => {
    store.close();
    const { closeTelegramMessageAuditStore } = await import("@/lib/telegram/message-audit-store");
    closeTelegramMessageAuditStore();
    delete process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH;
    delete process.env.TERMINALX_AUTH_MODE;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("requires an authenticated admin identity", async () => {
    const { GET } = await import("@/app/api/telegram/messages/route");
    const missing = await GET(request("http://localhost/api/telegram/messages"));
    const user = await GET(
      request("http://localhost/api/telegram/messages", {
        "x-user-role": "user",
        "x-username": "alice",
      })
    );

    expect(missing.status).toBe(403);
    expect(user.status).toBe(403);
  });

  it("filters records and only returns full content when explicitly requested", async () => {
    const { GET } = await import("@/app/api/telegram/messages/route");
    const admin = { "x-user-role": "admin", "x-username": "admin" };
    const filtered = await GET(
      request(
        "http://localhost/api/telegram/messages?direction=outbound&topicId=88&includeContent=true&includeSummary=true&limit=1",
        admin
      )
    );
    const body = await filtered.json();
    const defaultResponse = await GET(
      request("http://localhost/api/telegram/messages?direction=inbound", admin)
    );
    const defaultBody = await defaultResponse.json();

    expect(filtered.status).toBe(200);
    expect(body.messages).toEqual([
      expect.objectContaining({
        direction: "outbound",
        telegramTopicId: 88,
        sessionId: "admin-beta",
        content: "private outbound answer",
      }),
    ]);
    expect(body.summary.total).toBe(1);
    expect(body.page).toEqual({ limit: 1, hasMore: false, nextCursor: null });
    expect(filtered.headers.get("cache-control")).toBe("private, no-store");
    expect(defaultBody).not.toHaveProperty("summary");
    expect(defaultBody.messages[0]).not.toHaveProperty("content");
    expect(defaultBody.messages[0]).not.toHaveProperty("payload");
    expect(defaultBody.messages[0].contentPreview).toBe("private inbound prompt");
  });

  it("rejects malformed filters", async () => {
    const { GET } = await import("@/app/api/telegram/messages/route");
    const response = await GET(
      request("http://localhost/api/telegram/messages?topicId=not-a-number", {
        "x-user-role": "admin",
      })
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "topicId must be a positive integer" });
  });
});
