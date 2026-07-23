import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

describe("Telegram bot inbound audit boundary", () => {
  let dir: string;

  beforeEach(() => {
    vi.resetModules();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-telegram-bot-audit-"));
    process.env.TERMINALX_DATA_DIR = dir;
    process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH = path.join(dir, "messages.sqlite");
    process.env.TERMINALX_TELEGRAM_BOT_TOKEN = "777:test-token";
    process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID = "-1001234567890";
  });

  afterEach(async () => {
    const { closeTelegramMessageAuditStore } = await import("@/lib/telegram/message-audit-store");
    closeTelegramMessageAuditStore();
    delete process.env.TERMINALX_DATA_DIR;
    delete process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH;
    delete process.env.TERMINALX_TELEGRAM_BOT_TOKEN;
    delete process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("stores a stable bot/update identity before reporting that dispatch is unavailable", async () => {
    const { handleTelegramUpdate } = await import("@/lib/telegram/bot");
    const update = {
      update_id: 9001,
      message: {
        message_id: 501,
        date: 1_784_760_000,
        chat: { id: -1001234567890, type: "supergroup" },
        from: { id: 42, username: "alice" },
        text: "hello",
      },
    };

    expect(() => handleTelegramUpdate(update)).toThrow("update was stored for retry");
    expect(() => handleTelegramUpdate(update)).toThrow("update was stored for retry");

    const { getTelegramMessageAuditStore } = await import("@/lib/telegram/message-audit-store");
    const messages = getTelegramMessageAuditStore().query({ includeContent: true }).messages;
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({
      telegramBotId: 777,
      telegramUpdateId: 9001,
      telegramMessageId: 501,
      deliveryStatus: "received",
      processingStatus: "pending",
      processingAttempts: 0,
      receivedCount: 2,
      payload: update,
    });
  });
});
