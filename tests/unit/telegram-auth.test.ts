import { afterEach, describe, expect, it, vi } from "vitest";

async function loadTelegramAuth() {
  vi.resetModules();
  return await import("@/lib/telegram/auth");
}

describe("telegram auth configuration", () => {
  afterEach(() => {
    delete process.env.TERMINALX_TELEGRAM_BOT_TOKEN;
    delete process.env.TERMINALX_TELEGRAM_ALLOWED_USERS;
    delete process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID;
    delete process.env.TERMINALX_AUTH_MODE;
    vi.resetModules();
  });

  it("does not configure the bot without a valid forum chat id", async () => {
    process.env.TERMINALX_TELEGRAM_BOT_TOKEN = "123:token";
    process.env.TERMINALX_TELEGRAM_ALLOWED_USERS = "100:admin";

    const { botIsConfigured } = await loadTelegramAuth();

    expect(botIsConfigured()).toBe(false);
  });

  it("requires a non-zero finite forum chat id", async () => {
    process.env.TERMINALX_TELEGRAM_BOT_TOKEN = "123:token";
    process.env.TERMINALX_TELEGRAM_ALLOWED_USERS = "100:admin";
    process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID = "0";

    const { botIsConfigured, getTelegramForumChatId } = await loadTelegramAuth();

    expect(getTelegramForumChatId()).toBeNull();
    expect(botIsConfigured()).toBe(false);
  });

  it("configures the bot when token, allowlist, and forum chat id are present", async () => {
    process.env.TERMINALX_TELEGRAM_BOT_TOKEN = "123:token";
    process.env.TERMINALX_TELEGRAM_ALLOWED_USERS = "100:admin";
    process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID = "-100123";

    const { botIsConfigured, getTelegramForumChatId } = await loadTelegramAuth();

    expect(getTelegramForumChatId()).toBe(-100123);
    expect(botIsConfigured()).toBe(true);
  });
});
