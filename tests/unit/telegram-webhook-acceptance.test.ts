import { describe, expect, it, vi } from "vitest";
import { acceptTelegramWebhookUpdate } from "@/lib/telegram/webhook-acceptance";

describe("Telegram webhook durable acceptance", () => {
  it("returns the dispatch promise only after synchronous acceptance", async () => {
    const processing = Promise.resolve();
    const handler = vi.fn(() => processing);

    const result = acceptTelegramWebhookUpdate({ update_id: 9001 }, handler);

    expect(result).toEqual({ accepted: true, processing });
    if (result.accepted) await result.processing;
  });

  it("turns a synchronous persistence failure into a retryable rejection", () => {
    const result = acceptTelegramWebhookUpdate({ update_id: 9002 }, () => {
      throw new Error("database unavailable");
    });

    expect(result).toEqual({ accepted: false, errorMessage: "database unavailable" });
  });
});
