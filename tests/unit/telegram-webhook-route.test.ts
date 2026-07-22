import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const handleTelegramUpdate = vi.hoisted(() => vi.fn());

vi.mock("@/lib/telegram/bot", () => ({ handleTelegramUpdate }));

function request(body: string, secret = "test-webhook-secret"): NextRequest {
  return new NextRequest("http://localhost/api/telegram/webhook", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-telegram-bot-api-secret-token": secret,
    },
    body,
  });
}

describe("POST /api/telegram/webhook", () => {
  beforeEach(() => {
    process.env.TERMINALX_TELEGRAM_WEBHOOK_SECRET = "test-webhook-secret";
    handleTelegramUpdate.mockReset();
    handleTelegramUpdate.mockResolvedValue(undefined);
  });

  afterEach(() => {
    delete process.env.TERMINALX_TELEGRAM_WEBHOOK_SECRET;
    vi.restoreAllMocks();
  });

  it("acknowledges only after synchronous persistence acceptance", async () => {
    const { POST } = await import("@/app/api/telegram/webhook/route");
    const response = await POST(request(JSON.stringify({ update_id: 9001 })));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(handleTelegramUpdate).toHaveBeenCalledWith({ update_id: 9001 });
  });

  it("returns 503 when durable acceptance throws so Telegram can retry", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    handleTelegramUpdate.mockImplementationOnce(() => {
      throw new Error("database unavailable");
    });
    const { POST } = await import("@/app/api/telegram/webhook/route");
    const response = await POST(request(JSON.stringify({ update_id: 9002 })));

    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("1");
    expect(await response.json()).toEqual({ error: "telegram bot unavailable" });
  });

  it("rejects unauthorized and malformed requests before dispatch", async () => {
    const { POST } = await import("@/app/api/telegram/webhook/route");
    const unauthorized = await POST(request("{}", "wrong-secret"));
    const malformed = await POST(request("not-json"));

    expect(unauthorized.status).toBe(401);
    expect(malformed.status).toBe(400);
    expect(handleTelegramUpdate).not.toHaveBeenCalled();
  });
});
