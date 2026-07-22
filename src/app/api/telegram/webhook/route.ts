import { NextRequest, NextResponse } from "next/server";
import { acceptTelegramWebhookUpdate } from "@/lib/telegram/webhook-acceptance";

/**
 * Telegram webhook endpoint. Telegram POSTs updates here. Each request must
 * include the `X-Telegram-Bot-Api-Secret-Token` header matching the value we
 * passed to `setWebhook`. We verify it before doing anything else so an
 * attacker can't drive the bot via this URL even though the path is public.
 *
 * The inbound envelope is committed synchronously before we acknowledge it;
 * handler work continues asynchronously so Telegram still gets a fast 200.
 */
export async function POST(req: NextRequest): Promise<NextResponse> {
  const expected = process.env.TERMINALX_TELEGRAM_WEBHOOK_SECRET;
  if (!expected) {
    return NextResponse.json({ error: "bot not configured" }, { status: 503 });
  }
  const got = req.headers.get("x-telegram-bot-api-secret-token");
  if (got !== expected) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  let update: object;
  try {
    update = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }

  const acceptance = acceptTelegramWebhookUpdate(update);
  if (!acceptance.accepted) {
    console.error("[telegram/webhook] could not persist/accept update:", acceptance.errorMessage);
    return NextResponse.json(
      { error: "telegram bot unavailable" },
      { status: 503, headers: { "Retry-After": "1" } }
    );
  }

  // Process asynchronously so we can ack within Telegram's deadline.
  void acceptance.processing.catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error("[telegram/webhook] handleUpdate failed:", message);
  });

  return NextResponse.json({ ok: true });
}
