import { handleTelegramWebhook } from "@/lib/connections/webhook-http";
import { dispatchInboundKernelCommand } from "@/lib/connections/kernel-dispatch";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(
  request: Request,
  context: { params: Promise<{ installationId: string }> }
): Promise<Response> {
  const { installationId } = await context.params;
  return handleTelegramWebhook(request, installationId, {
    dispatchKernelCommand: dispatchInboundKernelCommand,
  });
}
