import { handleSlackWebhook } from "@/lib/connections/webhook-http";
import { dispatchInboundKernelCommand } from "@/lib/connections/kernel-dispatch";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  return handleSlackWebhook(request, {
    dispatchKernelCommand: dispatchInboundKernelCommand,
  });
}
