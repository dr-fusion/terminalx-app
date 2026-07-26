import { handleAttentionUnreadCount } from "@/lib/attention/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  return handleAttentionUnreadCount(request);
}
