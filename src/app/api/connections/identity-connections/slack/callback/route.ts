import { handleSlackOidcLinkCallback } from "@/lib/connections/identity-link-http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  return handleSlackOidcLinkCallback(request);
}
