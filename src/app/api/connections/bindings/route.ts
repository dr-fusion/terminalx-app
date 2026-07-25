import { handleCreateBinding } from "@/lib/connections/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  return handleCreateBinding(request);
}
