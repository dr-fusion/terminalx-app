import { handleSessionList } from "@/lib/team-sessions/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  return handleSessionList(request);
}
