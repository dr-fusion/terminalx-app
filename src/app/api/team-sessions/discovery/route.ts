import { handleWorkspaceDiscovery } from "@/lib/team-sessions/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  return handleWorkspaceDiscovery(request);
}
