import { handleTeamSessionCommand } from "@/lib/team-sessions/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  return handleTeamSessionCommand(request);
}
