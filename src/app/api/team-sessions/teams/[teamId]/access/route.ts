import { handleTeamAccess } from "@/lib/team-sessions/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ teamId: string }> }
): Promise<Response> {
  const { teamId } = await context.params;
  return handleTeamAccess(request, teamId);
}
