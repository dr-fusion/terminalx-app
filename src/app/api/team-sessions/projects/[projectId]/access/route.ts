import { handleProjectAccess } from "@/lib/team-sessions/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ projectId: string }> }
): Promise<Response> {
  const { projectId } = await context.params;
  return handleProjectAccess(request, projectId);
}
