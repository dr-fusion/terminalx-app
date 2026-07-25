import { handleRotateInstallation } from "@/lib/connections/installation-http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(
  request: Request,
  context: { params: Promise<{ installationId: string }> }
): Promise<Response> {
  const { installationId } = await context.params;
  return handleRotateInstallation(request, installationId);
}
