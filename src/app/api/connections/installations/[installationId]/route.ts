import { handleRevokeInstallation } from "@/lib/connections/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function DELETE(
  request: Request,
  context: { params: Promise<{ installationId: string }> }
): Promise<Response> {
  const { installationId } = await context.params;
  return handleRevokeInstallation(request, installationId);
}
