import { handleRevokeIdentityConnection } from "@/lib/connections/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function DELETE(
  request: Request,
  context: { params: Promise<{ connectionId: string }> }
): Promise<Response> {
  const { connectionId } = await context.params;
  return handleRevokeIdentityConnection(request, connectionId);
}
