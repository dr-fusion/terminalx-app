import { handleRevokeBinding, handleUpdateBinding } from "@/lib/connections/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function PATCH(
  request: Request,
  context: { params: Promise<{ bindingId: string }> }
): Promise<Response> {
  const { bindingId } = await context.params;
  return handleUpdateBinding(request, bindingId);
}

export async function DELETE(
  request: Request,
  context: { params: Promise<{ bindingId: string }> }
): Promise<Response> {
  const { bindingId } = await context.params;
  return handleRevokeBinding(request, bindingId);
}
