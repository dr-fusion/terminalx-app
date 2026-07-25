import { handleCreateInstallation } from "@/lib/connections/installation-http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  return handleCreateInstallation(request);
}
