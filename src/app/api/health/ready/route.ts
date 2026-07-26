import { handleReadiness } from "@/lib/ops/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Readiness probe — checks real dependencies (SQLite reachable + migrated to the
// expected schema + integrity-clean, and the Secret Broker when configured) and
// fails closed with a non-leaking status so a load balancer holds traffic until
// the node is ready. No auth: a probe must reach it, and it discloses nothing.
export async function GET(): Promise<Response> {
  return handleReadiness();
}
