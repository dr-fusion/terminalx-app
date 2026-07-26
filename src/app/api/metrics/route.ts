import pkg from "../../../../package.json";
import { handleMetrics } from "@/lib/ops/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Metrics surface (Prometheus text format). Access-controlled: requires the
// configured TERMINALX_METRICS_TOKEN bearer token or an authenticated admin, and
// returns 404 otherwise so the endpoint is not disclosed. See
// docs/production-readiness/deployment.md for the exposure model.
export async function GET(request: Request): Promise<Response> {
  return handleMetrics(request, { buildVersion: pkg.version });
}
