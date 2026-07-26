import { timingSafeEqual } from "node:crypto";
import { resolveRequestActor, type RequestActor } from "../request-actor";
import { evaluateReadiness, type ReadinessOptions, type ReadinessResult } from "./readiness";
import { collectDatabaseGauges, renderPrometheus } from "./metrics";

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
} as const;

/**
 * The readiness probe surface. It returns only a bare, non-leaking status — never
 * which dependency is degraded — so a probe cannot be used to map the deployment's
 * internal topology. It fails closed: any unmet dependency yields 503 so a load
 * balancer holds traffic until the node is truly ready.
 */
export interface ReadinessHttpDeps {
  readonly evaluate?: (options?: ReadinessOptions) => ReadinessResult;
}

export function handleReadiness(deps: ReadinessHttpDeps = {}): Response {
  let ready = false;
  try {
    ready = (deps.evaluate ?? evaluateReadiness)().ready;
  } catch {
    ready = false;
  }
  return Response.json(
    { status: ready ? "ready" : "not-ready" },
    { status: ready ? 200 : 503, headers: NO_STORE_HEADERS }
  );
}

/**
 * The metrics surface. It is access-controlled: a scraper must present the
 * configured `TERMINALX_METRICS_TOKEN` as a bearer token (constant-time compared),
 * or the caller must be an authenticated admin. When neither holds it returns 404
 * so the endpoint's existence is not disclosed. Operators may alternatively bind
 * the server to a private interface (see docs/production-readiness/deployment.md).
 */
export interface MetricsHttpDeps {
  readonly resolveActor?: (headers: Headers) => Promise<RequestActor | null>;
  readonly metricsToken?: string | undefined;
  readonly buildVersion?: string;
  readonly uptimeSeconds?: number;
  readonly residentMemoryBytes?: number;
  readonly ptySessions?: number;
  readonly collectGauges?: typeof collectDatabaseGauges;
}

function constantTimeEquals(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, "utf8");
  const bufferB = Buffer.from(b, "utf8");
  if (bufferA.length !== bufferB.length) return false;
  return timingSafeEqual(bufferA, bufferB);
}

function bearerToken(headers: Headers): string | null {
  const value = headers.get("authorization");
  if (!value || !value.toLowerCase().startsWith("bearer ")) return null;
  const token = value.slice(7).trim();
  return token.length > 0 ? token : null;
}

async function metricsAuthorized(request: Request, deps: MetricsHttpDeps): Promise<boolean> {
  const token = deps.metricsToken ?? process.env.TERMINALX_METRICS_TOKEN;
  if (typeof token === "string" && token.length > 0) {
    const presented = bearerToken(request.headers);
    if (presented !== null && constantTimeEquals(presented, token)) return true;
    // With a token configured, only the token grants access to scrapers.
    // Still allow an authenticated admin session for humans.
  }
  try {
    const actor = await (deps.resolveActor ?? resolveRequestActor)(request.headers);
    return actor !== null && actor.legacyRole === "admin";
  } catch {
    return false;
  }
}

export async function handleMetrics(
  request: Request,
  deps: MetricsHttpDeps = {}
): Promise<Response> {
  if (!(await metricsAuthorized(request, deps))) {
    // Non-leaking: do not confirm the endpoint exists to an unauthorized caller.
    return new Response("Not found", { status: 404, headers: NO_STORE_HEADERS });
  }
  const collect = deps.collectGauges ?? collectDatabaseGauges;
  let databaseGauges;
  try {
    databaseGauges = collect();
  } catch {
    databaseGauges = null;
  }
  const body = renderPrometheus({
    ...(deps.buildVersion ? { buildVersion: deps.buildVersion } : {}),
    uptimeSeconds: deps.uptimeSeconds ?? Math.round(process.uptime()),
    residentMemoryBytes: deps.residentMemoryBytes ?? process.memoryUsage().rss,
    // The PTY count is published to the shared metrics state by the custom
    // server (which owns the PTY manager); renderPrometheus falls back to it.
    ...(deps.ptySessions !== undefined ? { ptySessions: deps.ptySessions } : {}),
    databaseGauges,
  });
  return new Response(body, {
    status: 200,
    headers: {
      ...NO_STORE_HEADERS,
      "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
    },
  });
}
