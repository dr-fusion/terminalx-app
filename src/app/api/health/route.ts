import { NextResponse } from "next/server";
import pkg from "../../../../package.json";

const STARTED_AT = Date.now();

// Public health check — no auth, intentionally minimal. Useful for liveness
// probes. Do NOT add counts/timing data that could aid timing attacks.
export async function GET() {
  return NextResponse.json({
    status: "ok",
    version: pkg.version,
    uptimeSeconds: Math.round((Date.now() - STARTED_AT) / 1000),
    timestamp: new Date().toISOString(),
  });
}
