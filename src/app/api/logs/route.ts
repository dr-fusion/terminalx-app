import { NextRequest, NextResponse } from "next/server";
import { listLogFiles } from "@/lib/log-streamer";
import { resolveRequestActor } from "@/lib/request-actor";

export async function GET(req: NextRequest) {
  try {
    const actor = await resolveRequestActor(req.headers);
    if (!actor) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }
    if (actor.legacyRole !== "admin") {
      return NextResponse.json({ files: [] });
    }
    const files = listLogFiles();
    return NextResponse.json({ files }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
