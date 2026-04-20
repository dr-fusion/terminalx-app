import { NextRequest, NextResponse } from "next/server";
import { listLogFiles } from "@/lib/log-streamer";
import { getUserScoping } from "@/lib/session-scope";

export async function GET(req: NextRequest) {
  try {
    const { shouldScope, role } = getUserScoping(req.headers);
    if (shouldScope && role !== "admin") {
      return NextResponse.json({ files: [] });
    }
    const files = listLogFiles();
    return NextResponse.json({ files });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
