import { NextRequest, NextResponse } from "next/server";
import * as fs from "fs";
import { getRecordingPath, getRecordingMeta } from "@/lib/session-recorder";
import { getUserScoping } from "@/lib/session-scope";
import { audit } from "@/lib/audit-log";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const file = getRecordingPath(id);
    if (!file) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }

    const { username, shouldScope } = getUserScoping(req.headers);
    if (shouldScope && username) {
      const meta = getRecordingMeta(id);
      if (!meta || meta.createdBy !== username) {
        return NextResponse.json({ error: "Not found" }, { status: 404 });
      }
    }

    audit("replay_opened", { username: username || undefined, detail: id });
    const buf = fs.readFileSync(file);
    return new NextResponse(buf, {
      headers: {
        "Content-Type": "application/x-ndjson",
        "Cache-Control": "private, max-age=60",
      },
    });
  } catch (err) {
    console.error("[api/recordings/[id] GET]", err);
    return NextResponse.json({ error: "Failed to read recording" }, { status: 500 });
  }
}
