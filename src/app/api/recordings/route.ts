import { NextRequest, NextResponse } from "next/server";
import { listRecordings, isRecordingEnabled } from "@/lib/session-recorder";
import { getUserScoping } from "@/lib/session-scope";

export async function GET(req: NextRequest) {
  try {
    const { username, shouldScope } = getUserScoping(req.headers);
    let recordings = listRecordings();
    if (shouldScope && username) {
      recordings = recordings.filter((r) => r.createdBy === username);
    }
    return NextResponse.json({
      enabled: isRecordingEnabled(),
      recordings,
    });
  } catch (err) {
    console.error("[api/recordings GET]", err);
    return NextResponse.json({ error: "Failed to list recordings" }, { status: 500 });
  }
}
