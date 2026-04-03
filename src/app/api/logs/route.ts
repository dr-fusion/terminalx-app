import { NextResponse } from "next/server";
import { listLogFiles } from "@/lib/log-streamer";

export async function GET() {
  try {
    const files = listLogFiles();
    return NextResponse.json({ files });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
