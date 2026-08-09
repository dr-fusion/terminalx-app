import { NextResponse } from "next/server";
import { getMultiplayerTransportStatus } from "@/lib/team-sessions/feature";

export const dynamic = "force-dynamic";

export async function GET() {
  const status = getMultiplayerTransportStatus();
  return NextResponse.json(status, {
    headers: {
      "Cache-Control": "no-store",
    },
  });
}
