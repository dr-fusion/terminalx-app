import { NextResponse } from "next/server";
import { isMultiplayerTransportAvailable } from "@/lib/team-sessions/feature";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json(
    {
      enabled: isMultiplayerTransportAvailable(),
      runtime: {
        kind: "local-tmux",
        isolation: "trusted-shared-host",
        yoloEligible: false,
      },
    },
    {
      headers: {
        "Cache-Control": "no-store",
      },
    }
  );
}
