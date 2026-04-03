import { NextResponse } from "next/server";
import { getActivePtyCount } from "@/lib/pty-manager";
import * as path from "path";

export async function GET() {
  const terminusRoot = path.resolve(
    process.env.TERMINUS_ROOT || process.env.HOME || "/"
  );

  return NextResponse.json({
    status: "ok",
    uptime: process.uptime(),
    activePtys: getActivePtyCount(),
    terminusRoot,
    readOnly: process.env.TERMINUS_READ_ONLY === "true",
    timestamp: new Date().toISOString(),
  });
}
