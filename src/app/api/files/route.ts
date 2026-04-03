import { NextRequest, NextResponse } from "next/server";
import {
  listDirectory,
  readFile,
  getFileInfo,
  resolveSafePath,
} from "@/lib/file-service";
import * as fs from "fs";

export async function GET(req: NextRequest) {
  const searchParams = req.nextUrl.searchParams;
  const requestedPath = searchParams.get("path") || ".";
  const action = searchParams.get("action") || "auto"; // auto, list, read, info

  try {
    const safePath = resolveSafePath(requestedPath);
    const stats = fs.statSync(safePath);

    if (action === "info") {
      const info = getFileInfo(requestedPath);
      return NextResponse.json({ type: "info", data: info });
    }

    if (action === "list" || (action === "auto" && stats.isDirectory())) {
      const entries = listDirectory(requestedPath);
      return NextResponse.json({
        type: "directory",
        path: safePath,
        entries,
      });
    }

    if (action === "read" || (action === "auto" && stats.isFile())) {
      const content = readFile(requestedPath);
      return NextResponse.json({
        type: "file",
        path: safePath,
        content,
      });
    }

    return NextResponse.json(
      { error: "Cannot determine action for this path" },
      { status: 400 }
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const status = message.includes("outside the allowed root")
      ? 403
      : message.includes("ENOENT")
        ? 404
        : message.includes("File too large")
          ? 413
          : 500;
    return NextResponse.json({ error: message }, { status });
  }
}
