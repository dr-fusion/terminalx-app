import { NextRequest, NextResponse } from "next/server";
import { listDirectory, readFile, getFileInfo, resolveSafePath } from "@/lib/file-service";
import { getUserScoping } from "@/lib/session-scope";
import * as fs from "fs";

export async function GET(req: NextRequest) {
  const { role, hasIdentity } = getUserScoping(req.headers);
  if (!hasIdentity || role !== "admin") {
    return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  }

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

    return NextResponse.json({ error: "Cannot determine action for this path" }, { status: 400 });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // Sanitize error messages to avoid leaking internal filesystem paths
    if (message.includes("outside the allowed root")) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    if (message.includes("sensitive path")) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    if (message.includes("ENOENT") || message.includes("no such file")) {
      return NextResponse.json({ error: "File not found" }, { status: 404 });
    }
    if (message.includes("File too large")) {
      return NextResponse.json({ error: "File too large" }, { status: 413 });
    }
    if (message.includes("not a directory") || message.includes("not a file")) {
      return NextResponse.json({ error: message }, { status: 400 });
    }
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
