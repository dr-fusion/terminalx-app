import { NextRequest, NextResponse } from "next/server";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { getUserScoping } from "@/lib/session-scope";
import { audit } from "@/lib/audit-log";
import { assertNotSensitivePath } from "@/lib/file-service";

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
const USERNAME_SEGMENT_REGEX = /^[a-zA-Z0-9_.]+$/;

function getUploadDir(username: string | null): string {
  const root = path.resolve(process.env.TERMINUS_ROOT || process.env.HOME || "/");
  const uploadsRoot = path.resolve(root, "uploads");
  if (username && !USERNAME_SEGMENT_REGEX.test(username)) {
    throw new Error("Invalid username for upload path");
  }
  const uploadDir = username ? path.resolve(uploadsRoot, username) : uploadsRoot;
  if (!uploadDir.startsWith(uploadsRoot + path.sep) && uploadDir !== uploadsRoot) {
    throw new Error("Upload path is outside the allowed upload root");
  }
  assertNotSensitivePath(uploadDir);
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true, mode: 0o700 });
  }
  return uploadDir;
}

export async function POST(req: NextRequest) {
  const readOnly = process.env.TERMINUS_READ_ONLY === "true";
  if (readOnly) {
    return NextResponse.json({ error: "Uploads disabled in read-only mode" }, { status: 403 });
  }

  // CSRF protection: require custom header that CORS preflight would block
  if (!req.headers.get("x-requested-with")) {
    return NextResponse.json({ error: "Missing required header" }, { status: 403 });
  }

  const contentType = req.headers.get("content-type") || "";
  if (!contentType.includes("multipart/form-data")) {
    return NextResponse.json({ error: "Expected multipart/form-data" }, { status: 400 });
  }

  try {
    const formData = await req.formData();
    const file = formData.get("file") as File | null;

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large (max ${MAX_FILE_SIZE / 1024 / 1024}MB)` },
        { status: 413 }
      );
    }

    // Sanitize filename: keep only safe characters
    const ext = path.extname(file.name).replace(/[^a-zA-Z0-9.]/g, "");
    const baseName = path
      .basename(file.name, path.extname(file.name))
      .replace(/[^a-zA-Z0-9_.\-]/g, "_")
      .slice(0, 100);
    const uniqueSuffix = crypto.randomBytes(4).toString("hex");
    const safeFilename = `${baseName}-${uniqueSuffix}${ext}`;

    const { username, shouldScope, hasIdentity } = getUserScoping(req.headers);
    if (!hasIdentity || (shouldScope && !username)) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    const uploadDir = getUploadDir(shouldScope ? username : null);
    const filePath = path.join(uploadDir, safeFilename);

    // Write file
    const arrayBuffer = await file.arrayBuffer();
    fs.writeFileSync(filePath, Buffer.from(arrayBuffer), { mode: 0o600 });

    audit("file_uploaded", {
      username: username || undefined,
      detail: `${safeFilename} (${file.size} bytes)`,
    });

    const root = path.resolve(process.env.TERMINUS_ROOT || process.env.HOME || "/");
    const relativePath = path.relative(root, filePath);

    return NextResponse.json({
      success: true,
      filename: safeFilename,
      path: relativePath,
      size: file.size,
    });
  } catch (err) {
    console.error("[api/upload POST]", err);
    const message = err instanceof Error ? err.message : "Upload failed";
    if (message.includes("Invalid username") || message.includes("outside the allowed")) {
      return NextResponse.json({ error: message }, { status: 400 });
    }
    if (message.includes("sensitive path")) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    return NextResponse.json({ error: "Upload failed" }, { status: 500 });
  }
}
