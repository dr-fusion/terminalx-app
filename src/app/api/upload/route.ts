import { NextRequest, NextResponse } from "next/server";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

function getUploadDir(): string {
  const root = process.env.TERMINUS_ROOT || process.env.HOME || "/";
  const uploadDir = path.join(root, "uploads");
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
  }
  return uploadDir;
}

export async function POST(req: NextRequest) {
  const readOnly = process.env.TERMINUS_READ_ONLY === "true";
  if (readOnly) {
    return NextResponse.json(
      { error: "Uploads disabled in read-only mode" },
      { status: 403 }
    );
  }

  const contentType = req.headers.get("content-type") || "";
  if (!contentType.includes("multipart/form-data")) {
    return NextResponse.json(
      { error: "Expected multipart/form-data" },
      { status: 400 }
    );
  }

  try {
    const formData = await req.formData();
    const file = formData.get("file") as File | null;

    if (!file) {
      return NextResponse.json(
        { error: "No file provided" },
        { status: 400 }
      );
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

    const uploadDir = getUploadDir();
    const filePath = path.join(uploadDir, safeFilename);

    // Write file
    const arrayBuffer = await file.arrayBuffer();
    fs.writeFileSync(filePath, Buffer.from(arrayBuffer));

    return NextResponse.json({
      success: true,
      filename: safeFilename,
      path: filePath,
      size: file.size,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
