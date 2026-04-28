import * as fs from "fs";
import * as path from "path";
import type { Bot } from "grammy";
import { InputFile } from "grammy";
import { assertNotSensitivePath, resolveSafePath } from "@/lib/file-service";

const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024; // 50 MB — Telegram bot file limit
const IMAGE_EXTS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"]);

/**
 * Sanitise a filename. Drops directory components and anything that's not
 * `[a-zA-Z0-9._-]`; ensures non-empty fallback.
 */
function safeFileName(name: string | undefined, fallback = "upload"): string {
  if (!name) return fallback;
  const base = path.basename(name).replace(/[^a-zA-Z0-9._-]/g, "_");
  return base.length ? base : fallback;
}

function isImage(filename: string): boolean {
  return IMAGE_EXTS.has(path.extname(filename).toLowerCase());
}

/**
 * Download a Telegram file (photo, document, voice, etc.) by file_id and
 * save it under `<destDir>/<filename>`. destDir is resolved against
 * TERMINUS_ROOT via the same helper the web app uses, so users can't
 * write outside the box.
 */
export async function downloadFromTelegram(
  bot: Bot,
  fileId: string,
  destDir: string,
  preferredName?: string
): Promise<{ savedTo: string; bytes: number }> {
  const safeDir = resolveSafePath(destDir);
  assertNotSensitivePath(safeDir);
  if (!fs.existsSync(safeDir) || !fs.statSync(safeDir).isDirectory()) {
    throw new Error(`destination is not a directory: ${destDir}`);
  }

  const file = await bot.api.getFile(fileId);
  if (file.file_size && file.file_size > MAX_DOWNLOAD_BYTES) {
    throw new Error(`file too large (${file.file_size} bytes, max ${MAX_DOWNLOAD_BYTES})`);
  }
  if (!file.file_path) {
    throw new Error("telegram returned no file_path");
  }

  const token = process.env.TERMINALX_TELEGRAM_BOT_TOKEN;
  const url = `https://api.telegram.org/file/bot${token}/${file.file_path}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_DOWNLOAD_BYTES) {
    throw new Error(`file too large after download`);
  }

  const filename = safeFileName(preferredName ?? path.basename(file.file_path));
  const dest = path.join(safeDir, filename);
  fs.writeFileSync(dest, buf, { mode: 0o600 });
  const root = path.resolve(process.env.TERMINUS_ROOT || process.env.HOME || "/");
  return { savedTo: path.relative(root, dest) || filename, bytes: buf.length };
}

/**
 * Send a file from disk to a topic — picks `sendPhoto` for image extensions,
 * `sendDocument` otherwise. Caption is the relative path inside TERMINUS_ROOT.
 */
export async function sendFromServer(
  bot: Bot,
  chatId: number,
  topicId: number,
  requestedPath: string
): Promise<{ kind: "photo" | "document"; bytes: number }> {
  const safe = resolveSafePath(requestedPath);
  assertNotSensitivePath(safe);
  const stat = fs.statSync(safe);
  if (!stat.isFile()) throw new Error("not a regular file");
  const filename = path.basename(safe);
  const root = path.resolve(process.env.TERMINUS_ROOT || process.env.HOME || "/");
  const rel = path.relative(root, safe) || filename;
  const input = new InputFile(safe);
  if (isImage(filename)) {
    await bot.api.sendPhoto(chatId, input, {
      message_thread_id: topicId,
      caption: rel,
    });
    return { kind: "photo", bytes: stat.size };
  }
  await bot.api.sendDocument(chatId, input, {
    message_thread_id: topicId,
    caption: rel,
  });
  return { kind: "document", bytes: stat.size };
}
