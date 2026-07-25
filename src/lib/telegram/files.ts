import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { Bot } from "grammy";
import { InputFile } from "grammy";
import { assertNotSensitivePath, resolveSafePath } from "@/lib/file-service";
import { getTelegramConfig } from "./config";

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

async function downloadTelegramFile(
  bot: Bot,
  fileId: string
): Promise<{ buffer: Buffer; name: string }> {
  const file = await bot.api.getFile(fileId);
  if (file.file_size && file.file_size > MAX_DOWNLOAD_BYTES) {
    throw new Error(`file too large (${file.file_size} bytes, max ${MAX_DOWNLOAD_BYTES})`);
  }
  if (!file.file_path) {
    throw new Error("telegram returned no file_path");
  }

  const token = getTelegramConfig().botToken;
  if (!token) throw new Error("telegram bot token is not configured");
  const url = `https://api.telegram.org/file/bot${token}/${file.file_path}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const buffer = Buffer.from(await res.arrayBuffer());
  if (buffer.length > MAX_DOWNLOAD_BYTES) {
    throw new Error(`file too large after download`);
  }
  return { buffer, name: path.basename(file.file_path) };
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

  const { buffer: buf, name } = await downloadTelegramFile(bot, fileId);

  const filename = safeFileName(preferredName ?? name);
  const dest = path.join(safeDir, filename);
  assertNotSensitivePath(dest);
  // Exclusive creation rejects both existing files and symlinks, closing the
  // check/write race where an allowed name points at an authority store.
  fs.writeFileSync(dest, buf, { mode: 0o600, flag: "wx" });
  const root = path.resolve(process.env.TERMINUS_ROOT || process.env.HOME || "/");
  return { savedTo: path.relative(root, dest) || filename, bytes: buf.length };
}

export async function downloadTelegramFileToTemp(
  bot: Bot,
  fileId: string,
  preferredName?: string
): Promise<{ filePath: string; tempDir: string; bytes: number }> {
  const { buffer, name } = await downloadTelegramFile(bot, fileId);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-tg-"));
  const filename = safeFileName(preferredName ?? name, "voice-note");
  const filePath = path.join(tempDir, filename);
  fs.writeFileSync(filePath, buffer, { mode: 0o600 });
  return { filePath, tempDir, bytes: buffer.length };
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
