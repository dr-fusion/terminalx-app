import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { downloadFromTelegram } from "@/lib/telegram/files";
import { legacyTelegramIntegrationEnabled } from "@/lib/telegram/config";

type FakeBot = { api: { getFile: (fileId: string) => Promise<{ file_path: string }> } };

function fakeBot(filePath: string): FakeBot {
  return { api: { getFile: async () => ({ file_path: filePath }) } };
}

describe("legacy Telegram download descriptor-relative creation", () => {
  const previousRoot = process.env.TERMINUS_ROOT;
  const content = Buffer.from("payload-bytes", "utf8");
  let root: string;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "tg-download-race-"));
    process.env.TERMINUS_ROOT = root;
    fetchSpy = vi.fn(async () => ({
      ok: true,
      status: 200,
      arrayBuffer: async () => {
        const copy = new ArrayBuffer(content.length);
        new Uint8Array(copy).set(content);
        return copy;
      },
    }));
    vi.stubGlobal("fetch", fetchSpy);
    // A bot token is required by the download URL builder.
    process.env.TERMINALX_TELEGRAM_BOT_TOKEN = "111:legacy-test-token";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fs.rmSync(root, { recursive: true, force: true });
    if (previousRoot === undefined) delete process.env.TERMINUS_ROOT;
    else process.env.TERMINUS_ROOT = previousRoot;
    delete process.env.TERMINALX_TELEGRAM_BOT_TOKEN;
  });

  it("creates the file inside the destination directory", async () => {
    const destDir = path.join(root, "inbox");
    fs.mkdirSync(destDir);
    const result = await downloadFromTelegram(
      fakeBot("photos/file_1.png") as never,
      "file-id-1",
      destDir,
      "note.txt"
    );
    const saved = path.join(destDir, "note.txt");
    expect(fs.readFileSync(saved)).toEqual(content);
    expect((fs.statSync(saved).mode & 0o777).toString(8)).toBe("600");
    expect(result.bytes).toBe(content.length);
  });

  it("fails closed when the target name is a pre-existing symlink (O_EXCL|O_NOFOLLOW)", async () => {
    const destDir = path.join(root, "inbox");
    fs.mkdirSync(destDir);
    const authorityStore = path.join(root, "authority.db");
    fs.writeFileSync(authorityStore, "do-not-touch");
    // A same-host actor plants a symlink at the allowed name aimed at a store.
    fs.symlinkSync(authorityStore, path.join(destDir, "note.txt"));

    await expect(
      downloadFromTelegram(fakeBot("photos/file_1.png") as never, "file-id-1", destDir, "note.txt")
    ).rejects.toThrow();
    // The symlink target was never overwritten.
    expect(fs.readFileSync(authorityStore, "utf8")).toBe("do-not-touch");
  });

  it("fails closed when the file already exists (exclusive creation)", async () => {
    const destDir = path.join(root, "inbox");
    fs.mkdirSync(destDir);
    fs.writeFileSync(path.join(destDir, "note.txt"), "existing");
    await expect(
      downloadFromTelegram(fakeBot("photos/file_1.png") as never, "file-id-1", destDir, "note.txt")
    ).rejects.toThrow();
    expect(fs.readFileSync(path.join(destDir, "note.txt"), "utf8")).toBe("existing");
  });
});

describe("legacyTelegramIntegrationEnabled flag", () => {
  const previous = process.env.TERMINALX_LEGACY_TELEGRAM;
  afterEach(() => {
    if (previous === undefined) delete process.env.TERMINALX_LEGACY_TELEGRAM;
    else process.env.TERMINALX_LEGACY_TELEGRAM = previous;
  });

  it("defaults to today's behavior (enabled) when unset", () => {
    delete process.env.TERMINALX_LEGACY_TELEGRAM;
    expect(legacyTelegramIntegrationEnabled()).toBe(true);
  });

  it("is disabled only by an explicit falsey value", () => {
    for (const value of ["false", "0", "off", "no", "FALSE", " Off "]) {
      process.env.TERMINALX_LEGACY_TELEGRAM = value;
      expect(legacyTelegramIntegrationEnabled()).toBe(false);
    }
    for (const value of ["true", "1", "on", "", "yes"]) {
      process.env.TERMINALX_LEGACY_TELEGRAM = value;
      expect(legacyTelegramIntegrationEnabled()).toBe(true);
    }
  });
});
