import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

vi.mock("@/lib/telegram/config", () => ({
  getTelegramConfig: () => ({ botToken: "test-token" }),
}));

import { downloadFromTelegram } from "@/lib/telegram/files";

const TEST_ROOT = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-tg-files-")));
const UPLOAD_DIR = path.join(TEST_ROOT, "uploads");

beforeAll(() => {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
});

beforeEach(() => {
  fs.rmSync(UPLOAD_DIR, { recursive: true, force: true });
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  process.env.TERMINUS_ROOT = TEST_ROOT;
  process.env.TERMINALX_DEVICES_FILE = path.join(UPLOAD_DIR, "devices.json");
  process.env.TERMINALX_DEVICE_REVOCATIONS_DIR = path.join(UPLOAD_DIR, "device-fences");
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () => Uint8Array.from([1, 2, 3, 4]).buffer,
    })
  );
});

afterAll(() => {
  vi.unstubAllGlobals();
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
  delete process.env.TERMINUS_ROOT;
  delete process.env.TERMINALX_DEVICES_FILE;
  delete process.env.TERMINALX_DEVICE_REVOCATIONS_DIR;
});

describe("Telegram file destination authority", () => {
  it("cannot overwrite an exact sensitive authority file through an allowed directory", async () => {
    fs.writeFileSync(path.join(UPLOAD_DIR, "devices.json"), "original-authority-state");
    const bot = {
      api: {
        getFile: vi.fn().mockResolvedValue({
          file_path: "documents/remote.bin",
          file_size: 4,
        }),
      },
    };

    await expect(
      downloadFromTelegram(bot as never, "file-id", "uploads", "devices.json")
    ).rejects.toThrow("Access denied to sensitive path");
    expect(fs.readFileSync(path.join(UPLOAD_DIR, "devices.json"), "utf8")).toBe(
      "original-authority-state"
    );
  });

  it("cannot write inside a sensitive tombstone directory", async () => {
    fs.mkdirSync(path.join(UPLOAD_DIR, "device-fences"), { recursive: true });
    const bot = {
      api: {
        getFile: vi.fn().mockResolvedValue({
          file_path: "documents/remote.bin",
          file_size: 4,
        }),
      },
    };

    await expect(
      downloadFromTelegram(bot as never, "file-id", "uploads/device-fences", "claim.json")
    ).rejects.toThrow("Access denied to sensitive path");
    expect(fs.existsSync(path.join(UPLOAD_DIR, "device-fences", "claim.json"))).toBe(false);
  });

  it("cannot follow an allowed-name symlink into a sensitive authority file", async () => {
    const authorityFile = path.join(UPLOAD_DIR, "devices.json");
    fs.writeFileSync(authorityFile, "original-authority-state");
    fs.symlinkSync(authorityFile, path.join(UPLOAD_DIR, "notes.bin"));
    const bot = {
      api: {
        getFile: vi.fn().mockResolvedValue({
          file_path: "documents/remote.bin",
          file_size: 4,
        }),
      },
    };

    await expect(
      downloadFromTelegram(bot as never, "file-id", "uploads", "notes.bin")
    ).rejects.toThrow();
    expect(fs.readFileSync(authorityFile, "utf8")).toBe("original-authority-state");
  });

  it("still writes an ordinary sanitized filename", async () => {
    const bot = {
      api: {
        getFile: vi.fn().mockResolvedValue({
          file_path: "documents/remote.bin",
          file_size: 4,
        }),
      },
    };

    await expect(
      downloadFromTelegram(bot as never, "file-id", "uploads", "notes.bin")
    ).resolves.toEqual({ savedTo: "uploads/notes.bin", bytes: 4 });
    expect(fs.readFileSync(path.join(UPLOAD_DIR, "notes.bin"))).toEqual(Buffer.from([1, 2, 3, 4]));
  });
});
