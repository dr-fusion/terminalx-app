import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { isSensitivePath, resolveSafePath, listDirectory, readFile } from "@/lib/file-service";

// Set TERMINUS_ROOT to a temp directory for testing.
// Use realpathSync because macOS /var -> /private/var symlink causes path validation to fail.
const TEST_ROOT = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-test-")));

beforeAll(() => {
  process.env.TERMINUS_ROOT = TEST_ROOT;
  process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH = path.join(
    TEST_ROOT,
    "data",
    "telegram-audit.sqlite"
  );
  process.env.TERMINALX_TEAM_SESSION_DB_PATH = path.join(TEST_ROOT, "data", "team-sessions.sqlite");

  // Create test fixtures
  fs.mkdirSync(path.join(TEST_ROOT, "subdir"), { recursive: true });
  fs.writeFileSync(path.join(TEST_ROOT, "test.txt"), "hello world");
  fs.writeFileSync(path.join(TEST_ROOT, ".env"), "SECRET=do-not-read");
  fs.writeFileSync(path.join(TEST_ROOT, "subdir", "nested.txt"), "nested content");
  fs.mkdirSync(path.join(TEST_ROOT, "data"), { recursive: true });
  fs.writeFileSync(path.join(TEST_ROOT, "data", "users.json"), "[]");
  fs.writeFileSync(path.join(TEST_ROOT, "data", "telegram-audit.sqlite"), "private messages");
  for (const suffix of ["", "-wal", "-shm", "-journal"]) {
    fs.writeFileSync(
      path.join(TEST_ROOT, "data", `team-sessions.sqlite${suffix}`),
      "private Team state"
    );
  }
  fs.writeFileSync(
    path.join(TEST_ROOT, "large.txt"),
    "x".repeat(2 * 1024 * 1024) // 2MB file
  );
});

afterAll(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
  delete process.env.TERMINUS_ROOT;
  delete process.env.TERMINALX_ALLOW_SENSITIVE_FILE_ACCESS;
  delete process.env.TERMINALX_TELEGRAM_MESSAGE_DB_PATH;
  delete process.env.TERMINALX_TEAM_SESSION_DB_PATH;
  delete process.env.TERMINALX_REVOKED_TOKENS_FILE;
  delete process.env.TERMINALX_REVOKED_TOKEN_TOMBSTONE_DIR;
  delete process.env.TERMINALX_DEVICES_FILE;
  delete process.env.TERMINALX_DEVICE_REVOCATIONS_DIR;
  delete process.env.TERMINALX_PAIRING_CODES_FILE;
  delete process.env.TERMINALX_PAIRING_CONSUMPTIONS_DIR;
  delete process.env.TERMINALX_LEGACY_USERS_FILE;
});

describe("resolveSafePath", () => {
  it("resolves empty path to root", () => {
    expect(resolveSafePath("")).toBe(TEST_ROOT);
  });

  it("resolves '.' to root", () => {
    expect(resolveSafePath(".")).toBe(TEST_ROOT);
  });

  it("resolves '/' to root", () => {
    expect(resolveSafePath("/")).toBe(TEST_ROOT);
  });

  it("resolves '~' to root", () => {
    expect(resolveSafePath("~")).toBe(TEST_ROOT);
  });

  it("resolves valid subpath", () => {
    expect(resolveSafePath("subdir")).toBe(path.join(TEST_ROOT, "subdir"));
  });

  it("rejects path traversal with ../", () => {
    expect(() => resolveSafePath("../../../etc/passwd")).toThrow("outside the allowed root");
  });

  it("rejects path traversal with encoded ../", () => {
    expect(() => resolveSafePath("subdir/../../etc/passwd")).toThrow("outside the allowed root");
  });

  it("rejects absolute path outside root", () => {
    expect(() => resolveSafePath("/etc/passwd")).toThrow("outside the allowed root");
  });

  it("handles symlink traversal if symlink points outside root", () => {
    const symlinkPath = path.join(TEST_ROOT, "escape-link");
    try {
      fs.symlinkSync("/etc", symlinkPath);
      expect(() => resolveSafePath("escape-link")).toThrow("outside the allowed root");
    } finally {
      fs.unlinkSync(symlinkPath);
    }
  });

  it("allows symlink within root", () => {
    const symlinkPath = path.join(TEST_ROOT, "safe-link");
    try {
      fs.symlinkSync(path.join(TEST_ROOT, "subdir"), symlinkPath);
      const resolved = resolveSafePath("safe-link");
      expect(resolved).toBe(path.join(TEST_ROOT, "subdir"));
    } finally {
      fs.unlinkSync(symlinkPath);
    }
  });

  it("handles non-existent path (ENOENT) without throwing", () => {
    const result = resolveSafePath("nonexistent-file.txt");
    expect(result).toBe(path.join(TEST_ROOT, "nonexistent-file.txt"));
  });
});

describe("listDirectory", () => {
  it("lists directory contents", () => {
    const entries = listDirectory(".");
    const names = entries.map((e) => e.name);
    expect(names).toContain("test.txt");
    expect(names).toContain("subdir");
    expect(names).not.toContain(".env");
  });

  it("sorts directories before files", () => {
    const entries = listDirectory(".");
    const dirIndex = entries.findIndex((e) => e.name === "subdir");
    const fileIndex = entries.findIndex((e) => e.name === "test.txt");
    expect(dirIndex).toBeLessThan(fileIndex);
  });

  it("throws for non-directory path", () => {
    expect(() => listDirectory("test.txt")).toThrow("not a directory");
  });
});

describe("readFile", () => {
  it("reads file content", () => {
    const content = readFile("test.txt");
    expect(content).toBe("hello world");
  });

  it("rejects sensitive files", () => {
    expect(() => readFile(".env")).toThrow("sensitive path");
    expect(() => readFile("data/users.json")).toThrow("sensitive path");
    expect(() => readFile(`data/.revoked-tokens.json.d/${"a".repeat(64)}.json`)).toThrow(
      "sensitive path"
    );
    expect(() => readFile("data/devices.json")).toThrow("sensitive path");
    expect(() => readFile(`data/devices.json.revocations/${"b".repeat(64)}.json`)).toThrow(
      "sensitive path"
    );
    expect(() => readFile("data/pairing-codes.json")).toThrow("sensitive path");
    expect(() => readFile("data/telegram-audit.sqlite")).toThrow("sensitive path");
    for (const suffix of ["", "-wal", "-shm", "-journal"]) {
      expect(() => readFile(`data/team-sessions.sqlite${suffix}`)).toThrow("sensitive path");
    }
  });

  it("protects default authority files when the app is nested beneath TERMINUS_ROOT", () => {
    process.env.TERMINUS_ROOT = path.dirname(process.cwd());
    try {
      const data = path.join(process.cwd(), "data");
      expect(isSensitivePath(path.join(data, "devices.json"))).toBe(true);
      expect(
        isSensitivePath(path.join(data, "devices.json.revocations", `${"a".repeat(64)}.json`))
      ).toBe(true);
      expect(isSensitivePath(path.join(data, "pairing-codes.json"))).toBe(true);
      expect(
        isSensitivePath(path.join(data, "pairing-codes.json.consumed", `${"b".repeat(64)}.json`))
      ).toBe(true);
      expect(isSensitivePath(path.join(data, ".revoked-tokens.json"))).toBe(true);
      expect(isSensitivePath(path.join(data, "users.json"))).toBe(true);
      expect(isSensitivePath(path.join(data, "telegram-state.json.tmp"))).toBe(true);
      expect(isSensitivePath(path.join(data, "ai-sessions.json"))).toBe(true);
      expect(isSensitivePath(path.join(data, "snippets.json.tmp"))).toBe(true);
    } finally {
      process.env.TERMINUS_ROOT = TEST_ROOT;
    }
  });

  it("protects configured authority paths and their atomic temporary files", () => {
    const privateDir = path.join(TEST_ROOT, "custom-authority");
    const devicesFile = path.join(privateDir, "paired-state.json");
    const deviceRevocations = path.join(privateDir, "device-fences");
    const pairingFile = path.join(privateDir, "pair-state.json");
    const pairingConsumptions = path.join(privateDir, "pair-claims");
    const revokedTokensFile = path.join(privateDir, "logout-state.json");
    const revokedTokenTombstones = path.join(privateDir, "logout-fences");
    const legacyUsersFile = path.join(privateDir, "legacy-accounts.json");
    process.env.TERMINALX_DEVICES_FILE = devicesFile;
    process.env.TERMINALX_DEVICE_REVOCATIONS_DIR = deviceRevocations;
    process.env.TERMINALX_PAIRING_CODES_FILE = pairingFile;
    process.env.TERMINALX_PAIRING_CONSUMPTIONS_DIR = pairingConsumptions;
    process.env.TERMINALX_REVOKED_TOKENS_FILE = revokedTokensFile;
    process.env.TERMINALX_REVOKED_TOKEN_TOMBSTONE_DIR = revokedTokenTombstones;
    process.env.TERMINALX_LEGACY_USERS_FILE = legacyUsersFile;
    try {
      expect(isSensitivePath(devicesFile)).toBe(true);
      expect(isSensitivePath(path.join(privateDir, ".paired-state.json.1.abc.tmp"))).toBe(true);
      expect(isSensitivePath(path.join(deviceRevocations, "claim.json"))).toBe(true);
      expect(isSensitivePath(pairingFile)).toBe(true);
      expect(isSensitivePath(path.join(privateDir, ".pair-state.json.1.abc.tmp"))).toBe(true);
      expect(isSensitivePath(path.join(pairingConsumptions, "claim.json"))).toBe(true);
      expect(isSensitivePath(revokedTokensFile)).toBe(true);
      expect(isSensitivePath(path.join(revokedTokenTombstones, "claim.json"))).toBe(true);
      expect(isSensitivePath(legacyUsersFile)).toBe(true);
    } finally {
      delete process.env.TERMINALX_DEVICES_FILE;
      delete process.env.TERMINALX_DEVICE_REVOCATIONS_DIR;
      delete process.env.TERMINALX_PAIRING_CODES_FILE;
      delete process.env.TERMINALX_PAIRING_CONSUMPTIONS_DIR;
      delete process.env.TERMINALX_REVOKED_TOKENS_FILE;
      delete process.env.TERMINALX_REVOKED_TOKEN_TOMBSTONE_DIR;
      delete process.env.TERMINALX_LEGACY_USERS_FILE;
    }
  });

  it("throws for directory", () => {
    expect(() => readFile("subdir")).toThrow("not a file");
  });

  it("throws for file exceeding size limit", () => {
    expect(() => readFile("large.txt")).toThrow("File too large");
  });
});
