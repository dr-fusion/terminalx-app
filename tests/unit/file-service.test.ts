import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { resolveSafePath, listDirectory, readFile } from "@/lib/file-service";

// Set TERMINUS_ROOT to a temp directory for testing.
// Use realpathSync because macOS /var -> /private/var symlink causes path validation to fail.
const TEST_ROOT = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-test-")));

beforeAll(() => {
  process.env.TERMINUS_ROOT = TEST_ROOT;

  // Create test fixtures
  fs.mkdirSync(path.join(TEST_ROOT, "subdir"), { recursive: true });
  fs.writeFileSync(path.join(TEST_ROOT, "test.txt"), "hello world");
  fs.writeFileSync(path.join(TEST_ROOT, ".env"), "SECRET=do-not-read");
  fs.writeFileSync(path.join(TEST_ROOT, "subdir", "nested.txt"), "nested content");
  fs.mkdirSync(path.join(TEST_ROOT, "data"), { recursive: true });
  fs.writeFileSync(path.join(TEST_ROOT, "data", "users.json"), "[]");
  fs.writeFileSync(
    path.join(TEST_ROOT, "large.txt"),
    "x".repeat(2 * 1024 * 1024) // 2MB file
  );
});

afterAll(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
  delete process.env.TERMINUS_ROOT;
  delete process.env.TERMINALX_ALLOW_SENSITIVE_FILE_ACCESS;
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
  });

  it("throws for directory", () => {
    expect(() => readFile("subdir")).toThrow("not a file");
  });

  it("throws for file exceeding size limit", () => {
    expect(() => readFile("large.txt")).toThrow("File too large");
  });
});
