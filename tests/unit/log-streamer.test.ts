import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// Use realpathSync because macOS /var -> /private/var symlink causes path validation to fail.
const TEST_LOG_DIR = fs.realpathSync(
  fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-logs-test-"))
);

beforeAll(() => {
  process.env.TERMINUS_LOG_PATHS = TEST_LOG_DIR;
  // Create test log files
  fs.writeFileSync(path.join(TEST_LOG_DIR, "app.log"), "log line 1\nlog line 2\n");
  fs.writeFileSync(path.join(TEST_LOG_DIR, "error.err"), "error line\n");
  fs.writeFileSync(path.join(TEST_LOG_DIR, "output.out"), "output line\n");
  fs.writeFileSync(path.join(TEST_LOG_DIR, "binary.dat"), Buffer.from([0x00, 0x01, 0x02]));
  fs.writeFileSync(path.join(TEST_LOG_DIR, "config.conf"), "key=value\n");
});

afterAll(() => {
  fs.rmSync(TEST_LOG_DIR, { recursive: true, force: true });
  delete process.env.TERMINUS_LOG_PATHS;
});

describe("listLogFiles", () => {
  it("lists only .log, .out, .err files", async () => {
    const { listLogFiles } = await import("@/lib/log-streamer");
    const files = listLogFiles();
    const names = files.map((f) => f.name);
    expect(names).toContain("app.log");
    expect(names).toContain("error.err");
    expect(names).toContain("output.out");
    expect(names).not.toContain("binary.dat");
    expect(names).not.toContain("config.conf");
  });
});

describe("createLogStream", () => {
  it("rejects files with non-allowed extensions", async () => {
    const { createLogStream } = await import("@/lib/log-streamer");
    expect(() => createLogStream(path.join(TEST_LOG_DIR, "binary.dat"))).toThrow(
      "Only .log, .out, and .err files"
    );
    expect(() => createLogStream(path.join(TEST_LOG_DIR, "config.conf"))).toThrow(
      "Only .log, .out, and .err files"
    );
  });

  it("rejects paths outside allowed log directories", async () => {
    const { createLogStream } = await import("@/lib/log-streamer");
    expect(() => createLogStream("/etc/passwd")).toThrow("not within allowed log directories");
  });

  it("accepts valid log files", async () => {
    const { createLogStream, destroyLogStream } = await import("@/lib/log-streamer");
    const stream = createLogStream(path.join(TEST_LOG_DIR, "app.log"));
    expect(stream.id).toBeTruthy();
    expect(stream.filePath).toBe(path.join(TEST_LOG_DIR, "app.log"));
    destroyLogStream(stream.id);
  });
});
