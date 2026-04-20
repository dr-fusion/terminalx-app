import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as mod from "@/lib/session-recorder";

describe("session-recorder", () => {
  let tmpDir: string;
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tx-rec-"));
    process.chdir(tmpDir);
    delete process.env.TERMINUS_RECORD_SESSIONS;
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TERMINUS_RECORD_SESSIONS;
  });

  async function load() {
    return mod;
  }

  it("returns null from startRecorder when disabled", async () => {
    const mod = await load();
    const rec = mod.startRecorder({ sessionId: "x", cols: 80, rows: 24 });
    expect(rec).toBeNull();
  });

  it("returns a recorder when enabled and writes header + entries", async () => {
    process.env.TERMINUS_RECORD_SESSIONS = "true";
    const mod = await load();
    const rec = mod.startRecorder({
      sessionId: "my-sess",
      username: "alice",
      cols: 80,
      rows: 24,
    });
    expect(rec).not.toBeNull();
    rec!.write("hello");
    await rec!.close();

    const file = path.join(tmpDir, "data", "recordings", rec!.id + ".jsonl");
    expect(fs.existsSync(file)).toBe(true);
    const lines = fs.readFileSync(file, "utf-8").trim().split("\n");
    expect(lines.length).toBeGreaterThanOrEqual(2);
    const header = JSON.parse(lines[0]!);
    expect(header.v).toBe(1);
    expect(header.sessionId).toBe("my-sess");
    expect(header.username).toBe("alice");
    const entry = JSON.parse(lines[1]!);
    expect(entry.d).toBe("hello");
    expect(typeof entry.t).toBe("number");
  });

  it("sanitizes sessionId in the recording id (prevents path traversal)", async () => {
    process.env.TERMINUS_RECORD_SESSIONS = "true";
    const mod = await load();
    const rec = mod.startRecorder({
      sessionId: "../evil/../../etc",
      cols: 80,
      rows: 24,
    });
    expect(rec).not.toBeNull();
    expect(rec!.id).not.toMatch(/\//);
    expect(rec!.id).not.toMatch(/\\/);
    expect(rec!.file).toContain(path.join(tmpDir, "data", "recordings"));
    // File resolves inside recordings dir even with traversal-y input
    expect(path.resolve(rec!.file).startsWith(path.resolve(tmpDir, "data", "recordings"))).toBe(
      true
    );
    await rec!.close();
  });

  it("getRecordingPath returns null for traversal attempts", async () => {
    process.env.TERMINUS_RECORD_SESSIONS = "true";
    const mod = await load();
    expect(mod.getRecordingPath("../etc/passwd")).toBeNull();
    expect(mod.getRecordingPath("safe/nested")).toBeNull();
  });

  it("getRecordingPath returns null for non-existent recording", async () => {
    process.env.TERMINUS_RECORD_SESSIONS = "true";
    const mod = await load();
    expect(mod.getRecordingPath("does-not-exist-abc123")).toBeNull();
  });

  it("listRecordings returns recordings sorted by startedAt desc", async () => {
    process.env.TERMINUS_RECORD_SESSIONS = "true";
    const mod = await load();
    const a = mod.startRecorder({ sessionId: "a", cols: 80, rows: 24 });
    await new Promise((r) => setTimeout(r, 10));
    const b = mod.startRecorder({ sessionId: "b", cols: 80, rows: 24 });
    await a!.close();
    await b!.close();

    const recs = mod.listRecordings();
    expect(recs).toHaveLength(2);
    expect(recs[0]!.startedAt >= recs[1]!.startedAt).toBe(true);
  });

  it("getRecordingMeta includes createdBy from header", async () => {
    process.env.TERMINUS_RECORD_SESSIONS = "true";
    const mod = await load();
    const rec = mod.startRecorder({
      sessionId: "s",
      username: "bob",
      cols: 80,
      rows: 24,
    });
    await rec!.close();

    const meta = mod.getRecordingMeta(rec!.id);
    expect(meta).not.toBeNull();
    expect(meta!.createdBy).toBe("bob");
    expect(meta!.sessionId).toBe("s");
  });

  it("isRecordingEnabled respects env var", async () => {
    const mod = await load();
    expect(mod.isRecordingEnabled()).toBe(false);
    process.env.TERMINUS_RECORD_SESSIONS = "true";
    expect(mod.isRecordingEnabled()).toBe(true);
    process.env.TERMINUS_RECORD_SESSIONS = "false";
    expect(mod.isRecordingEnabled()).toBe(false);
  });
});
