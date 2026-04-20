import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as mod from "@/lib/snippets";

describe("snippets", () => {
  let tmpDir: string;
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tx-snippets-"));
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function load() {
    return mod;
  }

  it("creates a snippet with required fields", async () => {
    const mod = await load();
    const s = await mod.createSnippet({ name: "hello", command: "echo hi" });
    expect(s.id).toMatch(/[0-9a-f-]{36}/);
    expect(s.name).toBe("hello");
    expect(s.command).toBe("echo hi");
    expect(s.createdAt).toBeTruthy();
  });

  it("persists snippets to disk (atomic write)", async () => {
    const mod = await load();
    await mod.createSnippet({ name: "a", command: "ls" });
    const file = path.join(tmpDir, "data", "snippets.json");
    expect(fs.existsSync(file)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(file, "utf-8"));
    expect(parsed).toHaveLength(1);
    expect(parsed[0].name).toBe("a");
  });

  it("rejects missing name", async () => {
    const mod = await load();
    await expect(
      mod.createSnippet({ name: "", command: "ls" })
    ).rejects.toThrow(/Name required/);
  });

  it("rejects missing command", async () => {
    const mod = await load();
    await expect(
      mod.createSnippet({ name: "x", command: "" })
    ).rejects.toThrow(/Command required/);
  });

  it("rejects overlong name", async () => {
    const mod = await load();
    await expect(
      mod.createSnippet({ name: "x".repeat(100), command: "ls" })
    ).rejects.toThrow(/Name too long/);
  });

  it("rejects overlong command", async () => {
    const mod = await load();
    await expect(
      mod.createSnippet({ name: "x", command: "y".repeat(5000) })
    ).rejects.toThrow(/Command too long/);
  });

  it("deletes a snippet by id", async () => {
    const mod = await load();
    const s = await mod.createSnippet({ name: "a", command: "ls" });
    expect(mod.listSnippets()).toHaveLength(1);
    await mod.deleteSnippet(s.id);
    expect(mod.listSnippets()).toHaveLength(0);
  });

  it("getSnippet returns matching snippet", async () => {
    const mod = await load();
    const s = await mod.createSnippet({
      name: "a",
      command: "ls",
      createdBy: "alice",
    });
    const found = mod.getSnippet(s.id);
    expect(found?.createdBy).toBe("alice");
  });

  it("getSnippet returns undefined for unknown id", async () => {
    const mod = await load();
    expect(mod.getSnippet("nonexistent")).toBeUndefined();
  });
});
