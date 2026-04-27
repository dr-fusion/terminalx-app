import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { Bot } from "grammy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tmpHome: string;

function projectDirFor(cwd: string): string {
  return path.join(tmpHome, ".claude", "projects", cwd.replace(/[\\/]/g, "-"));
}

function writeJsonl(cwd: string, name: string): string {
  const dir = projectDirFor(cwd);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, name);
  fs.writeFileSync(
    file,
    JSON.stringify({
      type: "assistant",
      message: { content: [{ type: "text", text: "hello" }] },
    }) + "\n"
  );
  return file;
}

function writePromptJsonl(cwd: string, name: string, prompt: string, reply: string): string {
  const dir = projectDirFor(cwd);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, name);
  const timestamp = new Date().toISOString();
  fs.writeFileSync(
    file,
    [
      {
        type: "user",
        timestamp,
        message: { content: prompt },
      },
      {
        type: "assistant",
        timestamp,
        message: { content: [{ type: "text", text: reply }] },
      },
    ]
      .map((entry) => JSON.stringify(entry))
      .join("\n") + "\n"
  );
  return file;
}

async function loadTranscriptModule() {
  vi.resetModules();
  vi.doMock("os", () => ({
    homedir: () => tmpHome,
  }));
  return import("@/lib/telegram/claude-transcript");
}

describe("telegram Claude transcript routing", () => {
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-telegram-"));
  });

  afterEach(() => {
    vi.doUnmock("os");
    vi.resetModules();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it("does not guess when multiple transcripts exist outside the start window", async () => {
    const cwd = "/work/project";
    writeJsonl(cwd, "first.jsonl");
    writeJsonl(cwd, "second.jsonl");
    const { findJsonlForSession } = await loadTranscriptModule();

    expect(
      findJsonlForSession({
        cwd,
        sinceMs: Date.now() + 5 * 60_000,
        exclude: new Set(),
      })
    ).toBeNull();
  });

  it("does not use the globally latest transcript without a topic jsonl path", async () => {
    writeJsonl("/work/project", "latest.jsonl");
    const { readLastAssistantText } = await loadTranscriptModule();

    expect(readLastAssistantText()).toBeNull();
  });

  it("can match a delayed transcript by the Telegram prompt text", async () => {
    const cwd = "/work/project";
    const prompt = "hello from topic a";
    const jsonl = writePromptJsonl(cwd, "session.jsonl", prompt, "hi");
    const { findJsonlForSession } = await loadTranscriptModule();

    expect(
      findJsonlForSession({
        cwd,
        sinceMs: Date.now() - 120_000,
        exclude: new Set(),
        promptText: prompt,
      })
    ).toBe(jsonl);
  });

  it("does not let two topics tail the same persisted transcript", async () => {
    const jsonl = writeJsonl("/work/project", "session.jsonl");
    const bot = {
      api: {
        sendMessage: vi.fn().mockResolvedValue({}),
      },
    } as unknown as Bot;
    const { startClaudeTranscript } = await loadTranscriptModule();

    const first = startClaudeTranscript(bot, 1, 101, { persistedJsonl: jsonl });
    const second = startClaudeTranscript(bot, 1, 102, { persistedJsonl: jsonl });

    expect(first).not.toBeNull();
    expect(second).toBeNull();
    first?.stop();
  });
});
