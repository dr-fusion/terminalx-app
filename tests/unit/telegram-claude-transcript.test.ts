import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { Bot } from "grammy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tmpHome: string;
let patchTopicMock: ReturnType<typeof vi.fn>;

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
  patchTopicMock = vi.fn().mockResolvedValue(undefined);
  vi.doMock("os", () => ({
    homedir: () => tmpHome,
  }));
  vi.doMock("@/lib/telegram/state", () => ({
    getTopic: () => undefined,
    listTopics: () => [],
    patchTopic: patchTopicMock,
  }));
  return import("@/lib/telegram/claude-transcript");
}

describe("telegram Claude transcript routing", () => {
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-telegram-"));
  });

  afterEach(() => {
    vi.doUnmock("os");
    vi.doUnmock("@/lib/telegram/state");
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

  it("resumes from a persisted offset without replaying prior Telegram messages", async () => {
    const jsonl = writeJsonl("/work/project", "session.jsonl");
    const initialOffset = fs.statSync(jsonl).size;
    const bot = {
      api: {
        sendMessage: vi.fn().mockResolvedValue({}),
      },
    } as unknown as Bot;
    const { startClaudeTranscript } = await loadTranscriptModule();

    const started = startClaudeTranscript(bot, 1, 101, {
      persistedJsonl: jsonl,
      initialOffset,
    });

    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(bot.api.sendMessage).not.toHaveBeenCalled();
    expect(patchTopicMock).toHaveBeenCalledWith(
      101,
      expect.objectContaining({
        jsonlPath: jsonl,
        jsonlOffset: initialOffset,
      })
    );
    started?.stop();
  });

  it("does not advance the persisted offset when Telegram rejects a message", async () => {
    const jsonl = writeJsonl("/work/project", "retry.jsonl");
    const fullOffset = fs.statSync(jsonl).size;
    const bot = {
      api: {
        sendMessage: vi.fn().mockRejectedValue({
          error_code: 429,
          parameters: { retry_after: 1 },
        }),
      },
    } as unknown as Bot;
    const { startClaudeTranscript } = await loadTranscriptModule();

    const started = startClaudeTranscript(bot, 1, 101, {
      persistedJsonl: jsonl,
      initialOffset: 0,
    });

    await vi.waitFor(() => expect(bot.api.sendMessage).toHaveBeenCalled());
    expect(patchTopicMock).not.toHaveBeenCalledWith(101, {
      jsonlPath: jsonl,
      jsonlOffset: fullOffset,
    });
    expect(patchTopicMock).toHaveBeenCalledWith(
      101,
      expect.objectContaining({
        jsonlPath: jsonl,
        jsonlOffset: 0,
        telegramDelivery: expect.objectContaining({
          status: "failed",
          jsonlPath: jsonl,
          jsonlOffset: 0,
          nextJsonlOffset: fullOffset,
        }),
      })
    );
    started?.stop();

    const reloaded = await loadTranscriptModule();
    (bot.api.sendMessage as ReturnType<typeof vi.fn>).mockReset().mockResolvedValue({});
    const restarted = reloaded.startClaudeTranscript(bot, 1, 101, {
      persistedJsonl: jsonl,
      initialOffset: 0,
    });

    await vi.waitFor(() => expect(bot.api.sendMessage).toHaveBeenCalled());
    expect(patchTopicMock).toHaveBeenCalledWith(
      101,
      expect.objectContaining({
        jsonlPath: jsonl,
        jsonlOffset: fullOffset,
        telegramDelivery: expect.objectContaining({
          status: "sent",
          jsonlPath: jsonl,
          jsonlOffset: fullOffset,
        }),
      })
    );
    restarted?.stop();
  });
});
