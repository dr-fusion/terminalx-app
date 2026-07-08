import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { Bot } from "grammy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tmpHome: string;
let patchTopicMock: ReturnType<typeof vi.fn>;

type TestCodexEntry = {
  timestamp: string;
  type: string;
  payload: Record<string, unknown>;
};

function sessionsDir(): string {
  return path.join(tmpHome, ".codex", "sessions", "2026", "04", "27");
}

function writeCodexJsonl(opts: {
  name: string;
  cwd: string;
  sessionStartedAt: string;
  prompt?: string;
  promptAt?: string;
  reply?: string;
  replyAt?: string;
}): string {
  const dir = sessionsDir();
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, opts.name);
  const entries: TestCodexEntry[] = [
    {
      timestamp: opts.sessionStartedAt,
      type: "session_meta",
      payload: {
        id: opts.name.replace(/\.jsonl$/, ""),
        timestamp: opts.sessionStartedAt,
        cwd: opts.cwd,
      },
    },
  ];
  if (opts.prompt && opts.promptAt) {
    entries.push({
      timestamp: opts.promptAt,
      type: "event_msg",
      payload: {
        type: "user_message",
        message: opts.prompt,
      },
    });
  }
  if (opts.reply && opts.replyAt) {
    entries.push({
      timestamp: opts.replyAt,
      type: "event_msg",
      payload: {
        type: "agent_message",
        phase: "final_answer",
        message: opts.reply,
      },
    });
  }
  fs.writeFileSync(file, entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
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
  return import("@/lib/telegram/codex-transcript");
}

describe("telegram Codex transcript routing", () => {
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-codex-"));
  });

  afterEach(() => {
    vi.doUnmock("os");
    vi.doUnmock("@/lib/telegram/state");
    vi.resetModules();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it("matches a Codex transcript by cwd and Telegram prompt text", async () => {
    const cwd = "/work/project";
    const prompt = "ship the fix";
    const jsonl = writeCodexJsonl({
      name: "rollout-a.jsonl",
      cwd,
      sessionStartedAt: "2026-04-27T18:00:00.000Z",
      prompt,
      promptAt: "2026-04-27T18:10:00.100Z",
      reply: "done",
      replyAt: "2026-04-27T18:10:05.000Z",
    });
    writeCodexJsonl({
      name: "rollout-other-cwd.jsonl",
      cwd: "/other/project",
      sessionStartedAt: "2026-04-27T18:00:00.000Z",
      prompt,
      promptAt: "2026-04-27T18:10:00.000Z",
      reply: "wrong",
      replyAt: "2026-04-27T18:10:05.000Z",
    });
    const { findCodexJsonlForSession } = await loadTranscriptModule();

    expect(
      findCodexJsonlForSession({
        cwd,
        sinceMs: Date.parse("2026-04-27T18:10:00.000Z"),
        exclude: new Set(),
        promptText: prompt,
      })
    ).toBe(jsonl);
  });

  it("refuses ambiguous prompt matches instead of guessing between topics", async () => {
    const cwd = "/work/project";
    const prompt = "same prompt";
    for (const name of ["rollout-a.jsonl", "rollout-b.jsonl"]) {
      writeCodexJsonl({
        name,
        cwd,
        sessionStartedAt: "2026-04-27T18:00:00.000Z",
        prompt,
        promptAt: "2026-04-27T18:10:00.000Z",
        reply: name,
        replyAt: "2026-04-27T18:10:05.000Z",
      });
    }
    const { findCodexJsonlForSession } = await loadTranscriptModule();

    expect(
      findCodexJsonlForSession({
        cwd,
        sinceMs: Date.parse("2026-04-27T18:10:00.000Z"),
        exclude: new Set(),
        promptText: prompt,
        sessionStartedMs: Date.parse("2026-04-27T18:00:00.000Z"),
      })
    ).toBeNull();
  });

  it("uses session start time to break close prompt ties safely", async () => {
    const cwd = "/work/project";
    const prompt = "same prompt";
    const expected = writeCodexJsonl({
      name: "rollout-a.jsonl",
      cwd,
      sessionStartedAt: "2026-04-27T18:00:00.000Z",
      prompt,
      promptAt: "2026-04-27T18:10:00.000Z",
      reply: "a",
      replyAt: "2026-04-27T18:10:05.000Z",
    });
    writeCodexJsonl({
      name: "rollout-b.jsonl",
      cwd,
      sessionStartedAt: "2026-04-27T18:02:00.000Z",
      prompt,
      promptAt: "2026-04-27T18:10:00.300Z",
      reply: "b",
      replyAt: "2026-04-27T18:10:05.000Z",
    });
    const { findCodexJsonlForSession } = await loadTranscriptModule();

    expect(
      findCodexJsonlForSession({
        cwd,
        sinceMs: Date.parse("2026-04-27T18:10:00.000Z"),
        exclude: new Set(),
        promptText: prompt,
        sessionStartedMs: Date.parse("2026-04-27T18:00:00.000Z"),
      })
    ).toBe(expected);
  });

  it("binds a web-started Codex transcript by cwd and session start without a Telegram prompt", async () => {
    const cwd = "/work/project";
    const jsonl = writeCodexJsonl({
      name: "rollout-web.jsonl",
      cwd,
      sessionStartedAt: "2026-04-27T18:00:05.000Z",
      reply: "web response",
      replyAt: "2026-04-27T18:00:12.000Z",
    });
    writeCodexJsonl({
      name: "rollout-later.jsonl",
      cwd,
      sessionStartedAt: "2026-04-27T18:10:00.000Z",
      reply: "wrong response",
      replyAt: "2026-04-27T18:10:12.000Z",
    });
    const bot = {
      api: {
        sendMessage: vi.fn().mockResolvedValue({}),
      },
    } as unknown as Bot;
    const { startCodexTranscript } = await loadTranscriptModule();

    const started = startCodexTranscript(bot, 1, 101, {
      cwd,
      sessionStartedMs: Date.parse("2026-04-27T18:00:00.000Z"),
    });

    expect(started?.jsonl).toBe(jsonl);
    await vi.waitFor(() =>
      expect(bot.api.sendMessage).toHaveBeenCalledWith(
        1,
        "web response",
        expect.objectContaining({ message_thread_id: 101, parse_mode: "MarkdownV2" })
      )
    );
    started?.stop();
  });

  it("checkpoints commentary without sending it to Telegram", async () => {
    const dir = sessionsDir();
    fs.mkdirSync(dir, { recursive: true });
    const jsonl = path.join(dir, "rollout-commentary.jsonl");
    fs.writeFileSync(
      jsonl,
      JSON.stringify({
        timestamp: "2026-04-27T18:00:05.000Z",
        type: "event_msg",
        payload: {
          type: "agent_message",
          phase: "commentary",
          message: "working on it",
        },
      }) + "\n"
    );
    const fullOffset = fs.statSync(jsonl).size;
    const bot = {
      api: {
        sendMessage: vi.fn().mockResolvedValue({}),
      },
    } as unknown as Bot;
    const { startCodexTranscript } = await loadTranscriptModule();

    const started = startCodexTranscript(bot, 1, 101, {
      persistedJsonl: jsonl,
      initialOffset: 0,
    });

    await vi.waitFor(() =>
      expect(patchTopicMock).toHaveBeenCalledWith(
        101,
        expect.objectContaining({ jsonlPath: jsonl, jsonlOffset: fullOffset })
      )
    );
    expect(bot.api.sendMessage).not.toHaveBeenCalled();
    started?.stop();
  });

  it("refuses to bind a promptless transcript that started much later", async () => {
    const cwd = "/work/project";
    writeCodexJsonl({
      name: "rollout-too-late.jsonl",
      cwd,
      sessionStartedAt: "2026-04-27T18:10:00.000Z",
      reply: "wrong response",
      replyAt: "2026-04-27T18:10:12.000Z",
    });
    const { findCodexJsonlForSession } = await loadTranscriptModule();

    expect(
      findCodexJsonlForSession({
        cwd,
        sinceMs: Date.parse("2026-04-27T18:00:00.000Z"),
        exclude: new Set(),
        promptText: "",
        sessionStartedMs: Date.parse("2026-04-27T18:00:00.000Z"),
      })
    ).toBeNull();
  });

  it("does not let two topics tail the same persisted transcript", async () => {
    const jsonl = writeCodexJsonl({
      name: "rollout-a.jsonl",
      cwd: "/work/project",
      sessionStartedAt: "2026-04-27T18:00:00.000Z",
    });
    const bot = {
      api: {
        sendMessage: vi.fn().mockResolvedValue({}),
      },
    } as unknown as Bot;
    const { startCodexTranscript } = await loadTranscriptModule();

    const first = startCodexTranscript(bot, 1, 101, { persistedJsonl: jsonl });
    const second = startCodexTranscript(bot, 1, 102, { persistedJsonl: jsonl });

    expect(first).not.toBeNull();
    expect(second).toBeNull();
    first?.stop();
  });

  it("resumes from a persisted offset without replaying prior Telegram messages", async () => {
    const jsonl = writeCodexJsonl({
      name: "rollout-resume.jsonl",
      cwd: "/work/project",
      sessionStartedAt: "2026-04-27T18:00:00.000Z",
      reply: "already sent",
      replyAt: "2026-04-27T18:00:05.000Z",
    });
    const initialOffset = fs.statSync(jsonl).size;
    const bot = {
      api: {
        sendMessage: vi.fn().mockResolvedValue({}),
      },
    } as unknown as Bot;
    const { startCodexTranscript } = await loadTranscriptModule();

    const started = startCodexTranscript(bot, 1, 101, {
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
    const dir = sessionsDir();
    fs.mkdirSync(dir, { recursive: true });
    const jsonl = path.join(dir, "rollout-failure.jsonl");
    fs.writeFileSync(
      jsonl,
      JSON.stringify({
        timestamp: "2026-04-27T18:00:05.000Z",
        type: "event_msg",
        payload: {
          type: "agent_message",
          phase: "final_answer",
          message: "retry me",
        },
      }) + "\n"
    );
    const fullOffset = fs.statSync(jsonl).size;
    const bot = {
      api: {
        sendMessage: vi.fn().mockRejectedValue({
          error_code: 429,
          parameters: { retry_after: 1 },
        }),
      },
    } as unknown as Bot;
    const { startCodexTranscript } = await loadTranscriptModule();

    const started = startCodexTranscript(bot, 1, 101, {
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
    const restarted = reloaded.startCodexTranscript(bot, 1, 101, {
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
