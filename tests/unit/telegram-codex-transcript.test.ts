import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { Bot } from "grammy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tmpHome: string;

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
  vi.doMock("os", () => ({
    homedir: () => tmpHome,
  }));
  return import("@/lib/telegram/codex-transcript");
}

describe("telegram Codex transcript routing", () => {
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-codex-"));
  });

  afterEach(() => {
    vi.doUnmock("os");
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
});
