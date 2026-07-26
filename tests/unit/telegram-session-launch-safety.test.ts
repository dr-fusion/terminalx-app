import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const mocks = vi.hoisted(() => ({
  createSession: vi.fn(),
  saveMeta: vi.fn(),
  commandHandlers: new Map<string, (ctx: unknown) => unknown>(),
  nextTopicId: 100,
  worktreeRoot: "",
}));

vi.mock("grammy", () => ({
  Bot: class FakeBot {
    botInfo = { id: 777 };
    api = {
      createForumTopic: vi.fn(async () => ({
        message_thread_id: ++mocks.nextTopicId,
        name: "session",
        icon_color: 0x6fb9f0,
      })),
      sendMessage: vi.fn(async () => ({ message_id: 1 })),
      setWebhook: vi.fn(async () => true),
      deleteWebhook: vi.fn(async () => true),
      closeForumTopic: vi.fn(async () => true),
    };

    command(name: string, handler: (ctx: unknown) => unknown) {
      mocks.commandHandlers.set(name, handler);
      return this;
    }

    hears() {
      return this;
    }

    on() {
      return this;
    }

    async init() {}

    async handleUpdate(update: {
      message?: {
        text?: string;
        from?: { id?: number };
        chat?: { id?: number };
        message_thread_id?: number;
      };
    }) {
      const message = update.message;
      const command = message?.text?.match(/^\/([^@\s]+)/)?.[1];
      const handler = command ? mocks.commandHandlers.get(command) : undefined;
      if (!handler || !message) return;
      await handler({
        message,
        msg: message,
        from: message.from,
        chat: message.chat,
        reply: vi.fn(async () => ({ message_id: 1 })),
      });
    }
  },
}));

vi.mock("@/lib/tmux", () => ({
  listSessions: vi.fn(() => []),
  createSession: mocks.createSession,
  killSession: vi.fn(),
  hasSession: vi.fn(() => false),
  getSessionCreatedMs: vi.fn(() => 1_784_760_000_000),
  isPaneTui: vi.fn(() => false),
  paneForegroundCommand: vi.fn(() => ""),
}));

vi.mock("@/lib/ai-sessions", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ai-sessions")>();
  return {
    ...actual,
    saveMeta: mocks.saveMeta,
    getMeta: vi.fn(() => undefined),
    ensureManagedSession: vi.fn(() => true),
  };
});

// Hermetic model resolution. `resolveSessionModelSettings` (server-only) reads a
// mutable, gitignored settings store at `process.cwd()/data/settings/user.json`
// shared across the whole process. Whether that file happens to carry an
// explicit default model — set by a prior run or another test file — decides
// whether a model-less session persists `modelId: undefined` or a resolved
// default, which made the worktree assertion below order-dependent (green only
// when some other file cleared the store first). Pin the resolver to the
// "nothing explicitly configured" state so both tests exercise the intended
// "no explicit model -> unchanged command, modelId undefined" path (issue #11)
// regardless of ambient state or execution order.
vi.mock("@/lib/settings/session-settings", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/settings/session-settings")>();
  return {
    ...actual,
    resolveSessionModelSettings: vi.fn(() => ({
      modelId: "claude:opus-4-8-1m",
      effort: "high",
      personality: "pragmatic",
      planMode: false,
      fastMode: false,
      modelExplicit: false,
    })),
  };
});

vi.mock("@/lib/git-worktree", () => ({
  createGitWorktreeForSession: vi.fn((_directory: string, branch: string) => ({
    repoRoot: mocks.worktreeRoot,
    worktreePath: `${mocks.worktreeRoot}/worktree`,
    startDir: `${mocks.worktreeRoot}/worktree`,
    branch,
    linkedPaths: [],
  })),
  removeGitWorktree: vi.fn(),
}));

vi.mock("@/lib/workspace-config", () => ({
  resolveWorkspaceConfig: vi.fn(() => ({ copyFiles: [], env: {}, setup: null })),
  copyConfiguredFiles: vi.fn(),
}));

vi.mock("@/lib/workspace-port", () => ({
  allocateWorkspacePort: vi.fn(async () => 4100),
}));

vi.mock("@/lib/telegram/streamer", () => ({
  startStreamer: vi.fn(),
  stopStreamer: vi.fn(async () => undefined),
  stopAllStreamers: vi.fn(),
  resumePersistedStreamers: vi.fn(),
  sendCodexText: vi.fn(async () => true),
  sendKey: vi.fn(),
  sendText: vi.fn(() => true),
  scroll: vi.fn(),
  snap: vi.fn(),
  snapScreenMessage: vi.fn(),
  defaultViewMode: vi.fn(() => "chat"),
  resetChatBaseline: vi.fn(),
  resetStreamerSessionState: vi.fn(),
}));

vi.mock("@/lib/telegram/claude-transcript", () => ({
  startClaudeTranscript: vi.fn(() => null),
  isClaudeTranscriptRunning: vi.fn(() => false),
  stopClaudeTranscript: vi.fn(),
  stopAllClaudeTranscripts: vi.fn(),
  readLastAssistantText: vi.fn(() => null),
}));

vi.mock("@/lib/telegram/codex-transcript", () => ({
  startCodexTranscript: vi.fn(() => null),
  isCodexTranscriptRunning: vi.fn(() => false),
  stopCodexTranscript: vi.fn(),
  stopAllCodexTranscripts: vi.fn(),
  readLastCodexAssistantText: vi.fn(() => null),
}));

vi.mock("@/lib/telegram/message-audit", () => ({
  getTelegramMessageAuditor: vi.fn(() => ({ setTelegramBotId: vi.fn() })),
  installTelegramMessageAudit: vi.fn(),
  withTelegramMessageAuditSource: vi.fn((_source: unknown, operation: () => unknown) =>
    operation()
  ),
}));

describe("Telegram LocalTmux session launch safety", () => {
  let dataDir: string;

  function expectSafeHarnessLaunch(name: string, harness: "claude" | "codex") {
    const call = mocks.createSession.mock.calls.find(([sessionName]) => sessionName === name);
    expect(call, `${name} was not launched`).toBeDefined();
    expect(typeof call?.[1], `${name} did not receive a harness command`).toBe("string");
    const command = call?.[1] as string;
    expect(command).toContain(harness);
    expect(command).not.toContain("--yolo");
    expect(command).not.toContain("--dangerously-skip-permissions");
  }

  beforeEach(() => {
    vi.resetModules();
    mocks.createSession.mockReset();
    mocks.saveMeta.mockReset();
    mocks.commandHandlers.clear();
    mocks.nextTopicId = 100;
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-telegram-launch-safety-"));
    mocks.worktreeRoot = dataDir;

    process.env.TERMINALX_DATA_DIR = dataDir;
    process.env.TERMINALX_AUTH_MODE = "none";
    process.env.TERMINALX_TELEGRAM_BOT_TOKEN = "777:test-token";
    process.env.TERMINALX_TELEGRAM_WEBHOOK_URL = "https://terminalx.test/telegram";
    process.env.TERMINALX_TELEGRAM_WEBHOOK_SECRET = "test-secret";
    process.env.TERMINALX_TELEGRAM_ALLOWED_USERS = "42:alice";
    process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID = "-1001234567890";
  });

  afterEach(async () => {
    const { stopTelegramBot } = await import("@/lib/telegram/bot");
    await stopTelegramBot();
    delete process.env.TERMINALX_DATA_DIR;
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_TELEGRAM_BOT_TOKEN;
    delete process.env.TERMINALX_TELEGRAM_WEBHOOK_URL;
    delete process.env.TERMINALX_TELEGRAM_WEBHOOK_SECRET;
    delete process.env.TERMINALX_TELEGRAM_ALLOWED_USERS;
    delete process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID;
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it("starts Claude and Codex without permission-bypass flags", async () => {
    const { startTelegramBot } = await import("@/lib/telegram/bot");
    const bot = await startTelegramBot();
    expect(bot).not.toBeNull();

    for (const [updateId, name, kind] of [
      [1, "safe-claude", "claude"],
      [2, "safe-codex", "codex"],
    ] as const) {
      await bot!.handleUpdate({
        update_id: updateId,
        message: {
          message_id: updateId,
          date: 1_784_760_000,
          chat: { id: -1001234567890, type: "supergroup", title: "TerminalX" },
          from: { id: 42, is_bot: false, first_name: "Alice", username: "alice" },
          text: `/new ${name} ${kind}`,
          entities: [{ type: "bot_command", offset: 0, length: 4 }],
        },
      });
    }

    expect(mocks.createSession).toHaveBeenCalledTimes(2);
    expectSafeHarnessLaunch("safe-claude", "claude");
    expectSafeHarnessLaunch("safe-codex", "codex");
  });

  it("starts Claude and Codex worktrees without permission-bypass flags", async () => {
    const { startTelegramBot } = await import("@/lib/telegram/bot");
    const bot = await startTelegramBot();
    expect(bot).not.toBeNull();

    for (const [updateId, name, kind] of [
      [1, "safe-claude-worktree", "claude"],
      [2, "safe-codex-worktree", "codex"],
    ] as const) {
      await bot!.handleUpdate({
        update_id: updateId,
        message: {
          message_id: updateId,
          date: 1_784_760_000,
          chat: { id: -1001234567890, type: "supergroup", title: "TerminalX" },
          from: { id: 42, is_bot: false, first_name: "Alice", username: "alice" },
          text: `/worktree ${mocks.worktreeRoot} ${name} ${kind}`,
          entities: [{ type: "bot_command", offset: 0, length: 9 }],
        },
      });
    }

    expect(mocks.createSession).toHaveBeenCalledTimes(2);
    expectSafeHarnessLaunch("safe-claude-worktree", "claude");
    expectSafeHarnessLaunch("safe-codex-worktree", "codex");
    for (const name of ["safe-claude-worktree", "safe-codex-worktree"]) {
      expect(mocks.saveMeta).toHaveBeenCalledWith(
        expect.objectContaining({ name, modelId: undefined })
      );
    }
  });
});
