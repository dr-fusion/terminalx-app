import { describe, it, expect, beforeEach, afterAll } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// Point the state module at a throwaway dir BEFORE importing it, so these
// tests never touch the real data/telegram-state.json.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tgstate-"));
process.env.TERMINALX_DATA_DIR = tmp;
const STATE_FILE = path.join(tmp, "telegram-state.json");

const state = await import("@/lib/telegram/state");

describe("telegram state", () => {
  beforeEach(() => {
    fs.rmSync(STATE_FILE, { force: true });
  });

  afterAll(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("persists and reads back a binding", async () => {
    await state.setTopic({ topicId: 1, sessionName: "alpha", kind: "bash", cwd: "/" });
    expect(state.getTopic(1)?.sessionName).toBe("alpha");
    expect(state.getTopicByName("alpha")?.topicId).toBe(1);
  });

  it("sees a binding written to the file by another module instance", async () => {
    // The Telegram bot (tsx server) and the Next.js API routes are separate
    // module instances over the same file. A binding one writes must be visible
    // to the other without a restart — otherwise input from Telegram lands in a
    // topic the webhook handler thinks "isn't bound".
    await state.setTopic({ topicId: 1, sessionName: "alpha", kind: "bash", cwd: "/" });
    expect(state.getTopic(1)?.sessionName).toBe("alpha");

    const external = {
      forumChatId: -100,
      topics: { "2": { topicId: 2, sessionName: "beta", kind: "claude", cwd: "/tmp" } },
    };
    await new Promise((r) => setTimeout(r, 12)); // ensure the file mtime advances
    fs.writeFileSync(STATE_FILE, JSON.stringify(external));

    expect(state.getTopic(2)?.sessionName).toBe("beta");
    expect(state.getTopic(1)).toBeUndefined();
    expect(state.getForumChatId()).toBe(-100);
  });

  it("merges a concurrent external write instead of clobbering it", async () => {
    await state.setTopic({ topicId: 1, sessionName: "alpha", kind: "bash", cwd: "/" });

    // Another instance adds a binding directly to disk...
    const external = {
      topics: {
        "1": { topicId: 1, sessionName: "alpha", kind: "bash", cwd: "/" },
        "2": { topicId: 2, sessionName: "beta", kind: "codex", cwd: "/tmp" },
      },
    };
    await new Promise((r) => setTimeout(r, 12));
    fs.writeFileSync(STATE_FILE, JSON.stringify(external));

    // ...and our next write must not drop it.
    await state.setTopic({ topicId: 3, sessionName: "gamma", kind: "bash", cwd: "/" });
    expect(state.getTopic(2)?.sessionName).toBe("beta");
    expect(state.getTopic(3)?.sessionName).toBe("gamma");
  });

  it("clears transcript state when tmux reuses a session name", () => {
    const binding = {
      topicId: 7,
      sessionName: "admin-alpha",
      sessionCreatedAtMs: 1_000,
      kind: "codex" as const,
      cwd: "/srv/alpha",
      jsonlPath: "/old/rollout.jsonl",
      transcriptSessionId: "old-codex-id",
      jsonlOffset: 42,
      pendingPrompt: "old prompt",
      lastPromptAtMs: 1_500,
      pinnedMsgId: 99,
      endedAtMs: 1_900,
    };

    expect(state.topicSessionIncarnationPatch(binding, 2_000)).toEqual({
      changed: true,
      patch: {
        sessionCreatedAtMs: 2_000,
        jsonlPath: undefined,
        transcriptSessionId: undefined,
        jsonlOffset: undefined,
        pendingPrompt: undefined,
        lastPromptAtMs: undefined,
        pinnedMsgId: undefined,
        endedAtMs: undefined,
      },
    });
    expect(state.topicSessionIncarnationPatch(binding, 1_000)).toEqual({
      changed: false,
      patch: { sessionCreatedAtMs: 1_000 },
    });
  });
});
