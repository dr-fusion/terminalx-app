import { beforeEach, describe, expect, it, vi } from "vitest";

const execFileSync = vi.fn();

vi.mock("child_process", () => ({
  execFileSync,
}));

describe("telegram streamer input", () => {
  beforeEach(() => {
    execFileSync.mockReset();
  });

  it("sends Telegram text followed by Enter to the exact tmux session", async () => {
    const { sendText } = await import("@/lib/telegram/streamer");

    sendText("codex-a", "hello codex", true);

    expect(execFileSync).toHaveBeenNthCalledWith(
      1,
      "tmux",
      ["send-keys", "-t", "=codex-a:", "-l", "hello codex"],
      { timeout: 2000 }
    );
    expect(execFileSync).toHaveBeenNthCalledWith(
      2,
      "tmux",
      ["send-keys", "-t", "=codex-a:", "Enter"],
      { timeout: 2000 }
    );
  });
});
