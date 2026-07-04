import { describe, expect, it } from "vitest";
import {
  autoWorktreeName,
  parseWorktreeCommand,
  slugifySessionName,
} from "@/lib/telegram/worktree-command";

describe("Telegram /worktree command parsing", () => {
  it("requires a directory", () => {
    expect(parseWorktreeCommand("/worktree")).toBeNull();
  });

  it("defaults to a codex worktree when only a directory is supplied", () => {
    expect(parseWorktreeCommand("/worktree /repo/app")).toEqual({
      directory: "/repo/app",
      kind: "codex",
      name: undefined,
    });
  });

  it("accepts quoted paths and a kind without an explicit name", () => {
    expect(parseWorktreeCommand('/worktree "/repo/my app" claude')).toEqual({
      directory: "/repo/my app",
      kind: "claude",
      name: undefined,
    });
  });

  it("accepts a name followed by a kind", () => {
    expect(parseWorktreeCommand('/worktree /repo/app "Board Deck" claude')).toEqual({
      directory: "/repo/app",
      kind: "claude",
      name: "board-deck",
    });
  });

  it("generates valid session names", () => {
    expect(slugifySessionName("Board Deck!")).toBe("board-deck");
    expect(autoWorktreeName("Totem v2", new Date("2026-07-04T12:34:56Z"))).toBe(
      "totem-v2-worktree-20260704123456"
    );
  });
});
