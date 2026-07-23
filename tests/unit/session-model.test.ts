import { describe, it, expect } from "vitest";
import {
  isSafeHarnessArgumentToken,
  splitModelId,
  modelOptionsForKind,
} from "@/lib/harnesses/session-model";

/**
 * Feature #11: resolved Models settings must thread into a launched session.
 * `splitModelId` parses a provider-qualified id ("<harness>:<slug>") and
 * `modelOptionsForKind` derives the CommandOptions the harness command builder
 * consumes — but ONLY when the chosen model's harness matches the session kind
 * (a Codex model must never leak its slug into a `claude --model` invocation).
 */
describe("splitModelId", () => {
  it("splits a provider-qualified model id into harness + slug", () => {
    expect(splitModelId("claude:opus-4-8-1m")).toEqual({
      harness: "claude",
      slug: "opus-4-8-1m",
    });
  });

  it("keeps slashes in the slug (opencode provider/model ids)", () => {
    expect(splitModelId("opencode:anthropic/claude-sonnet")).toEqual({
      harness: "opencode",
      slug: "anthropic/claude-sonnet",
    });
  });

  it("keeps common provider/model slug punctuation", () => {
    expect(splitModelId("opencode:anthropic/claude:sonnet.4@2026_07+beta-1")).toEqual({
      harness: "opencode",
      slug: "anthropic/claude:sonnet.4@2026_07+beta-1",
    });
  });

  it("returns null for an unqualified or empty id", () => {
    expect(splitModelId("opus-4-8-1m")).toBeNull();
    expect(splitModelId("")).toBeNull();
    expect(splitModelId(undefined)).toBeNull();
    expect(splitModelId(null)).toBeNull();
  });

  it.each([
    "codex:gpt-5 --yolo",
    "claude:sonnet --dangerously-skip-permissions",
    "codex:gpt-5;touch-pwned",
    "codex:gpt-5$(touch-pwned)",
    "codex:gpt-5\n",
    "claude:--dangerously-skip-permissions",
  ])("rejects an unsafe provider-qualified model id: %s", (modelId) => {
    expect(splitModelId(modelId)).toBeNull();
  });
});

describe("isSafeHarnessArgumentToken", () => {
  it("accepts one allowlisted, non-option shell token", () => {
    expect(isSafeHarnessArgumentToken("anthropic/claude:sonnet.4@2026_07+beta-1")).toBe(true);
  });

  it.each(["gpt-5 --yolo", "gpt-5;touch-pwned", "$(touch-pwned)", "gpt-5\n", "--yolo"])(
    "rejects an unsafe token: %s",
    (value) => {
      expect(isSafeHarnessArgumentToken(value)).toBe(false);
    }
  );
});

describe("modelOptionsForKind", () => {
  it("threads the slug as `model` when the model's harness matches the kind", () => {
    const opts = modelOptionsForKind("claude", {
      modelId: "claude:opus-4-8-1m",
      planMode: false,
    });
    expect(opts.model).toBe("opus-4-8-1m");
  });

  it("drops the model when its harness does NOT match the session kind", () => {
    // A Codex default model must not be passed to a claude session.
    const opts = modelOptionsForKind("claude", {
      modelId: "codex:gpt-5-codex",
      planMode: false,
    });
    expect(opts.model).toBeUndefined();
  });

  it("drops an unsafe model instead of passing injected arguments to the command builder", () => {
    const opts = modelOptionsForKind("codex", {
      modelId: "codex:gpt-5 --yolo",
      planMode: false,
    });
    expect(opts.model).toBeUndefined();
  });

  it("passes planMode through verbatim", () => {
    expect(modelOptionsForKind("claude", { modelId: undefined, planMode: true }).planMode).toBe(
      true
    );
    expect(modelOptionsForKind("claude", { modelId: undefined, planMode: false }).planMode).toBe(
      false
    );
  });

  it("returns no model for bash and an unqualified/absent model id", () => {
    expect(
      modelOptionsForKind("bash", { modelId: undefined, planMode: false }).model
    ).toBeUndefined();
    expect(
      modelOptionsForKind("claude", { modelId: "not-qualified", planMode: false }).model
    ).toBeUndefined();
  });
});
