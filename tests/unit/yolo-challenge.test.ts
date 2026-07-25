import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  YOLO_CHALLENGE_TOKEN_PREFIX,
  YoloChallengeError,
  assertYoloChallengeToken,
  bindingDigestsMatch,
  digestYoloChallengeBinding,
  digestYoloChallengeToken,
  generateYoloChallengeToken,
  type YoloChallengeBinding,
} from "@/lib/runtime/yolo-challenge";

const binding: YoloChallengeBinding = {
  userId: "user-1",
  sessionId: "session-1",
  runPolicyDigest: "a".repeat(64),
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 2,
  sandboxId: "sandbox-1",
  sandboxGeneration: 3,
  runtimePrincipalId: "principal-1",
  runtimeAuthorizationGeneration: 4,
};

describe("yolo challenge token and binding", () => {
  it("generates a prefixed opaque token and a stable digest", () => {
    const token = generateYoloChallengeToken(randomBytes);
    expect(token.startsWith(YOLO_CHALLENGE_TOKEN_PREFIX)).toBe(true);
    expect(assertYoloChallengeToken(token)).toBe(token);
    expect(digestYoloChallengeToken(token)).toBe(digestYoloChallengeToken(token));
    expect(digestYoloChallengeToken(token)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects malformed tokens", () => {
    expect(() => assertYoloChallengeToken("nope")).toThrow(YoloChallengeError);
    expect(() => assertYoloChallengeToken(`${YOLO_CHALLENGE_TOKEN_PREFIX}zz`)).toThrow(
      YoloChallengeError
    );
  });

  it("binds the digest to every boundary field so a Sandbox change invalidates it", () => {
    const base = digestYoloChallengeBinding(binding);
    expect(base).toBe(digestYoloChallengeBinding(binding));
    expect(bindingDigestsMatch(base, digestYoloChallengeBinding(binding))).toBe(true);

    const newSandbox = digestYoloChallengeBinding({ ...binding, sandboxGeneration: 4 });
    expect(newSandbox).not.toBe(base);
    expect(bindingDigestsMatch(base, newSandbox)).toBe(false);

    const newPolicy = digestYoloChallengeBinding({ ...binding, runPolicyDigest: "b".repeat(64) });
    expect(newPolicy).not.toBe(base);
  });

  it("rejects bindings with missing or malformed fields", () => {
    expect(() => digestYoloChallengeBinding({ ...binding, sandboxGeneration: 0 })).toThrow(
      YoloChallengeError
    );
    expect(() => digestYoloChallengeBinding({ ...binding, runPolicyDigest: "short" })).toThrow(
      YoloChallengeError
    );
  });
});
