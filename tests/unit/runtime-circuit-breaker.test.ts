import { describe, expect, it } from "vitest";
import {
  RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
  RuntimeCircuitBreakerBlockedError,
  RuntimeCircuitBreakerCapacityError,
  RuntimeCircuitBreakerInputError,
  createRuntimeCircuitBreaker,
  fingerprintRuntimeFailure,
  fingerprintRuntimeProposal,
  type RuntimeFailureFingerprintInput,
} from "@/lib/runtime/circuit-breaker";

const TIMEOUT_FAILURE: RuntimeFailureFingerprintInput = {
  operation: "sandbox.create",
  code: "runtime_timeout",
  message: "Sandbox provider timed out",
  details: { provider: "daytona", phase: "provision" },
};

describe("Runtime failure fingerprints", () => {
  it("canonicalizes key order and excludes volatile identifiers, timestamps, retries, and secrets", () => {
    const first = fingerprintRuntimeFailure({
      operation: "Sandbox.Create",
      code: "RUNTIME_TIMEOUT",
      message:
        "Request ID: 1bc29b36-35f4-4d2f-9c31-46a292c6f499 failed at 2026-07-23T12:01:02.003Z with Bearer first-super-secret-token",
      details: {
        provider: "daytona",
        sessionId: "session-one",
        occurredAtMs: 1_774_440_062_003,
        attempt: 1,
        apiToken: "first-super-secret-token",
        nested: { phase: "provision", trace_id: "trace-one" },
      },
    });
    const second = fingerprintRuntimeFailure({
      code: "runtime_timeout",
      operation: "sandbox.create",
      message:
        "request id: b849d337-55b8-4f13-b9ee-180bd1a4586e failed at 2026-07-23T12:05:09.003Z with Bearer second-super-secret-token",
      details: {
        attempt: 88,
        nested: { trace_id: "trace-two", phase: "provision" },
        apiToken: "second-super-secret-token",
        occurredAtMs: 1_774_440_309_003,
        sessionId: "session-two",
        provider: "daytona",
      },
    });

    expect(first).toBe(second);
    expect(first).toMatch(/^runtime-failure:v1:[0-9a-f]{64}$/);
    expect(first).not.toContain("secret");
  });

  it("retains stable failure semantics", () => {
    const baseline = fingerprintRuntimeFailure(TIMEOUT_FAILURE);

    expect(
      fingerprintRuntimeFailure({ ...TIMEOUT_FAILURE, code: "runtime_permission_denied" })
    ).not.toBe(baseline);
    expect(
      fingerprintRuntimeFailure({
        ...TIMEOUT_FAILURE,
        details: { provider: "daytona", phase: "start" },
      })
    ).not.toBe(baseline);
  });

  it("rejects unsupported or unbounded canonical input", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const accessor = Object.defineProperty({}, "message", {
      enumerable: true,
      get: () => "do not invoke",
    });

    expect(() => fingerprintRuntimeFailure({ ...TIMEOUT_FAILURE, details: cyclic })).toThrow(
      RuntimeCircuitBreakerInputError
    );
    expect(() => fingerprintRuntimeFailure({ ...TIMEOUT_FAILURE, details: accessor })).toThrow(
      RuntimeCircuitBreakerInputError
    );
    expect(() =>
      fingerprintRuntimeFailure({ ...TIMEOUT_FAILURE, message: "x".repeat(16_385) })
    ).toThrow(RuntimeCircuitBreakerInputError);
  });
});

describe("Runtime proposal fingerprints", () => {
  it("ignores transport envelopes and secrets while retaining semantic target identifiers", () => {
    const first = fingerprintRuntimeProposal({
      id: "proposal-one",
      requestId: "request-one",
      occurredAtMs: 1_774_440_062_003,
      type: "sandbox.command",
      target: { id: "sandbox-one" },
      payload: { command: "pnpm test", accessToken: "secret-one" },
    });
    const equivalent = fingerprintRuntimeProposal({
      id: "proposal-two",
      requestId: "request-two",
      occurredAtMs: 1_774_440_309_003,
      type: "sandbox.command",
      target: { id: "sandbox-one" },
      payload: { command: "pnpm test", accessToken: "secret-two" },
    });
    const changedTarget = fingerprintRuntimeProposal({
      id: "proposal-three",
      requestId: "request-three",
      occurredAtMs: 1_774_440_309_003,
      type: "sandbox.command",
      target: { id: "sandbox-two" },
      payload: { command: "pnpm test", accessToken: "secret-three" },
    });

    expect(equivalent).toBe(first);
    expect(changedTarget).not.toBe(first);
  });
});

describe("Runtime circuit breaker", () => {
  it("opens on the third matching failure fingerprint and stays open", () => {
    const breaker = createRuntimeCircuitBreaker({ ttlMs: 10_000 });

    expect(breaker.recordFailure("session:one", TIMEOUT_FAILURE, 100)).toMatchObject({
      state: "closed",
      retryAllowed: true,
      identicalFailureCount: 1,
      opened: false,
    });
    expect(breaker.recordFailure("session:one", TIMEOUT_FAILURE, 200)).toMatchObject({
      state: "closed",
      retryAllowed: true,
      identicalFailureCount: 2,
      opened: false,
    });
    expect(breaker.recordFailure("session:one", TIMEOUT_FAILURE, 300)).toMatchObject({
      state: "open",
      retryAllowed: false,
      identicalFailureCount: RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
      opened: true,
    });

    expect(
      breaker.recordFailure("session:one", { ...TIMEOUT_FAILURE, code: "runtime_internal" }, 400)
    ).toMatchObject({ state: "open", retryAllowed: false, opened: false });
  });

  it("counts each stable fingerprint independently within its TTL", () => {
    const breaker = createRuntimeCircuitBreaker({ ttlMs: 10_000 });
    const conflict = { ...TIMEOUT_FAILURE, code: "runtime_conflict" };

    breaker.recordFailure("session:one", TIMEOUT_FAILURE, 100);
    breaker.recordFailure("session:one", conflict, 200);
    breaker.recordFailure("session:one", TIMEOUT_FAILURE, 300);

    expect(breaker.recordFailure("session:one", TIMEOUT_FAILURE, 400)).toMatchObject({
      state: "open",
      identicalFailureCount: 3,
    });
  });

  it("blocks an unchanged denied proposal but allows a substantive edit", () => {
    const breaker = createRuntimeCircuitBreaker({ ttlMs: 10_000 });
    const denied = {
      proposalId: "proposal-one",
      requestId: "request-one",
      type: "terminal.input",
      payload: { command: "rm -rf build-output", authorization: "Bearer token-one" },
    };
    breaker.recordDeniedProposal("session:one", denied, 100);

    const unchanged = {
      ...denied,
      proposalId: "proposal-two",
      requestId: "request-two",
      payload: { command: "rm -rf build-output", authorization: "Bearer token-two" },
    };
    expect(breaker.evaluateProposal("session:one", unchanged, 200)).toMatchObject({
      allowed: false,
      reason: "proposal_unchanged",
    });
    expect(() => breaker.assertProposalAllowed("session:one", unchanged, 200)).toThrow(
      RuntimeCircuitBreakerBlockedError
    );
    expect(
      breaker.evaluateProposal(
        "session:one",
        { ...unchanged, payload: { command: "rm -r build-output" } },
        200
      )
    ).toMatchObject({ allowed: true });
  });

  it("makes success and reset behavior explicit", () => {
    const breaker = createRuntimeCircuitBreaker({ ttlMs: 10_000 });
    const proposal = { type: "deploy", payload: { environment: "production" } };

    breaker.recordDeniedProposal("session:one", proposal, 100);
    breaker.recordFailure("session:one", TIMEOUT_FAILURE, 100);
    breaker.recordFailure("session:one", TIMEOUT_FAILURE, 200);

    expect(breaker.recordSuccess("session:one", 300)).toEqual({
      state: "closed",
      trackedFailureFingerprints: 0,
      deniedProposalFingerprints: 1,
    });
    expect(breaker.recordFailure("session:one", TIMEOUT_FAILURE, 400)).toMatchObject({
      identicalFailureCount: 1,
    });
    expect(breaker.resetFailures("session:one")).toBe(true);
    expect(breaker.status("session:one", 400)).toEqual({
      state: "closed",
      trackedFailureFingerprints: 0,
      deniedProposalFingerprints: 1,
    });
    expect(breaker.evaluateProposal("session:one", proposal, 400)).toMatchObject({
      allowed: false,
      reason: "proposal_unchanged",
    });

    expect(breaker.resetDeniedProposals("session:one")).toBe(true);
    expect(breaker.evaluateProposal("session:one", proposal, 400)).toMatchObject({ allowed: true });
    breaker.recordFailure("session:one", TIMEOUT_FAILURE, 400);
    expect(breaker.reset("session:one")).toBe(true);
    expect(breaker.status("session:one", 400)).toEqual({
      state: "closed",
      trackedFailureFingerprints: 0,
      deniedProposalFingerprints: 0,
    });
  });

  it("expires counters, open states, and denials at the configured TTL", () => {
    const breaker = createRuntimeCircuitBreaker({ ttlMs: 1_000 });
    const proposal = { type: "deploy", payload: { environment: "production" } };

    breaker.recordDeniedProposal("denial", proposal, 0);
    expect(breaker.evaluateProposal("denial", proposal, 999)).toMatchObject({ allowed: false });
    expect(breaker.evaluateProposal("denial", proposal, 1_000)).toMatchObject({ allowed: true });

    breaker.recordFailure("counter", TIMEOUT_FAILURE, 0);
    breaker.recordFailure("counter", TIMEOUT_FAILURE, 100);
    expect(breaker.recordFailure("counter", TIMEOUT_FAILURE, 1_100)).toMatchObject({
      state: "closed",
      identicalFailureCount: 1,
    });

    breaker.recordFailure("open", TIMEOUT_FAILURE, 0);
    breaker.recordFailure("open", TIMEOUT_FAILURE, 1);
    breaker.recordFailure("open", TIMEOUT_FAILURE, 2);
    expect(breaker.status("open", 1_001)).toMatchObject({ state: "open" });
    expect(breaker.status("open", 1_002)).toEqual({
      state: "closed",
      trackedFailureFingerprints: 0,
      deniedProposalFingerprints: 0,
    });
  });

  it("fails closed on invalid bounds, timestamps, and exhausted capacity", () => {
    expect(() => createRuntimeCircuitBreaker({ ttlMs: 0 })).toThrow(
      RuntimeCircuitBreakerInputError
    );
    expect(() => createRuntimeCircuitBreaker({ ttlMs: 31 * 24 * 60 * 60 * 1_000 })).toThrow(
      RuntimeCircuitBreakerInputError
    );
    expect(() => createRuntimeCircuitBreaker({ maxEntries: 1.5 })).toThrow(
      RuntimeCircuitBreakerInputError
    );

    const breaker = createRuntimeCircuitBreaker({ maxEntries: 1, ttlMs: 1_000 });
    breaker.recordFailure("session:one", TIMEOUT_FAILURE, 0);
    expect(() => breaker.recordFailure("session:two", TIMEOUT_FAILURE, 500)).toThrow(
      RuntimeCircuitBreakerCapacityError
    );
    expect(breaker.status("session:one", 500)).toMatchObject({
      state: "closed",
      trackedFailureFingerprints: 1,
    });
    expect(() =>
      breaker.recordFailure("session:one", TIMEOUT_FAILURE, Number.MAX_SAFE_INTEGER)
    ).toThrow(RuntimeCircuitBreakerInputError);

    expect(breaker.recordFailure("session:two", TIMEOUT_FAILURE, 1_000)).toMatchObject({
      identicalFailureCount: 1,
    });

    const perScope = createRuntimeCircuitBreaker({
      maxFingerprintsPerEntry: 1,
      ttlMs: 10_000,
    });
    const proposal = { type: "deploy", payload: { environment: "production" } };
    perScope.recordDeniedProposal("session:one", proposal, 0);
    expect(() => perScope.recordFailure("session:one", TIMEOUT_FAILURE, 1)).toThrow(
      RuntimeCircuitBreakerCapacityError
    );
    expect(perScope.evaluateProposal("session:one", proposal, 1)).toMatchObject({
      allowed: false,
      reason: "proposal_unchanged",
    });
  });
});
