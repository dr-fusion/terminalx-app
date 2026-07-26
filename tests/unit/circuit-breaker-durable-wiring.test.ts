import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createTeamSessions } from "@/lib/team-sessions/module";
import {
  RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
  type RuntimeFailureFingerprintInput,
} from "@/lib/runtime/circuit-breaker";

/**
 * Phase 12 — durable circuit-breaker composition.
 *
 * Phase 9 landed the in-process {@link RuntimeCircuitBreaker} and its SQLite
 * mirror (`circuit_breaker_state`) as independently tested modules. This spec
 * proves the Phase 12 wiring: the kernel now composes the two, mirrors every
 * failure/success to durable state in the same tick, and — critically —
 * rehydrates an open circuit when a fresh process reopens the SAME database, so
 * a restart cannot silently reopen a fenced Runtime scope.
 *
 * The failure/success *source* that drives this at real receipt volume is the
 * Phase 12 hosted-Daytona effect executor; here we drive the kernel-owned seam
 * directly, which is exactly what that executor will call.
 */

const SCOPE = "sandbox:test-scope";

const FAILURE: RuntimeFailureFingerprintInput = {
  operation: "sandbox.create",
  code: "provider_timeout",
};

describe("durable circuit breaker composed onto the kernel", () => {
  let workDir: string;
  let dbPath: string;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "tx-cb-wire-"));
    dbPath = path.join(workDir, "team-sessions.sqlite");
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  it("opens a scope after the failure threshold and mirrors it durably", () => {
    const now = 1_000_000;
    const kernel = createTeamSessions({ filename: dbPath, clock: () => now });
    try {
      let decision;
      for (let i = 0; i < RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD; i += 1) {
        decision = kernel.recordRuntimeCircuitFailure(SCOPE, FAILURE, now);
      }
      expect(decision?.state).toBe("open");
      expect(decision?.opened).toBe(true);
      expect(kernel.runtimeCircuitStatus(SCOPE, now).state).toBe("open");
    } finally {
      kernel.close();
    }
  });

  it("rehydrates an open circuit after a kernel restart (same database)", () => {
    const now = 2_000_000;

    const first = createTeamSessions({ filename: dbPath, clock: () => now });
    try {
      for (let i = 0; i < RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD; i += 1) {
        first.recordRuntimeCircuitFailure(SCOPE, FAILURE, now);
      }
      expect(first.runtimeCircuitStatus(SCOPE, now).state).toBe("open");
    } finally {
      first.close();
    }

    // Fresh process, same durable database — the open circuit must survive.
    const reopenNow = now + 60_000;
    const second = createTeamSessions({ filename: dbPath, clock: () => reopenNow });
    try {
      const status = second.runtimeCircuitStatus(SCOPE, reopenNow);
      expect(status.state).toBe("open");
    } finally {
      second.close();
    }
  });

  it("does not resurrect an open circuit after its TTL has elapsed", () => {
    const now = 3_000_000;
    const first = createTeamSessions({ filename: dbPath, clock: () => now });
    try {
      for (let i = 0; i < RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD; i += 1) {
        first.recordRuntimeCircuitFailure(SCOPE, FAILURE, now);
      }
    } finally {
      first.close();
    }

    // Reopen well past the breaker TTL (default 1h): the durable snapshot is
    // dropped as expired rather than reopening the circuit forever.
    const staleNow = now + 2 * 60 * 60 * 1_000;
    const second = createTeamSessions({ filename: dbPath, clock: () => staleNow });
    try {
      expect(second.runtimeCircuitStatus(SCOPE, staleNow).state).toBe("closed");
    } finally {
      second.close();
    }
  });

  it("clears the durable row on success so a restart sees a closed circuit", () => {
    const now = 4_000_000;
    const first = createTeamSessions({ filename: dbPath, clock: () => now });
    try {
      for (let i = 0; i < RUNTIME_CIRCUIT_BREAKER_FAILURE_THRESHOLD; i += 1) {
        first.recordRuntimeCircuitFailure(SCOPE, FAILURE, now);
      }
      expect(first.runtimeCircuitStatus(SCOPE, now).state).toBe("open");
      const status = first.recordRuntimeCircuitSuccess(SCOPE, now);
      expect(status.state).toBe("closed");
    } finally {
      first.close();
    }

    const second = createTeamSessions({ filename: dbPath, clock: () => now });
    try {
      expect(second.runtimeCircuitStatus(SCOPE, now).state).toBe("closed");
    } finally {
      second.close();
    }
  });
});
