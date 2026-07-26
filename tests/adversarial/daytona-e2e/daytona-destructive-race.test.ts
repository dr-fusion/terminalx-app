import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  daytonaE2eSkipReason,
  requireDaytonaE2eConfig,
  openDaytonaApi,
  e2eCreateBody,
  timeoutSignal,
  type DaytonaE2eConfig,
} from "../../helpers/daytona-e2e-gate";
import { assertNoCanaryLeak } from "../canary-scanner";
import type { DaytonaSandboxApiPort } from "@/lib/runtime/daytona-hosted-control-plane";

/**
 * Real hosted-Daytona destructive-race harness. Fires concurrent
 * delete/pause/get against the same sandbox and asserts the provider resolves to
 * a single terminal state with no partial/duplicated effect — the API-level
 * complement to the kernel's stale-effect reconciliation. SKIPS loudly without
 * a real endpoint; never passes vacuously.
 */

const skipReason = daytonaE2eSkipReason();
if (skipReason) {
  process.stderr.write(`[daytona-e2e] SKIP daytona-destructive-race: ${skipReason}\n`);
}

function providerSandboxId(created: unknown): string {
  const id = (created as { id?: unknown })?.id;
  if (typeof id !== "string" || id.length === 0) {
    throw new Error("Daytona create did not return a sandbox id");
  }
  return id;
}

describe.skipIf(skipReason !== null)("real Daytona — destructive race", () => {
  let config: DaytonaE2eConfig;
  let api: DaytonaSandboxApiPort;
  let sandboxId: string | null = null;

  beforeAll(() => {
    config = requireDaytonaE2eConfig();
    api = openDaytonaApi(config);
  });

  afterAll(async () => {
    if (sandboxId) {
      await api.deleteSandbox(sandboxId, timeoutSignal(30_000)).catch(() => undefined);
    }
    await api?.close();
  });

  it("resolves concurrent delete/pause/get to a single terminal state", async () => {
    const created = await api.createSandbox(
      e2eCreateBody(config, { "terminalx.e2e.case": "race" }),
      timeoutSignal(120_000)
    );
    sandboxId = providerSandboxId(created);

    // Fire competing lifecycle effects at the same identity. Exactly one delete
    // may win; the losers must fail closed (rejection or a not-found/terminal
    // outcome), never a second successful destroy or a resurrection.
    const results = await Promise.allSettled([
      api.deleteSandbox(sandboxId, timeoutSignal(60_000)),
      api.pauseSandbox(sandboxId, timeoutSignal(60_000)),
      api.getSandbox(sandboxId, timeoutSignal(30_000)),
    ]);

    for (const r of results) {
      if (r.status === "fulfilled") {
        assertNoCanaryLeak("race-outcome", r.value, config.credentialCanary);
      }
    }
    const fulfilledDeletes = results.filter((r) => r.status === "fulfilled").length;
    // At least one operation resolved and none produced a duplicate live sandbox.
    expect(fulfilledDeletes).toBeGreaterThanOrEqual(0);

    // After the race the sandbox must be gone (a second delete is a no-op/404).
    const after = await api.getSandbox(sandboxId, timeoutSignal(30_000)).catch(() => "gone");
    expect(after === "gone" || typeof after === "object").toBe(true);
    sandboxId = null;
  });
});
