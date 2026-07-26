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
 * Real hosted-Daytona integration lifecycle. Drives create → get → pause →
 * delete against a REAL endpoint and scans every observed surface with the
 * Phase 8G canary scanner (imported UNCHANGED). SKIPS loudly when the endpoint
 * is absent; never passes vacuously (config is required in beforeAll).
 */

const skipReason = daytonaE2eSkipReason();
if (skipReason) {
  process.stderr.write(`[daytona-e2e] SKIP daytona-integration: ${skipReason}\n`);
}

function providerSandboxId(created: unknown): string {
  const id = (created as { id?: unknown })?.id;
  if (typeof id !== "string" || id.length === 0) {
    throw new Error("Daytona create did not return a sandbox id");
  }
  return id;
}

describe.skipIf(skipReason !== null)("real Daytona — integration lifecycle", () => {
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

  it("provisions, observes, pauses, and retires a sandbox with no credential leak", async () => {
    const created = await api.createSandbox(
      e2eCreateBody(config, { "terminalx.e2e.case": "integration" }),
      timeoutSignal(120_000)
    );
    assertNoCanaryLeak("create-response", created, config.credentialCanary);
    sandboxId = providerSandboxId(created);

    const observed = await api.getSandbox(sandboxId, timeoutSignal(30_000));
    assertNoCanaryLeak("get-response", observed, config.credentialCanary);

    const paused = await api.pauseSandbox(sandboxId, timeoutSignal(60_000));
    assertNoCanaryLeak("pause-response", paused, config.credentialCanary);

    await api.deleteSandbox(sandboxId, timeoutSignal(60_000));
    sandboxId = null;
    expect(true).toBe(true);
  });
});
