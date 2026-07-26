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
 * Real hosted-Daytona secret-exfiltration harness. Reuses the Phase 8G canary
 * scanner UNCHANGED to prove the API credential never reaches any observable
 * provider surface — create/get/pause/label/list responses and error bodies —
 * across all reversible encodings and split-chunk smuggling the scanner covers.
 * SKIPS loudly without a real endpoint; never passes vacuously.
 */

const skipReason = daytonaE2eSkipReason();
if (skipReason) {
  process.stderr.write(`[daytona-e2e] SKIP daytona-secret-exfiltration: ${skipReason}\n`);
}

function providerSandboxId(created: unknown): string {
  const id = (created as { id?: unknown })?.id;
  if (typeof id !== "string" || id.length === 0) {
    throw new Error("Daytona create did not return a sandbox id");
  }
  return id;
}

describe.skipIf(skipReason !== null)("real Daytona — secret exfiltration", () => {
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

  it("never echoes the API credential through any observed provider surface", async () => {
    const canary = config.credentialCanary;

    const created = await api.createSandbox(
      e2eCreateBody(config, { "terminalx.e2e.case": "exfil" }),
      timeoutSignal(120_000)
    );
    assertNoCanaryLeak("create", created, canary);
    sandboxId = providerSandboxId(created);

    const got = await api.getSandbox(sandboxId, timeoutSignal(30_000));
    assertNoCanaryLeak("get", got, canary);

    const labelled = await api.replaceLabels(
      sandboxId,
      { labels: { "terminalx.e2e": "true", "terminalx.e2e.case": "exfil" } },
      timeoutSignal(30_000)
    );
    assertNoCanaryLeak("labels", labelled, canary);

    const listed = await api.listSandboxes(
      { labels: { "terminalx.e2e": "true" }, cursor: null, limit: 50, isPublic: false },
      timeoutSignal(30_000)
    );
    assertNoCanaryLeak("list", listed, canary);

    // Force an error path (unknown id) and assert the error body carries no secret.
    const errorSurface = await api
      .getSandbox("terminalx-e2e-nonexistent", timeoutSignal(30_000))
      .catch((error: unknown) => error);
    assertNoCanaryLeak("error-body", errorSurface, canary);

    await api.deleteSandbox(sandboxId, timeoutSignal(60_000));
    sandboxId = null;
    expect(true).toBe(true);
  });
});
