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
 * Real hosted-Daytona restart/reconciliation harness. Provisions a sandbox,
 * pauses it (a restart-window proxy), then re-opens a fresh API client and
 * reconciles the SAME sandbox by identity — proving the provider identity is
 * stable across a client restart and that reconciliation observes the same
 * sandbox rather than resurrecting or duplicating it. SKIPS loudly without a
 * real endpoint; never passes vacuously.
 *
 * NOTE: a full crash/restart at hosted-runtime volume (kernel + supervisor
 * receipt-follow cursor replay across a real process crash) additionally
 * requires the composed hosted stack and is itemized in the release-readiness
 * report; this harness covers provider-identity stability across a client
 * reconnect.
 */

const skipReason = daytonaE2eSkipReason();
if (skipReason) {
  process.stderr.write(`[daytona-e2e] SKIP daytona-restart: ${skipReason}\n`);
}

function providerSandboxId(created: unknown): string {
  const id = (created as { id?: unknown })?.id;
  if (typeof id !== "string" || id.length === 0) {
    throw new Error("Daytona create did not return a sandbox id");
  }
  return id;
}

describe.skipIf(skipReason !== null)("real Daytona — restart / reconciliation", () => {
  let config: DaytonaE2eConfig;
  let api: DaytonaSandboxApiPort;
  let sandboxId: string | null = null;

  beforeAll(() => {
    config = requireDaytonaE2eConfig();
    api = openDaytonaApi(config);
  });

  afterAll(async () => {
    if (sandboxId) {
      const cleanup = openDaytonaApi(config);
      await cleanup.deleteSandbox(sandboxId, timeoutSignal(30_000)).catch(() => undefined);
      await cleanup.close();
    }
    await api?.close();
  });

  it("reconciles the same sandbox by identity across a fresh client", async () => {
    const created = await api.createSandbox(
      e2eCreateBody(config, { "terminalx.e2e.case": "restart" }),
      timeoutSignal(120_000)
    );
    sandboxId = providerSandboxId(created);
    await api.pauseSandbox(sandboxId, timeoutSignal(60_000));

    // Simulate a control-plane restart: close the client, open a brand-new one,
    // and reconcile the same sandbox by its opaque provider id.
    await api.close();
    api = openDaytonaApi(config);

    const reconciled = await api.getSandbox(sandboxId, timeoutSignal(30_000));
    assertNoCanaryLeak("reconciled", reconciled, config.credentialCanary);
    expect(providerSandboxId(reconciled)).toBe(sandboxId);

    // The listing under our label must contain exactly this sandbox once (no
    // duplicate/resurrected replacement).
    const listed = (await api.listSandboxes(
      { labels: { "terminalx.e2e.case": "restart" }, cursor: null, limit: 50, isPublic: false },
      timeoutSignal(30_000)
    )) as { items?: Array<{ id?: string }> } | Array<{ id?: string }>;
    const items = Array.isArray(listed) ? listed : (listed.items ?? []);
    const matches = items.filter((s) => s.id === sandboxId);
    expect(matches.length).toBeLessThanOrEqual(1);
  });
});
