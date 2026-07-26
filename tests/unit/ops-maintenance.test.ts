import { describe, expect, it, vi } from "vitest";
import { createMaintenanceLoop } from "@/lib/ops/maintenance";
import type { AttentionDeliveryDeps, AttentionDeliveryResult } from "@/lib/attention/contracts";

const noopDelivery: AttentionDeliveryDeps = {
  resolveSessionBinding: () => null,
  deliverOutbound: async () => ({ delivered: false, shouldRetry: false, reason: "not-routed" }),
};

function deliveryResult(outcome: AttentionDeliveryResult["outcome"]): AttentionDeliveryResult {
  return { userId: "u1", sessionId: "s1", itemKind: "handoff-offer", itemSequence: 1, outcome };
}

describe("maintenance loop", () => {
  it("runs escalation and delivery each tick and summarizes outcomes", async () => {
    const attentionInbox = {
      escalateLapsedHandoffs: vi.fn(() => [{ id: "e1" }, { id: "e2" }] as never),
      deliverLapsedHandoffNotifications: vi.fn(async () => [
        deliveryResult("delivered"),
        deliveryResult("no-binding"),
      ]),
    };
    const loop = createMaintenanceLoop({ attentionInbox, deliveryDeps: noopDelivery });
    const result = await loop.runOnce();
    expect(result.escalated).toBe(2);
    expect(result.delivered).toBe(1);
    expect(result.deliveryOutcomes).toEqual({ delivered: 1, "no-binding": 1 });
    expect(result.errors).toHaveLength(0);
  });

  it("is fail-closed: an escalation error never aborts delivery", async () => {
    const deliver = vi.fn(async () => []);
    const attentionInbox = {
      escalateLapsedHandoffs: vi.fn(() => {
        throw new Error("db locked");
      }),
      deliverLapsedHandoffNotifications: deliver,
    };
    const loop = createMaintenanceLoop({ attentionInbox, deliveryDeps: noopDelivery });
    const result = await loop.runOnce();
    expect(result.errors).toContain("escalate");
    expect(deliver).toHaveBeenCalledTimes(1);
  });

  it("throttles backups to the backup interval", async () => {
    let now = 1_000_000;
    const runBackup = vi.fn(async () => undefined);
    const sweepRecordings = vi.fn(() => ({ deleted: 2 }));
    const attentionInbox = {
      escalateLapsedHandoffs: vi.fn(() => [] as never),
      deliverLapsedHandoffNotifications: vi.fn(async () => []),
    };
    const loop = createMaintenanceLoop(
      { attentionInbox, deliveryDeps: noopDelivery, runBackup, sweepRecordings, now: () => now },
      { backupIntervalMs: 10_000 }
    );
    const first = await loop.runOnce();
    expect(first.backupRan).toBe(true);
    expect(first.recordingsSwept).toBe(2);

    now += 5_000; // within the interval
    const second = await loop.runOnce();
    expect(second.backupRan).toBe(false);
    expect(runBackup).toHaveBeenCalledTimes(1);

    now += 6_000; // interval elapsed
    const third = await loop.runOnce();
    expect(third.backupRan).toBe(true);
    expect(runBackup).toHaveBeenCalledTimes(2);
  });

  it("records a backup failure without aborting the tick", async () => {
    const attentionInbox = {
      escalateLapsedHandoffs: vi.fn(() => [] as never),
      deliverLapsedHandoffNotifications: vi.fn(async () => []),
    };
    const loop = createMaintenanceLoop(
      {
        attentionInbox,
        deliveryDeps: noopDelivery,
        runBackup: async () => {
          throw new Error("disk full");
        },
      },
      { backupIntervalMs: 0 }
    );
    const result = await loop.runOnce();
    expect(result.errors).toContain("backup");
    expect(result.backupRan).toBe(false);
  });

  it("start/stop toggles the running flag", () => {
    const attentionInbox = {
      escalateLapsedHandoffs: vi.fn(() => [] as never),
      deliverLapsedHandoffNotifications: vi.fn(async () => []),
    };
    const loop = createMaintenanceLoop({ attentionInbox, deliveryDeps: noopDelivery });
    expect(loop.running).toBe(false);
    loop.start();
    expect(loop.running).toBe(true);
    loop.stop();
    expect(loop.running).toBe(false);
  });
});
