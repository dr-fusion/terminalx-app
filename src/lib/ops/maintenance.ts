import type { AttentionDeliveryDeps, AttentionDeliveryResult } from "../attention/contracts";
import type { AttentionInboxStore } from "../attention/store";
import { telemetry } from "./telemetry";

/**
 * The periodic server maintenance tick. It drives the Phase 11A attention
 * escalation and notification delivery on a schedule, and takes rotated online
 * backups and prunes expired recordings on their own longer cadence. Every step
 * is idempotent (escalation and delivery de-duplicate on their durable chains)
 * and fail-closed (a step that throws is logged and never aborts the others or
 * the loop). It holds no authority of its own; it only invokes existing durable
 * capabilities on a timer.
 */

export interface MaintenanceLoopDeps {
  readonly attentionInbox: Pick<
    AttentionInboxStore,
    "escalateLapsedHandoffs" | "deliverLapsedHandoffNotifications"
  >;
  readonly deliveryDeps: AttentionDeliveryDeps;
  /** Optional full online backup step (throttled to `backupIntervalMs`). */
  readonly runBackup?: () => Promise<unknown>;
  /** Optional expired-recording sweep (throttled to `backupIntervalMs`). */
  readonly sweepRecordings?: () => { deleted: number };
  readonly now?: () => number;
}

export interface MaintenanceLoopOptions {
  readonly tickIntervalMs?: number;
  readonly backupIntervalMs?: number;
}

export interface MaintenanceTickResult {
  readonly escalated: number;
  readonly delivered: number;
  readonly deliveryOutcomes: Readonly<Record<string, number>>;
  readonly backupRan: boolean;
  readonly recordingsSwept: number;
  readonly errors: readonly string[];
}

const DEFAULT_TICK_INTERVAL_MS = 60_000;
const DEFAULT_BACKUP_INTERVAL_MS = 6 * 60 * 60 * 1_000;
const MIN_TICK_INTERVAL_MS = 1_000;

export interface MaintenanceLoop {
  runOnce(): Promise<MaintenanceTickResult>;
  start(): void;
  stop(): void;
  readonly running: boolean;
}

export function createMaintenanceLoop(
  deps: MaintenanceLoopDeps,
  options: MaintenanceLoopOptions = {}
): MaintenanceLoop {
  const now = deps.now ?? (() => Date.now());
  const tickIntervalMs = Math.max(
    MIN_TICK_INTERVAL_MS,
    options.tickIntervalMs ?? DEFAULT_TICK_INTERVAL_MS
  );
  const backupIntervalMs = Math.max(0, options.backupIntervalMs ?? DEFAULT_BACKUP_INTERVAL_MS);

  let timer: ReturnType<typeof setInterval> | undefined;
  let inFlight = false;
  let lastBackupAt = 0;

  async function runOnce(): Promise<MaintenanceTickResult> {
    const errors: string[] = [];
    let escalated = 0;
    let delivered = 0;
    const deliveryOutcomes: Record<string, number> = {};
    let backupRan = false;
    let recordingsSwept = 0;
    const tickNow = now();

    try {
      const created = deps.attentionInbox.escalateLapsedHandoffs(tickNow);
      escalated = created.length;
    } catch (error) {
      errors.push("escalate");
      telemetry.error("maintenance.escalate-failed", { name: errorName(error) });
    }

    try {
      const results: AttentionDeliveryResult[] =
        await deps.attentionInbox.deliverLapsedHandoffNotifications(deps.deliveryDeps, tickNow);
      delivered = results.filter((result) => result.outcome === "delivered").length;
      for (const result of results) {
        deliveryOutcomes[result.outcome] = (deliveryOutcomes[result.outcome] ?? 0) + 1;
      }
    } catch (error) {
      errors.push("deliver");
      telemetry.error("maintenance.deliver-failed", { name: errorName(error) });
    }

    const backupDue = deps.runBackup !== undefined && tickNow - lastBackupAt >= backupIntervalMs;
    if (backupDue && deps.runBackup) {
      try {
        await deps.runBackup();
        backupRan = true;
        lastBackupAt = tickNow;
      } catch (error) {
        errors.push("backup");
        telemetry.error("maintenance.backup-failed", { name: errorName(error) });
      }
      if (deps.sweepRecordings) {
        try {
          recordingsSwept = deps.sweepRecordings().deleted;
        } catch (error) {
          errors.push("sweep");
          telemetry.error("maintenance.sweep-failed", { name: errorName(error) });
        }
      }
    }

    return {
      escalated,
      delivered,
      deliveryOutcomes,
      backupRan,
      recordingsSwept,
      errors,
    };
  }

  function tick(): void {
    if (inFlight) return;
    inFlight = true;
    void runOnce()
      .catch((error) => {
        telemetry.error("maintenance.tick-failed", { name: errorName(error) });
      })
      .finally(() => {
        inFlight = false;
      });
  }

  return {
    runOnce,
    start(): void {
      if (timer !== undefined) return;
      timer = setInterval(tick, tickIntervalMs);
      // Do not keep the event loop alive solely for maintenance.
      timer.unref?.();
    },
    stop(): void {
      if (timer === undefined) return;
      clearInterval(timer);
      timer = undefined;
    },
    get running(): boolean {
      return timer !== undefined;
    },
  };
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "Error";
}
