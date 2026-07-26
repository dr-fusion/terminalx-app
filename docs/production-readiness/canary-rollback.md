# TerminalX canary rollout and migration-aware rollback

## Rollout principle

TerminalX is single-instance per node (per-process WebSocket/PTY/SQLite state).
"Canary" therefore means **one node/one environment at a time**, verified before
the fleet, not multiple replicas behind a load balancer.

## Canary rollout procedure

1. **Snapshot first.** Confirm a verified recent backup exists
   (`backup-restore.md`). A schema-advancing deploy also takes an automatic,
   fail-closed pre-migration snapshot on first start.
2. **Deploy to the canary node.** Start the new binary. Migrations run inside the
   opener, transactionally, after the pre-migration snapshot.
3. **Gate on readiness.** Wait for `/api/health/ready` → 200. The load balancer
   holds traffic until then (fails closed on 503).
4. **Watch the SLOs** (`slos.md`) for a soak window: latency p95/p99, 5xx rate,
   outbox lag, memory. Alerts in `alerts.md` fire on regressions.
5. **Run a restore drill** against the canary's database (`runRestoreDrill`) to
   prove the post-migration database is recoverable and its event chain verifies.
6. **Promote** to the rest of the fleet, or **roll back** (below).

## Migrations: forward-compatible or gated

- Migrations are additive and gated by schema version in the opener. Each version
  bump is only applied from the exact preceding version; unknown versions are
  refused.
- Prefer forward-compatible changes (new tables/columns, append-only) so an
  in-flight rollback window is safe. A destructive change must be staged across
  two releases (add-and-backfill, then remove) so no single rollback strands data.

## Migration-aware rollback

The danger: rolling back to an **older binary** that does not understand a
**newer on-disk schema** can silently corrupt or misread durable authority.
TerminalX refuses this automatically.

- **Rollback guard** (`assertRollbackGuard`, `src/lib/ops/rollback-guard.ts`) runs
  at startup, before anything else. If the database `user_version` is greater than
  the schema this binary understands, it prints a clear operator message and exits
  non-zero. (The database opener independently rejects unknown versions too.)
- The guard's message points here and names the recovery artifact.

### Rollback procedure

1. **Stop** the node (graceful; `runbooks.md#restart`).
2. **Restore the pre-migration snapshot** taken before the upgrade:

   ```ts
   import { restoreSqliteDatabase } from "@/lib/ops/backup";
   // newest file in data/backups/pre-migration/ matching the from→to transition
   restoreSqliteDatabase(snapshotPath, "data/team-sessions.sqlite");
   ```

   (Or the newest verified full backup predating the migration.)

3. **Redeploy the matching (older) binary.** Its schema version now matches the
   restored database, so the rollback guard admits startup.
4. **Verify**: readiness → 200, and run a restore drill to confirm the restored
   database's integrity and event chain.

### Why not "just downgrade"?

Downgrading the binary without restoring the pre-migration snapshot leaves the
newer schema in place; the rollback guard will (correctly) refuse to start. This
is intentional — it converts a silent-corruption risk into a loud, recoverable
stop with a documented path back.
