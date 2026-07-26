import type Database from "better-sqlite3";
import type { RuntimeCircuitBreakerScopeSnapshot } from "../runtime/circuit-breaker";

/**
 * Gate 5 (Phase 9) durable persistence for the Runtime circuit breaker.
 *
 * The breaker itself is an in-process guard; this store is its durable mirror so
 * an open circuit or a denied-proposal set survives a restart. `persistScope`
 * upserts one scope's snapshot (or deletes the row when the scope is empty),
 * and `loadAll` returns every persisted snapshot for a fresh process to rehydrate
 * via {@link RuntimeCircuitBreaker.loadScope}. This is the one operational
 * (upsertable) Phase 9 projection — it is live state, not an audit record.
 */

export interface CircuitBreakerStateStore {
  persistScope(snapshot: RuntimeCircuitBreakerScopeSnapshot, nowMs: number): void;
  deleteScope(scope: string): void;
  loadAll(): ReadonlyArray<RuntimeCircuitBreakerScopeSnapshot>;
}

export class CircuitBreakerStateStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CircuitBreakerStateStoreError";
  }
}

export function createCircuitBreakerStateStore(db: Database.Database): CircuitBreakerStateStore {
  const upsert = db.prepare(
    `INSERT INTO circuit_breaker_state (scope, snapshot_json, updated_at_ms)
     VALUES (@scope, @snapshot_json, @updated_at_ms)
     ON CONFLICT(scope) DO UPDATE SET
       snapshot_json = excluded.snapshot_json,
       updated_at_ms = excluded.updated_at_ms`
  );
  const remove = db.prepare<[string]>("DELETE FROM circuit_breaker_state WHERE scope = ?");
  const selectAll = db.prepare(
    "SELECT snapshot_json FROM circuit_breaker_state ORDER BY scope ASC"
  );

  return Object.freeze({
    persistScope(snapshot: RuntimeCircuitBreakerScopeSnapshot, nowMs: number): void {
      if (!snapshot || typeof snapshot !== "object" || typeof snapshot.scope !== "string") {
        throw new CircuitBreakerStateStoreError("Snapshot must include a scope");
      }
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
        throw new CircuitBreakerStateStoreError("updated_at_ms must be a non-negative integer");
      }
      upsert.run({
        scope: snapshot.scope,
        snapshot_json: JSON.stringify(snapshot),
        updated_at_ms: nowMs,
      });
    },
    deleteScope(scope: string): void {
      remove.run(scope);
    },
    loadAll(): ReadonlyArray<RuntimeCircuitBreakerScopeSnapshot> {
      const rows = selectAll.all() as Array<{ snapshot_json: string }>;
      return Object.freeze(
        rows.map((row) => {
          let parsed: unknown;
          try {
            parsed = JSON.parse(row.snapshot_json);
          } catch {
            throw new CircuitBreakerStateStoreError(
              "Persisted circuit-breaker snapshot is corrupt"
            );
          }
          return parsed as RuntimeCircuitBreakerScopeSnapshot;
        })
      );
    },
  });
}
