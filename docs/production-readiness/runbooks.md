# TerminalX incident runbooks

Concise, tested response procedures for the top failure modes. Every step
preserves the security posture: never print secret material, never copy a live
WAL database by hand (use the backup tooling), and never kill the tmux/pty
cgroup during a restart.

General triage:

1. Check liveness `curl -fsS http://127.0.0.1:3000/health`.
2. Check readiness `curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api/health/ready` (200 = ready, 503 = holding).
3. Scrape metrics (with the token) and check structured telemetry (`journalctl -u terminalx` / `pm2 logs terminalx`).

---

## <a id="db-unavailable"></a>Database unavailable / readiness 503

Symptoms: `TerminalXNotReady`, readiness returns `not-ready`, no 5xx spike.

1. Confirm the DB file exists and is the expected schema:
   `sqlite3 data/team-sessions.sqlite 'PRAGMA application_id; PRAGMA user_version; PRAGMA quick_check;'`
   (expected `application_id` = 1414743345, `user_version` = current binary schema, `quick_check` = ok).
2. If `quick_check` is not `ok`: stop the server, restore the newest verified
   backup (`backup-restore.md`), then restart.
3. If the schema is **newer** than the binary: a bad rollback happened — see
   `canary-rollback.md`. The server already refuses to start (rollback guard).
4. If the file is missing: restore from backup; do not let the server initialize
   a fresh empty database over lost state.

## <a id="broker-down"></a>Secret Broker down

Symptoms: readiness 503 with the broker configured; `provider.*` telemetry errors;
connection/credential surfaces fail closed.

1. The main server intentionally fails closed — brokered credential surfaces are
   disabled until the broker republishes its verification key. No secret leaks.
2. Restart the broker sibling service; confirm its verification key file is
   present under `TERMINALX_SECRET_BROKER_ROOT`.
3. Readiness returns to 200 once the key is readable. In-app work continues; only
   outbound provider delivery and credential operations were paused.

## <a id="webhook-failures"></a>Oracle / webhook failures

Symptoms: `telegram/webhook` telemetry errors; inbound provider updates rejected.

1. Webhook auth failures (bad secret token) are expected to 401 — verify the
   configured `webhookSecret` matches the provider registration.
2. Replay/dedup rejections are by design (Phase 8). Persistent 503s from the
   webhook path mean the bot could not persist the update — check DB writability
   and disk (`disk` runbook).
3. Attention notification delivery is idempotent and retried by the maintenance
   tick; a transient outage self-heals without duplicate sends.

## <a id="latency"></a>High latency

1. Check `terminalx_pty_sessions` and memory — saturation drives latency
   (`capacity`).
2. Check `terminalx_runtime_outbox_oldest_age_seconds` — a stalled worker backs
   up request handlers (`worker-lag`).
3. Inspect slow queries: SQLite is single-writer; a long-running migration or a
   large backup can serialize writes. Backups use a read-only connection and the
   online API, so they should not block — confirm no manual `VACUUM`/`.dump` is
   running.

## <a id="errors"></a>Elevated 5xx

1. Correlate `terminalx_http_requests_total{status="5xx"}` with telemetry error
   events (they share a trace id per request).
2. 5xx from the readiness path is dependency-driven — follow `db-unavailable` /
   `broker-down`.
3. If a bad deploy is implicated, roll back per `canary-rollback.md`.

## <a id="worker-lag"></a>Runtime worker lag

Symptoms: `TerminalXOutboxLag`, `terminalx_runtime_outbox_pending` climbing.

1. Confirm the Runtime worker is running (server logs: `[team-sessions/runtime]`).
2. A stuck lease self-recovers after its TTL; a persistent stall usually means
   the Runtime adapter is unreachable — check the hosted runtime / broker.
3. Restart (graceful) if the worker thread is wedged; leases are crash-safe.

## <a id="disk"></a>Disk / retention pressure

1. Backups live under `data/backups/full`; pre-migration snapshots under
   `data/backups/pre-migration`; recordings under the recordings dir.
2. Retention rotates automatically (`TERMINALX_BACKUP_KEEP`,
   `TERMINALX_PRE_MIGRATION_SNAPSHOT_KEEP`, recordings TTL). If disk is full,
   lower the keep counts and re-run a maintenance tick, or prune old backups by
   mtime (keep at least one verified recent backup).
3. A full disk blocks SQLite writes → withdrawals/mutations fail closed. Free
   space first, then confirm readiness returns to 200.

## <a id="capacity"></a>Capacity limits

- PTY sessions are capped by `TERMINUS_MAX_SESSIONS` (default 20). At the ceiling,
  new terminals are refused with a clear message; this is intended backpressure.
- Container CPU/memory ceilings are set in `docker-compose.yml` / systemd
  (`LimitNOFILE`). Raise them deliberately, not reflexively.
- WebSocket payloads are bounded (4 MB terminal, 64 KB logs/files).

## <a id="restart"></a>Safe restart

TerminalX drains gracefully on SIGTERM/SIGINT: it stops accepting new HTTP, lets
in-flight requests finish, stops the maintenance loop, closes multiplayer
transports/workers and then SQLite, and destroys process resources — within a
bounded deadline (~335 s for the local-tmux profile).

- systemd: `sudo systemctl restart terminalx` — `KillMode=process` stops only the
  web server, never the tmux/pty cgroup.
- PM2: `pm2 reload terminalx` (fork mode; grandchildren survive).
- Verify afterward: `tmux list-sessions` still lists existing sessions.
- NEVER `systemctl kill` the unit or `pm2 delete` mid-drain — that would abandon
  in-flight work.
