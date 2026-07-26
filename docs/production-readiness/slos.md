# TerminalX service level objectives

These SLOs are the operator-facing targets for a single self-hosted TerminalX
node. They are measured from the Phase 11C metrics surface (`/api/metrics`,
Prometheus text format) and the liveness/readiness probes. They are objectives,
not contractual SLAs; tune the windows and targets to your deployment.

## Probes

| Probe     | Endpoint            | Auth | Meaning                                                                                                                                                                         |
| --------- | ------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Liveness  | `/health`           | none | Process is up. Never reports dependency state; used to restart hangs.                                                                                                           |
| Readiness | `/api/health/ready` | none | Dependencies usable: SQLite migrated to the expected schema + integrity-clean, and the Secret Broker ready when configured. Fails closed (503) with a bare, non-leaking status. |

A load balancer routes on **readiness**; an orchestrator restarts on **liveness**.

## Objectives

| SLO              | Target (28-day window)                     | Metric source                                                               |
| ---------------- | ------------------------------------------ | --------------------------------------------------------------------------- |
| Availability     | 99.5% of readiness checks succeed          | probe success ratio                                                         |
| Request latency  | p95 < 500 ms, p99 < 1.5 s for API requests | `terminalx_http_request_duration_seconds` histogram                         |
| Error rate       | < 1% of requests return 5xx                | `terminalx_http_requests_total{status="5xx"}` / total                       |
| Worker lag       | oldest pending Runtime outbox item < 60 s  | `terminalx_runtime_outbox_oldest_age_seconds`                               |
| Backup freshness | a verified backup < 24 h old               | last successful `backupTeamSessionDatabase` (maintenance tick, default 6 h) |

## Error budget

The availability budget over 28 days at 99.5% is ~3h 22m of not-ready time.
Burn faster than 2% of the budget per hour → page (see `alerts.md`). Exhausting
the budget freezes non-essential rollouts until a verified backup, a green
restore drill, and a clean readiness check are re-established.

## Metrics catalog (curated allowlist)

The metric set is fixed — there is no user-controlled metric name or label, and
label values are redaction-guarded.

- `terminalx_build_info{version}` — running build.
- `terminalx_uptime_seconds`, `terminalx_process_resident_memory_bytes`.
- `terminalx_pty_sessions` — active terminal/PTY sessions on the node.
- `terminalx_http_requests_total{method,status}` — request rate/errors by class.
- `terminalx_http_request_duration_seconds{_bucket,_sum,_count}` — latency.
- `terminalx_runtime_outbox_pending`, `terminalx_runtime_outbox_oldest_age_seconds` — worker lag.
- `terminalx_sessions{status}` — Team Sessions by status.
- `terminalx_attention_escalations_total` — Gate-8-adjacent escalation counter.
- `terminalx_limit_reservations_open` — Gate-5 authoritative-limit reservations.

## Exposure model

`/api/metrics` is access-controlled: a scraper presents `TERMINALX_METRICS_TOKEN`
as a bearer token (constant-time compared) or the caller is an authenticated
admin. Unauthorized callers receive `404` (the endpoint is not disclosed).
Operators may additionally bind the server to a private interface / scrape over a
private network. See `deployment.md`.
