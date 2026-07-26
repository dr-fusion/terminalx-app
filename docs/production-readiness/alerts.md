# TerminalX alert rules

These are reference Prometheus alerting rules an operator wires into their own
Alertmanager. They are configuration and documentation, not a hosted alerting
system. Each alert links to a runbook section in `runbooks.md`.

Scrape `/api/metrics` with the bearer token (`TERMINALX_METRICS_TOKEN`) and a
separate blackbox probe of `/api/health/ready` for the availability signal.

```yaml
groups:
  - name: terminalx
    rules:
      # --- Availability (readiness) ---
      - alert: TerminalXNotReady
        expr: probe_success{job="terminalx-readiness"} == 0
        for: 2m
        labels: { severity: page }
        annotations:
          summary: "TerminalX readiness failing"
          runbook: "runbooks.md#db-unavailable"

      - alert: TerminalXDown
        expr: up{job="terminalx"} == 0
        for: 2m
        labels: { severity: page }
        annotations:
          summary: "TerminalX metrics endpoint unreachable"
          runbook: "runbooks.md#restart"

      # --- Latency ---
      - alert: TerminalXHighLatencyP95
        expr: >
          histogram_quantile(0.95,
            sum(rate(terminalx_http_request_duration_seconds_bucket[5m])) by (le)) > 0.5
        for: 10m
        labels: { severity: warn }
        annotations:
          summary: "TerminalX p95 latency > 500ms"
          runbook: "runbooks.md#latency"

      # --- Error rate ---
      - alert: TerminalXHighErrorRate
        expr: >
          sum(rate(terminalx_http_requests_total{status="5xx"}[5m]))
            / clamp_min(sum(rate(terminalx_http_requests_total[5m])), 1) > 0.01
        for: 10m
        labels: { severity: page }
        annotations:
          summary: "TerminalX 5xx error rate > 1%"
          runbook: "runbooks.md#errors"

      # --- Worker lag ---
      - alert: TerminalXOutboxLag
        expr: terminalx_runtime_outbox_oldest_age_seconds > 60
        for: 5m
        labels: { severity: warn }
        annotations:
          summary: "Runtime outbox oldest item > 60s"
          runbook: "runbooks.md#worker-lag"

      # --- Capacity ---
      - alert: TerminalXPtySaturation
        expr: terminalx_pty_sessions >= 18
        for: 5m
        labels: { severity: warn }
        annotations:
          summary: "PTY sessions near the configured ceiling (TERMINUS_MAX_SESSIONS)"
          runbook: "runbooks.md#capacity"

      - alert: TerminalXMemoryHigh
        expr: terminalx_process_resident_memory_bytes > 1.5e9
        for: 10m
        labels: { severity: warn }
        annotations:
          summary: "TerminalX resident memory > 1.5GB"
          runbook: "runbooks.md#capacity"
```

Broker/oracle/webhook failures do not have a numeric gauge; they surface as
readiness failures (broker) or as structured telemetry error events
(`provider.*`, `telegram/webhook`). Alert on those via your log pipeline and
route to `runbooks.md#broker-down` / `runbooks.md#webhook-failures`.
