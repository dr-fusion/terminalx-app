import * as path from "path";
import Database from "better-sqlite3";
import { redactString } from "./redaction";

/**
 * A minimal, dependency-free Prometheus text-format metrics surface. It exposes
 * process health, request rate/latency/errors, terminal (PTY) session counts,
 * outbox/worker lag, and the durable Gate-5 accounting counters where they are
 * cheaply readable. It never emits secret material: label values are redacted
 * and the metric set is a fixed, curated allowlist — there is no user-controlled
 * metric name or label. The surface itself is access-controlled at the route.
 */

interface LabeledCounter {
  readonly labels: Record<string, string>;
  value: number;
}

const HTTP_BUCKETS_SECONDS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10] as const;

interface HttpHistogram {
  readonly bucketCounts: number[];
  count: number;
  sum: number;
}

interface MetricsState {
  httpRequests: Map<string, LabeledCounter>;
  httpDuration: HttpHistogram;
  ptySessions: number;
}

function freshState(): MetricsState {
  return {
    httpRequests: new Map(),
    httpDuration: {
      bucketCounts: new Array(HTTP_BUCKETS_SECONDS.length).fill(0),
      count: 0,
      sum: 0,
    },
    ptySessions: 0,
  };
}

const registry = globalThis as typeof globalThis & {
  __terminalxMetricsState?: MetricsState;
};

function state(): MetricsState {
  if (!registry.__terminalxMetricsState) {
    registry.__terminalxMetricsState = freshState();
  }
  return registry.__terminalxMetricsState;
}

/** Reset all in-process metrics (tests only). */
export function resetMetrics(): void {
  registry.__terminalxMetricsState = freshState();
}

/**
 * Publish the current terminal (PTY) session count. The custom server owns the
 * PTY manager; the Next route that renders metrics runs in the same process but a
 * separate module graph, so the count is shared through the globalThis-backed
 * metrics state rather than by importing the PTY manager into the route bundle.
 */
export function publishPtySessions(count: number): void {
  state().ptySessions = Number.isFinite(count) && count >= 0 ? count : 0;
}

function normalizeMethod(method: string): string {
  const upper = method.toUpperCase();
  return /^[A-Z]{3,10}$/.test(upper) ? upper : "OTHER";
}

function statusClass(status: number): string {
  if (!Number.isFinite(status) || status < 100 || status > 599) return "0xx";
  return `${Math.floor(status / 100)}xx`;
}

/** Record one served HTTP request: method, status class, and duration seconds. */
export function recordHttpRequest(method: string, status: number, durationSeconds: number): void {
  const s = state();
  const labels = { method: normalizeMethod(method), status: statusClass(status) };
  const key = `${labels.method}|${labels.status}`;
  const existing = s.httpRequests.get(key);
  if (existing) {
    existing.value += 1;
  } else {
    s.httpRequests.set(key, { labels, value: 1 });
  }
  const duration = Number.isFinite(durationSeconds) && durationSeconds >= 0 ? durationSeconds : 0;
  s.httpDuration.count += 1;
  s.httpDuration.sum += duration;
  for (let i = 0; i < HTTP_BUCKETS_SECONDS.length; i += 1) {
    const bound = HTTP_BUCKETS_SECONDS[i] ?? Infinity;
    if (duration <= bound)
      s.httpDuration.bucketCounts[i] = (s.httpDuration.bucketCounts[i] ?? 0) + 1;
  }
}

export interface DatabaseGauges {
  readonly outboxPending: number;
  readonly outboxOldestAgeSeconds: number;
  readonly sessionsActive: number;
  readonly sessionsAwaitingAssignee: number;
  readonly sessionsEnded: number;
  readonly attentionEscalations: number;
  readonly limitReservationsOpen: number;
}

function resolveDatabaseFilename(filename?: string): string {
  if (filename) return filename;
  return (
    process.env.TERMINALX_TEAM_SESSION_DB_PATH ??
    path.join(process.cwd(), "data", "team-sessions.sqlite")
  );
}

function countQuery(db: Database.Database, sql: string, ...params: unknown[]): number {
  try {
    const row = db.prepare(sql).get(...params) as { n?: number } | undefined;
    const n = row?.n;
    return typeof n === "number" && Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

/** Read durable gauges from a read-only snapshot. Returns null when unavailable. */
export function collectDatabaseGauges(filename?: string, now = Date.now()): DatabaseGauges | null {
  const resolved = resolveDatabaseFilename(filename);
  if (resolved === ":memory:") return null;
  let db: Database.Database | undefined;
  try {
    db = new Database(resolved, { readonly: true, fileMustExist: true });
    const outboxPending = countQuery(db, "SELECT COUNT(*) AS n FROM runtime_outbox");
    let outboxOldestAgeSeconds = 0;
    try {
      const oldest = db.prepare("SELECT MIN(created_at_ms) AS oldest FROM runtime_outbox").get() as
        | { oldest?: number }
        | undefined;
      if (oldest?.oldest && Number.isFinite(oldest.oldest)) {
        outboxOldestAgeSeconds = Math.max(0, (now - oldest.oldest) / 1000);
      }
    } catch {
      outboxOldestAgeSeconds = 0;
    }
    return {
      outboxPending,
      outboxOldestAgeSeconds,
      sessionsActive: countQuery(db, "SELECT COUNT(*) AS n FROM sessions WHERE status = 'active'"),
      sessionsAwaitingAssignee: countQuery(
        db,
        "SELECT COUNT(*) AS n FROM sessions WHERE status = 'awaiting_assignee'"
      ),
      sessionsEnded: countQuery(db, "SELECT COUNT(*) AS n FROM sessions WHERE status = 'ended'"),
      attentionEscalations: countQuery(db, "SELECT COUNT(*) AS n FROM attention_escalations"),
      limitReservationsOpen: countQuery(
        db,
        "SELECT COUNT(*) AS n FROM limit_reservations WHERE state = 'reserved'"
      ),
    };
  } catch {
    return null;
  } finally {
    db?.close();
  }
}

export interface RenderOptions {
  readonly buildVersion?: string;
  readonly uptimeSeconds?: number;
  readonly residentMemoryBytes?: number;
  readonly ptySessions?: number;
  readonly databaseGauges?: DatabaseGauges | null;
}

function escapeLabelValue(value: string): string {
  return redactString(value).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

function renderLabels(labels: Record<string, string>): string {
  const parts = Object.entries(labels).map(([key, value]) => `${key}="${escapeLabelValue(value)}"`);
  return parts.length > 0 ? `{${parts.join(",")}}` : "";
}

/** Render the current metrics in Prometheus text exposition format. */
export function renderPrometheus(options: RenderOptions = {}): string {
  const s = state();
  const lines: string[] = [];
  const push = (line: string) => lines.push(line);

  if (options.buildVersion) {
    push("# HELP terminalx_build_info Build metadata for the running TerminalX server.");
    push("# TYPE terminalx_build_info gauge");
    push(`terminalx_build_info{version="${escapeLabelValue(options.buildVersion)}"} 1`);
  }

  if (typeof options.uptimeSeconds === "number") {
    push("# HELP terminalx_uptime_seconds Seconds since the server process started.");
    push("# TYPE terminalx_uptime_seconds gauge");
    push(`terminalx_uptime_seconds ${Math.max(0, options.uptimeSeconds)}`);
  }

  if (typeof options.residentMemoryBytes === "number") {
    push("# HELP terminalx_process_resident_memory_bytes Resident memory of the process.");
    push("# TYPE terminalx_process_resident_memory_bytes gauge");
    push(`terminalx_process_resident_memory_bytes ${Math.max(0, options.residentMemoryBytes)}`);
  }

  const ptySessions = options.ptySessions ?? s.ptySessions;
  push("# HELP terminalx_pty_sessions Active terminal (PTY) sessions on this node.");
  push("# TYPE terminalx_pty_sessions gauge");
  push(`terminalx_pty_sessions ${Math.max(0, ptySessions)}`);

  push("# HELP terminalx_http_requests_total HTTP requests served, by method and status class.");
  push("# TYPE terminalx_http_requests_total counter");
  for (const counter of s.httpRequests.values()) {
    push(`terminalx_http_requests_total${renderLabels(counter.labels)} ${counter.value}`);
  }

  push("# HELP terminalx_http_request_duration_seconds HTTP request latency.");
  push("# TYPE terminalx_http_request_duration_seconds histogram");
  for (let i = 0; i < HTTP_BUCKETS_SECONDS.length; i += 1) {
    const cumulative = s.httpDuration.bucketCounts[i] ?? 0;
    push(
      `terminalx_http_request_duration_seconds_bucket{le="${HTTP_BUCKETS_SECONDS[i]}"} ${cumulative}`
    );
  }
  push(`terminalx_http_request_duration_seconds_bucket{le="+Inf"} ${s.httpDuration.count}`);
  push(`terminalx_http_request_duration_seconds_sum ${s.httpDuration.sum}`);
  push(`terminalx_http_request_duration_seconds_count ${s.httpDuration.count}`);

  const g = options.databaseGauges;
  if (g) {
    push("# HELP terminalx_runtime_outbox_pending Pending Runtime outbox deliveries.");
    push("# TYPE terminalx_runtime_outbox_pending gauge");
    push(`terminalx_runtime_outbox_pending ${g.outboxPending}`);

    push("# HELP terminalx_runtime_outbox_oldest_age_seconds Age of the oldest pending delivery.");
    push("# TYPE terminalx_runtime_outbox_oldest_age_seconds gauge");
    push(`terminalx_runtime_outbox_oldest_age_seconds ${g.outboxOldestAgeSeconds}`);

    push("# HELP terminalx_sessions Team Sessions by status.");
    push("# TYPE terminalx_sessions gauge");
    push(`terminalx_sessions{status="active"} ${g.sessionsActive}`);
    push(`terminalx_sessions{status="awaiting_assignee"} ${g.sessionsAwaitingAssignee}`);
    push(`terminalx_sessions{status="ended"} ${g.sessionsEnded}`);

    push("# HELP terminalx_attention_escalations_total Attention escalations recorded.");
    push("# TYPE terminalx_attention_escalations_total counter");
    push(`terminalx_attention_escalations_total ${g.attentionEscalations}`);

    push("# HELP terminalx_limit_reservations_open Open authoritative-limit reservations.");
    push("# TYPE terminalx_limit_reservations_open gauge");
    push(`terminalx_limit_reservations_open ${g.limitReservationsOpen}`);
  }

  return lines.join("\n") + "\n";
}
