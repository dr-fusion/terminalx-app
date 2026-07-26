import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import {
  collectDatabaseGauges,
  recordHttpRequest,
  renderPrometheus,
  resetMetrics,
} from "@/lib/ops/metrics";
import { handleMetrics } from "@/lib/ops/http";
import type { RequestActor } from "@/lib/request-actor";

function adminActor(): RequestActor {
  return {
    kind: "human",
    userId: "u1",
    username: "admin",
    displayName: "Admin",
    legacyRole: "admin",
  };
}

describe("metrics registry and rendering", () => {
  beforeEach(() => resetMetrics());

  it("renders counters, a latency histogram, and process/build gauges", () => {
    recordHttpRequest("GET", 200, 0.02);
    recordHttpRequest("get", 500, 1.5);
    recordHttpRequest("POST", 201, 0.2);
    const text = renderPrometheus({
      buildVersion: "9.9.9",
      uptimeSeconds: 42,
      residentMemoryBytes: 1234,
      ptySessions: 3,
    });
    expect(text).toContain('terminalx_build_info{version="9.9.9"} 1');
    expect(text).toContain("terminalx_uptime_seconds 42");
    expect(text).toContain("terminalx_pty_sessions 3");
    expect(text).toContain('terminalx_http_requests_total{method="GET",status="2xx"} 1');
    expect(text).toContain('terminalx_http_requests_total{method="GET",status="5xx"} 1');
    expect(text).toContain('terminalx_http_requests_total{method="POST",status="2xx"} 1');
    expect(text).toContain("terminalx_http_request_duration_seconds_count 3");
    expect(text).toContain('terminalx_http_request_duration_seconds_bucket{le="+Inf"} 3');
  });

  it("reads durable gauges from a real database snapshot", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-metrics-"));
    try {
      const filename = path.join(tmp, "team-sessions.sqlite");
      const database = openTeamSessionDatabase({ filename });
      const db = database.db;
      db.prepare("INSERT INTO teams (id, name, created_at_ms) VALUES ('t1','Team',1)").run();
      db.prepare(
        "INSERT INTO projects (id, team_id, name, created_at_ms) VALUES ('p1','t1','Project',1)"
      ).run();
      db.prepare(
        `INSERT INTO sessions
           (id, team_id, project_id, name, status, steering_policy,
            runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
         VALUES ('s1','t1','p1','S','active','shared','local-tmux','trusted-shared-host','s1-tmux',0,1)`
      ).run();
      database.close();

      const gauges = collectDatabaseGauges(filename);
      expect(gauges).not.toBeNull();
      expect(gauges?.sessionsActive).toBe(1);
      expect(gauges?.outboxPending).toBe(0);

      const text = renderPrometheus({ databaseGauges: gauges });
      expect(text).toContain('terminalx_sessions{status="active"} 1');
      expect(text).toContain("terminalx_runtime_outbox_pending 0");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("returns null gauges when the database is unavailable", () => {
    expect(collectDatabaseGauges("/nonexistent/path/team-sessions.sqlite")).toBeNull();
  });
});

describe("metrics HTTP access control", () => {
  beforeEach(() => resetMetrics());

  it("refuses an unauthenticated caller with a non-leaking 404", async () => {
    const response = await handleMetrics(new Request("http://localhost/api/metrics"), {
      metricsToken: undefined,
      resolveActor: async () => null,
      collectGauges: () => null,
    });
    expect(response.status).toBe(404);
    const text = await response.text();
    expect(text).not.toContain("terminalx_");
  });

  it("admits a correct bearer token, rejects a wrong one", async () => {
    const ok = await handleMetrics(
      new Request("http://localhost/api/metrics", {
        headers: { authorization: "Bearer scrape-secret" },
      }),
      { metricsToken: "scrape-secret", resolveActor: async () => null, collectGauges: () => null }
    );
    expect(ok.status).toBe(200);
    expect(ok.headers.get("Content-Type")).toContain("text/plain");
    expect(await ok.text()).toContain("terminalx_http_request_duration_seconds_count");

    const bad = await handleMetrics(
      new Request("http://localhost/api/metrics", {
        headers: { authorization: "Bearer wrong" },
      }),
      { metricsToken: "scrape-secret", resolveActor: async () => null, collectGauges: () => null }
    );
    expect(bad.status).toBe(404);
  });

  it("admits an authenticated admin when no token is configured", async () => {
    const response = await handleMetrics(new Request("http://localhost/api/metrics"), {
      metricsToken: undefined,
      resolveActor: async () => adminActor(),
      collectGauges: () => null,
    });
    expect(response.status).toBe(200);
  });

  it("refuses a non-admin actor", async () => {
    const response = await handleMetrics(new Request("http://localhost/api/metrics"), {
      metricsToken: undefined,
      resolveActor: async () => ({ ...adminActor(), legacyRole: "member" }),
      collectGauges: () => null,
    });
    expect(response.status).toBe(404);
  });
});
