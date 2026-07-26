import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  isSecretKey,
  redactFields,
  redactString,
  redactValue,
  REDACTED,
} from "@/lib/ops/redaction";
import {
  correlationIdFromHeaders,
  emitTelemetry,
  setTelemetrySink,
  telemetry,
} from "@/lib/ops/telemetry";
import { audit } from "@/lib/audit-log";

describe("ops redaction guard", () => {
  it("identifies secret-named field keys", () => {
    for (const key of [
      "token",
      "accessToken",
      "refresh_token",
      "password",
      "authorization",
      "cookie",
      "credential",
      "apiKey",
      "api_key",
      "jwt",
      "webhookSecret",
      "privateKey",
    ]) {
      expect(isSecretKey(key)).toBe(true);
    }
    for (const key of ["sessionId", "userId", "count", "status", "digest"]) {
      expect(isSecretKey(key)).toBe(false);
    }
  });

  it("drops secret-named fields wholesale and scrubs values", () => {
    const out = redactFields({
      sessionId: "sess-1",
      authorization: "Bearer abc.def.ghijklmnop",
      nested: { apiKey: "super-secret-value", note: "ok" },
      free: "call used Bearer sk-live-1234567890 to auth",
    });
    expect(out.sessionId).toBe("sess-1");
    expect(out.authorization).toBe(REDACTED);
    expect((out.nested as Record<string, unknown>).apiKey).toBe(REDACTED);
    expect((out.nested as Record<string, unknown>).note).toBe("ok");
    expect(String(out.free)).not.toContain("sk-live-1234567890");
    expect(String(out.free)).toContain("[redacted]");
  });

  it("scrubs bearer/basic tokens and JWTs from free text", () => {
    expect(redactString("Authorization Bearer abcDEF123._-token")).toContain("Bearer [redacted]");
    const jwt = "eyJhbGciOi.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4";
    expect(redactString(`token=${jwt}`)).toContain("[redacted-jwt]");
    expect(redactString(`token=${jwt}`)).not.toContain(jwt);
  });

  it("preserves SHA-256 digests (the safe, deliberately-recorded form)", () => {
    const digest = createHash("sha256").update("evidence").digest("hex");
    expect(redactString(`digest ${digest}`)).toContain(digest);
    const fields = redactFields({ evidenceDigest: digest });
    expect(fields.evidenceDigest).toBe(digest);
  });

  it("never serializes functions or symbols", () => {
    const out = redactValue({ fn: () => 1, sym: Symbol("x"), ok: 2 }) as Record<string, unknown>;
    expect(out.fn).toBe("[unserializable]");
    expect(out.ok).toBe(2);
  });
});

describe("structured telemetry", () => {
  afterEach(() => {
    delete process.env.TERMINALX_LOG_LEVEL;
    vi.restoreAllMocks();
  });

  it("emits redacted JSON records with level, event, and trace id", () => {
    const lines: string[] = [];
    const restore = setTelemetrySink((line) => lines.push(line));
    try {
      emitTelemetry(
        "warn",
        "provider.call",
        {
          authorization: "Bearer secret.jwt.here",
          host: "example.com",
          body: "x Bearer zzz.yyy.www",
        },
        { traceId: "trace-123" }
      );
    } finally {
      restore();
    }
    expect(lines).toHaveLength(1);
    const record = JSON.parse(lines[0] as string);
    expect(record.level).toBe("warn");
    expect(record.event).toBe("provider.call");
    expect(record.traceId).toBe("trace-123");
    expect(typeof record.ts).toBe("string");
    expect(record.fields.authorization).toBe(REDACTED);
    expect(record.fields.host).toBe("example.com");
    // Raw provider body content is value-scrubbed of embedded tokens.
    expect(JSON.stringify(record)).not.toContain("zzz.yyy.www");
  });

  it("suppresses records below the configured level", () => {
    process.env.TERMINALX_LOG_LEVEL = "error";
    const lines: string[] = [];
    const restore = setTelemetrySink((line) => lines.push(line));
    try {
      telemetry.info("ignored.event", {});
      telemetry.error("kept.event", {});
    } finally {
      restore();
    }
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] as string).event).toBe("kept.event");
  });

  it("propagates a well-formed inbound correlation id, else mints one", () => {
    const provided = new Headers({ "x-request-id": "req-abc_123" });
    expect(correlationIdFromHeaders(provided)).toBe("req-abc_123");
    const malformed = new Headers({ "x-request-id": "bad id with spaces" });
    const minted = correlationIdFromHeaders(malformed);
    expect(minted).not.toBe("bad id with spaces");
    expect(minted.length).toBeGreaterThan(0);
  });
});

describe("audit log redaction", () => {
  afterEach(() => vi.restoreAllMocks());

  it("redacts secret material passed through audit context", () => {
    const logged: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line: string) => {
      logged.push(line);
    });
    audit("login_success", { username: "alice", detail: "token=Bearer aaa.bbb.ccc granted" });
    expect(logged).toHaveLength(1);
    expect(logged[0]).toContain("[audit]");
    expect(logged[0]).not.toContain("aaa.bbb.ccc");
    expect(logged[0]).toContain("alice");
  });
});
