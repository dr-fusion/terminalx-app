import { describe, expect, it } from "vitest";
import { classifyOperatorError } from "@/lib/operator-error";

describe("classifyOperatorError", () => {
  it("maps HTTP status codes to safe operator classes", () => {
    expect(classifyOperatorError({ status: 401 }).kind).toBe("auth-expired");
    expect(classifyOperatorError({ status: 403 }).kind).toBe("permission-denied");
    expect(classifyOperatorError({ status: 404 }).kind).toBe("not-found");
    expect(classifyOperatorError({ status: 410 }).kind).toBe("not-found");
    expect(classifyOperatorError({ status: 409 }).kind).toBe("conflict");
    expect(classifyOperatorError({ status: 429 }).kind).toBe("rate-limited");
    expect(classifyOperatorError({ status: 503 }).kind).toBe("server");
  });

  it("treats fail-closed runtime/authority codes as runtime-unavailable", () => {
    expect(classifyOperatorError({ code: "runtime_unavailable" }).kind).toBe("runtime-unavailable");
    expect(classifyOperatorError({ code: "runtime-timeout" }).kind).toBe("runtime-unavailable");
    expect(classifyOperatorError({ code: "authority-unavailable" }).kind).toBe(
      "runtime-unavailable"
    );
  });

  it("classifies fetch/network failures and the offline hint as offline", () => {
    expect(classifyOperatorError(new TypeError("Failed to fetch")).kind).toBe("offline");
    expect(classifyOperatorError({}, { offline: true }).kind).toBe("offline");
    expect(classifyOperatorError({ status: 408 }).kind).toBe("offline");
  });

  it("falls back to unknown for unrecognized errors", () => {
    expect(classifyOperatorError(new Error("boom")).kind).toBe("unknown");
    expect(classifyOperatorError(null).kind).toBe("unknown");
    expect(classifyOperatorError("string error").kind).toBe("unknown");
  });

  it("never leaks the raw error message into operator copy", () => {
    const secret = "postgres://user:hunter2@db.internal/prod";
    const info = classifyOperatorError(new Error(secret));
    const rendered = `${info.title} ${info.description}`;
    expect(rendered).not.toContain(secret);
    expect(rendered).not.toContain("hunter2");
  });

  it("carries only the opaque digest through as a reference", () => {
    const info = classifyOperatorError({ status: 500, digest: "abc123" });
    expect(info.reference).toBe("abc123");
    expect(classifyOperatorError({ status: 500 }).reference).toBeUndefined();
  });

  it("assigns a recovery action for every class", () => {
    for (const status of [401, 403, 404, 409, 429, 500]) {
      const info = classifyOperatorError({ status });
      expect(["retry", "sign-in", "home", "none"]).toContain(info.action);
    }
  });
});
