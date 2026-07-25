import type { RequestOptions } from "node:http";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mockedHttpRequest = vi.hoisted(() => vi.fn());

vi.mock("node:http", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:http")>();
  return { ...original, request: mockedHttpRequest };
});

import { createDaytonaDaemonPtyDriver } from "../../packages/daytona-supervisor/src/daytona-daemon-pty-driver";

const TERMINAL_ID = "123e4567-e89b-42d3-a456-426614174000";

type ResponseStep = Readonly<{
  kind: "response";
  statusCode: number;
  body?: string;
}>;
type ErrorStep = Readonly<{ kind: "error"; beforeError?: () => void }>;
type Step = ResponseStep | ErrorStep;

interface ObservedRequest {
  readonly method: string;
  readonly path: string;
  readonly signal: AbortSignal;
}

let steps: Step[];
let observed: ObservedRequest[];

describe("Daytona daemon PTY create reconciliation", () => {
  beforeEach(() => {
    steps = [];
    observed = [];
    mockedHttpRequest.mockReset();
    mockedHttpRequest.mockImplementation(fakeHttpRequest);
  });

  it("deletes a possibly-created terminal with an independent signal after caller abort", async () => {
    const caller = new AbortController();
    steps.push(
      { kind: "error", beforeError: () => caller.abort() },
      { kind: "response", statusCode: 200 }
    );
    const driver = createDriver();

    await expect(driver.open(openRequest(), caller.signal)).rejects.toMatchObject({
      name: "DaytonaSupervisorProtocolError",
      code: "unavailable",
    });

    expect(observed.map(({ method, path }) => `${method} ${path}`)).toEqual([
      "POST /process/pty",
      `DELETE /process/pty/${TERMINAL_ID}`,
    ]);
    expect(observed[0]?.signal).toBe(caller.signal);
    expect(observed[1]?.signal).not.toBe(caller.signal);
    expect(observed[1]?.signal.aborted).toBe(false);
    expect(steps).toEqual([]);
    await driver.close();
  });

  it("removes a stale 409 identity, retries once, and reconciles a failed retry", async () => {
    steps.push(
      { kind: "response", statusCode: 409 },
      { kind: "response", statusCode: 200 },
      { kind: "error" },
      { kind: "response", statusCode: 404 }
    );
    const caller = new AbortController();
    const driver = createDriver();

    await expect(driver.open(openRequest(), caller.signal)).rejects.toMatchObject({
      name: "DaytonaSupervisorProtocolError",
      code: "unavailable",
    });

    expect(observed.map(({ method, path }) => `${method} ${path}`)).toEqual([
      "POST /process/pty",
      `DELETE /process/pty/${TERMINAL_ID}`,
      "POST /process/pty",
      `DELETE /process/pty/${TERMINAL_ID}`,
    ]);
    expect(observed[0]?.signal).toBe(caller.signal);
    expect(observed[1]?.signal).not.toBe(caller.signal);
    expect(observed[2]?.signal).toBe(caller.signal);
    expect(observed[3]?.signal).not.toBe(caller.signal);
    expect(steps).toEqual([]);
    await driver.close();
  });
});

function createDriver() {
  return createDaytonaDaemonPtyDriver({
    requestTimeoutMs: 1_000,
    maximumPendingWebSocketBytes: 64 * 1024,
  });
}

function openRequest() {
  return Object.freeze({ terminalId: TERMINAL_ID, cols: 80, rows: 24 });
}

function fakeHttpRequest(
  options: RequestOptions,
  receiveResponse: (response: unknown) => void
): unknown {
  const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
  const emit = (event: string, ...args: unknown[]): void => {
    const callbacks = [...(listeners.get(event) ?? [])];
    listeners.delete(event);
    for (const callback of callbacks) callback(...args);
  };
  const request = {
    once(event: string, listener: (...args: unknown[]) => void) {
      const callbacks = listeners.get(event) ?? new Set();
      callbacks.add(listener);
      listeners.set(event, callbacks);
      return request;
    },
    end() {
      const step = steps.shift();
      if (!step) throw new Error("Unexpected daemon request");
      observed.push({
        method: String(options.method),
        path: String(options.path),
        signal: options.signal as AbortSignal,
      });
      queueMicrotask(() => {
        if (step.kind === "error") {
          step.beforeError?.();
          emit("error", new Error("simulated ambiguous transport failure"));
          emit("close");
          return;
        }
        receiveResponse(fakeResponse(step));
        emit("close");
      });
    },
    destroy() {
      emit("error", new Error("simulated timeout"));
      emit("close");
    },
  };
  return request;
}

function fakeResponse(step: ResponseStep): unknown {
  const bytes = Buffer.from(step.body ?? "{}", "utf8");
  return {
    statusCode: step.statusCode,
    headers: { "content-type": "application/json; charset=utf-8" },
    destroy: vi.fn(),
    async *[Symbol.asyncIterator]() {
      yield bytes;
    },
  };
}
