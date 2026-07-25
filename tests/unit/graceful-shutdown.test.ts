import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ServerShutdownError,
  runOrderedServerShutdown,
  runServerShutdownWithin,
  type OrderedServerShutdownOptions,
  type ServerShutdownStage,
} from "../../server/graceful-shutdown";

afterEach(() => {
  vi.useRealTimers();
});

describe("ordered server shutdown", () => {
  it("starts HTTP drain, awaits multiplayer cleanup, then closes ancillary owners", async () => {
    const events: string[] = [];
    let releaseDrain!: () => void;
    const options = fixture(events, {
      beginHttpDrain: () => {
        events.push("http.begin");
        return new Promise<void>((resolve) => {
          releaseDrain = () => {
            events.push("http.drained");
            resolve();
          };
        });
      },
      closeLegacyWebSockets: async () => {
        events.push("legacy-websockets");
        releaseDrain();
      },
    });

    await runOrderedServerShutdown(options);

    expect(events).toEqual([
      "http.begin",
      "multiplayer",
      "telegram",
      "watcher",
      "legacy-websockets",
      "http.drained",
      "resources",
    ]);
  });

  it("propagates hosted cleanup failure only after attempting every later owner", async () => {
    const events: string[] = [];
    const failures: ServerShutdownStage[] = [];
    const options = fixture(events, {
      closeMultiplayer: async () => {
        events.push("multiplayer");
        throw new Error("private provider identifier");
      },
      reportFailure: (stage) => failures.push(stage),
    });

    await expect(runOrderedServerShutdown(options)).rejects.toEqual(
      new ServerShutdownError("cleanup-failed")
    );
    expect(events).toEqual([
      "http.begin",
      "multiplayer",
      "telegram",
      "watcher",
      "legacy-websockets",
      "resources",
    ]);
    expect(failures).toEqual(["multiplayer"]);
  });

  it("enforces the selected Runtime deadline instead of truncating it at five seconds", async () => {
    vi.useFakeTimers();
    const events: string[] = [];
    const options = fixture(events, {
      closeMultiplayer: () => new Promise<void>(() => undefined),
    });
    const shutdown = runServerShutdownWithin(options, 12_345);

    await vi.advanceTimersByTimeAsync(5_000);
    let settled = false;
    void shutdown.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      }
    );
    await Promise.resolve();
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(7_345);
    await expect(shutdown).rejects.toMatchObject({ code: "deadline-exceeded" });
  });

  it("treats an early HTTP drain rejection as a final non-zero cleanup result", async () => {
    const events: string[] = [];
    const failures: ServerShutdownStage[] = [];
    const options = fixture(events, {
      beginHttpDrain: () => {
        events.push("http.begin");
        return Promise.reject(new Error("private socket detail"));
      },
      reportFailure: (stage) => failures.push(stage),
    });

    await expect(runOrderedServerShutdown(options)).rejects.toMatchObject({
      code: "cleanup-failed",
    });
    expect(events).toContain("resources");
    expect(failures).toEqual(["http-drain"]);
  });
});

function fixture(
  events: string[],
  overrides: Partial<OrderedServerShutdownOptions> = {}
): OrderedServerShutdownOptions {
  return {
    beginHttpDrain: () => {
      events.push("http.begin");
      return Promise.resolve();
    },
    closeMultiplayer: async () => {
      events.push("multiplayer");
    },
    stopTelegram: async () => {
      events.push("telegram");
    },
    closeWatcher: async () => {
      events.push("watcher");
    },
    closeLegacyWebSockets: async () => {
      events.push("legacy-websockets");
    },
    destroyProcessResources: () => {
      events.push("resources");
    },
    ...overrides,
  };
}
