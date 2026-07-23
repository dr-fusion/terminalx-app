import { afterEach, describe, expect, it } from "vitest";
import {
  isMultiplayerTransportAvailable,
  isMultiplayerTransportEnabled,
  markMultiplayerTransportAvailable,
} from "@/lib/team-sessions/feature";
import { GET } from "@/app/api/team-sessions/status/route";

afterEach(() => {
  markMultiplayerTransportAvailable(false);
});

describe("multiplayer feature status", () => {
  it("keeps the trusted-host transport opt-in with strict flag parsing", () => {
    expect(isMultiplayerTransportEnabled(undefined)).toBe(false);
    expect(isMultiplayerTransportEnabled("")).toBe(false);
    expect(isMultiplayerTransportEnabled("false")).toBe(false);
    expect(isMultiplayerTransportEnabled("true")).toBe(true);
    expect(() => isMultiplayerTransportEnabled("TRUE")).toThrow(
      "TERMINALX_MULTIPLAYER_ENABLED must be true or false"
    );
  });

  it("reports actual custom-server ownership rather than configuration alone", async () => {
    expect(isMultiplayerTransportAvailable()).toBe(false);
    let response = await GET();
    await expect(response.json()).resolves.toMatchObject({
      enabled: false,
      runtime: {
        kind: "local-tmux",
        isolation: "trusted-shared-host",
        yoloEligible: false,
      },
    });
    expect(response.headers.get("cache-control")).toBe("no-store");

    markMultiplayerTransportAvailable(true);
    expect(isMultiplayerTransportAvailable()).toBe(true);
    response = await GET();
    await expect(response.json()).resolves.toMatchObject({ enabled: true });
  });
});
