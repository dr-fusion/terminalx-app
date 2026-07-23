import { describe, expect, it } from "vitest";
import {
  decideTeamSessionTerminalClose,
  parseTeamSessionTerminalServerMessage,
  serializeTeamSessionTerminalMutation,
  shouldPauseTeamSessionTerminalReconnect,
  type TeamSessionTerminalFences,
} from "@/hooks/team-sessions/use-team-session-terminal";

const FENCES: TeamSessionTerminalFences = {
  controlEpoch: 7,
  runtimeAuthorizationGeneration: 11,
};

describe("multiplayer terminal client protocol", () => {
  it("accepts only the closed server message schema", () => {
    expect(
      parseTeamSessionTerminalServerMessage(
        JSON.stringify({
          type: "terminal.ready",
          sessionId: "session-one",
          canInput: true,
          ...FENCES,
        })
      )
    ).toEqual({
      type: "terminal.ready",
      sessionId: "session-one",
      canInput: true,
      ...FENCES,
    });
    expect(
      parseTeamSessionTerminalServerMessage(
        JSON.stringify({ type: "terminal.output", data: "hello\r\n" })
      )
    ).toEqual({ type: "terminal.output", data: "hello\r\n" });
    expect(
      parseTeamSessionTerminalServerMessage(
        JSON.stringify({ type: "terminal.ended", sessionId: "session-one" })
      )
    ).toEqual({ type: "terminal.ended", sessionId: "session-one" });

    expect(parseTeamSessionTerminalServerMessage(new ArrayBuffer(8))).toBeNull();
    expect(parseTeamSessionTerminalServerMessage("not-json")).toBeNull();
    expect(
      parseTeamSessionTerminalServerMessage(
        JSON.stringify({
          type: "terminal.ready",
          sessionId: "session-one",
          canInput: true,
          ...FENCES,
          reusableAuthorization: "must-not-be-accepted",
        })
      )
    ).toBeNull();
  });

  it("never serializes input, resize, or interrupts for an observer", () => {
    expect(
      serializeTeamSessionTerminalMutation({ type: "input", data: "pwd\n" }, FENCES, false)
    ).toBeNull();
    expect(
      serializeTeamSessionTerminalMutation({ type: "resize", cols: 120, rows: 40 }, FENCES, false)
    ).toBeNull();
    expect(serializeTeamSessionTerminalMutation({ type: "interrupt" }, FENCES, false)).toBeNull();
  });

  it("places both live fences on every writable mutation", () => {
    expect(
      JSON.parse(
        serializeTeamSessionTerminalMutation({ type: "input", data: "whoami\n" }, FENCES, true)!
      )
    ).toEqual({
      type: "input",
      data: "whoami\n",
      ...FENCES,
    });
    expect(
      JSON.parse(
        serializeTeamSessionTerminalMutation({ type: "resize", cols: 132, rows: 48 }, FENCES, true)!
      )
    ).toEqual({
      type: "resize",
      cols: 132,
      rows: 48,
      ...FENCES,
    });
    expect(
      JSON.parse(serializeTeamSessionTerminalMutation({ type: "interrupt" }, FENCES, true)!)
    ).toEqual({ type: "interrupt", ...FENCES });
  });

  it("rejects absent fences and inputs outside the server bounds", () => {
    expect(
      serializeTeamSessionTerminalMutation({ type: "input", data: "pwd\n" }, null, true)
    ).toBeNull();
    expect(
      serializeTeamSessionTerminalMutation({ type: "input", data: "" }, FENCES, true)
    ).toBeNull();
    expect(
      serializeTeamSessionTerminalMutation(
        { type: "input", data: "😀".repeat(4_097) },
        FENCES,
        true
      )
    ).toBeNull();
    expect(
      serializeTeamSessionTerminalMutation({ type: "resize", cols: 501, rows: 24 }, FENCES, true)
    ).toBeNull();
  });

  it("ends on the terminal close code and pauses after repeated policy closes", () => {
    expect(decideTeamSessionTerminalClose(4000, 0)).toEqual({
      action: "ended",
      policyCloseCount: 0,
    });
    expect(decideTeamSessionTerminalClose(1006, 0)).toEqual({
      action: "retry",
      policyCloseCount: 0,
    });
    expect(decideTeamSessionTerminalClose(1008, 0)).toEqual({
      action: "retry",
      policyCloseCount: 1,
    });
    expect(decideTeamSessionTerminalClose(1008, 1)).toEqual({
      action: "block",
      policyCloseCount: 2,
    });
  });

  it("pauses retryable reconnects after a bounded number of consecutive failures", () => {
    expect(shouldPauseTeamSessionTerminalReconnect(4)).toBe(false);
    expect(shouldPauseTeamSessionTerminalReconnect(5)).toBe(true);
    expect(shouldPauseTeamSessionTerminalReconnect(6)).toBe(true);
  });
});
