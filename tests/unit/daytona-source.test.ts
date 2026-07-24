import { describe, expect, it } from "vitest";
import {
  DAYTONA_UPSTREAM_BASE_COMMIT,
  DAYTONA_UPSTREAM_REPOSITORY,
  resolveDaytonaSourcePin,
} from "@/lib/runtime/daytona-source";

describe("Daytona source pin", () => {
  it("keeps the adapter unavailable until the public fork is pinned", () => {
    expect(resolveDaytonaSourcePin({})).toBeNull();
  });

  it("binds a public fork commit to the accepted upstream base", () => {
    expect(
      resolveDaytonaSourcePin({
        TERMINALX_DAYTONA_FORK_REPOSITORY: "https://github.com/example/terminalx-daytona",
        TERMINALX_DAYTONA_FORK_COMMIT: "0123456789abcdef0123456789abcdef01234567",
      })
    ).toEqual({
      forkRepository: "https://github.com/example/terminalx-daytona",
      forkCommit: "0123456789abcdef0123456789abcdef01234567",
      upstreamRepository: DAYTONA_UPSTREAM_REPOSITORY,
      upstreamBaseCommit: DAYTONA_UPSTREAM_BASE_COMMIT,
    });
  });

  it.each([
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: "https://github.com/example/terminalx-daytona",
    },
    { TERMINALX_DAYTONA_FORK_COMMIT: "0123456789abcdef0123456789abcdef01234567" },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_UPSTREAM_REPOSITORY,
      TERMINALX_DAYTONA_FORK_COMMIT: "0123456789abcdef0123456789abcdef01234567",
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: "https://token@github.com/example/daytona",
      TERMINALX_DAYTONA_FORK_COMMIT: "0123456789abcdef0123456789abcdef01234567",
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: "https://github.com/example/daytona",
      TERMINALX_DAYTONA_FORK_COMMIT: "main",
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: "https://github.com/example/daytona.git",
      TERMINALX_DAYTONA_FORK_COMMIT: "0123456789abcdef0123456789abcdef01234567",
    },
  ])("rejects partial, upstream, credentialed, or floating source configuration", (environment) => {
    expect(() => resolveDaytonaSourcePin(environment)).toThrow();
  });
});
