export const DAYTONA_UPSTREAM_REPOSITORY = "https://github.com/daytonaio/daytona";
export const DAYTONA_UPSTREAM_BASE_COMMIT = "b5a5d9e78d76c8bcf351f2049620250e0f34eea4";

const FULL_GIT_COMMIT = /^[0-9a-f]{40}$/;
const PUBLIC_GITHUB_REPOSITORY = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export interface DaytonaSourcePin {
  readonly forkRepository: string;
  readonly forkCommit: string;
  readonly upstreamRepository: typeof DAYTONA_UPSTREAM_REPOSITORY;
  readonly upstreamBaseCommit: typeof DAYTONA_UPSTREAM_BASE_COMMIT;
}

export interface DaytonaSourceEnvironment {
  readonly TERMINALX_DAYTONA_FORK_REPOSITORY?: string;
  readonly TERMINALX_DAYTONA_FORK_COMMIT?: string;
}

/**
 * Resolve the immutable public-fork pin. An absent pair means the Daytona
 * adapter must remain unavailable; a partial or floating configuration is a
 * startup error rather than a fallback to upstream or a branch.
 */
export function resolveDaytonaSourcePin(
  environment: DaytonaSourceEnvironment = {
    TERMINALX_DAYTONA_FORK_REPOSITORY: process.env.TERMINALX_DAYTONA_FORK_REPOSITORY,
    TERMINALX_DAYTONA_FORK_COMMIT: process.env.TERMINALX_DAYTONA_FORK_COMMIT,
  }
): DaytonaSourcePin | null {
  const repository = environment.TERMINALX_DAYTONA_FORK_REPOSITORY?.trim();
  const commit = environment.TERMINALX_DAYTONA_FORK_COMMIT?.trim();
  if (!repository && !commit) return null;
  if (!repository || !commit) {
    throw new Error(
      "Daytona public fork repository and immutable commit must be configured together"
    );
  }
  if (
    !PUBLIC_GITHUB_REPOSITORY.test(repository) ||
    repository.endsWith(".git") ||
    repository === DAYTONA_UPSTREAM_REPOSITORY
  ) {
    throw new Error("Daytona source must be a public HTTPS GitHub fork repository");
  }
  if (!FULL_GIT_COMMIT.test(commit)) {
    throw new Error("Daytona fork commit must be a lowercase full Git commit SHA");
  }
  return Object.freeze({
    forkRepository: repository,
    forkCommit: commit,
    upstreamRepository: DAYTONA_UPSTREAM_REPOSITORY,
    upstreamBaseCommit: DAYTONA_UPSTREAM_BASE_COMMIT,
  });
}
