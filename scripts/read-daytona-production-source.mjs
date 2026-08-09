#!/usr/bin/env node

import {
  daytonaForkRepositorySlug,
  loadDaytonaProductionSource,
} from "./lib/daytona-production-source.mjs";

const [command, argument] = process.argv.slice(2);
const source = loadDaytonaProductionSource();

if (command === "field" && argument && Object.hasOwn(source, argument)) {
  process.stdout.write(`${source[argument]}\n`);
} else if (command === "github-output" && argument === undefined) {
  process.stdout.write(
    [
      `fork_repository=${daytonaForkRepositorySlug(source)}`,
      `fork_repository_url=${source.forkRepository}`,
      `production_fork_commit=${source.productionForkCommit}`,
      `upstream_repository_url=${source.upstreamRepository}`,
      `upstream_base_commit=${source.upstreamBaseCommit}`,
    ].join("\n") + "\n"
  );
} else if (command === "json" && argument === undefined) {
  process.stdout.write(`${JSON.stringify(source)}\n`);
} else {
  process.stderr.write(
    "usage: read-daytona-production-source.mjs field <name> | github-output | json\n"
  );
  process.exitCode = 64;
}
