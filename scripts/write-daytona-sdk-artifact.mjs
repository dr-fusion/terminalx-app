import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { loadDaytonaProductionSource } from "./lib/daytona-production-source.mjs";

const productionSource = loadDaytonaProductionSource();
const EXPECTED_FILES = [
  "daytona-api-client-0.0.0-dev.tgz",
  "daytona-sdk-0.0.0-dev.tgz",
  "daytona-toolbox-api-client-0.0.0-dev.tgz",
];

const [outputFile, ...unsafePackageFiles] = process.argv.slice(2);
if (!outputFile || unsafePackageFiles.length !== EXPECTED_FILES.length) {
  throw new TypeError("Expected an output file and the three pinned Daytona package archives");
}

const packageFiles = unsafePackageFiles.map((file) => resolve(file));
const packageNames = packageFiles.map((file) => basename(file));
if (packageNames.some((name, index) => name !== EXPECTED_FILES[index])) {
  throw new TypeError("Unexpected Daytona package archive set or ordering");
}

const packages = packageFiles.map((file, index) =>
  Object.freeze({
    file: EXPECTED_FILES[index],
    sha256: createHash("sha256").update(readFileSync(file)).digest("hex"),
  })
);

const artifact = Object.freeze({
  schemaVersion: 1,
  kind: "terminalx.daytona-typescript-sdk-build",
  source: Object.freeze({
    repository: productionSource.forkRepository,
    productionCommit: productionSource.productionForkCommit,
    upstreamBaseCommit: productionSource.upstreamBaseCommit,
  }),
  build: Object.freeze({
    packageVersion: "0.0.0-dev",
    command: "corepack yarn nx build sdk-typescript --configuration=production",
  }),
  packages: Object.freeze(packages),
});

writeFileSync(resolve(outputFile), `${JSON.stringify(artifact, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o644,
});
