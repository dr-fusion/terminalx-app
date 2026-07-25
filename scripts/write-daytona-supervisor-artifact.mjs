import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { loadDaytonaProductionSource } from "./lib/daytona-production-source.mjs";

const productionSource = loadDaytonaProductionSource();
const [outputFile, artifactRoot, sourceCommit, daytonaProductionCommit] = process.argv.slice(2);

if (
  !outputFile ||
  !artifactRoot ||
  !sourceCommit ||
  !/^[0-9a-f]{40}$/.test(sourceCommit) ||
  !daytonaProductionCommit ||
  daytonaProductionCommit !== productionSource.productionForkCommit
) {
  throw new TypeError(
    "Expected output, artifact root, exact TerminalX commit, and hardened Daytona commit"
  );
}

const root = resolve(artifactRoot);
const output = resolve(outputFile);
const files = walk(root)
  .filter((file) => resolve(file) !== output)
  .map((file) => {
    const bytes = readFileSync(file);
    const stat = statSync(file);
    return Object.freeze({
      file: relative(root, file).split(sep).join("/"),
      mode: stat.mode & 0o777,
      bytes: bytes.byteLength,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  });

const executableDefinitions = Object.freeze([
  Object.freeze({
    role: "root-supervisor",
    file: "bin/terminalx-daytona-supervisor",
    installPath: "/usr/local/libexec/terminalx/terminalx-daytona-supervisor",
  }),
  Object.freeze({
    role: "fixed-runner-relay",
    file: "bin/terminalx-supervisor-relay",
    installPath: "/usr/local/libexec/terminalx/terminalx-supervisor-relay",
  }),
  Object.freeze({
    role: "fixed-assignment-bootstrap",
    file: "bin/terminalx-assignment-bootstrap",
    installPath: "/usr/local/libexec/terminalx/terminalx-assignment-bootstrap",
  }),
]);
const fixedExecutables = executableDefinitions.map((definition) => {
  const measured = files.find((file) => file.file === definition.file);
  if (!measured || measured.mode !== 0o555) {
    throw new TypeError(`Missing immutable fixed executable: ${definition.file}`);
  }
  return Object.freeze({
    ...definition,
    mode: measured.mode,
    bytes: measured.bytes,
    sha256: measured.sha256,
  });
});

const artifact = Object.freeze({
  schemaVersion: 1,
  kind: "terminalx.daytona-supervisor-build",
  source: Object.freeze({
    terminalxCommit: sourceCommit,
    daytonaProductionCommit,
    daytonaUpstreamBaseCommit: productionSource.upstreamBaseCommit,
  }),
  protocol: Object.freeze({
    version: 1,
    transport: "root-uds-length-prefixed-canonical-json",
    runnerRelayMediaType: "application/vnd.terminalx.supervisor-framed",
    assignmentBootstrapRequestMediaType: "application/vnd.terminalx.assignment-bootstrap.v1",
    assignmentBootstrapResponseMediaType:
      "application/vnd.terminalx.assignment-bootstrap-installed.v1+json",
    activationRequiresLiveIsolationAttestation: true,
  }),
  fixedExecutables: Object.freeze(fixedExecutables),
  interpreter: Object.freeze({
    path: "/usr/local/bin/node",
    ownerUid: 0,
    mode: 0o555,
    digestSource: "/etc/terminalx/sandbox-trust-pins.json#nodeExecutableSha256",
    runnerRemeasureBeforeEveryRootExec: true,
  }),
  securityBoundary: Object.freeze({
    supervisorUid: 0,
    agentUid: "nonroot-distinct",
    assignmentScopedObservationKey: true,
    rawPrivateKeyInProtocol: false,
    initializeDaemonTelemetry: false,
    providerSandboxTokenInjected: false,
    otelEnvironmentInjected: false,
    permissiveEffectFallback: false,
    agentCanWriteEffectExecutor: false,
    runnerNetworkProfile: "io.terminalx.runner-network=v1",
  }),
  requiredExternalComponents: Object.freeze([
    "reviewed-hardened-daytona-descendant",
    "signed-effective-isolation-attestor",
    "pinned-idempotent-effect-executor",
  ]),
  files: Object.freeze(files),
});

writeFileSync(output, `${JSON.stringify(artifact, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o644,
});

function walk(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0
  )) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(path));
    else if (entry.isFile()) files.push(path);
    else throw new TypeError("Supervisor artifact cannot contain links or special files");
  }
  return files;
}
