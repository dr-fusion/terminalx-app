#!/usr/bin/env node
// Generate an in-toto / SLSA v1 build-provenance predicate over one or more
// release artifacts, plus a checksums.sha256 the CI attestation step signs.
//
// This documents and scripts the attestation FORMAT. In CI the signed bundle is
// produced by actions/attest-build-provenance (Sigstore/keyless) with
// subject-checksums pointed at the emitted checksums.sha256 — see
// .github/workflows/daytona-sdk-artifact.yml. This generator makes the same
// predicate reproducible and reviewable locally (no signing keys embedded).
//
// Usage:
//   node scripts/generate-provenance.mjs <output-file> <artifact> [<artifact> ...]

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { basename, resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function gitCommit() {
  try {
    return execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    return "UNKNOWN";
  }
}

function builderId() {
  // In CI this is the runner's OIDC-derived builder id; locally it is explicit
  // and clearly non-hosted so a local predicate can never masquerade as CI.
  return process.env.GITHUB_WORKFLOW_REF
    ? `https://github.com/${process.env.GITHUB_REPOSITORY}/${process.env.GITHUB_WORKFLOW_REF}`
    : "https://terminalx.dev/builders/local-unsigned";
}

function main() {
  const [outputFile, ...artifacts] = process.argv.slice(2);
  if (!outputFile || artifacts.length === 0) {
    process.stderr.write(
      "usage: node scripts/generate-provenance.mjs <output-file> <artifact> [...]\n"
    );
    process.exit(64);
  }
  const subjects = artifacts.map((path) => ({
    name: basename(path),
    digest: { sha256: sha256File(resolve(path)) },
  }));

  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: subjects,
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://terminalx.dev/build-types/release/v1",
        externalParameters: {
          repository: "https://github.com/dudhatparesh/terminalx-app-mono",
          ref: process.env.GITHUB_REF ?? `refs/heads/${gitCommit()}`,
        },
        internalParameters: {
          nodeVersion: process.version,
        },
        resolvedDependencies: [
          {
            uri: "git+https://github.com/dudhatparesh/terminalx-app-mono",
            digest: { gitCommit: gitCommit() },
          },
        ],
      },
      runDetails: {
        builder: { id: builderId() },
        metadata: {
          invocationId: process.env.GITHUB_RUN_ID ?? "local",
          startedOn: new Date().toISOString(),
        },
      },
    },
  };

  const json = `${JSON.stringify(statement, null, 2)}\n`;
  if (existsSync(resolve(outputFile))) {
    throw new Error(`refusing to overwrite existing provenance: ${outputFile}`);
  }
  writeFileSync(resolve(outputFile), json, { encoding: "utf8", flag: "wx", mode: 0o644 });

  // Emit the checksums file the CI attestation subject-checksums points at.
  const checksumPath = join(dirname(resolve(outputFile)), "checksums.sha256");
  const lines = subjects.map((s) => `${s.digest.sha256}  ${s.name}`);
  writeFileSync(checksumPath, `${lines.join("\n")}\n`, { encoding: "utf8", mode: 0o644 });

  process.stdout.write(`wrote ${outputFile} (${subjects.length} subjects)\n`);
  process.stdout.write(`wrote ${checksumPath}\n`);
}

main();
