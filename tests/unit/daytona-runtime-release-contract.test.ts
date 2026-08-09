import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import productionSource from "../../config/daytona-production-source.json";

const repositoryRoot = process.cwd();
const verifier = resolve(repositoryRoot, "scripts/verify-daytona-runtime-release-archive.sh");
const runtimeBuilder = resolve(repositoryRoot, "scripts/build-pinned-daytona-runtime.sh");
const archiveName = `terminalx-daytona-runtime-${productionSource.productionForkCommit.slice(0, 12)}.tar.gz`;
const runnerName = "daytona-runner-linux-amd64";
const daemonName = "daytona-daemon-linux-amd64";
const manifestName = "terminalx-daytona-runtime-artifacts.json";
const fileChecksumsName = "runtime-files.sha256";

describe.skipIf(process.platform !== "linux")("Daytona runtime release transport", () => {
  const roots: string[] = [];

  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true });
  });

  it("verifies the attested archive digest and restores exact executable modes", () => {
    const fixture = createReleaseFixture();
    const output = join(fixture.root, "verified-runtime");

    const result = spawnSync("bash", [verifier, fixture.archive, fixture.checksums, output], {
      encoding: "utf8",
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Verified TerminalX Daytona runtime release archive");
    expect(mode(join(output, runnerName))).toBe(0o555);
    expect(mode(join(output, daemonName))).toBe(0o555);
    expect(mode(join(output, manifestName))).toBe(0o444);
    expect(mode(join(output, fileChecksumsName))).toBe(0o444);
    expect(readFileSync(join(output, manifestName), "utf8")).toBe('{"kind":"fixture"}\n');
  });

  it("rejects a runtime archive whose downloaded checksum record was changed", () => {
    const fixture = createReleaseFixture();
    writeFileSync(fixture.checksums, `${"0".repeat(64)}  ${archiveName}\n`, { mode: 0o644 });
    const output = join(fixture.root, "must-not-extract");

    const result = spawnSync("bash", [verifier, fixture.archive, fixture.checksums, output], {
      encoding: "utf8",
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("release archive verification failed");
    expect(() => statSync(output)).toThrow();
  });

  it("rejects linked-worktree Git indirection before invoking the Go build", () => {
    const root = mkdtempSync(join(tmpdir(), "terminalx-daytona-linked-worktree-contract-"));
    roots.push(root);
    const source = join(root, "source");
    mkdirSync(source);
    writeFileSync(join(source, ".git"), "gitdir: /untrusted/shared/worktree\n");

    const result = spawnSync("bash", [runtimeBuilder, source, join(root, "output")], {
      encoding: "utf8",
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("standalone Git checkout, not a linked worktree");
  });

  it("uses an independent fork checkout and bypasses Nx caches for the SDK rebuild", () => {
    const workflow = readFileSync(
      resolve(repositoryRoot, ".github/workflows/daytona-sdk-artifact.yml"),
      "utf8"
    );
    const sdkBuilder = readFileSync(
      resolve(repositoryRoot, "scripts/build-pinned-daytona-sdk.sh"),
      "utf8"
    );
    const ci = readFileSync(resolve(repositoryRoot, ".github/workflows/ci.yml"), "utf8");

    expect(workflow).toContain("Check out an independent exact Daytona rebuild source");
    expect(workflow).toContain("path: .daytona-source-rebuild");
    expect(workflow).toContain(
      'build-pinned-daytona-sdk.sh "$GITHUB_WORKSPACE/.daytona-source-rebuild"'
    );
    expect(workflow).toContain(
      'build-pinned-daytona-runtime.sh "$GITHUB_WORKSPACE/.daytona-source-rebuild"'
    );
    expect(sdkBuilder).toContain("NX_DAEMON=false NX_SKIP_NX_CACHE=true");
    expect(ci).toContain("scripts/build-pinned-daytona-runtime.sh");
    expect(ci).toContain("scripts/verify-daytona-runtime-release-archive.sh");
    expect(ci).toContain("scripts/setup-whisper.sh");
  });

  function createReleaseFixture(): {
    root: string;
    archive: string;
    checksums: string;
  } {
    const root = mkdtempSync(join(tmpdir(), "terminalx-daytona-runtime-release-"));
    roots.push(root);
    const payload = join(root, "payload");
    mkdirSync(payload);
    writeFileSync(join(payload, runnerName), "runner", { mode: 0o555 });
    writeFileSync(join(payload, daemonName), "daemon", { mode: 0o555 });
    writeFileSync(join(payload, manifestName), '{"kind":"fixture"}\n', { mode: 0o444 });
    chmodSync(join(payload, runnerName), 0o555);
    chmodSync(join(payload, daemonName), 0o555);
    chmodSync(join(payload, manifestName), 0o444);
    writeFileSync(
      join(payload, fileChecksumsName),
      [runnerName, daemonName, manifestName]
        .map((name) => `${sha256(join(payload, name))}  ${name}`)
        .join("\n") + "\n",
      { mode: 0o444 }
    );
    chmodSync(join(payload, fileChecksumsName), 0o444);

    const archive = join(root, archiveName);
    const tar = spawnSync(
      "tar",
      [
        "--sort=name",
        "--mtime=UTC 1970-01-01",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "-czf",
        archive,
        "-C",
        payload,
        runnerName,
        daemonName,
        manifestName,
        fileChecksumsName,
      ],
      { encoding: "utf8" }
    );
    expect(tar.status, tar.stderr).toBe(0);
    chmodSync(archive, 0o644);
    const checksums = join(root, "checksums.sha256");
    writeFileSync(checksums, `${sha256(archive)}  ${basename(archive)}\n`, { mode: 0o644 });
    return { root, archive, checksums };
  }
});

function sha256(filename: string): string {
  return createHash("sha256").update(readFileSync(filename)).digest("hex");
}

function mode(filename: string): number {
  return statSync(filename).mode & 0o777;
}
