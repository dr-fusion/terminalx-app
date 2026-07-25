import { createHash, generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const IMAGE_ROOT = join(REPOSITORY_ROOT, "packages/daytona-sandbox-image");
const PREPARE_MODULE = join(IMAGE_ROOT, "scripts/prepare-build-context.mjs");
const STATIC_PINS_MODULE = join(IMAGE_ROOT, "scripts/write-static-pins.mjs");
const OCI_MODULE = join(IMAGE_ROOT, "scripts/verify-oci-layout.mjs");
const BASE_COMMIT = "b5a5d9e78d76c8bcf351f2049620250e0f34eea4";
const HARDENED_COMMIT = "f9b4dfe428d37f3d956acda4403879516aa8d923";
const TERMINALX_COMMIT = "1".repeat(40);

interface MutableSupervisorManifest {
  fixedExecutables: Array<{
    role: string;
    installPath: string;
    bytes: number;
    sha256: string;
  }>;
  interpreter: { runnerRemeasureBeforeEveryRootExec: boolean };
  [key: string]: unknown;
}

describe("hardened Daytona sandbox image", () => {
  const roots: string[] = [];

  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true });
  });

  it("has a content-addressed, network-disabled, side-channel-free Dockerfile contract", () => {
    const dockerfile = readFileSync(join(IMAGE_ROOT, "Dockerfile"), "utf8");
    expect(dockerfile).toContain("ARG TERMINALX_TOOLCHAIN_IMAGE\n");
    expect(dockerfile).toContain("ARG TERMINALX_RUNTIME_IMAGE\n");
    expect(dockerfile).toContain("FROM ${TERMINALX_TOOLCHAIN_IMAGE}");
    expect(dockerfile).toContain("FROM ${TERMINALX_RUNTIME_IMAGE}");
    expect(dockerfile).toContain("COPY --from=terminalx-native-build");
    expect(dockerfile).toContain("/run/terminalx-private");
    expect(dockerfile.match(/RUN --network=none/g)?.length).toBeGreaterThanOrEqual(3);
    expect(dockerfile).toContain(
      'USER 0\nSTOPSIGNAL SIGTERM\nHEALTHCHECK NONE\nENTRYPOINT ["/usr/local/bin/terminalx-sandbox-init"]\nCMD []'
    );
    expect(dockerfile).not.toMatch(/^\s*(?:VOLUME|EXPOSE)\b/m);
    expect(dockerfile).not.toMatch(/\b(?:apt|apt-get|apk|dnf|yum|curl|wget)\b/);
    expect(dockerfile).not.toMatch(/ARG\s+.*(?:PRIVATE|SECRET|TOKEN|PASSWORD|CREDENTIAL)/i);
    expect(dockerfile).toMatch(/^# syntax=TERMINALX_REQUIRES_PREPARED_CONTENT_ADDRESSED_FRONTEND/);
    expect(dockerfile).toContain("io.terminalx.deployment-binding-installer.sha256");
    expect(dockerfile).toContain("io.terminalx.isolation-probe.sha256");
    expect(dockerfile).not.toContain("--attest type=sbom");

    const buildScript = readFileSync(join(IMAGE_ROOT, "build-image.sh"), "utf8");
    expect(buildScript).toContain("--attest type=sbom");
    expect(buildScript).toContain("--attest type=provenance,mode=max,version=v1,reproducible=true");
    expect(buildScript).toContain("--network none");
    expect(buildScript).toContain("oci-mediatypes=true,oci-artifact=true,rewrite-timestamp=true");
    expect(buildScript).toContain("mv --no-target-directory --no-clobber");
    expect(buildScript).toContain("STAGING_OUTPUT_ID");
  });

  it("compiles all native helpers with the production warning policy", () => {
    const compiler = spawnSync("sh", ["-c", "command -v cc"], { encoding: "utf8" });
    if (compiler.status !== 0) return;
    const output = temporaryRoot("terminalx-native-test-");
    for (const name of [
      "terminalx-peercred",
      "terminalx-sandbox-init",
      "terminalx-isolation-probe",
    ]) {
      const result = spawnSync(
        "cc",
        [
          "-std=c17",
          "-O2",
          "-Wall",
          "-Wextra",
          "-Werror",
          "-Wformat=2",
          "-Wconversion",
          "-Wsign-conversion",
          "-Wshadow",
          "-Wstrict-prototypes",
          join(IMAGE_ROOT, "root-tools", `${name}.c`),
          "-o",
          join(output, name),
        ],
        { encoding: "utf8" }
      );
      expect(result.status, result.stderr).toBe(0);
    }
    expect(spawnSync(join(output, "terminalx-peercred"), ["unexpected"]).status).toBe(78);
    expect(spawnSync(join(output, "terminalx-sandbox-init"), ["unexpected"]).status).toBe(1);
    expect(spawnSync(join(output, "terminalx-isolation-probe"), ["unexpected"]).status).toBe(74);
  });

  it("pins the exact public 13-field bootstrap trust record", async () => {
    const { createStaticTrustPins } = await import(pathToFileURL(STATIC_PINS_MODULE).href);
    const isolation = publicKey();
    const effectManifest = publicKey();
    const deployment = publicKey();
    const trust = {
      version: 1,
      kind: "terminalx.daytona-sandbox-trust-input",
      supervisorArtifactDigest: "1".repeat(64),
      effectExecutableSha256: "2".repeat(64),
      nodeExecutableSha256: "3".repeat(64),
      isolationIssuerKeyId: "isolation-1",
      isolationIssuerPublicKeySpkiPem: isolation,
      hardenedDaytonaSourceCommit: HARDENED_COMMIT,
      effectManifestAuthorityIssuerKeyId: "effect-manifest-1",
      effectManifestAuthorityPublicKeySpkiPem: effectManifest,
      deploymentBindingIssuerKeyId: "deployment-1",
      deploymentBindingIssuerPublicKeySpkiPem: deployment,
    };
    const native = {
      isolationProbeSha256: "6".repeat(64),
      peerCredentialExecutableSha256: "7".repeat(64),
      sandboxInitSha256: "8".repeat(64),
    };
    const pins = createStaticTrustPins(trust, native);
    expect(Object.keys(pins)).toEqual([
      "version",
      "kind",
      "supervisorArtifactDigest",
      "peerCredentialExecutableSha256",
      "effectExecutableSha256",
      "nodeExecutableSha256",
      "isolationIssuerKeyId",
      "isolationIssuerPublicKeySpkiPem",
      "hardenedDaytonaSourceCommit",
      "effectManifestAuthorityIssuerKeyId",
      "effectManifestAuthorityPublicKeySpkiPem",
      "deploymentBindingIssuerKeyId",
      "deploymentBindingIssuerPublicKeySpkiPem",
    ]);
    expect(JSON.stringify(pins)).not.toContain("PRIVATE KEY");
    expect(() =>
      createStaticTrustPins({ ...trust, isolationIssuerPublicKeySpkiPem: privateKey() }, native)
    ).toThrow();
    expect(() => createStaticTrustPins({ ...trust, secret: "forbidden" }, native)).toThrow();
    expect(() =>
      createStaticTrustPins(
        { ...trust, effectManifestAuthorityPublicKeySpkiPem: isolation },
        native
      )
    ).toThrow();
  });

  it("prepares only release-pinned inputs from the measured supervisor archive", async () => {
    const fixture = createBuildFixture();
    const { prepareBuildContext } = await import(pathToFileURL(PREPARE_MODULE).href);
    const result = prepareBuildContext(fixture.configFile, fixture.output);
    expect(result.platform).toBe("linux/amd64");
    expect(result.artifact.source.daytonaProductionCommit).toBe(HARDENED_COMMIT);
    const trustInput = JSON.parse(
      readFileSync(join(fixture.output, "inputs/sandbox-trust-input.json"), "utf8")
    );
    expect(Object.keys(trustInput).sort()).toEqual(
      [
        "version",
        "kind",
        "supervisorArtifactDigest",
        "effectExecutableSha256",
        "nodeExecutableSha256",
        "isolationIssuerKeyId",
        "isolationIssuerPublicKeySpkiPem",
        "hardenedDaytonaSourceCommit",
        "effectManifestAuthorityIssuerKeyId",
        "effectManifestAuthorityPublicKeySpkiPem",
        "deploymentBindingIssuerKeyId",
        "deploymentBindingIssuerPublicKeySpkiPem",
      ].sort()
    );
    expect(
      readFileSync(join(fixture.output, "inputs/daytona")).subarray(0, 4).toString("hex")
    ).toBe("7f454c46");
    expect(readFileSync(join(fixture.output, "inputs/terminalx-effect-enforcer"), "utf8")).toBe(
      "#!/usr/local/bin/node\neffect-enforcer"
    );
    const preparedDockerfile = readFileSync(join(fixture.output, "Dockerfile"), "utf8");
    expect(preparedDockerfile).toMatch(
      new RegExp(`^# syntax=docker/dockerfile:1\\.7@sha256:f{64}\\n`)
    );
    expect(preparedDockerfile).not.toContain(
      "TERMINALX_REQUIRES_PREPARED_CONTENT_ADDRESSED_FRONTEND"
    );
    expect(readFileSync(join(fixture.output, ".dockerignore"), "utf8")).toContain(
      "!native-hashes.json\n"
    );
  });

  it.each([
    "floating runtime image",
    "floating Dockerfile frontend",
    "daemon digest mismatch",
    "scripted daemon",
    "symlinked daemon",
    "group-writable effect executor",
    "shell effect executor",
    "embedded private key",
    "shell supervisor",
    "wrong supervisor install path",
    "unmeasured root interpreter",
    "tagged output image",
    "reused authority key",
  ])("rejects adversarial build input: %s", async (attack: string) => {
    const fixture = createBuildFixture();
    const configuration = JSON.parse(readFileSync(fixture.configFile, "utf8"));
    if (attack === "floating runtime image") configuration.runtimeImage = "node:22";
    if (attack === "floating Dockerfile frontend") {
      configuration.dockerfileFrontendImage = "docker/dockerfile:1.7";
    }
    if (attack === "daemon digest mismatch") configuration.daytonaDaemonSha256 = "0".repeat(64);
    if (attack === "scripted daemon") {
      chmodSync(configuration.daytonaDaemonFile, 0o755);
      writeFileSync(configuration.daytonaDaemonFile, "#!/usr/local/bin/node\ndaemon", {
        mode: 0o555,
      });
      chmodSync(configuration.daytonaDaemonFile, 0o555);
      configuration.daytonaDaemonSha256 = sha256File(configuration.daytonaDaemonFile);
    }
    if (attack === "symlinked daemon") {
      const link = join(fixture.root, "daytona-link");
      symlinkSync(configuration.daytonaDaemonFile, link);
      configuration.daytonaDaemonFile = link;
    }
    if (attack === "group-writable effect executor")
      chmodSync(configuration.effectEnforcerFile, 0o575);
    if (attack === "shell effect executor") {
      chmodSync(configuration.effectEnforcerFile, 0o755);
      writeFileSync(configuration.effectEnforcerFile, "#!/bin/sh\nexit 0\n", { mode: 0o555 });
      chmodSync(configuration.effectEnforcerFile, 0o555);
      configuration.effectEnforcerSha256 = sha256File(configuration.effectEnforcerFile);
    }
    if (attack === "embedded private key") {
      chmodSync(configuration.effectEnforcerFile, 0o755);
      writeFileSync(configuration.effectEnforcerFile, privateKey(), { mode: 0o555 });
      chmodSync(configuration.effectEnforcerFile, 0o555);
      configuration.effectEnforcerSha256 = sha256File(configuration.effectEnforcerFile);
    }
    if (attack === "wrong supervisor install path") {
      rewriteSupervisorArchive(fixture, (manifest) => {
        const supervisor = manifest.fixedExecutables[0];
        if (!supervisor) throw new TypeError("fixture supervisor is unavailable");
        supervisor.installPath = "/usr/local/bin/terminalx-daytona-supervisor";
      });
      configuration.supervisorArtifactDigest = sha256File(configuration.supervisorArchiveFile);
    }
    if (attack === "shell supervisor") {
      const bytes = Buffer.from("#!/bin/sh\nexit 0\n");
      const supervisorFile = join(fixture.artifactRoot, "bin", "terminalx-daytona-supervisor");
      chmodSync(supervisorFile, 0o755);
      writeFileSync(supervisorFile, bytes, {
        mode: 0o555,
      });
      chmodSync(supervisorFile, 0o555);
      rewriteSupervisorArchive(fixture, (manifest) => {
        const supervisor = manifest.fixedExecutables.find(
          (entry) => entry.role === "root-supervisor"
        );
        if (!supervisor) throw new TypeError("fixture supervisor is unavailable");
        supervisor.bytes = bytes.byteLength;
        supervisor.sha256 = createHash("sha256").update(bytes).digest("hex");
      });
      configuration.supervisorArtifactDigest = sha256File(configuration.supervisorArchiveFile);
    }
    if (attack === "unmeasured root interpreter") {
      rewriteSupervisorArchive(fixture, (manifest) => {
        manifest.interpreter.runnerRemeasureBeforeEveryRootExec = false;
      });
      configuration.supervisorArtifactDigest = sha256File(configuration.supervisorArchiveFile);
    }
    if (attack === "tagged output image") {
      configuration.imageName = "registry.example/terminalx/sandbox:latest";
    }
    if (attack === "reused authority key") {
      configuration.trust.deploymentBindingIssuerPublicKeySpkiPem =
        configuration.trust.isolationIssuerPublicKeySpkiPem;
    }
    writeFileSync(fixture.configFile, `${JSON.stringify(configuration)}\n`, { mode: 0o600 });
    chmodSync(fixture.configFile, 0o600);
    const { prepareBuildContext } = await import(pathToFileURL(PREPARE_MODULE).href);
    expect(() => prepareBuildContext(fixture.configFile, fixture.output)).toThrow();
  });

  it("keeps deployment binding refresh claim-stable and atomic", () => {
    const source = readFileSync(
      join(IMAGE_ROOT, "root-tools/terminalx-deployment-binding-install.mjs"),
      "utf8"
    );
    expect(source).toContain("previous.claimsCanonical !== validated.claimsCanonical");
    expect(source).toContain("validated.issuedAtMs <= previous.issuedAtMs");
    expect(source).toContain("renameSync(temporary, TARGET_FILE)");
    expect(source).toContain("fsyncDirectory(RUNTIME_ROOT)");
    expect(source).toContain("validateSignedBinding(binding, false)");
    expect(source).not.toContain("inputBytes");
    expect(source).not.toMatch(/exec|spawn|shell|eval\s*\(/);
  });

  it("defines the exact public isolation probe measurements and denials", () => {
    const initSource = readFileSync(
      join(IMAGE_ROOT, "root-tools/terminalx-sandbox-init.c"),
      "utf8"
    );
    expect(initSource).toContain("confine_root_identity_and_capabilities");
    expect(initSource).toContain("EXPECTED_ROOT_CAPABILITIES UINT64_C(0x00000000000000e1)");
    expect(initSource).toContain("PR_CAPBSET_DROP");
    expect(initSource).toContain('SANDBOX_HOSTNAME = "terminalx-sandbox"');
    expect(initSource).not.toContain("hostname_matches(environment.sandbox_id)");
    expect(initSource).toContain(
      'DAYTONA_SOCKET =\n    "/run/terminalx-private/daytona-daemon.sock"'
    );
    const daemonLaunch = initSource.slice(
      initSource.indexOf("static pid_t spawn_daytona"),
      initSource.indexOf("static pid_t spawn_supervisor")
    );
    expect(daemonLaunch).toContain('"--terminalx-toolbox-listener-fd=3"');
    expect(daemonLaunch).toContain('"DAYTONA_SANDBOX_ID=terminalx-sandbox"');
    expect(daemonLaunch).not.toContain("sandbox_id_entry");
    expect(daemonLaunch).not.toContain("sandbox_snapshot_entry");
    expect(daemonLaunch).not.toContain("DAYTONA_SANDBOX_SNAPSHOT=");
    const source = readFileSync(join(IMAGE_ROOT, "root-tools/terminalx-isolation-probe.c"), "utf8");
    expect(source).toContain("EXPECTED_AGENT_BOUNDING_SET UINT64_C(0x00000000000000e1)");
    expect(source).toContain("agentPrivateKeyReadDenied");
    expect(source).toContain("agentPrivateKeyWriteDenied");
    expect(source).toContain("agent->process_count >= 1");
    expect(source).toContain("init_matches == 1 && daemon_matches == 1 && supervisor_matches == 1");
    expect(source).toContain("root.all_allowed");
    expect(source).toContain("root.all_capabilities_match");
    expect(source).toContain("fixed_node_helper_command_line_matches");
    expect(source).toContain("validate_fixed_hostname()");
    expect(source).toContain("all_agent_environments_safe");
    expect(source).toContain('"/run/terminalx-private/daytona-daemon.sock", "socket", 0600');
    expect(source).toContain("output.length > 4096");
    expect(source).not.toMatch(/system\s*\(|popen\s*\(|execv/);
  });

  it("validates final OCI configuration plus SPDX and SLSA attestations", async () => {
    const fixture = createOciFixture();
    const { verifyOciLayout } = await import(pathToFileURL(OCI_MODULE).href);
    const output = join(fixture.root, "release.json");
    const normalizedMetadata = join(fixture.root, "normalized-build-metadata.json");
    const release = verifyOciLayout(
      fixture.layout,
      fixture.context,
      output,
      fixture.rawBuildMetadata,
      normalizedMetadata
    );
    expect(release.dockerImageId).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(release.attestations).toEqual([
      "https://slsa.dev/provenance/v1",
      "https://spdx.dev/Document",
    ]);
    expect(JSON.parse(readFileSync(output, "utf8")).kind).toBe(
      "terminalx.daytona-sandbox-image-build"
    );
    expect(JSON.parse(readFileSync(normalizedMetadata, "utf8")).kind).toBe(
      "terminalx.daytona-sandbox-buildkit-metadata"
    );
  });

  it("rejects inherited OCI environment variables before release", async () => {
    const fixture = createOciFixture(["PATH=/usr/local/bin:/usr/bin:/bin"]);
    const { verifyOciLayout } = await import(pathToFileURL(OCI_MODULE).href);
    expect(() =>
      verifyOciLayout(
        fixture.layout,
        fixture.context,
        join(fixture.root, "release.json"),
        fixture.rawBuildMetadata,
        join(fixture.root, "normalized-build-metadata.json")
      )
    ).toThrow(/inherit environment/);
  });

  it("rejects malformed native helper measurements before release", async () => {
    const fixture = createOciFixture();
    writeFileSync(
      join(fixture.context, "native-hashes.json"),
      `${JSON.stringify({
        isolationProbeSha256: "not-a-digest",
        peerCredentialExecutableSha256: "c".repeat(64),
        sandboxInitSha256: "d".repeat(64),
      })}\n`
    );
    const { verifyOciLayout } = await import(pathToFileURL(OCI_MODULE).href);
    expect(() =>
      verifyOciLayout(
        fixture.layout,
        fixture.context,
        join(fixture.root, "release.json"),
        fixture.rawBuildMetadata,
        join(fixture.root, "normalized-build-metadata.json")
      )
    ).toThrow(/Native helper digest/);
  });

  it("rejects OCI attestations that are not bound to the built manifest", async () => {
    const fixture = createOciFixture([], false);
    const { verifyOciLayout } = await import(pathToFileURL(OCI_MODULE).href);
    expect(() =>
      verifyOciLayout(
        fixture.layout,
        fixture.context,
        join(fixture.root, "release.json"),
        fixture.rawBuildMetadata,
        join(fixture.root, "normalized-build-metadata.json")
      )
    ).toThrow(/not bound/);
  });

  it("rejects minimum-mode provenance presented as the production build", async () => {
    const fixture = createOciFixture([], true, false);
    const { verifyOciLayout } = await import(pathToFileURL(OCI_MODULE).href);
    expect(() =>
      verifyOciLayout(
        fixture.layout,
        fixture.context,
        join(fixture.root, "release.json"),
        fixture.rawBuildMetadata,
        join(fixture.root, "normalized-build-metadata.json")
      )
    ).toThrow(/maximum-mode/);
  });

  it("rejects BuildKit metadata that names a different image config", async () => {
    const fixture = createOciFixture();
    writeFileSync(
      fixture.rawBuildMetadata,
      `${JSON.stringify({
        "containerimage.config.digest": `sha256:${"f".repeat(64)}`,
        "containerimage.descriptor": {
          digest: `sha256:${"e".repeat(64)}`,
          mediaType: "application/vnd.oci.image.index.v1+json",
          size: 1,
        },
        "containerimage.digest": `sha256:${"e".repeat(64)}`,
      })}\n`
    );
    const { verifyOciLayout } = await import(pathToFileURL(OCI_MODULE).href);
    expect(() =>
      verifyOciLayout(
        fixture.layout,
        fixture.context,
        join(fixture.root, "release.json"),
        fixture.rawBuildMetadata,
        join(fixture.root, "normalized-build-metadata.json")
      )
    ).toThrow(/does not describe/);
  });

  function temporaryRoot(prefix: string): string {
    const root = mkdtempSync(join(tmpdir(), prefix));
    roots.push(root);
    return root;
  }

  function createBuildFixture() {
    const root = temporaryRoot("terminalx-image-input-");
    const artifactRoot = join(root, "artifact");
    mkdirSync(join(artifactRoot, "bin"), { recursive: true });
    const executables = {
      "terminalx-daytona-supervisor": Buffer.from("#!/usr/local/bin/node\nsupervisor"),
      "terminalx-supervisor-relay": Buffer.from("#!/usr/local/bin/node\nrelay"),
      "terminalx-assignment-bootstrap": Buffer.from("#!/usr/local/bin/node\nbootstrap"),
    };
    for (const [name, bytes] of Object.entries(executables)) {
      writeFileSync(join(artifactRoot, "bin", name), bytes, { mode: 0o555 });
      chmodSync(join(artifactRoot, "bin", name), 0o555);
    }
    writeManifest(artifactRoot, executables);
    const archive = join(root, "supervisor.tar.gz");
    createTar(artifactRoot, archive);
    const daytona = join(root, "daytona");
    const effect = join(root, "effect");
    writeFileSync(
      daytona,
      Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.from("daytona-daemon")]),
      {
        mode: 0o555,
      }
    );
    writeFileSync(effect, "#!/usr/local/bin/node\neffect-enforcer", { mode: 0o555 });
    chmodSync(daytona, 0o555);
    chmodSync(effect, 0o555);
    const bootstrap = {
      version: 1,
      kind: "terminalx.daytona-bootstrap-authority-pin",
      issuerKeyId: "bootstrap-1",
      publicKeySpkiPem: publicKey(),
    };
    const bootstrapFile = join(root, "bootstrap.json");
    writeFileSync(bootstrapFile, `${JSON.stringify(bootstrap)}\n`, { mode: 0o600 });
    chmodSync(bootstrapFile, 0o600);
    const configuration = {
      schemaVersion: 1,
      dockerfileFrontendImage: `docker/dockerfile:1.7@sha256:${"f".repeat(64)}`,
      runtimeImage: `registry.example/runtime@sha256:${"a".repeat(64)}`,
      toolchainImage: `registry.example/toolchain@sha256:${"b".repeat(64)}`,
      platform: "linux/amd64",
      imageName: "registry.example/terminalx/sandbox",
      sourceDateEpoch: 1,
      supervisorArchiveFile: archive,
      supervisorArtifactDigest: sha256File(archive),
      daytonaDaemonFile: daytona,
      daytonaDaemonSha256: sha256File(daytona),
      effectEnforcerFile: effect,
      effectEnforcerSha256: sha256File(effect),
      nodeExecutableSha256: "c".repeat(64),
      bootstrapAuthorityPinFile: bootstrapFile,
      trust: {
        isolationIssuerKeyId: "isolation-1",
        isolationIssuerPublicKeySpkiPem: publicKey(),
        hardenedDaytonaSourceCommit: HARDENED_COMMIT,
        effectManifestAuthorityIssuerKeyId: "effect-manifest-1",
        effectManifestAuthorityPublicKeySpkiPem: publicKey(),
        deploymentBindingIssuerKeyId: "deployment-1",
        deploymentBindingIssuerPublicKeySpkiPem: publicKey(),
      },
    };
    const configFile = join(root, "build.json");
    writeFileSync(configFile, `${JSON.stringify(configuration)}\n`, { mode: 0o600 });
    chmodSync(configFile, 0o600);
    return { root, artifactRoot, archive, configFile, output: join(root, "context") };
  }

  function rewriteSupervisorArchive(
    fixture: ReturnType<typeof createBuildFixture>,
    mutate: (manifest: MutableSupervisorManifest) => void
  ) {
    const manifestPath = join(fixture.artifactRoot, "daytona-supervisor-artifact.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as MutableSupervisorManifest;
    mutate(manifest);
    writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`, { mode: 0o644 });
    rmSync(fixture.archive);
    createTar(fixture.artifactRoot, fixture.archive);
  }

  function writeManifest(artifactRoot: string, executables: Record<string, Buffer>) {
    const definitions: Array<readonly [string, keyof typeof executables]> = [
      ["root-supervisor", "terminalx-daytona-supervisor"],
      ["fixed-runner-relay", "terminalx-supervisor-relay"],
      ["fixed-assignment-bootstrap", "terminalx-assignment-bootstrap"],
    ];
    const fixedExecutables = definitions.map(([role, name]) => {
      const executable = executables[name];
      if (!executable) throw new TypeError("fixture executable is unavailable");
      return {
        role,
        file: `bin/${name}`,
        installPath: `/usr/local/libexec/terminalx/${name}`,
        mode: 0o555,
        bytes: executable.byteLength,
        sha256: createHash("sha256").update(executable).digest("hex"),
      };
    });
    const manifest = {
      schemaVersion: 1,
      kind: "terminalx.daytona-supervisor-build",
      source: {
        terminalxCommit: TERMINALX_COMMIT,
        daytonaProductionCommit: HARDENED_COMMIT,
        daytonaUpstreamBaseCommit: BASE_COMMIT,
      },
      protocol: { activationRequiresLiveIsolationAttestation: true },
      fixedExecutables,
      interpreter: {
        path: "/usr/local/bin/node",
        ownerUid: 0,
        mode: 0o555,
        digestSource: "/etc/terminalx/sandbox-trust-pins.json#nodeExecutableSha256",
        runnerRemeasureBeforeEveryRootExec: true,
      },
      securityBoundary: {
        rawPrivateKeyInProtocol: false,
        providerSandboxTokenInjected: false,
        permissiveEffectFallback: false,
      },
      requiredExternalComponents: [],
      files: [],
    };
    writeFileSync(
      join(artifactRoot, "daytona-supervisor-artifact.json"),
      `${JSON.stringify(manifest)}\n`,
      { mode: 0o644 }
    );
  }

  function createTar(source: string, output: string) {
    const result = spawnSync("tar", ["-czf", output, "-C", source, "."], { encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
    chmodSync(output, 0o600);
  }

  function createOciFixture(
    environment: string[] = [],
    bindAttestations = true,
    maximumProvenance = true
  ) {
    const root = temporaryRoot("terminalx-oci-");
    const layout = join(root, "oci");
    const context = join(root, "context");
    mkdirSync(join(layout, "blobs", "sha256"), { recursive: true });
    mkdirSync(context);
    const args = {
      BUILDKIT_SYNTAX: `docker/dockerfile:1.7@sha256:${"0".repeat(64)}`,
      TERMINALX_RUNTIME_IMAGE: `runtime@sha256:${"1".repeat(64)}`,
      TERMINALX_TOOLCHAIN_IMAGE: `toolchain@sha256:${"2".repeat(64)}`,
      SOURCE_DATE_EPOCH: "1",
      TERMINALX_SUPERVISOR_ARTIFACT_SHA256: "3".repeat(64),
      TERMINALX_SUPERVISOR_SHA256: "4".repeat(64),
      TERMINALX_SUPERVISOR_RELAY_SHA256: "5".repeat(64),
      TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256: "6".repeat(64),
      TERMINALX_DAYTONA_DAEMON_SHA256: "7".repeat(64),
      TERMINALX_EFFECT_ENFORCER_SHA256: "8".repeat(64),
      TERMINALX_NODE_SHA256: "9".repeat(64),
      TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256: "a".repeat(64),
      TERMINALX_SOURCE_COMMIT: TERMINALX_COMMIT,
      TERMINALX_DAYTONA_SOURCE_COMMIT: HARDENED_COMMIT,
    };
    const native = {
      isolationProbeSha256: "b".repeat(64),
      peerCredentialExecutableSha256: "c".repeat(64),
      sandboxInitSha256: "d".repeat(64),
    };
    writeFileSync(join(context, "platform.txt"), "linux/amd64\n");
    writeFileSync(join(context, "image-name.txt"), "registry.example/terminalx/sandbox\n");
    writeFileSync(join(context, "Dockerfile"), `# syntax=${args.BUILDKIT_SYNTAX}\nFROM scratch\n`);
    writeFileSync(
      join(context, "build-arguments.txt"),
      `${Object.entries(args)
        .map(([key, value]) => `${key}=${value}`)
        .join("\n")}\n`
    );
    writeFileSync(join(context, "native-hashes.json"), `${JSON.stringify(native)}\n`);
    const labels = {
      "io.terminalx.sandbox.profile": "v1",
      "io.terminalx.supervisor-relay.sha256": args.TERMINALX_SUPERVISOR_RELAY_SHA256,
      "io.terminalx.assignment-bootstrap.sha256": args.TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256,
      "io.terminalx.node.sha256": args.TERMINALX_NODE_SHA256,
      "io.terminalx.deployment-binding-installer.sha256":
        args.TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256,
      "io.terminalx.isolation-probe.sha256": native.isolationProbeSha256,
      "io.terminalx.sandbox-init.sha256": native.sandboxInitSha256,
      "io.terminalx.peercred.sha256": native.peerCredentialExecutableSha256,
      "io.terminalx.daytona-daemon.sha256": args.TERMINALX_DAYTONA_DAEMON_SHA256,
      "io.terminalx.effect-enforcer.sha256": args.TERMINALX_EFFECT_ENFORCER_SHA256,
      "io.terminalx.supervisor.sha256": args.TERMINALX_SUPERVISOR_SHA256,
      "io.terminalx.supervisor-artifact.sha256": args.TERMINALX_SUPERVISOR_ARTIFACT_SHA256,
      "io.terminalx.daytona-source.commit": args.TERMINALX_DAYTONA_SOURCE_COMMIT,
      "org.opencontainers.image.revision": args.TERMINALX_SOURCE_COMMIT,
      "io.terminalx.source-date-epoch": args.SOURCE_DATE_EPOCH,
    };
    const config = blob(
      layout,
      {
        architecture: "amd64",
        os: "linux",
        created: "1970-01-01T00:00:01.000Z",
        config: {
          User: "0",
          Env: environment,
          Entrypoint: ["/usr/local/bin/terminalx-sandbox-init"],
          Cmd: [],
          WorkingDir: "/home/terminalx",
          StopSignal: "SIGTERM",
          Shell: ["/bin/sh", "-eu", "-c"],
          Labels: labels,
        },
        rootfs: { type: "layers", diff_ids: [`sha256:${"e".repeat(64)}`] },
        history: [],
      },
      "application/vnd.oci.image.config.v1+json"
    );
    const layer = blob(layout, Buffer.from("layer"), "application/vnd.oci.image.layer.v1.tar");
    const imageManifest = blob(
      layout,
      {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        config,
        layers: [layer],
      },
      "application/vnd.oci.image.manifest.v1+json"
    );
    const imageManifestSha256 = bindAttestations
      ? imageManifest.digest.slice("sha256:".length)
      : "f".repeat(64);
    const subject = [
      {
        name: "registry.example/terminalx/sandbox",
        digest: { sha256: imageManifestSha256 },
      },
    ];
    const spdx = blob(
      layout,
      {
        _type: "https://in-toto.io/Statement/v1",
        subject,
        predicateType: "https://spdx.dev/Document",
        predicate: {
          SPDXID: "SPDXRef-DOCUMENT",
          spdxVersion: "SPDX-2.3",
          dataLicense: "CC0-1.0",
          name: "terminalx-sandbox",
          documentNamespace: "https://terminalx.example/sbom/test",
          creationInfo: {
            created: "1970-01-01T00:00:01.000Z",
            creators: ["Tool: terminalx-test"],
          },
          packages: [{ SPDXID: "SPDXRef-Package-node", name: "node" }],
        },
      },
      "application/vnd.in-toto+json"
    );
    const slsa = blob(
      layout,
      {
        _type: "https://in-toto.io/Statement/v1",
        subject,
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: {
          buildDefinition: {
            buildType:
              "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
            externalParameters: {
              configSource: { path: "Dockerfile" },
              request: maximumProvenance
                ? {
                    frontend: "gateway.v0",
                    args: {
                      source: args.BUILDKIT_SYNTAX,
                      target: "terminalx-sandbox",
                      ...Object.fromEntries(
                        Object.entries(args).map(([key, value]) => [`build-arg:${key}`, value])
                      ),
                    },
                    locals: [{ name: "context" }, { name: "dockerfile" }],
                    secrets: [],
                    ssh: [],
                  }
                : {},
            },
            internalParameters: maximumProvenance ? { buildConfig: { llbDefinition: [{}] } } : {},
            resolvedDependencies: ["0", "1", "2"].map((digest) => ({
              uri: `pkg:docker/test@sha256:${digest.repeat(64)}`,
              digest: { sha256: digest.repeat(64) },
            })),
          },
          runDetails: {
            builder: { id: "terminalx-test-builder" },
            metadata: {
              buildkit_hermetic: true,
              buildkit_reproducible: maximumProvenance,
              buildkit_completeness: { request: maximumProvenance },
              buildkit_metadata: maximumProvenance ? { source: {}, layers: {} } : {},
            },
          },
        },
      },
      "application/vnd.in-toto+json"
    );
    const attestationConfig = blob(layout, {}, "application/vnd.oci.empty.v1+json");
    const attestationManifest = blob(
      layout,
      {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        artifactType: "application/vnd.docker.attestation.manifest.v1+json",
        config: attestationConfig,
        subject: imageManifest,
        layers: [
          { ...spdx, annotations: { "in-toto.io/predicate-type": "https://spdx.dev/Document" } },
          {
            ...slsa,
            annotations: {
              "in-toto.io/predicate-type": "https://slsa.dev/provenance/v1",
            },
          },
        ],
      },
      "application/vnd.oci.image.manifest.v1+json"
    );
    writeFileSync(join(layout, "oci-layout"), '{"imageLayoutVersion":"1.0.0"}\n');
    const indexBytes = Buffer.from(
      `${JSON.stringify({
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        manifests: [
          { ...imageManifest, platform: { os: "linux", architecture: "amd64" } },
          {
            ...attestationManifest,
            platform: { os: "unknown", architecture: "unknown" },
            annotations: {
              "vnd.docker.reference.digest": imageManifest.digest,
              "vnd.docker.reference.type": "attestation-manifest",
            },
          },
        ],
      })}\n`
    );
    writeFileSync(join(layout, "index.json"), indexBytes);
    const imageIndexDigest = `sha256:${createHash("sha256").update(indexBytes).digest("hex")}`;
    const rawBuildMetadata = join(root, "raw-build-metadata.json");
    writeFileSync(
      rawBuildMetadata,
      `${JSON.stringify({
        "containerimage.config.digest": config.digest,
        "containerimage.descriptor": {
          digest: imageIndexDigest,
          mediaType: "application/vnd.oci.image.index.v1+json",
          size: indexBytes.byteLength,
          annotations: { "config.digest": config.digest },
        },
        "containerimage.digest": imageIndexDigest,
      })}\n`
    );
    return { root, layout, context, rawBuildMetadata };
  }

  function blob(layout: string, value: unknown, mediaType: string) {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value));
    const digest = createHash("sha256").update(bytes).digest("hex");
    writeFileSync(join(layout, "blobs", "sha256", digest), bytes);
    return { mediaType, digest: `sha256:${digest}`, size: bytes.byteLength };
  }

  function publicKey(): string {
    return generateKeyPairSync("ed25519")
      .publicKey.export({ type: "spki", format: "pem" })
      .toString();
  }

  function privateKey(): string {
    return generateKeyPairSync("ed25519")
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
  }

  function sha256File(path: string): string {
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  }
});
