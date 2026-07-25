import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

const repositoryRoot = process.cwd();

describe("pinned whisper.cpp setup contract", () => {
  const setupScript = readFileSync(join(repositoryRoot, "scripts", "setup-whisper.sh"), "utf8");
  const artifactTool = join(repositoryRoot, "scripts", "whisper-artifacts.mjs");

  it("pins official source and model provenance to immutable revisions", () => {
    const configuration = JSON.parse(
      readFileSync(join(repositoryRoot, "config", "whisper-artifacts.json"), "utf8")
    ) as {
      source: { repository: string; tag: string; commit: string };
      modelRepository: { repository: string; revision: string };
      models: Record<string, { filename: string; sha256: string; size: number }>;
    };

    expect(configuration.source).toEqual({
      repository: "https://github.com/ggml-org/whisper.cpp.git",
      tag: "v1.8.6",
      commit: "23ee03506a91ac3d3f0071b40e66a430eebdfa1d",
    });
    expect(configuration.modelRepository).toEqual({
      repository: "https://huggingface.co/ggerganov/whisper.cpp",
      revision: "5359861c739e955e79d9a303bcbc70fb988958b1",
    });
    expect(configuration.models["tiny.en"]).toEqual({
      filename: "ggml-tiny.en.bin",
      sha256: "921e4cf8686fdd993dcd081a5da5b6c365bfde1162e72b08d75ac75289920b1f",
      size: 77_704_715,
    });
    expect(setupScript).toContain('actual_origin" != "$WHISPER_UPSTREAM"');
    expect(setupScript).toContain('actual_revision" != "$WHISPER_COMMIT"');
    expect(setupScript).toContain("status --porcelain --untracked-files=normal");
    expect(setupScript).toMatch(/--depth 1\s+\\\s+--branch "\$WHISPER_TAG"\s+\\\s+--single-branch/);
  });

  it("verifies exact file bytes through the installer artifact tool", () => {
    const directory = mkdtempSync(join(tmpdir(), "terminalx-whisper-artifact-tool-"));
    const artifact = join(directory, "artifact.bin");
    writeFileSync(artifact, "trusted fixture\n");
    const digest = createHash("sha256").update("trusted fixture\n").digest("hex");

    expect(() =>
      execFileSync(process.execPath, [artifactTool, "verify-file", artifact, digest, "16"])
    ).not.toThrow();
    expect(() =>
      execFileSync(
        process.execPath,
        [artifactTool, "verify-file", artifact, "0".repeat(64), "16"],
        {
          stdio: "pipe",
        }
      )
    ).toThrow();
    rmSync(directory, { recursive: true, force: true });
  });

  it("rejects a partial model download without replacing or blessing it", () => {
    const directory = mkdtempSync(join(tmpdir(), "terminalx-whisper-installer-"));
    const commands = join(directory, "commands");
    const toolRoot = join(directory, "tool-root");
    const modelPath = join(toolRoot, "models", "ggml-tiny.en.bin");
    execFileSync("mkdir", ["-p", commands, join(toolRoot, "models")]);
    writeFileSync(modelPath, "existing partial model");
    for (const command of ["cmake", "git"]) {
      writeExecutable(join(commands, command), "#!/bin/sh\nexit 99\n");
    }
    writeExecutable(
      join(commands, "curl"),
      '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do\n  if [ "$1" = "--output" ]; then shift; output="$1"; fi\n  shift\ndone\nprintf "%s" "new partial model" > "$output"\n'
    );

    const result = spawnSync(
      "bash",
      [join(repositoryRoot, "scripts", "setup-whisper.sh"), "tiny.en"],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        env: {
          NODE_ENV: "test",
          PATH: `${commands}:${process.env.PATH}`,
          TERMINALX_WHISPER_CPP_ROOT: toolRoot,
        },
      }
    );

    expect(result.status).not.toBe(0);
    expect(readFileSync(modelPath, "utf8")).toBe("existing partial model");
    expect(result.stdout).not.toContain("Whisper transcription is ready");
    expect(existsSync(join(toolRoot, "runtime-manifest.json"))).toBe(false);
    rmSync(directory, { recursive: true, force: true });
  });

  it("uses a fresh staged source/build and atomic final artifacts", () => {
    expect(setupScript).toContain('STAGE_DIR="$(mktemp -d "$WHISPER_ROOT/.install.XXXXXX")"');
    expect(setupScript).toContain('SOURCE_DIR="$STAGE_DIR/source"');
    expect(setupScript).toContain('BUILD_DIR="$STAGE_DIR/build"');
    expect(setupScript).toContain('MODELS_DIR="$WHISPER_ROOT/models"');
    expect(setupScript).toContain("--fail");
    expect(setupScript).toContain("--proto");
    expect(setupScript).toContain('mv -f -- "$MODEL_TEMP" "$MODEL_PATH"');
    expect(setupScript).toContain('mv -f -- "$BINARY_TEMP" "$WHISPER_BINARY"');
    expect(setupScript).toContain('mv -f -- "$MANIFEST_TEMP" "$RUNTIME_MANIFEST"');
    expect(setupScript).not.toContain("node_modules");
    expect(setupScript).not.toMatch(/git\s+(?:-C\s+\S+\s+)?reset\b/);
  });

  it("does not retain whisper-node in the application dependency manifests", () => {
    const packageManifest = readFileSync(join(repositoryRoot, "package.json"), "utf8");
    const packageLock = readFileSync(join(repositoryRoot, "package-lock.json"), "utf8");

    expect(packageManifest).not.toContain('"whisper-node"');
    expect(packageLock).not.toContain('"node_modules/whisper-node"');
  });
});

function writeExecutable(filename: string, contents: string): void {
  writeFileSync(filename, contents, { mode: 0o700 });
  chmodSync(filename, 0o700);
}
