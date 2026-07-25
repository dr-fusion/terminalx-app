import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyWhisperRuntimeArtifacts } from "@/lib/telegram/whisper-artifact-trust";

vi.mock("../../config/whisper-artifacts.json", () => ({
  default: {
    schemaVersion: 1,
    kind: "terminalx.whisper-artifacts",
    source: {
      repository: "https://github.com/ggml-org/whisper.cpp.git",
      tag: "v1.8.6",
      commit: "23ee03506a91ac3d3f0071b40e66a430eebdfa1d",
    },
    modelRepository: {
      repository: "https://huggingface.co/ggerganov/whisper.cpp",
      revision: "5359861c739e955e79d9a303bcbc70fb988958b1",
    },
    models: {
      "tiny.en": {
        filename: "ggml-tiny.en.bin",
        sha256: "21249a290a4255a0f3ee6685ff7933bffa241c3e35bb13a52dc0c7a679bed3b2",
        size: 13,
      },
    },
  },
}));

describe.skipIf(process.platform === "win32")("Whisper runtime artifact trust", () => {
  let root: string;
  let binaryPath: string;
  let modelPath: string;
  let manifestPath: string;

  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "test");
    root = mkdtempSync(join(tmpdir(), "terminalx-whisper-trust-"));
    binaryPath = join(root, "bin", "whisper-cli");
    modelPath = join(root, "models", "ggml-tiny.en.bin");
    manifestPath = join(root, "runtime-manifest.json");
    mkdirSync(join(root, "bin"));
    mkdirSync(join(root, "models"));
    writeFileSync(binaryPath, "trusted binary");
    chmodSync(binaryPath, 0o555);
    writeFileSync(modelPath, "model fixture");
    chmodSync(modelPath, 0o444);
    writeManifest(manifestPath, binaryPath, modelPath);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    rmSync(root, { force: true, recursive: true });
  });

  it("accepts an exact immutable artifact set from the private test authority fixture", async () => {
    await expect(verifyFixture(root, binaryPath, modelPath, manifestPath)).resolves.toEqual({
      binaryPath,
      modelPath,
      modelName: "tiny.en",
    });
  });

  it.each([
    ["digest", (model: { sha256: string; size: number }) => (model.sha256 = "0".repeat(64))],
    ["size", (model: { sha256: string; size: number }) => (model.size = 14)],
  ])("rejects a model %s that differs from its canonical authority", async (_field, mutate) => {
    rewriteManifest(manifestPath, (manifest) => mutate(manifest.model));

    await expect(verifyFixture(root, binaryPath, modelPath, manifestPath)).rejects.toThrow(
      "Invalid Whisper runtime artifact manifest"
    );
  });

  it("rejects a binary changed after its manifest was issued", async () => {
    chmodSync(binaryPath, 0o700);
    writeFileSync(binaryPath, "tampered binary");
    chmodSync(binaryPath, 0o555);

    await expect(verifyFixture(root, binaryPath, modelPath, manifestPath)).rejects.toThrow(
      /size mismatch|digest mismatch/
    );
  });

  it("rejects owner-writable executable artifacts", async () => {
    chmodSync(binaryPath, 0o755);

    await expect(verifyFixture(root, binaryPath, modelPath, manifestPath)).rejects.toThrow(
      "permissions are not protected"
    );
  });

  it("rejects a symbolic-link manifest before trusting its contents", async () => {
    const target = join(root, "manifest-target.json");
    writeManifest(target, binaryPath, modelPath);
    rmSync(manifestPath);
    symlinkSync(target, manifestPath);

    await expect(verifyFixture(root, binaryPath, modelPath, manifestPath)).rejects.toThrow();
  });

  it("rejects a symbolic-link executable even when its target has the expected bytes", async () => {
    const target = join(root, "bin", "whisper-cli-target");
    chmodSync(binaryPath, 0o700);
    writeFileSync(target, "trusted binary");
    chmodSync(target, 0o555);
    rmSync(binaryPath);
    symlinkSync(target, binaryPath);

    await expect(verifyFixture(root, binaryPath, modelPath, manifestPath)).rejects.toThrow();
  });

  it("rejects artifacts outside the configured trust root", async () => {
    const outsideBinary = join(root, "..", `outside-whisper-${process.pid}`);
    writeFileSync(outsideBinary, "outside");
    chmodSync(outsideBinary, 0o555);

    await expect(verifyFixture(root, outsideBinary, modelPath, manifestPath)).rejects.toThrow(
      "contained by its configured trust root"
    );
    rmSync(outsideBinary, { force: true });
  });

  it("fails closed in production when the trust root belongs to the server user", async () => {
    vi.stubEnv("NODE_ENV", "production");

    await expect(verifyFixture(root, binaryPath, modelPath, manifestPath)).rejects.toThrow(
      /root-owned|non-root POSIX/
    );
  });
});

function verifyFixture(root: string, binaryPath: string, modelPath: string, manifestPath: string) {
  return verifyWhisperRuntimeArtifacts({
    root,
    binaryPath,
    modelPath,
    manifestPath,
    modelName: "tiny.en",
  });
}

function writeManifest(manifestPath: string, binaryPath: string, modelPath: string): void {
  const binary = fileIdentity(binaryPath);
  const model = fileIdentity(modelPath);
  writeFileSync(
    manifestPath,
    `${JSON.stringify({
      schemaVersion: 1,
      kind: "terminalx.whisper-runtime-artifact",
      source: {
        repository: "https://github.com/ggml-org/whisper.cpp.git",
        tag: "v1.8.6",
        commit: "23ee03506a91ac3d3f0071b40e66a430eebdfa1d",
      },
      platform: process.platform,
      architecture: process.arch,
      binary: { kind: "whisper-cli", ...binary },
      model: {
        name: "tiny.en",
        repository: "https://huggingface.co/ggerganov/whisper.cpp",
        revision: "5359861c739e955e79d9a303bcbc70fb988958b1",
        filename: "ggml-tiny.en.bin",
        ...model,
      },
    })}\n`,
    { mode: 0o400 }
  );
  chmodSync(manifestPath, 0o444);
}

function fileIdentity(filename: string): { sha256: string; size: number } {
  const bytes = Buffer.from(filename.endsWith("whisper-cli") ? "trusted binary" : "model fixture");
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: statSync(filename).size,
  };
}

function rewriteManifest(
  filename: string,
  update: (manifest: { model: { sha256: string; size: number } }) => void
): void {
  const manifest = JSON.parse(readFileSync(filename, "utf8")) as {
    model: { sha256: string; size: number };
  };
  update(manifest);
  chmodSync(filename, 0o600);
  writeFileSync(filename, `${JSON.stringify(manifest)}\n`);
  chmodSync(filename, 0o444);
}
