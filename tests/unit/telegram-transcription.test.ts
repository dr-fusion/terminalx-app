import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { transcribeAudioFile } from "@/lib/telegram/transcription";

const TEST_MODEL_CONTENTS = "model";

vi.mock("@/lib/telegram/whisper-artifact-trust", () => ({
  verifyWhisperRuntimeArtifacts: async (options: {
    binaryPath: string;
    modelPath: string;
    modelName: string;
  }) => ({
    binaryPath: options.binaryPath,
    modelPath: options.modelPath,
    modelName: options.modelName,
  }),
}));

const ENVIRONMENT_KEYS = [
  "TERMINALX_FFMPEG_PATH",
  "TERMINALX_WHISPER_CPP_ROOT",
  "TERMINALX_WHISPER_CPP_BINARY_PATH",
  "TERMINALX_WHISPER_CPP_RUNTIME_MANIFEST_PATH",
  "TERMINALX_TELEGRAM_TRANSCRIBE_MODEL",
  "TERMINALX_TELEGRAM_TRANSCRIBE_MODEL_PATH",
  "TERMINALX_TELEGRAM_TRANSCRIBE_LANGUAGE",
  "TERMINALX_TELEGRAM_TRANSCRIBE_MAX_CONCURRENCY",
  "TERMINALX_JWT_SECRET",
  "DAYTONA_API_KEY",
  "AWS_SECRET_ACCESS_KEY",
] as const;

describe.skipIf(process.platform === "win32")("Telegram voice transcription", () => {
  let directory: string;
  let toolRoot: string;
  let cliPath: string;
  let ffmpegPath: string;
  let sourcePath: string;
  let originalEnvironment: Record<(typeof ENVIRONMENT_KEYS)[number], string | undefined>;

  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "test");
    originalEnvironment = Object.fromEntries(
      ENVIRONMENT_KEYS.map((key) => [key, process.env[key]])
    ) as Record<(typeof ENVIRONMENT_KEYS)[number], string | undefined>;
    directory = mkdtempSync(join(tmpdir(), "terminalx whisper transcription "));
    toolRoot = join(directory, "tool root");
    cliPath = join(toolRoot, "bin", "whisper-cli");
    ffmpegPath = join(directory, "fake ffmpeg");
    sourcePath = join(directory, "voice;touch should-not-run.ogg");

    mkdirSync(join(toolRoot, "bin"), { recursive: true });
    mkdirSync(join(toolRoot, "models"), { recursive: true });
    writeFileSync(join(toolRoot, "models", "ggml-tiny.en.bin"), TEST_MODEL_CONTENTS);
    chmodSync(join(toolRoot, "models", "ggml-tiny.en.bin"), 0o444);
    writeFileSync(sourcePath, "audio");
    writeExecutable(
      ffmpegPath,
      '#!/bin/sh\nset -eu\nfor arg in "$@"; do output="$arg"; done\n: > "$output"\n'
    );
    writeExecutable(
      cliPath,
      "#!/bin/sh\nprintf '%s\\n' \"diagnostic path: $PWD\" >&2\nprintf '%s\\n' '[00:00.000 --> 00:01.000] hello secure world'\n"
    );
    process.env.TERMINALX_WHISPER_CPP_ROOT = toolRoot;
    process.env.TERMINALX_FFMPEG_PATH = ffmpegPath;
    process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MODEL = "tiny.en";
    process.env.TERMINALX_TELEGRAM_TRANSCRIBE_LANGUAGE = "auto";
    delete process.env.TERMINALX_WHISPER_CPP_BINARY_PATH;
    delete process.env.TERMINALX_WHISPER_CPP_RUNTIME_MANIFEST_PATH;
    delete process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MODEL_PATH;
    process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MAX_CONCURRENCY = "1";
    delete process.env.TERMINALX_JWT_SECRET;
    delete process.env.DAYTONA_API_KEY;
    delete process.env.AWS_SECRET_ACCESS_KEY;
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    for (const key of ENVIRONMENT_KEYS) {
      const value = originalEnvironment[key];
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    vi.unstubAllEnvs();
    rmSync(directory, { force: true, recursive: true });
  });

  it("uses the configured tool root without interpolating audio paths into a shell", async () => {
    const result = await transcribeAudioFile(sourcePath);

    expect(result.text).toBe("hello secure world");
    expect(result.model).toBe("tiny.en");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(existsSync(join(directory, "should-not-run.ogg"))).toBe(false);
    expect(existsSync(`${sourcePath}.16k.wav`)).toBe(false);
  });

  it("honors separately managed binary and model paths", async () => {
    const managedDirectory = join(toolRoot, "managed");
    mkdirSync(managedDirectory);
    const externalBinary = join(managedDirectory, "managed whisper-cli");
    const externalModel = join(managedDirectory, "managed model.bin");
    writeExecutable(
      externalBinary,
      "#!/bin/sh\nprintf '%s\\n' '[00:00.000 --> 00:01.000] managed artifacts'\n"
    );
    writeFileSync(externalModel, TEST_MODEL_CONTENTS);
    chmodSync(externalModel, 0o444);
    process.env.TERMINALX_WHISPER_CPP_BINARY_PATH = externalBinary;
    process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MODEL_PATH = externalModel;

    const result = await transcribeAudioFile(sourcePath);

    expect(result.text).toBe("managed artifacts");
    expect(result.model).toBe("tiny.en");
  });

  it("does not expose native conversion errors or local paths", async () => {
    writeExecutable(
      ffmpegPath,
      `#!/bin/sh\nprintf '%s\\n' 'private failure at ${directory}' >&2\nexit 9\n`
    );

    const error = await captureError(transcribeAudioFile(sourcePath));

    expect(error.message).toBe("audio conversion failed");
    expect(error.message).not.toContain(directory);
  });

  it("requires an explicit operator-managed ffmpeg path in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    delete process.env.TERMINALX_FFMPEG_PATH;

    const error = await captureError(transcribeAudioFile(sourcePath));

    expect(error.message).toBe("audio conversion is not set up with a protected ffmpeg executable");
    expect(error.message).not.toContain("@ffmpeg-installer");
  });

  it("does not expose temporary-directory creation failures or local paths", async () => {
    const readOnlyDirectory = join(directory, "read-only-source");
    mkdirSync(readOnlyDirectory);
    sourcePath = join(readOnlyDirectory, "voice.ogg");
    writeFileSync(sourcePath, "audio");
    chmodSync(readOnlyDirectory, 0o555);

    const error = await captureError(transcribeAudioFile(sourcePath));
    chmodSync(readOnlyDirectory, 0o755);

    expect(error.message).toBe("audio conversion failed");
    expect(error.message).not.toContain(readOnlyDirectory);
  });

  it("does not expose whisper errors or local paths", async () => {
    writeExecutable(
      cliPath,
      `#!/bin/sh\nprintf '%s\\n' 'private failure at ${directory}' >&2\nexit 9\n`
    );

    const error = await captureError(transcribeAudioFile(sourcePath));

    expect(error.message).toBe("voice transcription failed");
    expect(error.message).not.toContain(directory);
    expect(existsSync(`${sourcePath}.16k.wav`)).toBe(false);
  });

  it("rejects invalid language input before invoking native tools", async () => {
    const invokedMarker = join(directory, "ffmpeg-invoked");
    writeExecutable(ffmpegPath, `#!/bin/sh\n: > '${invokedMarker}'\n`);
    process.env.TERMINALX_TELEGRAM_TRANSCRIBE_LANGUAGE = "en; touch injected";

    const error = await captureError(transcribeAudioFile(sourcePath));

    expect(error.message).toBe("invalid transcription language");
    expect(existsSync(invokedMarker)).toBe(false);
  });

  it("does not pass server secrets to either native process", async () => {
    process.env.TERMINALX_JWT_SECRET = "jwt-private";
    process.env.DAYTONA_API_KEY = "daytona-private";
    process.env.AWS_SECRET_ACCESS_KEY = "aws-private";
    const secretCheck = [
      "#!/bin/sh",
      'if [ -n "${TERMINALX_JWT_SECRET+x}" ] || [ -n "${DAYTONA_API_KEY+x}" ] || [ -n "${AWS_SECRET_ACCESS_KEY+x}" ]; then',
      '  printf "%s\\n" "secret leaked" >&2',
      "  exit 90",
      "fi",
    ].join("\n");
    writeExecutable(
      ffmpegPath,
      `${secretCheck}\nfor arg in "$@"; do output="$arg"; done\n: > "$output"\n`
    );
    writeExecutable(
      cliPath,
      `${secretCheck}\nprintf '%s\\n' '[00:00.000 --> 00:01.000] no secrets'\n`
    );

    await expect(transcribeAudioFile(sourcePath)).resolves.toMatchObject({ text: "no secrets" });
  });

  it("fails fast when the process-wide transcription capacity is occupied", async () => {
    const startedMarker = join(directory, "ffmpeg-started");
    const releaseMarker = join(directory, "ffmpeg-release");
    writeExecutable(
      ffmpegPath,
      `#!/bin/sh\nfor arg in "$@"; do output="$arg"; done\n: > "${startedMarker}"\nwhile [ ! -f "${releaseMarker}" ]; do :; done\n: > "$output"\n`
    );

    const first = transcribeAudioFile(sourcePath);
    await waitForFile(startedMarker);
    const secondError = await captureError(transcribeAudioFile(sourcePath));
    writeFileSync(releaseMarker, "release");

    expect(secondError.message).toBe("voice transcription is busy; try again later");
    await expect(first).resolves.toMatchObject({ text: "hello secure world" });
  });

  it("rejects oversized source audio before invoking native tools", async () => {
    const invokedMarker = join(directory, "ffmpeg-invoked");
    writeExecutable(ffmpegPath, `#!/bin/sh\n: > '${invokedMarker}'\n`);
    truncateSync(sourcePath, 50 * 1024 * 1024 + 1);

    const error = await captureError(transcribeAudioFile(sourcePath));

    expect(error.message).toBe("audio source exceeds the 50 MiB transcription limit");
    expect(existsSync(invokedMarker)).toBe(false);
  });
});

function writeExecutable(filename: string, contents: string): void {
  if (existsSync(filename)) chmodSync(filename, 0o700);
  writeFileSync(filename, contents, { mode: 0o700 });
  chmodSync(filename, 0o555);
}

async function waitForFile(filename: string): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!existsSync(filename)) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for native test process");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function captureError(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected promise to reject");
}
