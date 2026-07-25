import * as fs from "node:fs";
import * as path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { verifyWhisperRuntimeArtifacts } from "./whisper-artifact-trust";

const execFileAsync = promisify(execFile);

const MODEL_FILES: Record<string, string> = {
  tiny: "ggml-tiny.bin",
  "tiny.en": "ggml-tiny.en.bin",
  base: "ggml-base.bin",
  "base.en": "ggml-base.en.bin",
  small: "ggml-small.bin",
  "small.en": "ggml-small.en.bin",
  medium: "ggml-medium.bin",
  "medium.en": "ggml-medium.en.bin",
  "large-v1": "ggml-large-v1.bin",
  "large-v2": "ggml-large-v2.bin",
  "large-v3": "ggml-large-v3.bin",
  "large-v3-turbo": "ggml-large-v3-turbo.bin",
};

const DEFAULT_MODEL = "tiny.en";
const MAX_AUDIO_BYTES = 50 * 1024 * 1024;
const MAX_AUDIO_DURATION_SECONDS = 10 * 60;
const FFMPEG_TIMEOUT_MS = 60_000;
const WHISPER_TIMEOUT_MS = 120_000;
const FFMPEG_MAX_OUTPUT_BYTES = 1024 * 1024;
const WHISPER_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_CONFIGURED_CONCURRENCY = 4;
const FFMPEG_PACKAGES: Record<string, string> = {
  "darwin:arm64": "darwin-arm64",
  "darwin:x64": "darwin-x64",
  "linux:arm": "linux-arm",
  "linux:arm64": "linux-arm64",
  "linux:ia32": "linux-ia32",
  "linux:x64": "linux-x64",
  "win32:ia32": "win32-ia32",
  "win32:x64": "win32-x64",
};
const SAFE_NATIVE_ENVIRONMENT_KEYS = [
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "TMPDIR",
  "TEMP",
  "TMP",
  "SystemRoot",
  "SYSTEMROOT",
  "WINDIR",
] as const;

let activeTranscriptions = 0;

function whisperCppRoot(): string {
  const explicitRoot = process.env.TERMINALX_WHISPER_CPP_ROOT?.trim();
  return path.resolve(
    /* turbopackIgnore: true */ explicitRoot ||
      path.join(process.cwd(), "data", "tools", "whisper.cpp")
  );
}

function whisperCliPath(root: string): string {
  const explicitPath = process.env.TERMINALX_WHISPER_CPP_BINARY_PATH?.trim();
  if (explicitPath) return path.resolve(/* turbopackIgnore: true */ explicitPath);
  return path.join(root, "bin", process.platform === "win32" ? "whisper-cli.exe" : "whisper-cli");
}

function whisperRuntimeManifestPath(root: string): string {
  const explicitPath = process.env.TERMINALX_WHISPER_CPP_RUNTIME_MANIFEST_PATH?.trim();
  return path.resolve(
    /* turbopackIgnore: true */ explicitPath || path.join(root, "runtime-manifest.json")
  );
}

function ffmpegPath(): string {
  const explicitPath = process.env.TERMINALX_FFMPEG_PATH?.trim();
  if (explicitPath) return path.resolve(/* turbopackIgnore: true */ explicitPath);
  if (process.env.NODE_ENV === "production") {
    throw new Error("production requires an explicit ffmpeg path");
  }
  const platformPackage = FFMPEG_PACKAGES[`${process.platform}:${process.arch}`];
  if (!platformPackage) {
    throw new Error(`unsupported ffmpeg platform: ${process.platform}/${process.arch}`);
  }
  const executable = process.platform === "win32" ? "ffmpeg.exe" : "ffmpeg";
  return path.join(process.cwd(), "node_modules", "@ffmpeg-installer", platformPackage, executable);
}

function modelPath(root: string): { name: string; path: string } {
  const explicitPath = process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MODEL_PATH?.trim();
  const name = (process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MODEL || DEFAULT_MODEL).trim();
  const filename = MODEL_FILES[name];
  if (!filename) throw new Error("unsupported transcription model");
  return {
    name,
    path: explicitPath
      ? path.resolve(/* turbopackIgnore: true */ explicitPath)
      : path.join(root, "models", filename),
  };
}

function parseWhisperText(output: string): string {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/^\[[^\]]+\]\s*/, ""))
    .filter((line) => {
      if (!line) return false;
      return !(
        line.startsWith("whisper_") ||
        line.startsWith("ggml_") ||
        line.startsWith("system_info:") ||
        line.startsWith("main:") ||
        line.startsWith("common_init_")
      );
    })
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

function commandFailure(
  operation: "audio conversion" | "voice transcription",
  err: unknown
): Error {
  const failure = err as { killed?: boolean; code?: string; signal?: string };
  const timedOut =
    failure?.killed === true ||
    failure?.code === "ETIMEDOUT" ||
    failure?.signal === "SIGTERM" ||
    failure?.signal === "SIGKILL";
  return new Error(`${operation} ${timedOut ? "timed out" : "failed"}`);
}

function nativeToolEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = Object.create(null) as NodeJS.ProcessEnv;
  for (const key of SAFE_NATIVE_ENVIRONMENT_KEYS) {
    const value = process.env[key];
    if (value !== undefined) environment[key] = value;
  }
  return environment;
}

function assertProtectedExecutable(filename: string): string {
  const resolved = path.resolve(/* turbopackIgnore: true */ filename);
  const stat = fs.lstatSync(/* turbopackIgnore: true */ resolved);
  const real = path.resolve(/* turbopackIgnore: true */ fs.realpathSync.native(resolved));
  const pathsMatch =
    process.platform === "win32"
      ? real.toLowerCase() === resolved.toLowerCase()
      : real === resolved;
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    !pathsMatch ||
    (process.platform !== "win32" && ((stat.mode & 0o002) !== 0 || (stat.mode & 0o111) === 0))
  ) {
    throw new Error("native audio converter is not protected");
  }
  if (process.env.NODE_ENV === "production") {
    if (
      process.platform === "win32" ||
      process.geteuid?.() === 0 ||
      stat.uid !== 0 ||
      (stat.mode & 0o022) !== 0
    ) {
      throw new Error("production audio converter must be root-owned and protected");
    }
    let current = path.dirname(resolved);
    for (;;) {
      const directory = fs.lstatSync(current);
      if (
        !directory.isDirectory() ||
        directory.isSymbolicLink() ||
        directory.uid !== 0 ||
        (directory.mode & 0o022) !== 0 ||
        fs.realpathSync.native(current) !== current
      ) {
        throw new Error("production audio converter directory is not protected");
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  return resolved;
}

function inspectAudioSource(filename: string): string {
  const resolved = path.resolve(/* turbopackIgnore: true */ filename);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(/* turbopackIgnore: true */ resolved);
  } catch {
    throw new Error("audio source is missing");
  }
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("audio source is unsafe");
  if (stat.size > MAX_AUDIO_BYTES) {
    throw new Error("audio source exceeds the 50 MiB transcription limit");
  }
  return resolved;
}

function configuredConcurrency(): number {
  const raw = process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MAX_CONCURRENCY?.trim();
  if (!raw) return 1;
  if (!/^[1-9]\d*$/.test(raw)) throw new Error("invalid transcription concurrency limit");
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed > MAX_CONFIGURED_CONCURRENCY) {
    throw new Error(
      `transcription concurrency limit must be between 1 and ${MAX_CONFIGURED_CONCURRENCY}`
    );
  }
  return parsed;
}

function acquireTranscriptionSlot(): () => void {
  if (activeTranscriptions >= configuredConcurrency()) {
    throw new Error("voice transcription is busy; try again later");
  }
  activeTranscriptions += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeTranscriptions -= 1;
  };
}

export async function transcribeAudioFile(audioPath: string): Promise<{
  text: string;
  model: string;
  durationMs: number;
}> {
  const release = acquireTranscriptionSlot();
  const startedAt = Date.now();
  let conversionDirectory: string | undefined;
  try {
    const sourcePath = inspectAudioSource(audioPath);
    const root = whisperCppRoot();
    const configuredModel = modelPath(root);
    let artifacts;
    try {
      artifacts = await verifyWhisperRuntimeArtifacts({
        root,
        binaryPath: whisperCliPath(root),
        modelPath: configuredModel.path,
        manifestPath: whisperRuntimeManifestPath(root),
        modelName: configuredModel.name,
      });
    } catch {
      throw new Error("voice transcription artifacts are not trusted");
    }

    const language = (process.env.TERMINALX_TELEGRAM_TRANSCRIBE_LANGUAGE || "auto").trim();
    const shouldPassLanguage =
      Boolean(language) && (language !== "auto" || !artifacts.modelName.endsWith(".en"));
    if (shouldPassLanguage && !/^[a-zA-Z_-]+$/.test(language)) {
      throw new Error("invalid transcription language");
    }

    let converterPath: string;
    try {
      converterPath = assertProtectedExecutable(ffmpegPath());
    } catch {
      throw new Error("audio conversion is not set up with a protected ffmpeg executable");
    }

    try {
      conversionDirectory = fs.mkdtempSync(
        /* turbopackIgnore: true */ path.join(path.dirname(sourcePath), ".terminalx-whisper-")
      );
    } catch {
      throw new Error("audio conversion failed");
    }
    const wavPath = path.join(conversionDirectory, "audio.16k.wav");
    const childEnvironment = nativeToolEnvironment();
    const killSignal = process.platform === "win32" ? "SIGTERM" : "SIGKILL";

    try {
      await execFileAsync(
        converterPath,
        [
          "-nostdin",
          "-hide_banner",
          "-loglevel",
          "error",
          "-y",
          "-i",
          sourcePath,
          "-t",
          String(MAX_AUDIO_DURATION_SECONDS),
          "-ar",
          "16000",
          "-ac",
          "1",
          "-c:a",
          "pcm_s16le",
          wavPath,
        ],
        {
          encoding: "utf8",
          env: childEnvironment,
          killSignal,
          maxBuffer: FFMPEG_MAX_OUTPUT_BYTES,
          shell: false,
          timeout: FFMPEG_TIMEOUT_MS,
          windowsHide: true,
        }
      );
    } catch (err) {
      throw commandFailure("audio conversion", err);
    }

    const args = ["-m", artifacts.modelPath, "-f", wavPath, "-nt", "-t", "4", "-p", "1"];
    if (shouldPassLanguage) args.push("-l", language);

    let stdout: string;
    try {
      ({ stdout } = await execFileAsync(artifacts.binaryPath, args, {
        encoding: "utf8",
        env: childEnvironment,
        killSignal,
        maxBuffer: WHISPER_MAX_OUTPUT_BYTES,
        shell: false,
        timeout: WHISPER_TIMEOUT_MS,
        windowsHide: true,
      }));
    } catch (err) {
      throw commandFailure("voice transcription", err);
    }

    return {
      text: parseWhisperText(stdout),
      model: artifacts.modelName,
      durationMs: Date.now() - startedAt,
    };
  } finally {
    if (conversionDirectory) {
      try {
        fs.rmSync(/* turbopackIgnore: true */ conversionDirectory, {
          force: true,
          recursive: true,
        });
      } catch {
        /* ignore */
      }
    }
    release();
  }
}
