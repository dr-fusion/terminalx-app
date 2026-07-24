import * as fs from "fs";
import * as path from "path";
import { execFile } from "child_process";
import { promisify } from "util";

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
  large: "ggml-large.bin",
};

const DEFAULT_MODEL = "tiny.en";
const FFMPEG_TIMEOUT_MS = 60_000;
const WHISPER_TIMEOUT_MS = 120_000;
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

function whisperCppDir(): string {
  return path.join(process.cwd(), "node_modules", "whisper-node", "lib", "whisper.cpp");
}

function whisperMainPath(): string {
  return path.join(whisperCppDir(), process.platform === "win32" ? "main.exe" : "main");
}

function ffmpegPath(): string {
  const explicitPath = process.env.TERMINALX_FFMPEG_PATH?.trim();
  if (explicitPath) return path.resolve(/* turbopackIgnore: true */ explicitPath);
  const platformPackage = FFMPEG_PACKAGES[`${process.platform}:${process.arch}`];
  if (!platformPackage) {
    throw new Error(`unsupported ffmpeg platform: ${process.platform}/${process.arch}`);
  }
  const executable = process.platform === "win32" ? "ffmpeg.exe" : "ffmpeg";
  const binaryPath = path.join(
    process.cwd(),
    "node_modules",
    "@ffmpeg-installer",
    platformPackage,
    executable
  );
  if (!fs.existsSync(/* turbopackIgnore: true */ binaryPath)) {
    throw new Error("ffmpeg binary is missing; run `npm ci` or set TERMINALX_FFMPEG_PATH");
  }
  return binaryPath;
}

function modelPath(): { name: string; path: string } {
  const explicitPath = process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MODEL_PATH?.trim();
  const name = (process.env.TERMINALX_TELEGRAM_TRANSCRIBE_MODEL || DEFAULT_MODEL).trim();
  if (explicitPath) {
    return {
      name: path.basename(explicitPath),
      path: path.resolve(/* turbopackIgnore: true */ explicitPath),
    };
  }
  const filename = MODEL_FILES[name];
  if (!filename) {
    throw new Error(`unsupported transcription model: ${name}`);
  }
  return { name, path: path.join(whisperCppDir(), "models", filename) };
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
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

function commandError(err: unknown): string {
  const e = err as { stderr?: string; stdout?: string; message?: string };
  return (e.stderr || e.stdout || e.message || String(err)).trim();
}

export async function transcribeAudioFile(audioPath: string): Promise<{
  text: string;
  model: string;
  durationMs: number;
}> {
  const startedAt = Date.now();
  const sourcePath = path.resolve(/* turbopackIgnore: true */ audioPath);
  const wavPath = path.join(
    /* turbopackIgnore: true */ path.dirname(sourcePath),
    `${path.basename(sourcePath)}.16k.wav`
  );
  const mainPath = whisperMainPath();
  if (!fs.existsSync(/* turbopackIgnore: true */ mainPath)) {
    throw new Error("voice transcription is not set up; run `npm run setup:whisper -- tiny.en`");
  }

  const model = modelPath();
  if (!fs.existsSync(/* turbopackIgnore: true */ model.path)) {
    throw new Error(
      `transcription model ${model.name} is missing; run \`npm run setup:whisper -- ${model.name}\``
    );
  }

  try {
    await execFileAsync(
      ffmpegPath(),
      ["-y", "-i", sourcePath, "-ar", "16000", "-ac", "1", "-c:a", "pcm_s16le", wavPath],
      { timeout: FFMPEG_TIMEOUT_MS, maxBuffer: 1024 * 1024 }
    );
  } catch (err) {
    throw new Error(`audio conversion failed: ${commandError(err)}`);
  }

  const language = (process.env.TERMINALX_TELEGRAM_TRANSCRIBE_LANGUAGE || "auto").trim();
  const args = ["-m", model.path, "-f", wavPath, "-nt"];
  const shouldPassLanguage = language && (language !== "auto" || !model.name.endsWith(".en"));
  if (shouldPassLanguage) {
    if (!/^[a-zA-Z_-]+$/.test(language)) {
      throw new Error("invalid transcription language");
    }
    args.push("-l", language);
  }

  try {
    const { stdout, stderr } = await execFileAsync(mainPath, args, {
      cwd: whisperCppDir(),
      timeout: WHISPER_TIMEOUT_MS,
      maxBuffer: 4 * 1024 * 1024,
    });
    return {
      text: parseWhisperText(`${stdout}\n${stderr}`),
      model: model.name,
      durationMs: Date.now() - startedAt,
    };
  } catch (err) {
    throw new Error(`voice transcription failed: ${commandError(err)}`);
  } finally {
    try {
      fs.rmSync(/* turbopackIgnore: true */ wavPath, { force: true });
    } catch {
      /* ignore */
    }
  }
}
