#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$APP_ROOT"

MODEL="${1:-tiny.en}"
REQUESTED_WHISPER_ROOT="${TERMINALX_WHISPER_CPP_ROOT:-$APP_ROOT/data/tools/whisper.cpp}"
ARTIFACT_TOOL="$APP_ROOT/scripts/whisper-artifacts.mjs"

case "$REQUESTED_WHISPER_ROOT" in
  /*) ;;
  *) REQUESTED_WHISPER_ROOT="$APP_ROOT/$REQUESTED_WHISPER_ROOT" ;;
esac

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

need_cmd bash
need_cmd cmake
need_cmd curl
need_cmd git
need_cmd install
need_cmd node

if [ "$EUID" -eq 0 ]; then
  echo "Refusing to build whisper.cpp as root. Build as an unprivileged user, then promote the verified artifacts with root-owned install commands from README.md." >&2
  exit 1
fi

case "$MODEL" in
  tiny | tiny.en | base | base.en | small | small.en | medium | medium.en | large-v1 | large-v2 | large-v3 | large-v3-turbo) ;;
  *)
    echo "Unsupported whisper.cpp model. Choose a model documented in .env.example." >&2
    exit 1
    ;;
esac

if [ -L "$REQUESTED_WHISPER_ROOT" ]; then
  echo "whisper.cpp tool root must not be a symbolic link." >&2
  exit 1
fi
mkdir -p "$REQUESTED_WHISPER_ROOT"
WHISPER_ROOT="$(cd "$REQUESTED_WHISPER_ROOT" && pwd -P)"
if [ "$WHISPER_ROOT" != "$REQUESTED_WHISPER_ROOT" ]; then
  echo "whisper.cpp tool root must use its canonical path without symbolic-link parents." >&2
  exit 1
fi

IFS=$'\t' read -r \
  WHISPER_UPSTREAM \
  WHISPER_TAG \
  WHISPER_COMMIT \
  MODEL_REPOSITORY \
  MODEL_REVISION \
  MODEL_FILENAME \
  MODEL_SHA256 \
  MODEL_SIZE \
  MODEL_URL \
  <<< "$(node "$ARTIFACT_TOOL" model "$MODEL")"

if [ -z "$WHISPER_UPSTREAM" ] || [ -z "$MODEL_URL" ]; then
  echo "Unable to load the canonical Whisper artifact configuration." >&2
  exit 1
fi

MODELS_DIR="$WHISPER_ROOT/models"
BIN_DIR="$WHISPER_ROOT/bin"
MODEL_PATH="$MODELS_DIR/$MODEL_FILENAME"
RUNTIME_MANIFEST="$WHISPER_ROOT/runtime-manifest.json"
case "$(node -p 'process.platform')" in
  win32) WHISPER_BINARY="$BIN_DIR/whisper-cli.exe" ;;
  *) WHISPER_BINARY="$BIN_DIR/whisper-cli" ;;
esac

if [ -L "$MODELS_DIR" ] || [ -L "$BIN_DIR" ]; then
  echo "whisper.cpp model and binary directories must not be symbolic links." >&2
  exit 1
fi
mkdir -p "$MODELS_DIR" "$BIN_DIR"
chmod go-w "$WHISPER_ROOT" "$MODELS_DIR" "$BIN_DIR"

MODEL_TEMP=""
BINARY_TEMP=""
MANIFEST_TEMP=""
STAGE_DIR=""
cleanup() {
  if [ -n "$MODEL_TEMP" ] && [ -e "$MODEL_TEMP" ]; then rm -f -- "$MODEL_TEMP"; fi
  if [ -n "$BINARY_TEMP" ] && [ -e "$BINARY_TEMP" ]; then rm -f -- "$BINARY_TEMP"; fi
  if [ -n "$MANIFEST_TEMP" ] && [ -e "$MANIFEST_TEMP" ]; then rm -f -- "$MANIFEST_TEMP"; fi
  if [ -n "$STAGE_DIR" ] && [ -d "$STAGE_DIR" ]; then rm -rf -- "$STAGE_DIR"; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

model_is_trusted=0
if [ -e "$MODEL_PATH" ]; then
  if [ -L "$MODEL_PATH" ]; then
    echo "Existing whisper.cpp model must not be a symbolic link." >&2
    exit 1
  fi
  if node "$ARTIFACT_TOOL" verify-file "$MODEL_PATH" "$MODEL_SHA256" "$MODEL_SIZE"; then
    model_is_trusted=1
    chmod 0444 "$MODEL_PATH"
    echo "Verified existing immutable whisper.cpp model: $MODEL"
  else
    echo "Existing whisper.cpp model failed its pinned digest; downloading a verified replacement." >&2
  fi
fi

if [ "$model_is_trusted" -eq 0 ]; then
  MODEL_TEMP="$(mktemp "$MODELS_DIR/.$MODEL_FILENAME.download.XXXXXX")"
  echo "Downloading pinned whisper.cpp model: $MODEL"
  curl \
    --fail \
    --location \
    --proto '=https' \
    --tlsv1.2 \
    --retry 3 \
    --retry-all-errors \
    --connect-timeout 30 \
    --max-time 7200 \
    --output "$MODEL_TEMP" \
    "$MODEL_URL"
  node "$ARTIFACT_TOOL" verify-file "$MODEL_TEMP" "$MODEL_SHA256" "$MODEL_SIZE"
  chmod 0444 "$MODEL_TEMP"
  mv -f -- "$MODEL_TEMP" "$MODEL_PATH"
  MODEL_TEMP=""
fi

STAGE_DIR="$(mktemp -d "$WHISPER_ROOT/.install.XXXXXX")"
SOURCE_DIR="$STAGE_DIR/source"
BUILD_DIR="$STAGE_DIR/build"

pinned_git() {
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git \
    -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null \
    -c protocol.file.allow=never \
    "$@"
}

verify_source_checkout() {
  local actual_origin actual_revision dirty_state

  if [ -L "$SOURCE_DIR" ] || [ ! -d "$SOURCE_DIR/.git" ]; then
    echo "Fresh whisper.cpp source checkout is missing or unsafe." >&2
    exit 1
  fi
  actual_origin="$(pinned_git -C "$SOURCE_DIR" remote get-url origin 2>/dev/null || true)"
  if [ "$actual_origin" != "$WHISPER_UPSTREAM" ]; then
    echo "whisper.cpp source origin does not match the pinned official upstream." >&2
    exit 1
  fi
  actual_revision="$(pinned_git -C "$SOURCE_DIR" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)"
  if [ "$actual_revision" != "$WHISPER_COMMIT" ]; then
    echo "whisper.cpp source revision does not match the pinned release." >&2
    exit 1
  fi
  if ! dirty_state="$(pinned_git -C "$SOURCE_DIR" status --porcelain --untracked-files=normal 2>/dev/null)"; then
    echo "Unable to verify the whisper.cpp source checkout state." >&2
    exit 1
  fi
  if [ -n "$dirty_state" ]; then
    echo "whisper.cpp source checkout changed during the build." >&2
    exit 1
  fi
}

echo "Cloning official whisper.cpp $WHISPER_TAG at its pinned revision into a fresh build stage"
pinned_git clone \
  --depth 1 \
  --branch "$WHISPER_TAG" \
  --single-branch \
  "$WHISPER_UPSTREAM" \
  "$SOURCE_DIR"
verify_source_checkout

echo "Building a fresh static whisper.cpp CLI"
cmake \
  -S "$SOURCE_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DGGML_CCACHE=OFF \
  -DWHISPER_BUILD_EXAMPLES=ON \
  -DWHISPER_BUILD_SERVER=OFF \
  -DWHISPER_BUILD_TESTS=OFF
cmake --build "$BUILD_DIR" --config Release --target whisper-cli --parallel
verify_source_checkout

BUILD_BINARY="$BUILD_DIR/bin/whisper-cli"
if [ "$(node -p 'process.platform')" = "win32" ]; then
  if [ -f "$BUILD_DIR/bin/Release/whisper-cli.exe" ]; then
    BUILD_BINARY="$BUILD_DIR/bin/Release/whisper-cli.exe"
  else
    BUILD_BINARY="$BUILD_DIR/bin/whisper-cli.exe"
  fi
fi
if [ -L "$BUILD_BINARY" ] || [ ! -f "$BUILD_BINARY" ] || [ ! -x "$BUILD_BINARY" ]; then
  echo "whisper.cpp build did not produce the expected executable." >&2
  exit 1
fi

BINARY_TEMP="$(mktemp "$BIN_DIR/.whisper-cli.install.XXXXXX")"
install -m 0555 "$BUILD_BINARY" "$BINARY_TEMP"
MANIFEST_TEMP="$(mktemp "$WHISPER_ROOT/.runtime-manifest.install.XXXXXX")"
node "$ARTIFACT_TOOL" \
  write-runtime-manifest \
  "$MANIFEST_TEMP" \
  "$MODEL" \
  "$BINARY_TEMP" \
  "$MODEL_PATH"

mv -f -- "$BINARY_TEMP" "$WHISPER_BINARY"
BINARY_TEMP=""
mv -f -- "$MANIFEST_TEMP" "$RUNTIME_MANIFEST"
MANIFEST_TEMP=""

echo "Whisper transcription is ready with pinned $WHISPER_TAG and model: $MODEL"
echo "Runtime manifest: $RUNTIME_MANIFEST"
