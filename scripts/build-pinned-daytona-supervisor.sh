#!/usr/bin/env bash
set -euo pipefail

readonly DAYTONA_UPSTREAM_BASE_COMMIT="b5a5d9e78d76c8bcf351f2049620250e0f34eea4"
readonly DAYTONA_PRODUCTION_FORK_COMMIT="f9b4dfe428d37f3d956acda4403879516aa8d923"

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <terminalx-source-directory> <empty-output-directory>" >&2
  exit 64
fi

SOURCE_DIRECTORY=$(realpath "$1")
OUTPUT_DIRECTORY=$(realpath -m "$2")
SCRIPT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SOURCE_COMMIT=$(git -C "$SOURCE_DIRECTORY" rev-parse --verify HEAD)

if [[ ! -f "$SOURCE_DIRECTORY/packages/daytona-supervisor/tsconfig.build.json" ]]; then
  echo "TerminalX supervisor source is unavailable" >&2
  exit 1
fi
if [[ -e "$OUTPUT_DIRECTORY" ]] && [[ -n "$(find "$OUTPUT_DIRECTORY" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "TerminalX supervisor output directory must be empty" >&2
  exit 1
fi
if ! git -C "$SOURCE_DIRECTORY" diff --quiet --ignore-submodules -- ||
  ! git -C "$SOURCE_DIRECTORY" diff --cached --quiet --ignore-submodules --; then
  echo "TerminalX source checkout must not contain tracked changes" >&2
  exit 1
fi
if [[ -n "$(
  git -C "$SOURCE_DIRECTORY" status --porcelain=v1 --untracked-files=all -- . \
    ':(exclude).daytona-source'
)" ]]; then
  echo "TerminalX source checkout must not contain untracked or modified files" >&2
  exit 1
fi
if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "TerminalX source commit is invalid" >&2
  exit 1
fi

BUILD_DIRECTORY=$(mktemp -d)
cleanup() {
  rm -rf -- "$BUILD_DIRECTORY"
}
trap cleanup EXIT

mkdir -p "$OUTPUT_DIRECTORY" "$BUILD_DIRECTORY/artifact"
chmod 0755 "$BUILD_DIRECTORY/artifact"

(
  cd "$SOURCE_DIRECTORY"
  npx tsc \
    --project packages/daytona-supervisor/tsconfig.build.json \
    --outDir "$BUILD_DIRECTORY/artifact/lib"
)

readonly ESBUILD="$SOURCE_DIRECTORY/node_modules/.bin/esbuild"
if [[ ! -x "$ESBUILD" ]] || [[ "$($ESBUILD --version)" != "0.28.1" ]]; then
  echo "Exact pinned esbuild 0.28.1 is unavailable" >&2
  exit 1
fi
mkdir -p "$BUILD_DIRECTORY/artifact/bin"
chmod 0755 "$BUILD_DIRECTORY/artifact/bin"
"$ESBUILD" "$SOURCE_DIRECTORY/packages/daytona-supervisor/src/daemon.ts" \
  --bundle --platform=node --format=cjs --target=node22 --charset=utf8 \
  --legal-comments=none --log-level=warning \
  --outfile="$BUILD_DIRECTORY/artifact/bin/terminalx-daytona-supervisor"
"$ESBUILD" "$SOURCE_DIRECTORY/packages/daytona-supervisor/src/relay.ts" \
  --bundle --platform=node --format=cjs --target=node22 --charset=utf8 \
  --legal-comments=none --log-level=warning \
  --outfile="$BUILD_DIRECTORY/artifact/bin/terminalx-supervisor-relay"
"$ESBUILD" "$SOURCE_DIRECTORY/packages/daytona-supervisor/src/assignment-bootstrap-daemon.ts" \
  --bundle --platform=node --format=cjs --target=node22 --charset=utf8 \
  --legal-comments=none --log-level=warning \
  --outfile="$BUILD_DIRECTORY/artifact/bin/terminalx-assignment-bootstrap"

install -m 0644 \
  "$SOURCE_DIRECTORY/packages/daytona-supervisor/package.json" \
  "$BUILD_DIRECTORY/artifact/package.json"
install -m 0644 \
  "$SOURCE_DIRECTORY/packages/daytona-supervisor/README.md" \
  "$BUILD_DIRECTORY/artifact/README.md"
install -m 0644 \
  "$SOURCE_DIRECTORY/LICENSE" \
  "$BUILD_DIRECTORY/artifact/LICENSE"
find "$BUILD_DIRECTORY/artifact/lib" -type d -exec chmod 0755 {} +
find "$BUILD_DIRECTORY/artifact/lib" -type f -exec chmod 0644 {} +
readonly SUPERVISOR_ENTRYPOINT="bin/terminalx-daytona-supervisor"
readonly RELAY_ENTRYPOINT="bin/terminalx-supervisor-relay"
readonly BOOTSTRAP_ENTRYPOINT="bin/terminalx-assignment-bootstrap"
for entrypoint in "$SUPERVISOR_ENTRYPOINT" "$RELAY_ENTRYPOINT" "$BOOTSTRAP_ENTRYPOINT"; do
  if [[ ! -f "$BUILD_DIRECTORY/artifact/$entrypoint" ]]; then
    echo "Required TerminalX fixed executable was not emitted: $entrypoint" >&2
    exit 1
  fi
  chmod 0555 "$BUILD_DIRECTORY/artifact/$entrypoint"
done

node "$SCRIPT_DIRECTORY/write-daytona-supervisor-artifact.mjs" \
  "$BUILD_DIRECTORY/artifact/daytona-supervisor-artifact.json" \
  "$BUILD_DIRECTORY/artifact" \
  "$SOURCE_COMMIT" \
  "$DAYTONA_PRODUCTION_FORK_COMMIT"

ARCHIVE="terminalx-daytona-supervisor-${SOURCE_COMMIT:0:12}.tar.gz"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$BUILD_DIRECTORY/artifact" -cf - . | gzip -n >"$OUTPUT_DIRECTORY/$ARCHIVE"
install -m 0644 \
  "$BUILD_DIRECTORY/artifact/daytona-supervisor-artifact.json" \
  "$OUTPUT_DIRECTORY/daytona-supervisor-artifact.json"

(
  cd "$OUTPUT_DIRECTORY"
  sha256sum "$ARCHIVE" daytona-supervisor-artifact.json >checksums.sha256
  sha256sum --check checksums.sha256
)

if ! grep -q "$DAYTONA_UPSTREAM_BASE_COMMIT" "$OUTPUT_DIRECTORY/daytona-supervisor-artifact.json"; then
  echo "Supervisor artifact omitted the exact Daytona base ancestry anchor" >&2
  exit 1
fi
