#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <daytona-source-directory> <empty-output-directory>" >&2
  exit 64
fi

SOURCE_DIRECTORY=$(realpath "$1")
OUTPUT_DIRECTORY=$(realpath -m "$2")
SCRIPT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
PIN_READER="$SCRIPT_DIRECTORY/read-daytona-production-source.mjs"
EXPECTED_REPOSITORY=$(node "$PIN_READER" field forkRepository)
DAYTONA_UPSTREAM_BASE_COMMIT=$(node "$PIN_READER" field upstreamBaseCommit)
DAYTONA_PRODUCTION_FORK_COMMIT=$(node "$PIN_READER" field productionForkCommit)
readonly SOURCE_DIRECTORY OUTPUT_DIRECTORY SCRIPT_DIRECTORY PIN_READER EXPECTED_REPOSITORY
readonly DAYTONA_UPSTREAM_BASE_COMMIT DAYTONA_PRODUCTION_FORK_COMMIT

if [[ ! -d "$SOURCE_DIRECTORY/.git" || -L "$SOURCE_DIRECTORY/.git" ]]; then
  echo "Daytona source must be a standalone Git checkout, not a linked worktree" >&2
  exit 1
fi
if [[ -e "$OUTPUT_DIRECTORY" ]] && [[ -n "$(find "$OUTPUT_DIRECTORY" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Daytona runtime output directory must be empty" >&2
  exit 1
fi

ACTUAL_COMMIT=$(git -C "$SOURCE_DIRECTORY" rev-parse --verify HEAD)
ACTUAL_REPOSITORY=$(git -C "$SOURCE_DIRECTORY" remote get-url origin)
ACTUAL_REPOSITORY=${ACTUAL_REPOSITORY%.git}
if [[ "$ACTUAL_COMMIT" != "$DAYTONA_PRODUCTION_FORK_COMMIT" || "$ACTUAL_REPOSITORY" != "$EXPECTED_REPOSITORY" ]]; then
  echo "Daytona source pin does not match the TerminalX production baseline" >&2
  exit 1
fi
if ! git -C "$SOURCE_DIRECTORY" merge-base --is-ancestor \
  "$DAYTONA_UPSTREAM_BASE_COMMIT" "$DAYTONA_PRODUCTION_FORK_COMMIT"; then
  echo "Daytona production commit does not descend from the reviewed upstream base" >&2
  exit 1
fi
if ! git -C "$SOURCE_DIRECTORY" diff --quiet --ignore-submodules -- ||
  ! git -C "$SOURCE_DIRECTORY" diff --cached --quiet --ignore-submodules -- ||
  [[ -n "$(git -C "$SOURCE_DIRECTORY" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "Daytona source checkout must be exact and clean" >&2
  exit 1
fi

BUILD_DIRECTORY=$(mktemp -d)
cleanup() {
  rm -rf -- "$BUILD_DIRECTORY"
}
trap cleanup EXIT

umask 022
mkdir -p "$OUTPUT_DIRECTORY" "$BUILD_DIRECTORY/rebuild"
readonly RUNNER_NAME="daytona-runner-linux-amd64"
readonly DAEMON_NAME="daytona-daemon-linux-amd64"
readonly MANIFEST_NAME="terminalx-daytona-runtime-artifacts.json"
readonly FILE_CHECKSUMS_NAME="runtime-files.sha256"
readonly ARCHIVE_NAME="terminalx-daytona-runtime-${DAYTONA_PRODUCTION_FORK_COMMIT:0:12}.tar.gz"

build_runtime() {
  local destination=$1
  local build_identity=$2
  mkdir -p "$destination"
  (
    cd "$SOURCE_DIRECTORY/apps/runner"
    GOCACHE="$BUILD_DIRECTORY/go-cache-runner-$build_identity" \
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=true -trimpath \
      -o "$destination/$RUNNER_NAME" ./cmd/runner
  )
  (
    cd "$SOURCE_DIRECTORY"
    GOCACHE="$BUILD_DIRECTORY/go-cache-daemon-$build_identity" \
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=true -trimpath \
      -o "$destination/$DAEMON_NAME" ./apps/daemon/cmd/daemon
  )
}

build_runtime "$OUTPUT_DIRECTORY" first
build_runtime "$BUILD_DIRECTORY/rebuild" second
cmp "$OUTPUT_DIRECTORY/$RUNNER_NAME" "$BUILD_DIRECTORY/rebuild/$RUNNER_NAME"
cmp "$OUTPUT_DIRECTORY/$DAEMON_NAME" "$BUILD_DIRECTORY/rebuild/$DAEMON_NAME"

(
  cd "$SOURCE_DIRECTORY"
  go run ./apps/runner/cmd/terminalx-artifact-manifest \
    -runner "$OUTPUT_DIRECTORY/$RUNNER_NAME" \
    -daemon "$OUTPUT_DIRECTORY/$DAEMON_NAME" \
    -expected-source-commit "$DAYTONA_PRODUCTION_FORK_COMMIT"
) >"$OUTPUT_DIRECTORY/$MANIFEST_NAME"

chmod 0555 "$OUTPUT_DIRECTORY/$RUNNER_NAME" "$OUTPUT_DIRECTORY/$DAEMON_NAME"
chmod 0444 "$OUTPUT_DIRECTORY/$MANIFEST_NAME"
(
  cd "$OUTPUT_DIRECTORY"
  sha256sum "$RUNNER_NAME" "$DAEMON_NAME" "$MANIFEST_NAME" >"$FILE_CHECKSUMS_NAME"
  chmod 0444 "$FILE_CHECKSUMS_NAME"
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -cf - \
    "$RUNNER_NAME" \
    "$DAEMON_NAME" \
    "$MANIFEST_NAME" \
    "$FILE_CHECKSUMS_NAME" \
    | gzip -n >"$ARCHIVE_NAME"
  chmod 0444 "$ARCHIVE_NAME"
  sha256sum \
    "$RUNNER_NAME" \
    "$DAEMON_NAME" \
    "$MANIFEST_NAME" \
    "$FILE_CHECKSUMS_NAME" \
    "$ARCHIVE_NAME" \
    >checksums.sha256
  sha256sum --check checksums.sha256
)
