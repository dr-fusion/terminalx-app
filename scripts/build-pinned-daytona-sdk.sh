#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_REPOSITORY="https://github.com/procyon-labs-io/daytona"
readonly DAYTONA_UPSTREAM_BASE_COMMIT="b5a5d9e78d76c8bcf351f2049620250e0f34eea4"
readonly DAYTONA_PRODUCTION_FORK_COMMIT="f9b4dfe428d37f3d956acda4403879516aa8d923"

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <daytona-source-directory> <empty-output-directory>" >&2
  exit 64
fi

SOURCE_DIRECTORY=$(realpath "$1")
OUTPUT_DIRECTORY=$(realpath -m "$2")
SCRIPT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

if [[ ! -d "$SOURCE_DIRECTORY/.git" && ! -f "$SOURCE_DIRECTORY/.git" ]]; then
  echo "Daytona source must be a Git checkout" >&2
  exit 1
fi
if [[ -e "$OUTPUT_DIRECTORY" ]] && [[ -n "$(find "$OUTPUT_DIRECTORY" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Daytona SDK output directory must be empty" >&2
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
  ! git -C "$SOURCE_DIRECTORY" diff --cached --quiet --ignore-submodules --; then
  echo "Daytona source checkout must not contain tracked changes" >&2
  exit 1
fi
if [[ -n "$(git -C "$SOURCE_DIRECTORY" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "Daytona source checkout must not contain untracked or modified files" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIRECTORY"

(
  cd "$SOURCE_DIRECTORY"
  corepack yarn install --immutable
  corepack yarn nx build sdk-typescript --configuration=production
  npm pack ./dist/libs/api-client --pack-destination "$OUTPUT_DIRECTORY" --json >/dev/null
  npm pack ./dist/libs/sdk-typescript --pack-destination "$OUTPUT_DIRECTORY" --json >/dev/null
  npm pack ./dist/libs/toolbox-api-client --pack-destination "$OUTPUT_DIRECTORY" --json >/dev/null
)

node "$SCRIPT_DIRECTORY/write-daytona-sdk-artifact.mjs" \
  "$OUTPUT_DIRECTORY/daytona-sdk-artifact.json" \
  "$OUTPUT_DIRECTORY/daytona-api-client-0.0.0-dev.tgz" \
  "$OUTPUT_DIRECTORY/daytona-sdk-0.0.0-dev.tgz" \
  "$OUTPUT_DIRECTORY/daytona-toolbox-api-client-0.0.0-dev.tgz"

PRODUCTION_COMMIT_SHORT=${DAYTONA_PRODUCTION_FORK_COMMIT:0:12}
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$OUTPUT_DIRECTORY" \
  -cf - \
  daytona-api-client-0.0.0-dev.tgz \
  daytona-sdk-0.0.0-dev.tgz \
  daytona-sdk-artifact.json \
  daytona-toolbox-api-client-0.0.0-dev.tgz \
  | gzip -n >"$OUTPUT_DIRECTORY/daytona-typescript-sdk-$PRODUCTION_COMMIT_SHORT.tar.gz"

(
  cd "$OUTPUT_DIRECTORY"
  sha256sum \
    "daytona-typescript-sdk-$PRODUCTION_COMMIT_SHORT.tar.gz" \
    daytona-api-client-0.0.0-dev.tgz \
    daytona-sdk-0.0.0-dev.tgz \
    daytona-sdk-artifact.json \
    daytona-toolbox-api-client-0.0.0-dev.tgz \
    >checksums.sha256
  sha256sum --check checksums.sha256
)
