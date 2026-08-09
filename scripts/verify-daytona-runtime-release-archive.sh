#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <runtime-archive> <checksums.sha256> <new-output-directory>" >&2
  exit 64
fi

export LC_ALL=C
ARCHIVE=$(realpath "$1")
CHECKSUMS=$(realpath "$2")
OUTPUT_DIRECTORY=$(realpath -m "$3")
SCRIPT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
PIN_READER="$SCRIPT_DIRECTORY/read-daytona-production-source.mjs"
DAYTONA_PRODUCTION_FORK_COMMIT=$(node "$PIN_READER" field productionForkCommit)
readonly ARCHIVE CHECKSUMS OUTPUT_DIRECTORY SCRIPT_DIRECTORY PIN_READER
readonly DAYTONA_PRODUCTION_FORK_COMMIT
readonly RUNNER_NAME="daytona-runner-linux-amd64"
readonly DAEMON_NAME="daytona-daemon-linux-amd64"
readonly MANIFEST_NAME="terminalx-daytona-runtime-artifacts.json"
readonly FILE_CHECKSUMS_NAME="runtime-files.sha256"
readonly EXPECTED_ARCHIVE_NAME="terminalx-daytona-runtime-${DAYTONA_PRODUCTION_FORK_COMMIT:0:12}.tar.gz"

fail() {
  echo "TerminalX Daytona runtime release archive verification failed" >&2
  exit 1
}

protected_input() {
  local path=$1
  local maximum_bytes=$2
  local mode links size
  [[ -f "$path" && ! -L "$path" && "$(realpath "$path")" == "$path" ]] || fail
  mode=$(stat -c '%a' "$path")
  links=$(stat -c '%h' "$path")
  size=$(stat -c '%s' "$path")
  [[ "$mode" =~ ^[0-7]{3,4}$ && "$links" == "1" ]] || fail
  [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le "$maximum_bytes" ]] || fail
  (( (8#$mode & 8#022) == 0 )) || fail
}

[[ "$1" == /* && "$ARCHIVE" == "$1" && "$2" == /* && "$CHECKSUMS" == "$2" ]] || fail
protected_input "$ARCHIVE" $((512 * 1024 * 1024))
protected_input "$CHECKSUMS" $((64 * 1024))
[[ "$(basename "$ARCHIVE")" == "$EXPECTED_ARCHIVE_NAME" ]] || fail
[[ "$(basename "$CHECKSUMS")" == "checksums.sha256" ]] || fail
[[ "$3" == /* && "$OUTPUT_DIRECTORY" == "$3" && ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]] || fail

mapfile -t archive_checksum_lines < <(
  awk -v name="$EXPECTED_ARCHIVE_NAME" '$2 == name { print }' "$CHECKSUMS"
)
[[ ${#archive_checksum_lines[@]} -eq 1 ]] || fail
read -r expected_archive_digest checksum_name checksum_extra <<<"${archive_checksum_lines[0]}"
[[ -z "${checksum_extra:-}" && "$checksum_name" == "$EXPECTED_ARCHIVE_NAME" ]] || fail
[[ "$expected_archive_digest" =~ ^[0-9a-f]{64}$ ]] || fail
actual_archive_digest=$(sha256sum "$ARCHIVE")
actual_archive_digest=${actual_archive_digest%% *}
[[ "$actual_archive_digest" == "$expected_archive_digest" ]] || fail

mapfile -t archive_members < <(tar -tzf "$ARCHIVE")
[[ ${#archive_members[@]} -eq 4 ]] || fail
actual_members=$(printf '%s\n' "${archive_members[@]}" | sort)
expected_members=$(printf '%s\n' \
  "$DAEMON_NAME" \
  "$RUNNER_NAME" \
  "$FILE_CHECKSUMS_NAME" \
  "$MANIFEST_NAME")
[[ "$actual_members" == "$expected_members" ]] || fail
while IFS= read -r member; do
  [[ "${member:0:1}" == "-" ]] || fail
done < <(tar -tvzf "$ARCHIVE")

mkdir -m 0700 -- "$OUTPUT_DIRECTORY"
tar --extract --gzip --file "$ARCHIVE" --directory "$OUTPUT_DIRECTORY" --no-same-owner

mapfile -t file_checksum_lines <"$OUTPUT_DIRECTORY/$FILE_CHECKSUMS_NAME"
[[ ${#file_checksum_lines[@]} -eq 3 ]] || fail
expected_files=("$RUNNER_NAME" "$DAEMON_NAME" "$MANIFEST_NAME")
for index in "${!expected_files[@]}"; do
  read -r digest filename extra <<<"${file_checksum_lines[$index]}"
  [[ -z "${extra:-}" && "$filename" == "${expected_files[$index]}" ]] || fail
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail
done
(
  cd "$OUTPUT_DIRECTORY"
  sha256sum --check "$FILE_CHECKSUMS_NAME" >/dev/null
)

for executable in "$RUNNER_NAME" "$DAEMON_NAME"; do
  [[ -f "$OUTPUT_DIRECTORY/$executable" && ! -L "$OUTPUT_DIRECTORY/$executable" ]] || fail
  [[ "$(stat -c '%a' "$OUTPUT_DIRECTORY/$executable")" == "555" ]] || fail
  [[ "$(stat -c '%h' "$OUTPUT_DIRECTORY/$executable")" == "1" ]] || fail
done
for immutable in "$MANIFEST_NAME" "$FILE_CHECKSUMS_NAME"; do
  [[ -f "$OUTPUT_DIRECTORY/$immutable" && ! -L "$OUTPUT_DIRECTORY/$immutable" ]] || fail
  [[ "$(stat -c '%a' "$OUTPUT_DIRECTORY/$immutable")" == "444" ]] || fail
  [[ "$(stat -c '%h' "$OUTPUT_DIRECTORY/$immutable")" == "1" ]] || fail
done

printf 'Verified TerminalX Daytona runtime release archive into %s\n' "$OUTPUT_DIRECTORY"
