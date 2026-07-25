#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <absolute-build-config.json> <new-output-directory>" >&2
  exit 64
fi

readonly SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly CONFIGURATION_FILE="$1"
readonly OUTPUT_DIRECTORY="$2"

if [[ "$CONFIGURATION_FILE" != /* ]] || [[ "$OUTPUT_DIRECTORY" != /* ]]; then
  echo "TerminalX sandbox build paths must be absolute" >&2
  exit 64
fi
if [[ ! -f "$CONFIGURATION_FILE" ]] || [[ -L "$CONFIGURATION_FILE" ]]; then
  echo "TerminalX sandbox build configuration is unavailable" >&2
  exit 1
fi
if [[ -e "$OUTPUT_DIRECTORY" ]]; then
  echo "TerminalX sandbox image output must not already exist" >&2
  exit 1
fi
for command_name in cut docker id install mkdir mktemp mv node realpath sha256sum stat tar tr; do
  if ! command -v "$command_name" >/dev/null; then
    echo "Required sandbox image build tool is unavailable" >&2
    exit 1
  fi
done
if ! docker buildx version >/dev/null 2>&1; then
  echo "Docker Buildx with attestations is required" >&2
  exit 1
fi
if [[ "$(realpath -m "$OUTPUT_DIRECTORY")" != "$OUTPUT_DIRECTORY" ]] ||
  [[ ! -d "$(dirname "$OUTPUT_DIRECTORY")" ]] ||
  [[ "$(realpath "$(dirname "$OUTPUT_DIRECTORY")")" != "$(dirname "$OUTPUT_DIRECTORY")" ]]; then
  echo "TerminalX sandbox output path must have a canonical existing parent" >&2
  exit 1
fi

BUILD_ROOT="$(mktemp -d)"
STAGING_OUTPUT="$(mktemp -d "$(dirname "$OUTPUT_DIRECTORY")/.terminalx-sandbox-output.XXXXXX")"
cleanup() {
  rm -rf -- "$BUILD_ROOT"
  if [[ -n "$STAGING_OUTPUT" && -d "$STAGING_OUTPUT" ]]; then
    rm -rf -- "$STAGING_OUTPUT"
  fi
}
trap cleanup EXIT

readonly BUILD_CONTEXT="$BUILD_ROOT/context"
readonly NATIVE_EXPORT="$BUILD_ROOT/native-export"
node "$SCRIPT_DIRECTORY/scripts/prepare-build-context.mjs" \
  "$CONFIGURATION_FILE" \
  "$BUILD_CONTEXT"

readonly PLATFORM="$(tr -d '\n' <"$BUILD_CONTEXT/platform.txt")"
readonly IMAGE_NAME="$(tr -d '\n' <"$BUILD_CONTEXT/image-name.txt")"
if [[ "$PLATFORM" != "linux/amd64" && "$PLATFORM" != "linux/arm64" ]]; then
  echo "Prepared sandbox platform is invalid" >&2
  exit 1
fi
if [[ ! "$IMAGE_NAME" =~ ^[a-z0-9][a-z0-9._:/-]{0,250}$ ]] ||
  [[ "${IMAGE_NAME##*/}" == *:* ]]; then
  echo "Prepared sandbox image name is invalid" >&2
  exit 1
fi

declare -a BUILD_ARGUMENTS=()
declare -A BUILD_ARGUMENT_VALUES=()
while IFS='=' read -r argument_name argument_value; do
  if [[ -z "$argument_name" || -z "$argument_value" ]] ||
    [[ ! "$argument_name" =~ ^[A-Z][A-Z0-9_]+$ ]] ||
    [[ -n "${BUILD_ARGUMENT_VALUES[$argument_name]+present}" ]]; then
    echo "Prepared sandbox build argument is invalid" >&2
    exit 1
  fi
  BUILD_ARGUMENT_VALUES["$argument_name"]="$argument_value"
  BUILD_ARGUMENTS+=(--build-arg "$argument_name=$argument_value")
done <"$BUILD_CONTEXT/build-arguments.txt"

if [[ -n "${BUILD_ARGUMENT_VALUES[BUILDKIT_MULTI_PLATFORM]+present}" ]]; then
  echo "Prepared sandbox build arguments contain a reserved override" >&2
  exit 1
fi
BUILD_ARGUMENT_VALUES[BUILDKIT_MULTI_PLATFORM]="1"
BUILD_ARGUMENTS+=(--build-arg "BUILDKIT_MULTI_PLATFORM=1")

for required_argument in \
  BUILDKIT_SYNTAX \
  BUILDKIT_MULTI_PLATFORM \
  TERMINALX_RUNTIME_IMAGE \
  TERMINALX_TOOLCHAIN_IMAGE \
  SOURCE_DATE_EPOCH \
  TERMINALX_SUPERVISOR_ARTIFACT_SHA256 \
  TERMINALX_SUPERVISOR_SHA256 \
  TERMINALX_SUPERVISOR_RELAY_SHA256 \
  TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256 \
  TERMINALX_DAYTONA_DAEMON_SHA256 \
  TERMINALX_EFFECT_ENFORCER_SHA256 \
  TERMINALX_NODE_SHA256 \
  TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256 \
  TERMINALX_SOURCE_COMMIT \
  TERMINALX_DAYTONA_SOURCE_COMMIT; do
  if [[ -z "${BUILD_ARGUMENT_VALUES[$required_argument]+present}" ]]; then
    echo "Prepared sandbox build arguments are incomplete" >&2
    exit 1
  fi
done

mkdir -m 0700 "$NATIVE_EXPORT"
SOURCE_DATE_EPOCH="${BUILD_ARGUMENT_VALUES[SOURCE_DATE_EPOCH]}" \
  docker buildx build \
  --file "$BUILD_CONTEXT/Dockerfile" \
  --platform "$PLATFORM" \
  --network none \
  --target terminalx-native-artifacts \
  --output "type=local,dest=$NATIVE_EXPORT" \
  --progress plain \
  "${BUILD_ARGUMENTS[@]}" \
  "$BUILD_CONTEXT"

mkdir -m 0700 "$BUILD_CONTEXT/native"
for native_name in terminalx-sandbox-init terminalx-peercred terminalx-isolation-probe; do
  native_file="$NATIVE_EXPORT/$native_name"
  if [[ ! -f "$native_file" || -L "$native_file" ]] ||
    [[ "$(stat -c '%h:%u:%g' "$native_file")" != "1:$(id -u):$(id -g)" &&
      "$(stat -c '%h:%u:%g' "$native_file")" != "1:0:0" ]]; then
    echo "Native sandbox helper export is invalid" >&2
    exit 1
  fi
done
install -m 0555 "$NATIVE_EXPORT/terminalx-sandbox-init" "$BUILD_CONTEXT/native/terminalx-sandbox-init"
install -m 0500 "$NATIVE_EXPORT/terminalx-peercred" "$BUILD_CONTEXT/native/terminalx-peercred"
install -m 0555 "$NATIVE_EXPORT/terminalx-isolation-probe" "$BUILD_CONTEXT/native/terminalx-isolation-probe"

readonly SANDBOX_INIT_SHA256="$(sha256sum "$BUILD_CONTEXT/native/terminalx-sandbox-init" | cut -d' ' -f1)"
readonly PEERCRED_SHA256="$(sha256sum "$BUILD_CONTEXT/native/terminalx-peercred" | cut -d' ' -f1)"
readonly ISOLATION_PROBE_SHA256="$(sha256sum "$BUILD_CONTEXT/native/terminalx-isolation-probe" | cut -d' ' -f1)"
for digest_value in "$SANDBOX_INIT_SHA256" "$PEERCRED_SHA256" "$ISOLATION_PROBE_SHA256"; do
  if [[ ! "$digest_value" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Native sandbox helper digest is invalid" >&2
    exit 1
  fi
done

node - "$BUILD_CONTEXT/native-hashes.json" \
  "$ISOLATION_PROBE_SHA256" "$PEERCRED_SHA256" "$SANDBOX_INIT_SHA256" <<'NODE'
const { writeFileSync } = require("node:fs");
const [output, isolationProbeSha256, peerCredentialExecutableSha256, sandboxInitSha256] = process.argv.slice(2);
const value = { isolationProbeSha256, peerCredentialExecutableSha256, sandboxInitSha256 };
writeFileSync(output, `${JSON.stringify(value)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
NODE
chmod 0600 "$BUILD_CONTEXT/native-hashes.json"

BUILD_ARGUMENTS+=(
  --build-arg "TERMINALX_SANDBOX_INIT_SHA256=$SANDBOX_INIT_SHA256"
  --build-arg "TERMINALX_PEERCRED_SHA256=$PEERCRED_SHA256"
  --build-arg "TERMINALX_ISOLATION_PROBE_SHA256=$ISOLATION_PROBE_SHA256"
)

readonly OCI_LAYOUT="$BUILD_ROOT/terminalx-sandbox.oci"
readonly RAW_BUILD_METADATA="$BUILD_ROOT/buildkit-metadata.raw.json"
readonly BUILD_METADATA="$STAGING_OUTPUT/buildkit-metadata.json"
readonly RELEASE_METADATA="$STAGING_OUTPUT/terminalx-sandbox-image.json"
readonly BUILD_TAG="$IMAGE_NAME:terminalx-${BUILD_ARGUMENT_VALUES[TERMINALX_SOURCE_COMMIT]:0:12}"

BUILDX_METADATA_PROVENANCE=disabled \
  BUILDX_METADATA_WARNINGS=0 \
  SOURCE_DATE_EPOCH="${BUILD_ARGUMENT_VALUES[SOURCE_DATE_EPOCH]}" \
  docker buildx build \
  --file "$BUILD_CONTEXT/Dockerfile" \
  --platform "$PLATFORM" \
  --network none \
  --target terminalx-sandbox \
  --tag "$BUILD_TAG" \
  --attest type=sbom \
  --attest type=provenance,mode=max,version=v1,reproducible=true \
  --metadata-file "$RAW_BUILD_METADATA" \
  --output "type=oci,dest=$OCI_LAYOUT,tar=false,oci-mediatypes=true,oci-artifact=true,rewrite-timestamp=true" \
  --progress plain \
  "${BUILD_ARGUMENTS[@]}" \
  "$BUILD_CONTEXT"

node "$SCRIPT_DIRECTORY/scripts/verify-oci-layout.mjs" \
  "$OCI_LAYOUT" \
  "$BUILD_CONTEXT" \
  "$RELEASE_METADATA" \
  "$RAW_BUILD_METADATA" \
  "$BUILD_METADATA"

readonly OCI_ARCHIVE="$STAGING_OUTPUT/terminalx-daytona-sandbox.oci.tar"
tar --sort=name \
  --mtime="@${BUILD_ARGUMENT_VALUES[SOURCE_DATE_EPOCH]}" \
  --owner=0 --group=0 --numeric-owner \
  -C "$OCI_LAYOUT" -cf "$OCI_ARCHIVE" .
(
  cd "$STAGING_OUTPUT"
  sha256sum \
    buildkit-metadata.json \
    terminalx-sandbox-image.json \
    terminalx-daytona-sandbox.oci.tar >checksums.sha256
  sha256sum --check checksums.sha256
)

chmod 0644 \
  "$BUILD_METADATA" \
  "$RELEASE_METADATA" \
  "$OCI_ARCHIVE" \
  "$STAGING_OUTPUT/checksums.sha256"

chmod 0755 "$STAGING_OUTPUT"
readonly STAGING_OUTPUT_ID="$(stat -c '%d:%i' "$STAGING_OUTPUT")"
mv --no-target-directory --no-clobber -- "$STAGING_OUTPUT" "$OUTPUT_DIRECTORY"
if [[ -d "$STAGING_OUTPUT" ]] || [[ ! -d "$OUTPUT_DIRECTORY" ]] ||
  [[ "$(stat -c '%d:%i' "$OUTPUT_DIRECTORY")" != "$STAGING_OUTPUT_ID" ]]; then
  echo "TerminalX sandbox image output could not be published atomically" >&2
  exit 1
fi
STAGING_OUTPUT=""
