#!/usr/bin/env bash
# Cosign-style container image signing + SBOM/provenance attestation for the
# TerminalX app image. Keys are REFERENCED, never embedded: keyless (Sigstore
# OIDC) is the default; a KMS key reference (TERMINALX_COSIGN_KEY, e.g.
# awskms://..., gcpkms://..., or a hardware/file ref) is the alternative. No
# private key material is ever read or written by this script.
#
# The house CI path attests via actions/attest-build-provenance + BuildKit
# (sbom:true, provenance:mode=max); this script is the registry-side signing
# complement for operators who publish the image outside that pipeline.
#
# Usage:
#   scripts/sign-container-image.sh <image-ref-with-digest> [<sbom-file> [<provenance-file>]]
# Requires: cosign on PATH. Verifies its own signature after signing.
set -euo pipefail
export LC_ALL=C

fail() { echo "sign-container-image: $*" >&2; exit 1; }

[[ $# -ge 1 ]] || { echo "usage: $0 <image-ref@sha256:...> [sbom] [provenance]" >&2; exit 64; }
IMAGE_REF="$1"
SBOM_FILE="${2:-}"
PROVENANCE_FILE="${3:-}"
readonly IMAGE_REF SBOM_FILE PROVENANCE_FILE

command -v cosign >/dev/null 2>&1 || fail "cosign is not installed (documentation-only in this environment)"

# Pin by digest so signature binds the exact image, never a mutable tag.
[[ "$IMAGE_REF" == *"@sha256:"* ]] || fail "image ref must be pinned by digest (…@sha256:…)"

KEYLESS=1
COSIGN_KEY_ARGS=()
if [[ -n "${TERMINALX_COSIGN_KEY:-}" ]]; then
  KEYLESS=0
  COSIGN_KEY_ARGS=(--key "${TERMINALX_COSIGN_KEY}")
  echo "signing with referenced KMS/key: ${TERMINALX_COSIGN_KEY%%:*}:… (value not shown)"
else
  export COSIGN_EXPERIMENTAL=1
  echo "signing keyless (Sigstore OIDC); no key material touched"
fi

echo "==> cosign sign ${IMAGE_REF}"
cosign sign --yes "${COSIGN_KEY_ARGS[@]}" "${IMAGE_REF}"

if [[ -n "$SBOM_FILE" ]]; then
  [[ -f "$SBOM_FILE" ]] || fail "sbom file not found: $SBOM_FILE"
  echo "==> cosign attest (spdxjson SBOM)"
  cosign attest --yes "${COSIGN_KEY_ARGS[@]}" --type spdxjson --predicate "$SBOM_FILE" "${IMAGE_REF}"
fi

if [[ -n "$PROVENANCE_FILE" ]]; then
  [[ -f "$PROVENANCE_FILE" ]] || fail "provenance file not found: $PROVENANCE_FILE"
  echo "==> cosign attest (slsaprovenance)"
  cosign attest --yes "${COSIGN_KEY_ARGS[@]}" --type slsaprovenance \
    --predicate "$PROVENANCE_FILE" "${IMAGE_REF}"
fi

echo "==> cosign verify (self-check)"
if [[ "$KEYLESS" -eq 1 ]]; then
  : "${TERMINALX_COSIGN_IDENTITY:?set TERMINALX_COSIGN_IDENTITY for keyless verify}"
  : "${TERMINALX_COSIGN_OIDC_ISSUER:?set TERMINALX_COSIGN_OIDC_ISSUER for keyless verify}"
  cosign verify \
    --certificate-identity "${TERMINALX_COSIGN_IDENTITY}" \
    --certificate-oidc-issuer "${TERMINALX_COSIGN_OIDC_ISSUER}" \
    "${IMAGE_REF}" >/dev/null
else
  cosign verify "${COSIGN_KEY_ARGS[@]}" "${IMAGE_REF}" >/dev/null
fi

echo "signed and verified: ${IMAGE_REF}"
