#!/usr/bin/env bash
# SemVer release cutter for TerminalX: bump the version, roll the CHANGELOG
# [Unreleased] section into a dated release, and create an annotated git tag.
# NEVER pushes — a human runs `git push --follow-tags` after review.
#
# Usage:
#   scripts/release.sh <major|minor|patch|X.Y.Z> [--dry-run]
#
# --dry-run prints every mutation without writing files or tagging.
set -euo pipefail
export LC_ALL=C

fail() { echo "release: $*" >&2; exit 1; }

[[ $# -ge 1 ]] || { echo "usage: $0 <major|minor|patch|X.Y.Z> [--dry-run]" >&2; exit 64; }
BUMP="$1"; shift || true
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
readonly BUMP DRY_RUN SCRIPT_DIR ROOT

CURRENT=$(node -p "require('$ROOT/package.json').version")
[[ "$CURRENT" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || fail "current version is not SemVer: $CURRENT"
MAJOR="${BASH_REMATCH[1]}"; MINOR="${BASH_REMATCH[2]}"; PATCH="${BASH_REMATCH[3]}"

case "$BUMP" in
  major) NEXT="$((MAJOR + 1)).0.0" ;;
  minor) NEXT="${MAJOR}.$((MINOR + 1)).0" ;;
  patch) NEXT="${MAJOR}.${MINOR}.$((PATCH + 1))" ;;
  *)
    [[ "$BUMP" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "explicit version must be X.Y.Z: $BUMP"
    NEXT="$BUMP"
    ;;
esac
readonly CURRENT NEXT
TAG="v${NEXT}"
TODAY=$(date -u +%Y-%m-%d)

echo "release: ${CURRENT} -> ${NEXT} (tag ${TAG}, date ${TODAY})"
[[ "$DRY_RUN" -eq 1 ]] && echo "release: DRY RUN — no files written, no tag created"

if [[ "$DRY_RUN" -eq 0 ]]; then
  [[ -z "$(git -C "$ROOT" status --porcelain)" ]] || fail "working tree not clean; commit or stash first"
  git -C "$ROOT" rev-parse "$TAG" >/dev/null 2>&1 && fail "tag $TAG already exists"
fi

# Bump the root and every workspace package.json version field.
bump_pkg() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "  would set version in $file -> $NEXT"
    return 0
  fi
  node -e '
    const fs = require("fs");
    const [file, next] = [process.argv[1], process.argv[2]];
    const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
    pkg.version = next;
    fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
  ' "$file" "$NEXT"
  echo "  set version in $file -> $NEXT"
}
bump_pkg "$ROOT/package.json"
for p in "$ROOT"/packages/*/package.json; do bump_pkg "$p"; done

# Roll CHANGELOG [Unreleased] into a dated release section.
CHANGELOG="$ROOT/CHANGELOG.md"
if [[ -f "$CHANGELOG" ]]; then
  if grep -q "## \[Unreleased\]" "$CHANGELOG"; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "  would insert '## [${NEXT}] - ${TODAY}' after [Unreleased] in CHANGELOG.md"
    else
      node -e '
        const fs = require("fs");
        const [file, next, today] = [process.argv[1], process.argv[2], process.argv[3]];
        let text = fs.readFileSync(file, "utf8");
        text = text.replace(/## \[Unreleased\]\n/, `## [Unreleased]\n\n## [${next}] - ${today}\n`);
        fs.writeFileSync(file, text);
      ' "$CHANGELOG" "$NEXT" "$TODAY"
      echo "  rolled CHANGELOG.md [Unreleased] -> [${NEXT}] - ${TODAY}"
    fi
  else
    echo "  WARNING: no [Unreleased] section in CHANGELOG.md; skipping changelog roll"
  fi
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "release: dry run complete"
  exit 0
fi

git -C "$ROOT" add -A
git -C "$ROOT" commit -m "chore(release): ${NEXT}"
git -C "$ROOT" tag -a "$TAG" -m "TerminalX ${NEXT}"
echo "release: committed and tagged ${TAG}. Review, then: git push --follow-tags"
