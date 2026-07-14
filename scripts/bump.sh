#!/usr/bin/env bash
# Bump semver in Cargo.toml, commit, and create an annotated git tag.
#
# The commit message "chore: release vX.Y.Z" triggers .github/workflows/release.yml
# when pushed to main/master.
#
# Usage:
#   ./scripts/bump.sh patch|minor|major
#   PUSH=1 ./scripts/bump.sh patch   # also push commit + tag to origin
#
# Example: 0.1.3 -> patch 0.1.4 | minor 0.2.0 | major 1.0.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

kind="${1:-}"
case "$kind" in
  patch|minor|major) ;;
  *)
    echo "usage: $0 patch|minor|major" >&2
    exit 1
    ;;
esac

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree has uncommitted changes; commit or stash first" >&2
  exit 1
fi

current="$(sed -n 's/^version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"/\1/p' Cargo.toml | head -1)"
if [[ -z "$current" ]]; then
  echo "error: could not parse version from Cargo.toml" >&2
  exit 1
fi

IFS=. read -r major minor patch <<<"$current"
case "$kind" in
  patch) patch=$((patch + 1)) ;;
  minor)
    minor=$((minor + 1))
    patch=0
    ;;
  major)
    major=$((major + 1))
    minor=0
    patch=0
    ;;
esac

next="${major}.${minor}.${patch}"
tag="v${next}"

if git rev-parse "$tag" >/dev/null 2>&1; then
  echo "error: tag $tag already exists" >&2
  exit 1
fi

echo "==> bumping $current -> $next ($kind)"

# Only rewrite the package version line (first match under [package]).
tmp="$(mktemp)"
awk -v ver="$next" '
  BEGIN { done = 0 }
  /^\[package\]/ { in_pkg = 1 }
  in_pkg && /^version = "/ && !done {
    print "version = \"" ver "\""
    done = 1
    next
  }
  /^\[/ && !/^\[package\]/ { in_pkg = 0 }
  { print }
' Cargo.toml >"$tmp"
mv "$tmp" Cargo.toml

git add Cargo.toml
git commit -m "$(cat <<EOF
chore: release v${next}

EOF
)"

git tag -a "$tag" -m "Release v${next}"

echo "==> created commit and tag $tag"
if [[ "${PUSH:-0}" == "1" ]]; then
  git push origin HEAD
  git push origin "$tag"
  echo "==> pushed HEAD and $tag"
else
  echo "==> push with: git push origin HEAD && git push origin $tag"
  echo "    or:         make ${kind} PUSH=1"
fi
