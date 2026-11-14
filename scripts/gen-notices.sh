#!/usr/bin/env bash
# Generates cli/THIRD_PARTY_NOTICES.md: the licence of every Go module the capm
# CLI can link, detected from the LICENSE files in the module cache.
#
#   gen-notices.sh            rewrite cli/THIRD_PARTY_NOTICES.md
#   gen-notices.sh --check    regenerate to a temp file and fail (exit 1) if it
#                             differs from the committed file
#
# Needs the modules in the module cache (run `go mod download` or any build
# first) and no network otherwise. Unrecognised licences are listed as UNKNOWN
# in the output, never guessed; the script still exits 0 so the list can be
# reviewed, but a test fails if any UNKNOWN remains in the committed file.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/cli/THIRD_PARTY_NOTICES.md"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

(cd "$root/cli" && go run ../scripts/gen-notices.go >"$tmp")

if [ "${1:-}" = "--check" ]; then
  if cmp -s "$tmp" "$out"; then
    echo "THIRD_PARTY_NOTICES.md is up to date"
    exit 0
  fi
  echo "cli/THIRD_PARTY_NOTICES.md is out of date; run scripts/gen-notices.sh" >&2
  exit 1
fi

cp "$tmp" "$out"
grep -c '^| `' "$out" | sed 's/$/ modules/'
if grep -q '^\*\*Modules with an unrecognised licence' "$out"; then
  echo "WARNING: some licences are UNKNOWN; see the Summary section of $out" >&2
fi
