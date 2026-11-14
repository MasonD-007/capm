#!/usr/bin/env bash
# Refreshes cli/internal/sigverify/trusted_root.json from Sigstore's public-good
# TUF repository (read-only network access; no credentials), prints a summary
# of what changed, and updates the sha256 and date recorded in the package's
# TRUSTED_ROOT.md. Run it, review the diff, run the tests, then commit.
#
#   update-trusted-root.sh [--check]    --check only reports; it never writes
#
# Exit status with --check: 0 if the embedded root is current, 1 if it differs.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
dir="$root/cli/internal/sigverify"
cur="$dir/trusted_root.json"
readme="$dir/TRUSTED_ROOT.md"
check=0
[ "${1:-}" = "--check" ] && check=1

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sha() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

(cd "$root/cli" && go run ../scripts/fetch-trusted-root.go "$tmp/trusted_root.json" "$cur")

old="$(sha "$cur")"
new="$(sha "$tmp/trusted_root.json")"
echo "embedded sha256: $old"
echo "official sha256: $new"

if [ "$old" = "$new" ]; then
  echo "embedded trusted root is current"
  exit 0
fi
if [ "$check" = 1 ]; then
  echo "embedded trusted root DIFFERS from the official one" >&2
  exit 1
fi

cp "$tmp/trusted_root.json" "$cur"
today="$(date -u +%Y-%m-%d)"
sed -i.bak -e "s/^- sha256: .*/- sha256: $new/" -e "s/^- retrieved: .*/- retrieved: $today/" "$readme"
rm -f "$readme.bak"
echo "updated $cur and $readme; now run: (cd cli && go test ./internal/sigverify/)"
