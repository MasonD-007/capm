#!/usr/bin/env bash
# Cross-compiles the four capm CLI binaries and writes checksums.txt.
# Shared by the per-commit job in release.yml and by cli-release.yml.
#
#   build-cli.sh VERSION [OUTDIR]     VERSION is baked in with -X main.version
#                                     (a full commit SHA, or a semver for tags);
#                                     OUTDIR defaults to ./dist
set -eu

if [ $# -lt 1 ] || [ -z "$1" ]; then
  echo "usage: build-cli.sh VERSION [OUTDIR]" >&2
  exit 2
fi
version="$1"
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "${2:-dist}"
out="$(cd "${2:-dist}" && pwd)"

for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  (cd "$root/cli" && GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=${version}" \
    -o "$out/capm-${os}-${arch}" .)
done

cd "$out"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum capm-* >checksums.txt
else
  shasum -a 256 capm-* >checksums.txt
fi
cat checksums.txt
