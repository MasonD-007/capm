#!/bin/sh
# Experiment C: binary sizes with the release script's flags. Usage:
#   OUT=<scratch dir> sh run-sizes.sh
# Builds (all CGO_ENABLED=0 -trimpath -ldflags "-s -w"):
#   real CLI (cli/), empty main, empty main + verifier, for 4 targets.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${OUT:?set OUT}
mkdir -p "$OUT/sz"
printf '%-14s %12s %12s %12s\n' target capm-cli empty-main empty+verifier
for t in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
  os=${t%/*}; arch=${t#*/}
  (cd "$ROOT/cli" && GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=spike" -o "$OUT/sz/cli-$os-$arch" .)
  (cd "$HERE" && GOWORK=off GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/sz/empty-$os-$arch" ./emptymain)
  (cd "$HERE" && GOWORK=off GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/sz/verif-$os-$arch" ./verifymain)
  printf '%-14s %12s %12s %12s\n' "$os/$arch" \
    "$(stat -f %z "$OUT/sz/cli-$os-$arch")" "$(stat -f %z "$OUT/sz/empty-$os-$arch")" "$(stat -f %z "$OUT/sz/verif-$os-$arch")"
done
