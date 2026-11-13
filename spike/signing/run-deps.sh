#!/bin/sh
# Dependency-graph and stdlib-matched-baseline measurements. OUT=<scratch>.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${OUT:?}
echo "== go list -m all (modules in graph incl. main)"
echo "cli     : $(cd "$ROOT/cli" && GOWORK=off go list -m all | wc -l)"
echo "backend : $(cd "$ROOT/backend" && GOWORK=off go list -m all | wc -l)"
echo "spike   : $(cd "$HERE" && GOWORK=off go list -m all | wc -l)"
echo "== modules actually linked into verifymain (go list -deps, non-std)"
(cd "$HERE" && GOWORK=off go list -deps -f '{{if .Module}}{{.Module.Path}}@{{.Module.Version}}{{end}}' ./verifymain | sort -u | wc -l)
(cd "$HERE" && GOWORK=off go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./verifymain | grep -c .) | sed 's/^/non-std packages: /'
(cd "$ROOT/cli" && GOWORK=off go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' . | grep -c .) | sed 's/^/cli non-std packages: /'
echo "== CGO check: packages with CgoFiles in verifymain deps (non-std)"
(cd "$HERE" && GOWORK=off go list -deps -f '{{if and (not .Standard) .CgoFiles}}{{.ImportPath}}{{end}}' ./verifymain | grep . || echo none)
echo "== direct+indirect modules linked, by path"
(cd "$HERE" && GOWORK=off go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./verifymain | sort | uniq -c | sort -rn | head -50)
echo "== sizes with stdlib-matched baseline"
for t in darwin/arm64 linux/amd64; do
  os=${t%/*}; arch=${t#*/}
  (cd "$HERE" && GOWORK=off GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/sz/std-$os-$arch" ./stdbase)
  printf '%s stdbase=%s verif=%s delta=%s\n' $t "$(stat -f %z "$OUT/sz/std-$os-$arch")" "$(stat -f %z "$OUT/sz/verif-$os-$arch")" \
    "$(( $(stat -f %z "$OUT/sz/verif-$os-$arch") - $(stat -f %z "$OUT/sz/std-$os-$arch") ))"
done
