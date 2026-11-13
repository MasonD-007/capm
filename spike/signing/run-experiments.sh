#!/bin/sh
# Experiment B driver. Usage: WORK=/some/empty/dir sh run-experiments.sh
# Needs network ONLY for fetching the public cosign release asset the first
# time; every verification below runs under a macOS sandbox profile that
# denies all network access (see NOSNET).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:?set WORK}
mkdir -p "$WORK/b"
SG=$(cd "$HERE" && GOWORK=off go list -m -f '{{.Dir}}' github.com/sigstore/sigstore-go)
ROOT=$HERE/trusted_root.json
COS=https://github.com/sigstore/cosign/releases/download/v3.1.4
[ -f "$WORK/cosign-darwin-arm64" ] || curl -sSL -o "$WORK/cosign-darwin-arm64" $COS/cosign-darwin-arm64
[ -f "$WORK/cosign-darwin-arm64.sigstore.json" ] || curl -sSL -o "$WORK/cosign-darwin-arm64.sigstore.json" $COS/cosign-darwin-arm64.sigstore.json
(cd "$HERE" && GOWORK=off go build -o "$WORK/spikeverify" ./cmd/spikeverify)
V=$WORK/spikeverify
ART=$WORK/cosign-darwin-arm64
B1=$WORK/cosign-darwin-arm64.sigstore.json
B2="$SG/pkg/testing/data/bundles/sigstore.js@2.0.0-provenance.sigstore.json"
D2=46d4e2f74c4877316640000a6fdf8a8b59f1e0847667973e9859f774dd31b8f1e0937813b777fb66a2ac67d50540fe34640966eee9fc2ccca387082b4c85cd3c
GCP_SAN='^keyless@projectsigstore\.iam\.gserviceaccount\.com$'

# Deny-network sandbox: proves the verification path is offline.
cat >"$WORK/nonet.sb" <<'EOF'
(version 1)
(allow default)
(deny network*)
EOF
NOSNET="sandbox-exec -f $WORK/nonet.sb"

run() { n=$1; shift; echo "--- $n"; $NOSNET "$@"; echo "exit=$?"; }

python3 -I "$HERE/tamper.py" "$B1" "$WORK/b" cosign >/dev/null
python3 -I "$HERE/tamper.py" "$B2" "$WORK/b" actions >/dev/null

echo "===== Case 1: messageSignature bundle, GCP service-account identity (cosign v3.1.4 release)"
run "1.1 valid" $V -bundle "$B1" -digest "$ART" -owner x -issuer https://accounts.google.com -san-re "$GCP_SAN"
run "1.2 wrong digest" $V -bundle "$B1" -digest 0000000000000000000000000000000000000000000000000000000000000000 -owner x -issuer https://accounts.google.com -san-re "$GCP_SAN"
run "1.3 wrong SAN" $V -bundle "$B1" -digest "$ART" -owner x -issuer https://accounts.google.com -san-re '^someone@example\.com$'
run "1.4 wrong issuer" $V -bundle "$B1" -digest "$ART" -owner x -issuer https://token.actions.githubusercontent.com -san-re "$GCP_SAN"
run "1.5 default Actions policy (owner=sigstore) must reject a non-Actions cert" $V -bundle "$B1" -digest "$ART" -owner sigstore
for t in tamper-signature tamper-certificate tamper-inclusion-proof tamper-set strip-tlog; do
  run "1.6 $t" $V -bundle "$WORK/b/cosign-$t.json" -digest "$ART" -owner x -issuer https://accounts.google.com -san-re "$GCP_SAN"
done

echo "===== Case 2: DSSE bundle from a GitHub Actions workflow (sigstore-js, sigstore-go fixture), sha512 subject"
run "2.1 valid, owner=sigstore + owner-id 71096353" $V -bundle "$B2" -alg sha512 -digest $D2 -owner sigstore -owner-id 71096353
run "2.2 valid, owner id not checked" $V -bundle "$B2" -alg sha512 -digest $D2 -owner sigstore
run "2.3 wrong digest" $V -bundle "$B2" -alg sha512 -digest ${D2%??}00 -owner sigstore -owner-id 71096353
run "2.4 wrong owner login (attacker-owned repo shape)" $V -bundle "$B2" -alg sha512 -digest $D2 -owner evil -owner-id 71096353
run "2.5 login prefix trick: owner=sig" $V -bundle "$B2" -alg sha512 -digest $D2 -owner sig
run "2.6 right login, wrong numeric owner id (login-reassignment case)" $V -bundle "$B2" -alg sha512 -digest $D2 -owner sigstore -owner-id 71096354
run "2.7 wrong issuer" $V -bundle "$B2" -alg sha512 -digest $D2 -owner sigstore -issuer https://accounts.google.com
for t in tamper-signature tamper-certificate tamper-inclusion-proof tamper-set strip-tlog; do
  [ -f "$WORK/b/actions-$t.json" ] && run "2.8 $t" $V -bundle "$WORK/b/actions-$t.json" -alg sha512 -digest $D2 -owner sigstore -owner-id 71096353
done
