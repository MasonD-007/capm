#!/bin/sh
# Stale-trusted-root experiment: verify a 2026 bundle with the trusted root
# that shipped inside sigstore-go v1.4.0 fixtures (older snapshot) and with
# the current one. Usage: WORK=<dir from run-experiments.sh> sh run-stale-root.sh
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:?}
SG=$(cd "$HERE" && GOWORK=off go list -m -f '{{.Dir}}' github.com/sigstore/sigstore-go)
V=$WORK/spikeverify
GCP='^keyless@projectsigstore\.iam\.gserviceaccount\.com$'
for r in "$HERE/trusted_root.json" "$SG/pkg/testing/data/trusted-roots/public-good.json" "$SG/examples/trusted-root-public-good.json"; do
  echo "--- root: $r"
  python3 -I -c "
import json,sys
r=json.load(open(sys.argv[1]))
print(' tlogs:',[t['baseUrl'] for t in r['tlogs']],' cas:',len(r['certificateAuthorities']),' ctlogs:',len(r['ctlogs']),' tsa:',len(r.get('timestampAuthorities',[])))
" "$r"
  $V -bundle "$WORK/cosign-darwin-arm64.sigstore.json" -root "$r" -digest "$WORK/cosign-darwin-arm64" -owner x -issuer https://accounts.google.com -san-re "$GCP" 2>&1 | head -3
done
