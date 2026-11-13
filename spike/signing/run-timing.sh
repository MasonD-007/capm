#!/bin/sh
# Experiment C timing. WORK=<dir used by run-experiments.sh>
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:?}
SG=$(cd "$HERE" && GOWORK=off go list -m -f '{{.Dir}}' github.com/sigstore/sigstore-go)
V=$WORK/spikeverify
D1=9f9b8cd557cf2e5b3df3373a00baa005a86b02391e3e06dd0ce37b3a1533d3a4
D2=46d4e2f74c4877316640000a6fdf8a8b59f1e0847667973e9859f774dd31b8f1e0937813b777fb66a2ac67d50540fe34640966eee9fc2ccca387082b4c85cd3c
echo "messageSignature bundle (Rekor v1 inclusion proof + SET, SCT, GCP SA):"
python3 -I "$HERE/time-verify.py" $V "$WORK/cosign-darwin-arm64.sigstore.json" sha256 $D1 -owner x -issuer https://accounts.google.com -san-re '^keyless@projectsigstore\.iam\.gserviceaccount\.com$'
echo "DSSE bundle, GitHub Actions identity + owner id:"
python3 -I "$HERE/time-verify.py" $V "$SG/pkg/testing/data/bundles/sigstore.js@2.0.0-provenance.sigstore.json" sha512 $D2 -owner sigstore -owner-id 71096353
echo "baseline: process start of the same binary with bad flag (exec + runtime init only)"
python3 - "$V" <<'EOF'
import statistics, subprocess, sys, time
ts=[]
for i in range(21):
    t=time.perf_counter(); subprocess.run([sys.argv[1], "-h"], capture_output=True); ts.append((time.perf_counter()-t)*1000)
print("median=%.1fms" % statistics.median(ts[1:]))
EOF
