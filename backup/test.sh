#!/usr/bin/env bash
# Integration test for the backup image. Runs the container the way the
# CronJob does (read-only rootfs, uid 65532, no capabilities) against a local
# directory restic repository. Needs only Docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG=capm-backup:test
UIDGID=65532:65532
PASS=0
FAIL=0

# Data, repository and restore target live in named Docker volumes rather than
# host bind mounts: restic cannot read files from macOS Docker Desktop bind
# mounts (input/output error), and volumes avoid host-uid permission problems
# and root-owned leftovers on Linux. Cleanup is just `docker volume rm`.
P=capm-backup-test-$$
V_DATA=$P-data V_EMPTY=$P-empty V_REPO=$P-repo V_OUT=$P-out
HOLDER=$P-holder

cleanup() {
  docker rm -f "$HOLDER" >/dev/null 2>&1 || true
  docker volume rm -f "$V_DATA" "$V_EMPTY" "$V_REPO" "$V_OUT" >/dev/null 2>&1 || true
  docker rmi -f "$IMG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok()  { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }
check() { # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

# Production-equivalent sandbox. /data is mounted read-write (needed for the
# SQLite WAL shared-memory file); /scratch, /cache and /tmp are the only other
# writable paths.
sandbox() {
  echo --read-only --user "$UIDGID" --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:uid=65532,gid=65532 \
    --tmpfs /cache:uid=65532,gid=65532 \
    --tmpfs /scratch:uid=65532,gid=65532
}

run_backup() { # run_backup <data volume>
  # shellcheck disable=SC2046
  docker run --rm $(sandbox) \
    -e DATA_DIR=/data -e SCRATCH_DIR=/scratch -e RESTIC_CACHE_DIR=/cache \
    -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD=test \
    -v "$1:/data" -v "$V_REPO:/repo" "$IMG"
}

restic_in() { # restic_in <args...>: run restic against the repo, same sandbox
  # shellcheck disable=SC2046
  docker run --rm $(sandbox) --entrypoint restic \
    -e RESTIC_CACHE_DIR=/cache -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD=test \
    -v "$V_REPO:/repo" -v "$V_OUT:/out" "$IMG" "$@"
}

sqlite_in() { # sqlite_in <volume> <sqlite3 args...>
  local vol=$1; shift
  # shellcheck disable=SC2046
  docker run --rm $(sandbox) --entrypoint sqlite3 -v "$vol:/d" "$IMG" "$@"
}

# Setup helper only: runs as root to hand the volumes to uid 65532.
rootsh() {
  docker run --rm --user 0 --entrypoint sh \
    -v "$V_DATA:/v/data" -v "$V_EMPTY:/v/empty" -v "$V_REPO:/v/repo" -v "$V_OUT:/v/out" \
    "$IMG" -c "$1"
}

echo "== build"
docker build -q -t "$IMG" "$HERE" >/dev/null

rootsh 'mkdir -p /v/data/blobs
  printf "known blob content\n" > /v/data/blobs/abc
  printf "in-flight upload\n"   > /v/data/blobs/.tmp-123
  chown -R 65532:65532 /v/data /v/empty /v/repo /v/out'

echo "== set up WAL database with an uncheckpointed write"
# The holder keeps one connection open so SQLite cannot checkpoint and delete
# the WAL; its insert therefore lives only in capm.db-wal, like a live backend.
docker run -d --name "$HOLDER" $(sandbox) --entrypoint sh -v "$V_DATA:/d" "$IMG" -c \
  '(echo "PRAGMA journal_mode=WAL;"; echo "CREATE TABLE t(x);"; echo "INSERT INTO t VALUES(1);"; sleep 600) | sqlite3 /d/capm.db' >/dev/null
for _ in $(seq 1 50); do
  [ "$(rootsh 'stat -c %s /v/data/capm.db-wal 2>/dev/null || echo 0')" -gt 0 ] && break
  sleep 0.2
done
[ "$(rootsh 'stat -c %s /v/data/capm.db-wal 2>/dev/null || echo 0')" -gt 0 ] \
  && ok "setup: WAL holds uncheckpointed data" || bad "setup: WAL is empty"

echo "== 1: first run against an empty repository"
if run_backup "$V_DATA"; then ok "first run on empty repo exits 0"; else bad "first run on empty repo exits 0"; fi

echo "== 2: second run"
if run_backup "$V_DATA"; then ok "second run exits 0"; else bad "second run exits 0"; fi
COUNT="$(restic_in snapshots --json | grep -o '"short_id"' | wc -l | tr -d ' ')"
check "repository lists 2 snapshots" 2 "$COUNT"
check "snapshots are tagged host (stable across pods so prune groups them) 'capm'" capm "$(restic_in snapshots --json | grep -o '"hostname":"[^"]*"' | head -n 1 | cut -d'"' -f4)"

echo "== 3: restore and verify"
restic_in restore latest --target /out >/dev/null
RDB="$(rootsh 'find /v/out -name capm.db | head -n 1')"
[ -n "$RDB" ] || { bad "restored capm.db exists"; RDB=/v/out/missing/capm.db; }
RSUB="$(dirname "${RDB#/v/out}")"   # e.g. /scratch; where the db was restored
check "restored db integrity_check" ok "$(sqlite_in "$V_OUT" "/d$RSUB/capm.db" 'PRAGMA integrity_check;' 2>&1)"
check "restored db has the WAL-only row" 1 "$(sqlite_in "$V_OUT" "/d$RSUB/capm.db" 'SELECT count(*) FROM t;' 2>&1)"
if rootsh 'f=$(find /v/out -path "*/blobs/abc"); [ -n "$f" ] && [ "$(cat "$f")" = "known blob content" ]'; then
  ok "restored blobs/abc is byte-identical"
else bad "restored blobs/abc is byte-identical"; fi
check "no -wal/-shm files in snapshot" 0 "$(rootsh 'find /v/out \( -name "capm.db-wal" -o -name "capm.db-shm" \) | wc -l' | tr -d ' ')"
check "in-flight blobs/.tmp-* excluded" 0 "$(rootsh 'find /v/out -name ".tmp-*" | wc -l' | tr -d ' ')"

echo "== 4: missing database fails"
if run_backup "$V_EMPTY" >/dev/null 2>&1; then bad "missing capm.db exits non-zero"; else ok "missing capm.db exits non-zero"; fi
COUNT="$(restic_in snapshots --json | grep -o '"short_id"' | wc -l | tr -d ' ')"
check "failed run created no snapshot" 2 "$COUNT"

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
