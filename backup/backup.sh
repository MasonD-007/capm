#!/bin/sh
# Nightly backup of the capm data directory into a restic repository.
#
# Reads: DATA_DIR (default /data), SCRATCH_DIR (default /scratch),
# RESTIC_REPOSITORY, RESTIC_PASSWORD, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
# RESTIC_CACHE_DIR. Exits 0 only if snapshot, upload and prune all succeeded.
#
# The snapshot contains two paths: $SCRATCH_DIR/capm.db (a consistent copy made
# with SQLite's online backup) and $DATA_DIR/blobs (minus in-flight .tmp-*
# uploads). The live database is never copied with cp and its -wal/-shm files
# are never backed up. Only $SCRATCH_DIR is written to, apart from the SQLite
# shared-memory file SQLite itself maintains next to the database.
set -eu

DATA_DIR="${DATA_DIR:-/data}"
SCRATCH_DIR="${SCRATCH_DIR:-/scratch}"

if [ ! -f "$DATA_DIR/capm.db" ]; then
  echo "backup: $DATA_DIR/capm.db not found" >&2
  exit 1
fi

snap="$SCRATCH_DIR/capm.db"
trap 'rm -f "$snap"' EXIT
rm -f "$snap"

echo "backup: snapshotting database"
sqlite3 "$DATA_DIR/capm.db" ".timeout 5000" ".backup '$snap'"
[ "$(sqlite3 "$snap" 'PRAGMA integrity_check;')" = "ok" ] || {
  echo "backup: snapshot failed integrity_check" >&2
  exit 1
}

# A missing repository (first run) is initialised. Any other failure of
# `cat config` (bad credentials, network) makes `init` fail too, so we still
# exit non-zero.
if ! restic cat config >/dev/null 2>&1; then
  echo "backup: initialising repository"
  restic init
fi

echo "backup: uploading"
# --host is fixed because the hostname is the pod name, which changes every run;
# without it each night would be its own retention group and nothing is pruned.
restic backup --host capm --exclude "$DATA_DIR/blobs/.tmp-*" "$snap" "$DATA_DIR/blobs"

echo "backup: pruning"
restic forget --host capm --keep-daily 7 --keep-weekly 4 --prune

echo "backup: done"
