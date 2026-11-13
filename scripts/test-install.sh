#!/usr/bin/env bash
# Tests frontend/public/install.sh against a local HTTP server and fake binaries.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_SH="$ROOT/frontend/public/install.sh"

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
[ -f "$INSTALL_SH" ] || echo "note: $INSTALL_SH does not exist yet"

# Same mapping as install.sh.
case "$(uname -s)" in
  Darwin) OS=darwin ;;
  Linux) OS=linux ;;
  *) echo "unsupported host OS for this test" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "unsupported host arch for this test" >&2; exit 2 ;;
esac
ASSET="capm-$OS-$ARCH"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Start the HTTP server on a free port. Ask the OS for one, then retry with a
# new port if the server fails to come up (another process may grab it).
SERVE="$WORK/serve"
mkdir -p "$SERVE"
PORT=""
attempt=0
while [ $attempt -lt 5 ] && [ -z "$PORT" ]; do
  attempt=$((attempt + 1))
  cand="$(python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')"
  python3 -m http.server "$cand" --bind 127.0.0.1 --directory "$SERVE" >"$WORK/server.log" 2>&1 &
  SERVER_PID=$!
  : >"$SERVE/ping"
  i=0
  while [ $i -lt 50 ]; do
    if python3 -c "import sys,urllib.request
urllib.request.urlopen('http://127.0.0.1:$cand/ping', timeout=1)" 2>/dev/null; then
      PORT="$cand"
      break
    fi
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
  done
  if [ -z "$PORT" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=""
  fi
done
rm -f "$SERVE/ping"
if [ -z "$PORT" ]; then
  echo "could not start http server:" >&2
  cat "$WORK/server.log" >&2
  exit 2
fi

FAILS=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }
check() { # check <description> <command...>
  local d="$1"; shift
  if "$@"; then pass "$d"; else fail "$d"; fi
}

# make_case <name> : creates a release dir with a good fake binary and checksums.
make_case() {
  local d="$SERVE/$1"
  mkdir -p "$d"
  printf '#!/bin/sh\nif [ "${1:-}" = version ]; then echo "capm test"; fi\n' >"$d/$ASSET"
  (cd "$d" && printf '%s  %s\n' "$(sha256 "$ASSET")" "$ASSET" >checksums.txt)
}

# run_install <case> <installdir> [shell] : output in $WORK/out, status in $RC
RC=0
run_install() {
  local c="$1" dir="$2" sh="${3:-sh}"
  CAPM_DOWNLOAD_BASE="http://127.0.0.1:$PORT/$c" CAPM_INSTALL_DIR="$dir" \
    "$sh" "$INSTALL_SH" >"$WORK/out" 2>&1
  RC=$?
}

is_exec() { [ -x "$1" ]; }
not_exists() { [ ! -e "$1" ]; }
no_leftovers() { [ ! -d "$1" ] || [ -z "$(ls -A "$1")" ]; }
out_has() { grep -q -- "$1" "$WORK/out"; }
rc_zero() { [ "$RC" -eq 0 ]; }
rc_nonzero() { [ "$RC" -ne 0 ]; }
runs_ok() { [ "$("$1" version 2>&1)" = "capm test" ]; }
content_is() { [ "$(cat "$1")" = "$2" ]; }

echo "== 1. happy path (sh)"
make_case happy
D="$WORK/i1"
run_install happy "$D"
check "exit 0" rc_zero
check "installed file is executable" is_exec "$D/capm"
check "installed binary prints 'capm test'" runs_ok "$D/capm"
check "no leftover files besides capm" test "$(ls -A "$D")" = capm

echo "== 2. reinstall over existing file"
printf 'OLD' >"$D/capm"
run_install happy "$D"
check "exit 0" rc_zero
check "old file replaced" runs_ok "$D/capm"
check "still executable" is_exec "$D/capm"

echo "== 3. checksum mismatch"
make_case badsum
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" "$ASSET" >"$SERVE/badsum/checksums.txt"
D="$WORK/i3"
run_install badsum "$D"
check "non-zero exit" rc_nonzero
check "mismatch reported" out_has "checksum mismatch"
check "nothing installed" not_exists "$D/capm"
check "no leftovers" no_leftovers "$D"
D="$WORK/i3b"
mkdir -p "$D"
printf 'KEEPME' >"$D/capm"
run_install badsum "$D"
check "non-zero exit with existing install" rc_nonzero
check "existing install untouched" content_is "$D/capm" KEEPME

echo "== 4. checksums.txt lacks the asset"
make_case nosum
printf '%s  %s\n' "$(sha256 "$SERVE/nosum/$ASSET")" "some-other-file" >"$SERVE/nosum/checksums.txt"
D="$WORK/i4"
run_install nosum "$D"
check "non-zero exit" rc_nonzero
check "nothing installed" not_exists "$D/capm"
check "no leftovers" no_leftovers "$D"

echo "== 5. asset 404"
make_case missing
rm "$SERVE/missing/$ASSET"
D="$WORK/i5"
run_install missing "$D"
check "non-zero exit" rc_nonzero
check "nothing installed" not_exists "$D/capm"
check "no leftovers" no_leftovers "$D"

echo "== 6. unsupported OS / arch via fake uname"
FAKEBIN="$WORK/fakebin"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/uname" <<'UN'
#!/bin/sh
case "${1:-}" in
  -s) echo "${FAKE_UNAME_S:-Linux}" ;;
  -m) echo "${FAKE_UNAME_M:-x86_64}" ;;
  *) echo "${FAKE_UNAME_S:-Linux}" ;;
esac
UN
chmod 755 "$FAKEBIN/uname"
D="$WORK/i6"
RC=0
PATH="$FAKEBIN:$PATH" FAKE_UNAME_S=FreeBSD FAKE_UNAME_M=x86_64 \
  CAPM_DOWNLOAD_BASE="http://127.0.0.1:$PORT/happy" CAPM_INSTALL_DIR="$D" \
  sh "$INSTALL_SH" >"$WORK/out" 2>&1 || RC=$?
check "unsupported OS: non-zero exit" rc_nonzero
check "unsupported OS: error names FreeBSD" out_has "FreeBSD"
check "unsupported OS: nothing installed" not_exists "$D/capm"
RC=0
PATH="$FAKEBIN:$PATH" FAKE_UNAME_S=Linux FAKE_UNAME_M=riscv64 \
  CAPM_DOWNLOAD_BASE="http://127.0.0.1:$PORT/happy" CAPM_INSTALL_DIR="$D" \
  sh "$INSTALL_SH" >"$WORK/out" 2>&1 || RC=$?
check "unsupported arch: non-zero exit" rc_nonzero
check "unsupported arch: error names riscv64" out_has "riscv64"
check "unsupported arch: nothing installed" not_exists "$D/capm"

echo "== 7. happy path under dash"
if command -v dash >/dev/null 2>&1; then
  D="$WORK/i7"
  run_install happy "$D" dash
  check "dash: exit 0" rc_zero
  check "dash: installed binary prints 'capm test'" runs_ok "$D/capm"
else
  echo "SKIP: dash not installed"
fi

echo "== 8. completions hint (stderr only; no rc file is touched)"
# run_install merges stderr into $WORK/out; HOME is a scratch dir so any rc
# edit would show up there. The fake binary only answers "version", so the
# installer must not call "capm completion".
hint_case() { # hint_case <label> <SHELL value> <expected text> <forbidden text>
  local label="$1" sh_val="$2" want="$3" nope="$4"
  local d="$WORK/i8-$label" home="$WORK/home-$label"
  mkdir -p "$home"
  RC=0
  HOME="$home" SHELL="$sh_val" CAPM_DOWNLOAD_BASE="http://127.0.0.1:$PORT/happy" CAPM_INSTALL_DIR="$d" \
    sh "$INSTALL_SH" >"$WORK/out" 2>&1 || RC=$?
  check "$label: exit 0" rc_zero
  check "$label: hint says '$want'" out_has "$want"
  if [ -n "$nope" ]; then check "$label: hint does not mention '$nope'" not_out_has "$nope"; fi
  check "$label: exactly one hint line" test "$(grep -c -i 'completion' "$WORK/out")" = 1
  check "$label: HOME untouched (no rc edits)" no_leftovers "$home"
  check "$label: installed binary still works" runs_ok "$d/capm"
}
not_out_has() { ! grep -q -- "$1" "$WORK/out"; }
hint_case bash /bin/bash "source <(capm completion bash)" "completion zsh"
hint_case zsh /usr/bin/zsh "source <(capm completion zsh)" "completion bash"
hint_case fish /opt/homebrew/bin/fish "capm completion fish >" "completion zsh"
hint_case unknown /bin/tcsh "capm completion" "source <("
hint_case noshell "" "capm completion" "source <("
check "hint goes to stderr, not stdout" test -z "$(HOME="$WORK/home-bash" SHELL=/bin/bash CAPM_DOWNLOAD_BASE="http://127.0.0.1:$PORT/happy" CAPM_INSTALL_DIR="$WORK/i8-out" sh "$INSTALL_SH" 2>/dev/null)"

echo
if [ "$FAILS" -ne 0 ]; then
  echo "$FAILS check(s) FAILED"
  exit 1
fi
echo "all checks passed"
