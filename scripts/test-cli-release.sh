#!/usr/bin/env bash
# Tests scripts/release-tag.sh and scripts/build-cli.sh (used by the CLI
# release workflows) against temp git repos and a real cross-compile.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAGSH="$ROOT/scripts/release-tag.sh"
BUILDSH="$ROOT/scripts/build-cli.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT TERM

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && echo "     $2"; }

# expect <name> <want-exit> <want-stdout-or-""> -- cmd...
expect() {
  local name="$1" want="$2" wantout="$3"
  shift 4
  local out code
  out="$("$@" 2>"$WORK/stderr")"
  code=$?
  if [ "$code" != "$want" ]; then bad "$name" "exit $code, want $want (stderr: $(cat "$WORK/stderr"))"; return; fi
  if [ -n "$wantout" ] && [ "$out" != "$wantout" ]; then bad "$name" "stdout '$out', want '$wantout'"; return; fi
  ok "$name"
}

# --- classify -------------------------------------------------------------
expect "classify v1.2.3"        0 release    -- bash "$TAGSH" classify v1.2.3
expect "classify v0.0.1"        0 release    -- bash "$TAGSH" classify v0.0.1
expect "classify v10.20.30"     0 release    -- bash "$TAGSH" classify v10.20.30
expect "classify v1.2.3-rc.1"   0 prerelease -- bash "$TAGSH" classify v1.2.3-rc.1
expect "classify v1.2.3-beta"   0 prerelease -- bash "$TAGSH" classify v1.2.3-beta
expect "classify missing v"     1 ""         -- bash "$TAGSH" classify 1.2.3
expect "classify v1.2"          1 ""         -- bash "$TAGSH" classify v1.2
expect "classify v1.2.3.4"      1 ""         -- bash "$TAGSH" classify v1.2.3.4
expect "classify cli-sha tag"   1 ""         -- bash "$TAGSH" classify cli-abc123
expect "classify v1.2.3-"       1 ""         -- bash "$TAGSH" classify v1.2.3-
expect "classify v1.2.3+meta"   1 ""         -- bash "$TAGSH" classify v1.2.3+meta
expect "classify empty"         1 ""         -- bash "$TAGSH" classify ""
expect "classify v1.2.3 junk"   1 ""         -- bash "$TAGSH" classify 'v1.2.3-rc;rm'
expect "version v1.2.3"         0 1.2.3      -- bash "$TAGSH" version v1.2.3
expect "version v1.2.3-rc.1"    0 1.2.3-rc.1 -- bash "$TAGSH" version v1.2.3-rc.1
expect "version invalid"        1 ""         -- bash "$TAGSH" version nope

# --- check-main -----------------------------------------------------------
G="$WORK/repo"
git init -q "$G" && cd "$G" || exit 2
git config user.email t@example.com
git config user.name t
git checkout -q -b main
echo a >f
git add f
git commit -q -m a
# A bare "origin" so origin/main exists like in the workflow checkout.
git init -q --bare "$WORK/origin.git"
git remote add origin "$WORK/origin.git"
git push -q origin main
git fetch -q origin
git tag v1.0.0                        # on main
git tag -a v1.0.1 -m annotated        # annotated tag, on main
git checkout -q -b side
echo b >f
git commit -q -am b                   # commit NOT on main
git tag v1.1.0
git checkout -q main
echo c >f
git commit -q -am c
git push -q origin main
git fetch -q origin
git tag v1.2.0                        # newer main commit

expect "check-main lightweight on main" 0 "" -- bash "$TAGSH" check-main v1.0.0
expect "check-main annotated on main"   0 "" -- bash "$TAGSH" check-main v1.0.1
expect "check-main tip of main"         0 "" -- bash "$TAGSH" check-main v1.2.0
expect "check-main off main refused"    1 "" -- bash "$TAGSH" check-main v1.1.0
if grep -q "not on main" "$WORK/stderr"; then ok "check-main off main message"; else bad "check-main off main message" "$(cat "$WORK/stderr")"; fi
expect "check-main unknown tag"         1 "" -- bash "$TAGSH" check-main v9.9.9
git remote remove origin
expect "check-main without origin/main" 1 "" -- bash "$TAGSH" check-main v1.0.0
cd "$ROOT" || exit 2

# --- build-cli --------------------------------------------------------------
case "$(uname -s)" in Darwin) OS=darwin ;; Linux) OS=linux ;; *) OS="" ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; arm64|aarch64) ARCH=arm64 ;; *) ARCH="" ;; esac
OUT="$WORK/dist"
if bash "$BUILDSH" 9.8.7 "$OUT" >"$WORK/build.log" 2>&1; then ok "build-cli exits 0"; else bad "build-cli exits 0" "$(tail -5 "$WORK/build.log")"; fi
for t in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64; do
  if [ -s "$OUT/capm-$t" ]; then ok "built capm-$t"; else bad "built capm-$t"; fi
done
lines="$(wc -l <"$OUT/checksums.txt" 2>/dev/null | tr -d ' ')"
if [ "$lines" = 4 ]; then ok "checksums.txt has 4 lines"; else bad "checksums.txt has 4 lines" "got '$lines'"; fi
if [ -n "$OS" ] && [ -n "$ARCH" ] && [ -f "$OUT/capm-$OS-$ARCH" ]; then
  got="$("$OUT/capm-$OS-$ARCH" version 2>&1)"
  if [ "$got" = "capm 9.8.7" ]; then ok "binary reports capm 9.8.7"; else bad "binary reports capm 9.8.7" "got '$got'"; fi
  want="$( (cd "$OUT" && { sha256sum "capm-$OS-$ARCH" 2>/dev/null || shasum -a 256 "capm-$OS-$ARCH"; }) | awk '{print $1}')"
  if grep -q "^$want  capm-$OS-$ARCH$" "$OUT/checksums.txt"; then ok "checksum line matches binary"; else bad "checksum line matches binary"; fi
fi
expect "build-cli without version" 2 "" -- bash "$BUILDSH"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
