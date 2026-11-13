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

# --- homebrew-formula ---------------------------------------------------------
FORMULASH="$ROOT/scripts/homebrew-formula.sh"
A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
C=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
D=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SUMS="$WORK/sums-ok.txt"
printf '%s  capm-darwin-amd64\n%s  capm-darwin-arm64\n%s  capm-linux-amd64\n%s  capm-linux-arm64\n' "$A" "$B" "$C" "$D" >"$SUMS"

# fexpect <name> <want-exit> -- cmd...: like expect, stdout kept in $WORK/f.out
fexpect() {
  local name="$1" want="$2"
  shift 3
  "$@" >"$WORK/f.out" 2>"$WORK/f.err"
  local code=$?
  if [ "$code" != "$want" ]; then bad "$name" "exit $code, want $want (stderr: $(cat "$WORK/f.err"))"; return 1; fi
  ok "$name"
}
# fhas <name> <fixed string> : $WORK/f.out contains it; fnot: it does not
fhas() { if grep -qF -- "$2" "$WORK/f.out"; then ok "$1"; else bad "$1" "missing: $2"; fi; }
fnot() { if grep -qF -- "$2" "$WORK/f.out"; then bad "$1" "unexpected: $2"; else ok "$1"; fi; }
ferr() { if grep -qF -- "$2" "$WORK/f.err"; then ok "$1"; else bad "$1" "stderr was: $(cat "$WORK/f.err")"; fi; }

if fexpect "formula: sample checksums" 0 -- bash "$FORMULASH" 1.2.3 "$SUMS"; then
  cp "$WORK/f.out" "$WORK/capm.rb"
  fhas "formula: class"            "class Capm < Formula"
  fhas "formula: homepage"         'homepage "https://capm.masondrake.dev"'
  fhas "formula: desc"             'desc "'
  fhas "formula: version"          'version "1.2.3"'
  fhas "formula: on_macos"         "on_macos do"
  fhas "formula: on_linux"         "on_linux do"
  fhas "formula: on_arm"           "on_arm do"
  fhas "formula: on_intel"         "on_intel do"
  fhas "formula: darwin-arm64 url" 'url "https://github.com/MasonD-007/capm/releases/download/v1.2.3/capm-darwin-arm64"'
  fhas "formula: darwin-amd64 url" 'url "https://github.com/MasonD-007/capm/releases/download/v1.2.3/capm-darwin-amd64"'
  fhas "formula: linux-arm64 url"  'url "https://github.com/MasonD-007/capm/releases/download/v1.2.3/capm-linux-arm64"'
  fhas "formula: linux-amd64 url"  'url "https://github.com/MasonD-007/capm/releases/download/v1.2.3/capm-linux-amd64"'
  fhas "formula: darwin-amd64 sha" "sha256 \"$A\""
  fhas "formula: darwin-arm64 sha" "sha256 \"$B\""
  fhas "formula: linux-amd64 sha"  "sha256 \"$C\""
  fhas "formula: linux-arm64 sha"  "sha256 \"$D\""
  fhas "formula: installs as capm" 'bin.install Dir["capm-*"].first => "capm"'
  fhas "formula: completions"      'generate_completions_from_executable(bin/"capm", "completion"'
  fhas "formula: test block"       'assert_match version.to_s, shell_output("#{bin}/capm version")'
  # Each checksum sits right under its own url.
  if awk '/capm-darwin-arm64"/{getline; print}' "$WORK/capm.rb" | grep -q "$B" \
    && awk '/capm-darwin-amd64"/{getline; print}' "$WORK/capm.rb" | grep -q "$A" \
    && awk '/capm-linux-arm64"/{getline; print}' "$WORK/capm.rb" | grep -q "$D" \
    && awk '/capm-linux-amd64"/{getline; print}' "$WORK/capm.rb" | grep -q "$C"; then ok "formula: each sha256 follows its own url"; else bad "formula: each sha256 follows its own url"; fi
  if command -v ruby >/dev/null 2>&1; then
    if ruby -c "$WORK/capm.rb" >"$WORK/ruby.out" 2>&1; then ok "formula: ruby -c"; else bad "formula: ruby -c" "$(cat "$WORK/ruby.out")"; fi
    # Evaluate it against a stub Formula to check the platform blocks.
    cat >"$WORK/stub.rb" <<'RUBY'
$ctx = []
$got = {}
class Formula
  class << self
    def desc(v); end
    def homepage(v); end
    def version(v); end
    def test; end # Formula's "test do" block; Kernel#test would otherwise be called
    def on_macos; $ctx.push("macos"); yield; $ctx.pop; end
    def on_linux; $ctx.push("linux"); yield; $ctx.pop; end
    def on_arm; $ctx.push("arm"); yield; $ctx.pop; end
    def on_intel; $ctx.push("intel"); yield; $ctx.pop; end
    def url(v); ($got[$ctx.join("/")] ||= {})[:url] = v; end
    def sha256(v); ($got[$ctx.join("/")] ||= {})[:sha] = v; end
  end
end
load ARGV[0]
want = {
  "macos/arm" => "capm-darwin-arm64", "macos/intel" => "capm-darwin-amd64",
  "linux/arm" => "capm-linux-arm64", "linux/intel" => "capm-linux-amd64",
}
want.each do |k, asset|
  g = $got[k] or abort("no block for #{k}")
  abort("#{k}: url #{g[:url]}") unless g[:url].end_with?("/v1.2.3/#{asset}")
  abort("#{k}: sha #{g[:sha]}") unless g[:sha] =~ /\A[0-9a-f]{64}\z/
end
abort("extra blocks: #{$got.keys}") unless $got.size == 4
RUBY
    if ruby "$WORK/stub.rb" "$WORK/capm.rb" >"$WORK/ruby.out" 2>&1; then ok "formula: platform blocks map to the right assets (ruby stub)"; else bad "formula: platform blocks map to the right assets (ruby stub)" "$(cat "$WORK/ruby.out")"; fi
  else
    echo "SKIP formula: ruby is not installed; the formula was not syntax-checked"
  fi
fi

# the same checksums as `sha256sum` writes them in binary mode ("*name")
sed 's/  capm-/ *capm-/' "$SUMS" >"$WORK/sums-star.txt"
fexpect "formula: binary-mode checksums" 0 -- bash "$FORMULASH" 1.2.3 "$WORK/sums-star.txt"
# checksums.txt with unrelated lines is fine
{ cat "$SUMS"; printf '%s  other-file\n' "$A"; } >"$WORK/sums-extra.txt"
fexpect "formula: extra lines ignored" 0 -- bash "$FORMULASH" 1.2.3 "$WORK/sums-extra.txt"

fexpect "formula: no args"            2 -- bash "$FORMULASH"
fexpect "formula: one arg"            2 -- bash "$FORMULASH" 1.2.3
fexpect "formula: three args"         2 -- bash "$FORMULASH" 1.2.3 "$SUMS" x
for v in v1.2.3 1.2 1.2.3.4 1.2.3-rc.1 1.2.3+meta 01.2.3 "" abc "1.2.3;rm -rf" "$(printf '1.2.3\nx')"; do
  fexpect "formula: rejects version '$(printf '%s' "$v" | tr '\n' '~')'" 1 -- bash "$FORMULASH" "$v" "$SUMS"
  fnot "formula: ...and prints nothing" "class"
done
fexpect "formula: missing checksums file" 1 -- bash "$FORMULASH" 1.2.3 "$WORK/nope.txt"
for asset in capm-darwin-amd64 capm-darwin-arm64 capm-linux-amd64 capm-linux-arm64; do
  grep -v " $asset\$" "$SUMS" >"$WORK/sums-missing.txt"
  fexpect "formula: $asset missing from checksums" 1 -- bash "$FORMULASH" 1.2.3 "$WORK/sums-missing.txt"
  ferr "formula: ...names $asset" "$asset"
  fnot "formula: ...and prints nothing" "class"
done
sed 's/^a*/abc/' "$SUMS" >"$WORK/sums-short.txt"
fexpect "formula: short digest"       1 -- bash "$FORMULASH" 1.2.3 "$WORK/sums-short.txt"
ferr "formula: ...says 64 hex"        "64 lowercase hex"
sed '1s/^a/g/' "$SUMS" >"$WORK/sums-nothex.txt"
fexpect "formula: non-hex digest"     1 -- bash "$FORMULASH" 1.2.3 "$WORK/sums-nothex.txt"
sed '1s/^a/A/' "$SUMS" >"$WORK/sums-upper.txt"
fexpect "formula: uppercase digest"   1 -- bash "$FORMULASH" 1.2.3 "$WORK/sums-upper.txt"
{ cat "$SUMS"; printf '%s  capm-linux-arm64\n' "$A"; } >"$WORK/sums-dup.txt"
fexpect "formula: duplicate entry"    1 -- bash "$FORMULASH" 1.2.3 "$WORK/sums-dup.txt"
: >"$WORK/sums-empty.txt"
fexpect "formula: empty checksums"    1 -- bash "$FORMULASH" 1.2.3 "$WORK/sums-empty.txt"
# real checksums from the build above feed straight through
if [ -s "$OUT/checksums.txt" ]; then
  fexpect "formula: real build checksums" 0 -- bash "$FORMULASH" 9.8.7 "$OUT/checksums.txt"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
