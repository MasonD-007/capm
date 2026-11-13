#!/usr/bin/env bash
# Local test of publish.sh with a stub `capm`; no network, no GitHub.
#   bash .github/actions/publish/test.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/publish.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
check() { # check <name> <condition-exit-status>
  if [[ "$2" == 0 ]]; then pass=$((pass + 1)); else echo "FAIL: $1"; exit 1; fi
}

# The stub records its arguments and the credential environment per call, and
# prints a fake registry token for `login --oidc`.
cat >"$work/capm" <<'EOF'
#!/usr/bin/env bash
echo "$* | CAPM_TOKEN=${CAPM_TOKEN:-} CAPM_OWNER=${CAPM_OWNER:-} CAPM_REGISTRY=${CAPM_REGISTRY:-}" >>"$STUB_LOG"
if [[ "$1 $2" == "login --oidc" ]]; then
  [[ "${STUB_LOGIN_FAIL:-}" == 1 ]] && { echo "capm login --oidc: refused" >&2; exit 1; }
  echo "fake-registry-token-123"
fi
exit "${STUB_EXIT:-0}"
EOF
chmod +x "$work/capm"

readcalls() { calls=(); while IFS= read -r l; do calls+=("$l"); done <"$work/log"; }

run() { # run <extra env...> -- ; output in $work/out, status in $?
  : >"$work/log"
  env STUB_LOG="$work/log" PUBLISH_CAPM_BIN="$work/capm" RUNNER_TEMP="$work" \
    ACTIONS_ID_TOKEN_REQUEST_URL=https://x.actions.githubusercontent.com/t \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN=req-token GITHUB_REPOSITORY_OWNER=alice \
    "$@" bash "$script" publish >"$work/out" 2>&1
}

# 1. Happy path: login, lint --strict, push, in that order, token masked.
run INPUT_DIRECTORY=bundle INPUT_STRICT=true && s=0 || s=$?
check "happy path exits 0" "$s"
readcalls
[[ "${calls[0]}" == login\ --oidc* ]]; check "login first" $?
[[ "${calls[1]}" == "lint --strict bundle |"* ]]; check "lint --strict second" $?
[[ "${calls[2]}" == "push bundle |"* ]]; check "push third" $?
[[ "${calls[1]}" == *"CAPM_TOKEN=fake-registry-token-123 CAPM_OWNER=alice"* ]]; check "token and owner exported to lint" $?
[[ "${calls[2]}" == *"CAPM_TOKEN=fake-registry-token-123 CAPM_OWNER=alice"* ]]; check "token and owner exported to push" $?
[[ "${calls[0]}" != *"fake-registry-token-123"* ]]; check "login runs without a token" $?
grep -q '^::add-mask::fake-registry-token-123$' "$work/out"; check "token is masked" $?
# The mask line must come before any use of the token (and the token is never
# echoed anywhere else).
[[ "$(grep -c 'fake-registry-token-123' "$work/out")" == 1 ]]; check "token appears only in the mask command" $?

# 2. strict=false drops --strict.
run INPUT_DIRECTORY=. INPUT_STRICT=false; readcalls
[[ "${calls[1]}" == "lint . |"* ]]; check "strict=false" $?

# 3. A directory starting with - is not read as a flag.
run INPUT_DIRECTORY=-rf; readcalls
[[ "${calls[2]}" == "push ./-rf |"* ]]; check "leading dash directory" $?

# 4. Missing id-token permission: clear error, nothing runs.
run ACTIONS_ID_TOKEN_REQUEST_URL= && s=0 || s=$?
[[ "$s" != 0 ]]; check "no id-token exits non-zero" $?
grep -q 'id-token: write' "$work/out"; check "error names permissions: id-token: write" $?
[[ ! -s "$work/log" ]]; check "nothing ran without id-token" $?

# 5. Failure of the exchange stops before lint/push.
run STUB_LOGIN_FAIL=1 && s=0 || s=$?
[[ "$s" != 0 ]]; check "login failure fails the action" $?
[[ "$(wc -l <"$work/log" | tr -d ' ')" == 1 ]]; check "no lint or push after a failed login" $?

# 6. A failing lint stops before push.
run STUB_EXIT=1 && s=0 || s=$?
[[ "$s" != 0 ]]; check "lint failure fails the action" $?

# 7. Input validation.
for bad in http://registry.example ftp://x '' 'https://a b'; do
  run INPUT_REGISTRY="$bad" && s=0 || s=$?
  if [[ -z "$bad" ]]; then continue; fi # empty means the default
  [[ "$s" != 0 ]]; check "registry '$bad' refused" $?
done
run INPUT_REGISTRY=http://127.0.0.1:9; check "loopback http registry allowed (local testing)" $?
run INPUT_STRICT=maybe && s=0 || s=$?
[[ "$s" != 0 ]]; check "bad strict refused" $?
for bad in 'a/b' '../x' 'v1;rm -rf' ''; do
  env RUNNER_TEMP="$work" INPUT_VERSION="$bad" INPUT_REGISTRY=https://r.example bash "$script" install >"$work/out" 2>&1 && s=0 || s=$?
  if [[ -z "$bad" ]]; then continue; fi
  [[ "$s" != 0 ]]; check "version '$bad' refused" $?
done

# 8. Token never reaches GITHUB_ENV / GITHUB_OUTPUT.
: >"$work/ghenv"
run GITHUB_ENV="$work/ghenv" GITHUB_OUTPUT="$work/ghenv"
[[ ! -s "$work/ghenv" ]]; check "nothing written to GITHUB_ENV/GITHUB_OUTPUT" $?

echo "publish action script: $pass checks passed"
