#!/usr/bin/env bash
# Steps of the capm "publish" composite action (action.yml). Kept in a script,
# not inline YAML, so it can be run and tested locally (see test.sh).
#
#   publish.sh install   download and install the capm CLI into $RUNNER_TEMP
#   publish.sh publish   exchange the job's OIDC identity for a registry token,
#                        then lint and push
#
# Inputs arrive as environment variables set from `inputs.*` in action.yml
# (never interpolated into the script text):
#   INPUT_DIRECTORY  bundle directory                  (default .)
#   INPUT_REGISTRY   registry base URL                 (default https://capm.masondrake.dev)
#   INPUT_VERSION    CLI release tag, or "latest"      (default latest)
#   INPUT_STRICT     "true" runs `capm lint --strict`  (default true)
# Test hook: PUBLISH_CAPM_BIN uses that binary instead of the installed one.
set -euo pipefail

directory="${INPUT_DIRECTORY:-.}"
registry="${INPUT_REGISTRY:-https://capm.masondrake.dev}"
registry="${registry%/}"
version="${INPUT_VERSION:-latest}"
strict="${INPUT_STRICT:-true}"
tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
bin_dir="${tmp}/capm-bin"

fail() {
  # GitHub renders ::error:: as an annotation; the text goes to the log too.
  echo "::error title=capm publish::$*"
  echo "capm publish: $*" >&2
  exit 1
}

# https only. Plain http is accepted for a loopback registry (local testing),
# the same exception the backend makes for its own URLs.
check_registry() {
  case "$registry" in
    https://?*) ;;
    http://127.0.0.1 | http://127.0.0.1:* | http://localhost | http://localhost:*) ;;
    *) fail "registry must be an https:// URL (got: ${registry:0:80})" ;;
  esac
  case "$registry" in
    *[[:space:]]* | *[[:cntrl:]]*) fail "registry contains whitespace or control characters" ;;
  esac
}

install_cli() {
  check_registry
  if [[ ! "$version" =~ ^[A-Za-z0-9._-]+$ ]]; then
    fail "version must be \"latest\" or a release tag such as cli-<sha> (letters, digits, . _ -)"
  fi
  local proto='=https'
  case "$registry" in http://*) proto='=http,https' ;; esac
  mkdir -p "$bin_dir"
  local installer="${tmp}/capm-install.sh"
  # TRUST: this runs the installer served by the registry's website, which
  # then downloads the release binary and checks it against the release's
  # checksums.txt. Both come from the same two origins (the registry site and
  # GitHub Releases); nothing here pins them beyond that.
  curl -fsSL --proto "$proto" --tlsv1.2 --max-time 60 -o "$installer" "${registry}/install.sh" ||
    fail "could not download ${registry}/install.sh"
  if [[ "$version" == latest ]]; then
    CAPM_INSTALL_DIR="$bin_dir" sh "$installer" || fail "installing capm failed"
  else
    CAPM_INSTALL_DIR="$bin_dir" \
      CAPM_DOWNLOAD_BASE="https://github.com/MasonD-007/capm/releases/download/${version}" \
      sh "$installer" || fail "installing capm ${version} failed"
  fi
}

publish() {
  check_registry
  local capm="${PUBLISH_CAPM_BIN:-${bin_dir}/capm}"
  [[ -x "$capm" ]] || fail "the capm CLI is not installed at ${capm}"
  case "$strict" in true | false) ;; *) fail "strict must be true or false" ;; esac
  # A leading "-" would be read as a flag.
  case "$directory" in -*) directory="./${directory}" ;; esac

  if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" || -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
    fail "no OIDC token is available to this job. Add 'permissions: id-token: write' (and 'contents: read') to the workflow or job that uses this action."
  fi
  if [[ -z "${GITHUB_REPOSITORY_OWNER:-}" ]]; then
    fail "GITHUB_REPOSITORY_OWNER is not set; this action only runs inside GitHub Actions"
  fi

  export CAPM_REGISTRY="$registry"
  # The token lives only in this process and its children: it is not written
  # to GITHUB_ENV or GITHUB_OUTPUT, so the caller's later steps never see it.
  local token
  token="$("$capm" login --oidc)" || fail "could not exchange the OIDC token with ${registry} (see the messages above)"
  echo "::add-mask::${token}"
  export CAPM_TOKEN="$token"
  # A publish-only token cannot say whose it is; the namespace is the
  # repository owner (the registry refuses anything else).
  export CAPM_OWNER="$GITHUB_REPOSITORY_OWNER"
  unset token

  # version_not_bumped is a registry comparison. It works with CAPM_TOKEN
  # (it only reads public bundle data), so lint runs online here.
  if [[ "$strict" == true ]]; then
    "$capm" lint --strict "$directory"
  else
    "$capm" lint "$directory"
  fi
  "$capm" push "$directory"
}

case "${1:-}" in
  install) install_cli ;;
  publish) publish ;;
  *) echo "usage: publish.sh install|publish" >&2; exit 2 ;;
esac
