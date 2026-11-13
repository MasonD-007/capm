#!/bin/sh
# capm installer: curl -fsSL https://capm.masondrake.dev/install.sh | sh
#
# Downloads the capm CLI for your OS/CPU from GitHub Releases, verifies its
# SHA-256 against the release's checksums.txt, and installs it. No sudo, no
# telemetry, no shell rc edits.
#
# Environment:
#   CAPM_INSTALL_DIR     install directory (default: $HOME/.local/bin)
#   CAPM_DOWNLOAD_BASE   release download URL prefix
#                        (default: https://github.com/MasonD-007/capm/releases/latest/download)
set -eu

TMPDIR_CAPM=""
TMPDEST=""

cleanup() {
  if [ -n "$TMPDIR_CAPM" ]; then rm -rf "$TMPDIR_CAPM"; fi
  if [ -n "$TMPDEST" ]; then rm -f "$TMPDEST"; fi
}

err() {
  printf 'capm install: %s\n' "$*" >&2
}

die() {
  err "$*"
  exit 1
}

info() {
  printf '%s\n' "$*" >&2
}

fetch() { # fetch <url> <dest>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$2" "$1" || die "download failed: $1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1" || die "download failed: $1"
  else
    die "neither curl nor wget is installed; install one and retry"
  fi
}

sha256_of() { # sha256_of <file>
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "neither sha256sum nor shasum is installed; refusing to install an unverified binary"
  fi
}

main() {
  os_raw=$(uname -s)
  case "$os_raw" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) die "unsupported operating system: $os_raw (capm supports macOS and Linux)" ;;
  esac

  arch_raw=$(uname -m)
  case "$arch_raw" in
    x86_64 | amd64) arch=amd64 ;;
    arm64 | aarch64) arch=arm64 ;;
    *) die "unsupported CPU architecture: $arch_raw (capm supports amd64 and arm64)" ;;
  esac

  asset="capm-${os}-${arch}"
  base="${CAPM_DOWNLOAD_BASE:-https://github.com/MasonD-007/capm/releases/latest/download}"
  base="${base%/}"
  install_dir="${CAPM_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}"

  trap cleanup EXIT
  trap 'exit 1' INT TERM HUP
  TMPDIR_CAPM=$(mktemp -d)

  info "Downloading ${asset}..."
  fetch "${base}/${asset}" "${TMPDIR_CAPM}/${asset}"
  fetch "${base}/checksums.txt" "${TMPDIR_CAPM}/checksums.txt"

  expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "${TMPDIR_CAPM}/checksums.txt")
  if [ -z "$expected" ]; then
    die "checksums.txt has no entry for ${asset}; refusing to install"
  fi
  actual=$(sha256_of "${TMPDIR_CAPM}/${asset}")
  if [ "$actual" != "$expected" ]; then
    err "checksum mismatch for ${asset}"
    err "  expected: ${expected}"
    err "  actual:   ${actual}"
    exit 1
  fi
  info "Checksum verified (sha256 ${actual})."

  mkdir -p "$install_dir" || die "cannot create ${install_dir}"
  dest="${install_dir}/capm"
  # Stage next to the destination so the final mv is an atomic rename on the
  # same filesystem; a running capm keeps its old inode.
  TMPDEST=$(mktemp "${install_dir}/.capm.XXXXXX") || die "cannot write to ${install_dir}"
  cp "${TMPDIR_CAPM}/${asset}" "$TMPDEST" || die "cannot write to ${install_dir}"
  chmod 755 "$TMPDEST"
  mv -f "$TMPDEST" "$dest"
  TMPDEST=""

  info "Installed capm to ${dest}"
  if ver=$("$dest" version 2>&1); then
    info "$ver"
  else
    info "warning: '${dest} version' failed: ${ver}"
  fi

  # One line telling the user how to turn on tab completion for their shell.
  # It only prints; it never edits an rc file (and never runs the binary).
  case "${SHELL:-}" in
    */bash|bash) info 'Tab completion (bash): add  eval "$(capm completion bash)"  to ~/.bashrc' ;;
    */zsh|zsh) info "Tab completion (zsh): add  source <(capm completion zsh)  to ~/.zshrc, after compinit" ;;
    */fish|fish) info "Tab completion (fish): run  capm completion fish > ~/.config/fish/completions/capm.fish" ;;
    *) info "Tab completion: run  capm completion  to see how to enable it for bash, zsh or fish" ;;
  esac

  case ":${PATH:-}:" in
    *":${install_dir}:"*) ;;
    *)
      info ""
      info "${install_dir} is not on your PATH. Add it with:"
      info "  export PATH=\"${install_dir}:\$PATH\""
      ;;
  esac
}

main "$@"
