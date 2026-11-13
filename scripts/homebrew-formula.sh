#!/usr/bin/env bash
# Prints the Homebrew formula (capm.rb) for a capm CLI release to stdout.
#
#   homebrew-formula.sh <version> <checksums.txt>
#
# <version> is a plain X.Y.Z (no leading v, no prerelease: prereleases never go
# to the tap). <checksums.txt> is the release's checksums file, with one
# "<sha256>  capm-<os>-<arch>" line for each of the four release assets. The
# release workflow (cli-release.yml) pushes the output to
# MasonD-007/homebrew-capm as Formula/capm.rb. Exit 2 on a usage error, 1 on
# bad input; nothing is printed to stdout unless the whole formula can be
# generated.
set -eu

if [ $# -ne 2 ]; then
  echo "usage: homebrew-formula.sh <version> <checksums.txt>" >&2
  exit 2
fi
version="$1"
sums="$2"

die() {
  echo "homebrew-formula: $*" >&2
  exit 1
}

semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if ! [[ "$version" =~ $semver_re ]]; then
  die "version '$version' is not a plain X.Y.Z release version (prereleases are not published to the tap)"
fi
[ -f "$sums" ] || die "checksums file '$sums' not found"

# digest <asset>: the one sha256 recorded for the asset; fail when missing,
# repeated or not 64 lowercase hex digits.
digest() {
  local asset="$1" found n d
  found="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$sums")"
  n="$(printf '%s' "$found" | grep -c . || true)"
  [ "$n" -ge 1 ] || die "checksums file has no entry for $asset"
  [ "$n" -eq 1 ] || die "checksums file has $n entries for $asset"
  d="$found"
  printf '%s\n' "$d" | grep -Eq '^[0-9a-f]{64}$' || die "checksum for $asset is not 64 lowercase hex digits"
  printf '%s\n' "$d"
}

darwin_amd64="$(digest capm-darwin-amd64)" || exit 1
darwin_arm64="$(digest capm-darwin-arm64)" || exit 1
linux_amd64="$(digest capm-linux-amd64)" || exit 1
linux_arm64="$(digest capm-linux-arm64)" || exit 1

base="https://github.com/MasonD-007/capm/releases/download/v${version}"

cat <<EOF
class Capm < Formula
  desc "Share AI agents and run them in a sandbox"
  homepage "https://capm.masondrake.dev"
  version "${version}"

  on_macos do
    on_arm do
      url "${base}/capm-darwin-arm64"
      sha256 "${darwin_arm64}"
    end
    on_intel do
      url "${base}/capm-darwin-amd64"
      sha256 "${darwin_amd64}"
    end
  end

  on_linux do
    on_arm do
      url "${base}/capm-linux-arm64"
      sha256 "${linux_arm64}"
    end
    on_intel do
      url "${base}/capm-linux-amd64"
      sha256 "${linux_amd64}"
    end
  end

  def install
    # The download is the bare binary, staged under its release asset name.
    bin.install Dir["capm-*"].first => "capm"
    generate_completions_from_executable(bin/"capm", "completion", shells: [:bash, :zsh, :fish])
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/capm version")
  end
end
EOF
