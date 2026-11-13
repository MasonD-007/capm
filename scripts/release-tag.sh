#!/usr/bin/env bash
# Helpers for .github/workflows/cli-release.yml (tested by scripts/test-cli-release.sh).
#
#   release-tag.sh classify TAG     print "release" (vX.Y.Z) or "prerelease"
#                                   (vX.Y.Z-pre); exit 1 for anything else
#   release-tag.sh version TAG      print TAG without the leading v (same validation)
#   release-tag.sh check-main TAG   exit 0 only if TAG's commit is reachable from
#                                   origin/main; exit 1 with a clear message otherwise
set -eu

TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

die() {
  echo "release-tag: $*" >&2
  exit 1
}

valid() {
  # bash [[ =~ ]] is anchored by the regex itself; reject newlines explicitly.
  case "$1" in *$'\n'*) return 1 ;; esac
  [[ "$1" =~ $TAG_RE ]] && [[ "$1" != *- ]]
}

cmd="${1:-}"
tag="${2-}"

case "$cmd" in
  classify)
    valid "$tag" || die "'$tag' is not a release tag (want vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-prerelease)"
    case "$tag" in
      *-*) echo prerelease ;;
      *) echo release ;;
    esac
    ;;
  version)
    valid "$tag" || die "'$tag' is not a release tag (want vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-prerelease)"
    echo "${tag#v}"
    ;;
  check-main)
    valid "$tag" || die "'$tag' is not a release tag"
    git rev-parse --verify --quiet "refs/remotes/origin/main^{commit}" >/dev/null ||
      die "origin/main is not available in this checkout (fetch full history of main first)"
    commit="$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}")" ||
      die "tag $tag does not exist in this checkout"
    if ! git merge-base --is-ancestor "$commit" refs/remotes/origin/main; then
      die "tag $tag points at ${commit}, which is not on main; tags must point at a commit on main. Delete the tag (git push origin :refs/tags/$tag) and re-tag a commit on main."
    fi
    ;;
  *)
    echo "usage: release-tag.sh classify|version|check-main TAG" >&2
    exit 2
    ;;
esac
