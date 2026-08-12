#!/bin/sh
set -eu

: "${GH_BIN:=gh}"

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

if [ "$#" -ne 3 ]; then
	printf 'usage: %s OWNER/REPO TAG EXPECTED_SHA\n' "$0" >&2
	exit 2
fi

repository=$1
tag=$2
expected_sha=$3

if [ "$tag" = "${tag#v}" ] || ! is_semver "${tag#v}"; then
	printf 'release guard: invalid tag %s\n' "$tag" >&2
	exit 1
fi
is_full_sha "$expected_sha" || { printf 'release guard: expected full SHA\n' >&2; exit 1; }

tag_sha=$(git rev-parse "$tag^{commit}")
expected_commit=$(git rev-parse "$expected_sha^{commit}") \
	|| { printf 'release guard: event SHA does not resolve to a commit\n' >&2; exit 1; }
[ "$tag_sha" = "$expected_commit" ] \
	|| { printf 'release guard: tag resolves to %s, event resolves to %s\n' "$tag_sha" "$expected_commit" >&2; exit 1; }

git fetch --quiet origin main
git merge-base --is-ancestor "$tag_sha" origin/main \
	|| { printf 'release guard: tagged commit is not reachable from main\n' >&2; exit 1; }

lookup_error=$(mktemp "${TMPDIR:-/tmp}/hikyo-release-lookup.XXXXXX")
trap 'rm -f "$lookup_error"' EXIT HUP INT TERM
if "$GH_BIN" api "repos/$repository/releases/tags/$tag" >/dev/null 2>"$lookup_error"; then
	printf 'release guard: version %s already has a GitHub release\n' "$tag" >&2
	exit 1
fi
grep -F '(HTTP 404)' "$lookup_error" >/dev/null || {
	printf 'release guard: cannot prove tag is unused: %s\n' "$(tr '\n' ' ' <"$lookup_error")" >&2
	exit 1
}

printf 'release guard: %s is unused and reachable from main\n' "$tag"
