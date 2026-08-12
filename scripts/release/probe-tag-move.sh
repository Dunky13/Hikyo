#!/bin/sh
set -eu

: "${GH_BIN:=gh}"

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

if [ "$#" -ne 3 ]; then
	printf 'usage: %s OWNER/REPO TAG REPLACEMENT_SHA\n' "$0" >&2
	exit 2
fi
[ "${HIKYO_ALLOW_IMMUTABLE_TAG_PROBE:-}" = YES ] || {
	printf 'tag probe refused: set HIKYO_ALLOW_IMMUTABLE_TAG_PROBE=YES only for the disposable probe tag\n' >&2
	exit 2
}

repository=$1
tag=$2
replacement_sha=$3

[ "$tag" = v-ruleset-probe ] || {
	printf 'tag probe refused: only v-ruleset-probe is disposable\n' >&2
	exit 2
}
is_full_sha "$replacement_sha" || { printf 'tag probe refused: replacement SHA must be full\n' >&2; exit 2; }

current_commit=$(git rev-parse "$tag^{commit}")
replacement_commit=$(git rev-parse "$replacement_sha^{commit}")
[ "$replacement_commit" != "$current_commit" ] || {
	printf 'tag probe refused: replacement must differ from current probe tag\n' >&2
	exit 2
}
probe_error=$(mktemp "${TMPDIR:-/tmp}/hikyo-tag-probe.XXXXXX")
trap 'rm -f "$probe_error"' EXIT HUP INT TERM

if "$GH_BIN" api --method PATCH "repos/$repository/git/refs/tags/$tag" \
	-f sha="$replacement_commit" -F force=true >/dev/null 2>"$probe_error"; then
	printf 'tag-move probe FAILED: GitHub accepted a forced update of %s\n' "$tag" >&2
	exit 1
fi
grep -F 'Repository rule violations found' "$probe_error" >/dev/null || {
	printf 'tag-move probe failed inconclusively: %s\n' "$(tr '\n' ' ' <"$probe_error")" >&2
	exit 1
}

printf 'tag-move probe passed: GitHub refused moving %s\n' "$tag"
