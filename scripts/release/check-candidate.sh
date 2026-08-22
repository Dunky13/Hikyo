#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

[ "$#" -eq 2 ] || {
	printf 'usage: %s RELEASE_CANDIDATE EXPECTED_SHA256\n' "$0" >&2
	exit 2
}

check_release_candidate_hash "$1" "$2"
printf 'candidate: record hash and canonical form verified\n'
