#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || {
	printf 'usage: %s TRUST_METADATA VERSION COMMIT [pending]\n' "$0" >&2
	exit 2
}

resolve_release_candidate "$@"
