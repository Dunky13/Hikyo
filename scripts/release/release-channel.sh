#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

[ "$#" -eq 1 ] || { printf 'usage: %s TAG\n' "$0" >&2; exit 2; }
tag=$1
version=${tag#v}
if [ "$tag" = "$version" ] || ! is_semver "$version"; then
	printf 'release channel: invalid tag %s\n' "$tag" >&2
	exit 2
fi

core_version=${version%%+*}
case "$core_version" in
	0.* | *-*) printf 'prerelease\n' ;;
	*) printf 'stable\n' ;;
esac
