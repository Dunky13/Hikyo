#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

if [ "$#" -ne 4 ]; then
	printf 'usage: %s VERSION TRUST_ROOT VERIFIER OUTPUT\n' "$0" >&2
	exit 2
fi

version=$1
root=$2
verifier=$3
output=$4
template="$script_dir/../../install/install.sh.in"
release_lib="$script_dir/../lib/release.sh"

is_semver "$version" || { printf 'installer: invalid version %s\n' "$version" >&2; exit 2; }
[ -f "$root" ] || { printf 'installer: missing trust root\n' >&2; exit 2; }
[ -f "$verifier" ] || { printf 'installer: missing verifier\n' >&2; exit 2; }
[ -f "$release_lib" ] || { printf 'installer: missing verifier library\n' >&2; exit 2; }
[ -f "$template" ] || { printf 'installer: missing template\n' >&2; exit 2; }

root_sha=$(sha256_file "$root")
verifier_sha=$(sha256_file "$verifier")
release_lib_sha=$(sha256_file "$release_lib")
sed \
	-e "s/@VERSION@/$version/g" \
	-e "s/@ROOT_SHA256@/$root_sha/g" \
	-e "s/@VERIFIER_SHA256@/$verifier_sha/g" \
	-e "s/@RELEASE_LIB_SHA256@/$release_lib_sha/g" \
	"$template" >"$output"
chmod +x "$output"
printf 'installer: wrote %s with pinned trust root\n' "$output"
