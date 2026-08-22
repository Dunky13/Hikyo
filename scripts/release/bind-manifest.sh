#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

[ "$#" -eq 3 ] || {
	printf 'usage: %s RELEASE_MANIFEST INPUT_METADATA OUTPUT_METADATA\n' "$0" >&2
	exit 2
}
manifest=$1
input=$2
output=$3
[ -f "$manifest" ] || { printf 'bind manifest: release manifest is absent\n' >&2; exit 2; }
[ -f "$input" ] || { printf 'bind manifest: trust metadata is absent\n' >&2; exit 2; }
[ "$input" != "$output" ] || { printf 'bind manifest: output must differ from input\n' >&2; exit 2; }
output_dir=$(dirname "$output")
[ -d "$output_dir" ] || { printf 'bind manifest: output directory is absent\n' >&2; exit 2; }

bundle_dir=$(CDPATH='' cd -- "$(dirname "$manifest")" && pwd)
candidate="$bundle_dir/release-candidate.json"
verify_release_candidate_artifact "$manifest" "$bundle_dir" || exit 1
release_manifest_matches_candidate "$manifest" "$candidate" || exit 1
authorize_release_candidate "$input" "$candidate" || exit 1
version=$(jq -r '.version' "$candidate")
release_sequence=$(jq -r '.sequence' "$candidate")
manifest_sha256=$(sha256_file "$manifest")
matches=$(jq -r --arg version "$version" --argjson sequence "$release_sequence" \
	'[.pending_release | select(.version == $version and .sequence == $sequence)] | length' "$input")
[ "$matches" -eq 1 ] || { printf 'bind manifest: pending release is absent or mismatched\n' >&2; exit 1; }

output_tmp=$(mktemp "$output.tmp.XXXXXX")
trap 'rm -f "$output_tmp"' EXIT HUP INT TERM
jq --arg version "$version" --argjson release_sequence "$release_sequence" \
	--arg manifest_sha256 "$manifest_sha256" '
	.sequence += 1 |
	.event = {type: "release", signed_by: .recovery.id} |
	.releases += [{version: $version, sequence: $release_sequence, manifest_sha256: $manifest_sha256}] |
	.highest_release = $version |
	.highest_release_sequence = $release_sequence |
	del(.pending_release)
	' "$input" >"$output_tmp"
mv "$output_tmp" "$output"
trap - EXIT HUP INT TERM
printf 'bind manifest: %s -> %s\n' "$version" "$manifest_sha256"
