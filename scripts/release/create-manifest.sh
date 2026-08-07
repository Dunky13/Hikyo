#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

if [ "$#" -ne 9 ]; then
	printf 'usage: %s VERSION COMMIT KEY_ID IMAGE IMAGE_DIGEST CHART CHART_DIGEST DIST TRUST_METADATA\n' "$0" >&2
	exit 2
fi

version=$1
commit=$2
key_id=$3
image=$4
image_digest=$5
chart=$6
chart_digest=$7
dist=$8
metadata=$9

is_semver "$version" || { printf 'manifest: invalid version %s\n' "$version" >&2; exit 2; }
is_full_sha "$commit" || { printf 'manifest: commit must be a full SHA\n' >&2; exit 2; }
is_digest "$image_digest" || { printf 'manifest: invalid image digest\n' >&2; exit 2; }
is_digest "$chart_digest" || { printf 'manifest: invalid chart digest\n' >&2; exit 2; }
[ -d "$dist" ] || { printf 'manifest: missing dist directory\n' >&2; exit 2; }
[ -f "$metadata" ] || { printf 'manifest: missing trust metadata\n' >&2; exit 2; }
if find "$dist" -maxdepth 1 -type l | grep . >/dev/null; then
	printf 'manifest: symlinked release artifacts are forbidden\n' >&2
	exit 1
fi

release_sequence=$(jq -r --arg version "$version" \
	'([.releases[]?, .pending_release?] | .[] | select(.version == $version) | .sequence)' "$metadata")
[ -n "$release_sequence" ] && [ "$release_sequence" != null ] \
	|| { printf 'manifest: version %s absent from trust metadata\n' "$version" >&2; exit 1; }
[ "$(printf '%s\n' "$release_sequence" | wc -l | tr -d ' ')" -eq 1 ] \
	|| { printf 'manifest: duplicate version in trust metadata\n' >&2; exit 1; }

printf '%s\n' "$image_digest" >"$dist/image-index.digest"
printf '%s\n' "$chart_digest" >"$dist/chart-index.digest"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/wenv-manifest.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
find "$dist" -maxdepth 1 -type f -print | LC_ALL=C sort >"$scratch/files"
: >"$scratch/artifacts.jsonl"

while IFS= read -r path; do
	name=$(basename "$path")
	case "$name" in
		release-manifest.json | *.sigstore.json) continue ;;
		image-index.oci-payload.json) kind='oci-payload'; subject_kind=image ;;
		chart-index.oci-payload.json) kind='oci-payload'; subject_kind=chart ;;
		wenv_*.tar.gz | wenv_*.zip) kind=binary ;;
		*.spdx.json | *.cdx.json) kind=sbom ;;
		checksums.txt) kind=checksum ;;
		image-index.digest) kind=image ;;
		chart-index.digest) kind='chart-digest' ;;
		wenv-*.tgz) kind=chart ;;
		install.sh) kind=installer ;;
		*) printf 'manifest: unclassified artifact %s\n' "$name" >&2; exit 1 ;;
	esac
	digest=$(sha256_file "$path")
	if [ "$kind" = image ]; then
		jq -nc --arg name "$name" --arg kind "$kind" --arg sha256 "$digest" \
			--arg image "$image" --arg image_digest "$image_digest" --arg tag "$version" \
			'{name: $name, kind: $kind, sha256: $sha256, image: $image, tag: $tag, digest: $image_digest}' \
			>>"$scratch/artifacts.jsonl"
	elif [ "$kind" = chart-digest ]; then
		jq -nc --arg name "$name" --arg kind "$kind" --arg sha256 "$digest" \
			--arg chart "$chart" --arg chart_digest "$chart_digest" \
			'{name: $name, kind: $kind, sha256: $sha256, chart: $chart, digest: $chart_digest}' \
			>>"$scratch/artifacts.jsonl"
	elif [ "$kind" = chart ]; then
		jq -nc --arg name "$name" --arg kind "$kind" --arg sha256 "$digest" \
			--arg version "$version" --arg image_repository "$image" --arg image_digest "$image_digest" \
			'{name: $name, kind: $kind, sha256: $sha256, chart_version: $version, app_version: $version, image_repository: $image_repository, image_digest: $image_digest}' \
			>>"$scratch/artifacts.jsonl"
	elif [ "$kind" = oci-payload ]; then
		if [ "$subject_kind" = image ]; then
			subject="$image@$image_digest"
			subject_digest=$image_digest
		else
			subject="$chart@$chart_digest"
			subject_digest=$chart_digest
		fi
		jq -nc --arg name "$name" --arg kind "$kind" --arg sha256 "$digest" \
			--arg subject_kind "$subject_kind" --arg subject "$subject" --arg subject_digest "$subject_digest" \
			'{name: $name, kind: $kind, sha256: $sha256, subject_kind: $subject_kind, subject: $subject, digest: $subject_digest}' \
			>>"$scratch/artifacts.jsonl"
	else
		jq -nc --arg name "$name" --arg kind "$kind" --arg sha256 "$digest" \
			'{name: $name, kind: $kind, sha256: $sha256}' >>"$scratch/artifacts.jsonl"
	fi
done <"$scratch/files"

jq -s \
	--arg version "$version" \
	--arg tag "v$version" \
	--arg commit "$commit" \
	--argjson release_sequence "$release_sequence" \
	--arg key_id "$key_id" \
	'{
		schema: "wenv.dev/release-manifest/v1",
		version: $version,
		tag: $tag,
		source_commit: $commit,
		release_sequence: $release_sequence,
		signing_key_id: $key_id,
		artifacts: .
	}' "$scratch/artifacts.jsonl" >"$dist/release-manifest.json"

printf 'manifest: wrote %s\n' "$dist/release-manifest.json"
