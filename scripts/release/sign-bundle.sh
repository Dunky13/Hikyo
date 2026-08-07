#!/bin/sh
set -eu

: "${COSIGN_BIN:=cosign}"

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

if [ "$#" -ne 3 ]; then
	printf 'usage: %s BUNDLE PRIMARY_PRIVATE_KEY TRUST_METADATA\n' "$0" >&2
	exit 2
fi

bundle=$1
primary_key=$2
metadata=$3
manifest="$bundle/release-manifest.json"
image_digest="$bundle/image-index.digest"

[ -f "$manifest" ] || { printf 'sign: missing release manifest\n' >&2; exit 2; }
[ -f "$image_digest" ] || { printf 'sign: missing image digest\n' >&2; exit 2; }
[ -f "$primary_key" ] || { printf 'sign: missing primary private key\n' >&2; exit 2; }
[ -f "$metadata" ] || { printf 'sign: missing trust metadata\n' >&2; exit 2; }
# Every supported signing shell provides ulimit -c.
# shellcheck disable=SC3045
[ "$(ulimit -c)" = 0 ] || { printf 'sign: core dumps must be disabled with ulimit -c 0\n' >&2; exit 1; }

key_id=$(jq -r '.signing_key_id' "$manifest")
version=$(jq -r '.version' "$manifest")
release_sequence=$(jq -r '.release_sequence' "$manifest")
bound_manifest_sha=$(jq -r --arg version "$version" --argjson sequence "$release_sequence" \
	'.releases[] | select(.version == $version and .sequence == $sequence) | .manifest_sha256' "$metadata")
[ "$bound_manifest_sha" = "$(sha256_file "$manifest")" ] || {
	printf 'sign: recovery metadata does not bind this release manifest\n' >&2
	exit 1
}
authorized=$(jq -r --arg id "$key_id" --argjson sequence "$release_sequence" \
	'[.primary_keys[] | select(
		.id == $id and .revoked == false and
		.valid_from_release_sequence <= $sequence and
		(.valid_through_release_sequence == null or .valid_through_release_sequence >= $sequence)
	)] | length' "$metadata")
[ "$authorized" -eq 1 ] || { printf 'sign: manifest key %s is not uniquely authorized\n' "$key_id" >&2; exit 1; }

"$COSIGN_BIN" sign-blob --yes --new-bundle-format=false --tlog-upload=false \
	--use-signing-config=false --key "$primary_key" \
	--bundle "$bundle/release-manifest.sigstore.json" "$manifest"

artifact_count=$(jq -r '.artifacts | length' "$manifest")
i=0
while [ "$i" -lt "$artifact_count" ]; do
	name=$(jq -r --argjson i "$i" '.artifacts[$i].name' "$manifest")
	case "$name" in '' | */* | *..*) printf 'sign: unsafe artifact path %s\n' "$name" >&2; exit 1 ;; esac
	artifact="$bundle/$name"
	[ -f "$artifact" ] || { printf 'sign: missing artifact %s\n' "$name" >&2; exit 1; }
	kind=$(jq -r --argjson i "$i" '.artifacts[$i].kind' "$manifest")
	if [ "$kind" = oci-payload ]; then
		"$COSIGN_BIN" sign-blob --yes --new-bundle-format=false --tlog-upload=false \
			--use-signing-config=false --output-signature "$artifact.signature" \
			--key "$primary_key" --bundle "$artifact.sigstore.json" "$artifact" >/dev/null
		[ -s "$artifact.signature" ] || { printf 'sign: empty OCI signature for %s\n' "$name" >&2; exit 1; }
	else
		"$COSIGN_BIN" sign-blob --yes --new-bundle-format=false --tlog-upload=false \
			--use-signing-config=false --key "$primary_key" \
			--bundle "$artifact.sigstore.json" "$artifact" >/dev/null
	fi
	i=$((i + 1))
done

printf 'sign: manifest and per-artifact bundles written; re-encrypt key before network access\n'
