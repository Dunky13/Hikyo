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
candidate="$bundle/release-candidate.json"

[ -f "$manifest" ] || { printf 'sign: missing release manifest\n' >&2; exit 2; }
[ -f "$image_digest" ] || { printf 'sign: missing image digest\n' >&2; exit 2; }
[ -f "$primary_key" ] || { printf 'sign: missing primary private key\n' >&2; exit 2; }
[ -f "$metadata" ] || { printf 'sign: missing trust metadata\n' >&2; exit 2; }
# Every supported signing shell provides ulimit -c.
# shellcheck disable=SC3045
[ "$(ulimit -c)" = 0 ] || { printf 'sign: core dumps must be disabled with ulimit -c 0\n' >&2; exit 1; }

verify_release_candidate_artifact "$manifest" "$bundle" || exit 1
release_manifest_matches_candidate "$manifest" "$candidate" || exit 1
authorize_release_candidate "$metadata" "$candidate" || exit 1
version=$(jq -r '.version' "$candidate")
release_sequence=$(jq -r '.sequence' "$candidate")
public_key_name=$(jq -r '.public_key' "$candidate")
trust_dir=$(CDPATH='' cd -- "$(dirname "$metadata")" && pwd)
candidate_public_key="$trust_dir/$public_key_name"
[ -f "$candidate_public_key" ] || { printf 'sign: missing candidate public key\n' >&2; exit 2; }
candidate_key_sha=$(jq -r --arg public_key "$public_key_name" \
	'.primary_keys[] | select(.public_key == $public_key) | .sha256' "$metadata")
[ "$(sha256_file "$candidate_public_key")" = "$candidate_key_sha" ] || {
	printf 'sign: candidate public-key hash mismatch\n' >&2
	exit 1
}
bound_manifest_sha=$(jq -r --arg version "$version" --argjson sequence "$release_sequence" \
	'.releases[] | select(.version == $version and .sequence == $sequence) | .manifest_sha256' "$metadata")
[ "$bound_manifest_sha" = "$(sha256_file "$manifest")" ] || {
	printf 'sign: recovery metadata does not bind this release manifest\n' >&2
	exit 1
}
"$COSIGN_BIN" sign-blob --yes --new-bundle-format=false --tlog-upload=false \
	--use-signing-config=false --key "$primary_key" \
	--bundle "$bundle/release-manifest.sigstore.json" "$manifest"
"$COSIGN_BIN" verify-blob --insecure-ignore-tlog --key "$candidate_public_key" \
	--bundle "$bundle/release-manifest.sigstore.json" "$manifest" >/dev/null || {
	rm -f "$bundle/release-manifest.sigstore.json"
	printf 'sign: private key does not match release candidate\n' >&2
	exit 1
}

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
	"$COSIGN_BIN" verify-blob --insecure-ignore-tlog --key "$candidate_public_key" \
		--bundle "$artifact.sigstore.json" "$artifact" >/dev/null || {
		printf 'sign: generated signature invalid for %s\n' "$name" >&2
		exit 1
	}
	i=$((i + 1))
done

printf 'sign: manifest and per-artifact bundles written; re-encrypt key before network access\n'
