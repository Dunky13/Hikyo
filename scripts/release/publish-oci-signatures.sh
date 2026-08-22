#!/bin/sh
set -eu

: "${COSIGN_BIN:=cosign}"

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

if [ "$#" -ne 4 ]; then
	printf 'usage: %s VERIFIED_BUNDLE TRUST_ROOT TRUST_METADATA METADATA_SIGNATURE\n' "$0" >&2
	exit 2
fi

bundle=$1
root=$2
metadata=$3
metadata_signature=$4
manifest="$bundle/release-manifest.json"
[ -f "$manifest" ] || { printf 'publish signatures: missing release manifest\n' >&2; exit 2; }
manifest_signature="$bundle/release-manifest.sigstore.json"
[ -f "$manifest_signature" ] || { printf 'publish signatures: missing manifest signature\n' >&2; exit 2; }
publish_state=$(mktemp "${TMPDIR:-/tmp}/hikyo-publish-state.XXXXXX")
rm -f "$publish_state"
trap 'rm -f "$publish_state"' EXIT HUP INT TERM
"$script_dir/verify-bundle.sh" \
	--root "$root" \
	--metadata "$metadata" \
	--metadata-signature "$metadata_signature" \
	--bundle "$bundle" \
	--state "$publish_state" \
	--latest >/dev/null || {
	printf 'publish signatures: bundle is not candidate-authorized\n' >&2
	exit 1
}
candidate="$bundle/release-candidate.json"
public_key_name=$(jq -r '.public_key' "$candidate")
root_dir=$(CDPATH='' cd -- "$(dirname "$root")" && pwd)
public_key="$root_dir/$public_key_name"
[ -f "$public_key" ] || { printf 'publish signatures: missing candidate public key\n' >&2; exit 2; }

count=$(jq -r '[.artifacts[] | select(.kind == "oci-payload")] | length' "$manifest")
[ "$count" -eq 2 ] || { printf 'publish signatures: expected image and chart payloads\n' >&2; exit 1; }
i=0
while [ "$i" -lt "$count" ]; do
	name=$(jq -r --argjson i "$i" '[.artifacts[] | select(.kind == "oci-payload")][$i].name' "$manifest")
	subject=$(jq -r --argjson i "$i" '[.artifacts[] | select(.kind == "oci-payload")][$i].subject' "$manifest")
	want_sha=$(jq -r --argjson i "$i" '[.artifacts[] | select(.kind == "oci-payload")][$i].sha256' "$manifest")
	safe_release_name "$name" || { printf 'publish signatures: unsafe payload name\n' >&2; exit 1; }
	payload="$bundle/$name"
	signature="$payload.signature"
	[ -f "$payload" ] || { printf 'publish signatures: missing %s\n' "$name" >&2; exit 1; }
	[ -s "$signature" ] || { printf 'publish signatures: missing raw signature for %s\n' "$name" >&2; exit 1; }
	[ "$(sha256_file "$payload")" = "$want_sha" ] \
		|| { printf 'publish signatures: payload hash mismatch for %s\n' "$name" >&2; exit 1; }
	"$COSIGN_BIN" verify-blob --insecure-ignore-tlog --key "$public_key" \
		--bundle "$payload.sigstore.json" "$payload" >/dev/null \
		|| { printf 'publish signatures: payload signature invalid for %s\n' "$name" >&2; exit 1; }
	"$COSIGN_BIN" attach signature --payload "$payload" --signature "$signature" "$subject"
	"$COSIGN_BIN" verify --insecure-ignore-tlog --key "$public_key" "$subject" >/dev/null
	printf 'publish signatures: verified %s\n' "$subject"
	i=$((i + 1))
done
rm -f "$publish_state"
trap - EXIT HUP INT TERM
