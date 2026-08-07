#!/bin/sh
set -eu

: "${COSIGN_BIN:=cosign}"

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

fail() {
	printf 'release verification failed: %s\n' "$*" >&2
	exit 1
}

root=
metadata=
metadata_signature=
bundle=
mode=
historical_version=
state=
verify_published=false
trust_only=false

while [ "$#" -gt 0 ]; do
	case "$1" in
		--root) root=$2; shift 2 ;;
		--metadata) metadata=$2; shift 2 ;;
		--metadata-signature) metadata_signature=$2; shift 2 ;;
		--bundle) bundle=$2; shift 2 ;;
		--state) state=$2; shift 2 ;;
		--latest) mode=latest; shift ;;
		--historical) mode=historical; historical_version=$2; shift 2 ;;
		--published) verify_published=true; shift ;;
		--trust-only) trust_only=true; shift ;;
		*) fail "unknown argument $1" ;;
	esac
done

[ -n "$root" ] || fail '--root is required'
[ -n "$metadata" ] || fail '--metadata is required'
[ -n "$metadata_signature" ] || fail '--metadata-signature is required'
[ -n "$state" ] || fail '--state is required'
if [ "$trust_only" = false ]; then
	[ -n "$bundle" ] || fail '--bundle is required'
	[ -n "$mode" ] || fail 'choose --latest or --historical VERSION'
fi
command -v jq >/dev/null 2>&1 || fail 'jq is required'
command -v "$COSIGN_BIN" >/dev/null 2>&1 || fail "cosign not found: $COSIGN_BIN"

root_dir=$(CDPATH='' cd -- "$(dirname "$root")" && pwd)
[ -f "$root" ] || fail "missing trust root $root"
[ -f "$metadata" ] || fail "missing trust metadata $metadata"
[ -f "$metadata_signature" ] || fail "missing trust metadata signature $metadata_signature"

jq -e '
	.schema == "wenv.dev/trust-root/v1" and
	(.recovery.id | type == "string" and length > 0) and
	(.recovery.public_key | type == "string" and length > 0) and
	(.recovery.sha256 | test("^[0-9a-f]{64}$")) and
	(.bootstrap_primary.id | type == "string" and length > 0) and
	(.bootstrap_primary.public_key | type == "string" and length > 0) and
	(.bootstrap_primary.sha256 | test("^[0-9a-f]{64}$"))
' "$root" >/dev/null || fail 'invalid trust root schema'

recovery_id=$(jq -r '.recovery.id' "$root")
recovery_name=$(jq -r '.recovery.public_key' "$root")
recovery_sha=$(jq -r '.recovery.sha256' "$root")
safe_release_name "$recovery_name" || fail 'unsafe recovery public-key path'
recovery_key="$root_dir/$recovery_name"
[ -f "$recovery_key" ] || fail "missing recovery public key $recovery_name"
[ "$(sha256_file "$recovery_key")" = "$recovery_sha" ] || fail 'recovery public-key hash mismatch'

jq -e --arg recovery_id "$recovery_id" --arg recovery_sha "$recovery_sha" '
	. as $metadata |
	.event.type as $event_type |
	.schema == "wenv.dev/trust-metadata/v1" and
	((.sequence | type) == "number") and .sequence >= 1 and (.sequence | floor) == .sequence and
	.recovery.id == $recovery_id and
	.recovery.sha256 == $recovery_sha and
	.event.signed_by == $recovery_id and
	(["bootstrap", "release-candidate", "release", "rotation", "revocation"] | index($event_type)) != null and
	(.primary_keys | type == "array" and length > 0) and
	(.releases | type == "array") and
	([.releases[].version] | unique | length) == (.releases | length) and
	([.releases[].sequence] | unique | length) == (.releases | length) and
	(if $event_type == "bootstrap" and (.releases | length) == 0 then
		.sequence == 1 and
		.highest_release == null and
		.highest_release_sequence == null and
		(.pending_release.version | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][0-9A-Za-z.-]+)?$")) and
		.pending_release.sequence == 1 and
		.pending_release.manifest_sha256 == ("0" * 64)
	else
		(.highest_release | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][0-9A-Za-z.-]+)?$")) and
		((.highest_release_sequence | type) == "number") and .highest_release_sequence >= 1 and
		(.highest_release_sequence | floor) == .highest_release_sequence and
		(.releases | length) > 0 and
		all(.releases[]; .manifest_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
		(.pending_release == null or (
			(.pending_release.version | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][0-9A-Za-z.-]+)?$")) and
			((.pending_release.sequence | type) == "number") and
			(.pending_release.sequence > .highest_release_sequence) and
			(.pending_release.manifest_sha256 == ("0" * 64)) and
			([.releases[] | select(.version == $metadata.pending_release.version or .sequence == $metadata.pending_release.sequence)] | length) == 0
		)) and
		([.releases[] | select(.version == $metadata.highest_release and .sequence == $metadata.highest_release_sequence)] | length) == 1
	end)
' "$metadata" >/dev/null || fail 'invalid trust metadata'

"$COSIGN_BIN" verify-blob --insecure-ignore-tlog \
	--key "$recovery_key" --bundle "$metadata_signature" "$metadata" >/dev/null \
	|| fail 'trust metadata is not signed by pinned recovery root'

metadata_sequence=$(jq -r '.sequence' "$metadata")
bootstrap_id=$(jq -r '.bootstrap_primary.id' "$root")
bootstrap_sha=$(jq -r '.bootstrap_primary.sha256' "$root")
bootstrap_matches=$(jq -r \
	--arg id "$bootstrap_id" --arg sha "$bootstrap_sha" \
	'[.primary_keys[] | select(.id == $id and .sha256 == $sha and .valid_from_release_sequence == 1)] | length' \
	"$metadata")
[ "$bootstrap_matches" -eq 1 ] || fail 'bootstrap primary does not match pinned root'

jq -e '
	all(.primary_keys[]; . as $key |
		($key.id | type == "string" and length > 0) and
		($key.public_key | type == "string" and length > 0) and
		($key.sha256 | test("^[0-9a-f]{64}$")) and
		(($key.valid_from_release_sequence | type) == "number") and
		($key.valid_from_release_sequence >= 1) and
		(($key.valid_from_release_sequence | floor) == $key.valid_from_release_sequence) and
		($key.valid_through_release_sequence == null or
			((($key.valid_through_release_sequence | type) == "number") and
			($key.valid_through_release_sequence >= $key.valid_from_release_sequence) and
			(($key.valid_through_release_sequence | floor) == $key.valid_through_release_sequence))) and
		(($key.revoked | type) == "boolean")) and
	([.primary_keys[].id] | unique | length) == (.primary_keys | length)
' "$metadata" >/dev/null || fail 'invalid primary-key metadata'

primary_key_total=$(jq -r '.primary_keys | length' "$metadata")
primary_key_index=0
while [ "$primary_key_index" -lt "$primary_key_total" ]; do
	key_name=$(jq -r --argjson i "$primary_key_index" '.primary_keys[$i].public_key' "$metadata")
	key_sha=$(jq -r --argjson i "$primary_key_index" '.primary_keys[$i].sha256' "$metadata")
	safe_release_name "$key_name" || fail 'unsafe primary public-key path'
	[ -f "$root_dir/$key_name" ] || fail "missing primary public key $key_name"
	[ "$(sha256_file "$root_dir/$key_name")" = "$key_sha" ] \
		|| fail "primary public-key hash mismatch: $key_name"
	primary_key_index=$((primary_key_index + 1))
done

metadata_sha=$(sha256_file "$metadata")
if [ -e "$state" ]; then
	[ -f "$state" ] || fail 'verification state is not a regular file'
	jq -e '
		((.trust_sequence | type) == "number") and .trust_sequence >= 1 and
		(.trust_sequence | floor) == .trust_sequence and
		((.highest_release_sequence == null and .highest_release == null) or (
			((.highest_release_sequence | type) == "number") and .highest_release_sequence >= 1 and
			(.highest_release_sequence | floor) == .highest_release_sequence and
			(.highest_release | type == "string")
		)) and
		(.metadata_sha256 | test("^[0-9a-f]{64}$"))
	' "$state" >/dev/null || fail 'invalid verification state'
	state_sequence=$(jq -r '.trust_sequence' "$state")
	state_highest_sequence=$(jq -r '.highest_release_sequence' "$state")
	state_metadata_sha=$(jq -r '.metadata_sha256' "$state")
	[ "$metadata_sequence" -ge "$state_sequence" ] || fail 'trust metadata rollback refused'
	metadata_highest_sequence=$(jq -r '.highest_release_sequence' "$metadata")
	if [ "$state_highest_sequence" != null ]; then
		[ "$metadata_highest_sequence" != null ] \
			|| fail 'highest-release rollback refused'
		[ "$metadata_highest_sequence" -ge "$state_highest_sequence" ] \
			|| fail 'highest-release rollback refused'
	fi
	if [ "$metadata_sequence" -eq "$state_sequence" ]; then
		[ "$metadata_sha" = "$state_metadata_sha" ] || fail 'conflicting trust metadata at known sequence'
	fi
fi

write_state() {
	state_dir=$(dirname "$state")
	[ -d "$state_dir" ] || fail "verification state directory does not exist: $state_dir"
	umask 077
	state_tmp=$(mktemp "$state.tmp.XXXXXX")
	trap 'rm -f "$state_tmp"' EXIT HUP INT TERM
	jq -n \
		--argjson trust_sequence "$metadata_sequence" \
		--argjson highest_release_sequence "$(jq -c '.highest_release_sequence' "$metadata")" \
		--argjson highest_release "$(jq -c '.highest_release' "$metadata")" \
		--arg metadata_sha256 "$metadata_sha" \
		'{
			trust_sequence: $trust_sequence,
			highest_release_sequence: $highest_release_sequence,
			highest_release: $highest_release,
			metadata_sha256: $metadata_sha256
		}' >"$state_tmp"
	mv "$state_tmp" "$state"
	trap - EXIT HUP INT TERM
}

if [ "$trust_only" = true ]; then
	write_state
	printf 'verified trust metadata sequence %s\n' "$metadata_sequence"
	exit 0
fi

[ -d "$bundle" ] || fail "missing bundle directory $bundle"
bundle_dir=$(CDPATH='' cd -- "$bundle" && pwd)
manifest="$bundle_dir/release-manifest.json"
manifest_signature="$bundle_dir/release-manifest.sigstore.json"
[ -f "$manifest" ] || fail 'missing release-manifest.json'
[ -f "$manifest_signature" ] || fail 'missing release-manifest.sigstore.json'

jq -e '
	. as $manifest |
	.schema == "wenv.dev/release-manifest/v1" and
	(.version | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][0-9A-Za-z.-]+)?$")) and
	.tag == ("v" + .version) and
	(.source_commit | test("^[0-9a-f]{40}$")) and
	((.release_sequence | type) == "number") and .release_sequence >= 1 and
	(.release_sequence | floor) == .release_sequence and
	(.signing_key_id | type == "string" and length > 0) and
	(.artifacts | type == "array" and length > 0) and
	([.artifacts[].name] | unique | length) == (.artifacts | length) and
	all(.artifacts[]; . as $artifact |
		($artifact.name | type == "string" and length > 0) and
		($artifact.kind as $kind | ["binary", "sbom", "image", "checksum", "chart", "chart-digest", "installer", "oci-payload"] | index($kind) != null) and
		($artifact.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
		(if $artifact.kind == "image" then
			($artifact.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
			$artifact.tag == $manifest.version and
			($artifact.image | type == "string" and test("^ghcr\\.io/[a-z0-9._-]+/[a-z0-9._/-]+$"))
		elif $artifact.kind == "chart-digest" then
			($artifact.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
			($artifact.chart | type == "string" and test("^ghcr\\.io/[a-z0-9._-]+/[a-z0-9._/-]+$"))
		elif $artifact.kind == "chart" then
			$artifact.chart_version == $manifest.version and
			$artifact.app_version == $manifest.version and
			($artifact.image_repository | type == "string" and test("^ghcr\\.io/[a-z0-9._-]+/[a-z0-9._/-]+$")) and
			($artifact.image_digest | type == "string" and test("^sha256:[0-9a-f]{64}$"))
		elif $artifact.kind == "oci-payload" then
			($artifact.subject_kind as $subject_kind | ["image", "chart"] | index($subject_kind) != null) and
			($artifact.subject | type == "string" and test("^ghcr\\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")) and
			($artifact.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
			($artifact.subject | endswith("@" + $artifact.digest))
		else true end))
' "$manifest" >/dev/null || fail 'invalid release manifest'

version=$(jq -r '.version' "$manifest")
release_sequence=$(jq -r '.release_sequence' "$manifest")
release_matches=$(jq -r --arg version "$version" --argjson sequence "$release_sequence" \
	'[.releases[] | select(.version == $version and .sequence == $sequence)] | length' "$metadata")
[ "$release_matches" -eq 1 ] || fail "release $version is absent from trust metadata"
expected_manifest_sha=$(jq -r --arg version "$version" --argjson sequence "$release_sequence" \
	'.releases[] | select(.version == $version and .sequence == $sequence) | .manifest_sha256' "$metadata")
[ "$(sha256_file "$manifest")" = "$expected_manifest_sha" ] \
	|| fail "release manifest hash mismatch for $version"

if [ "$mode" = latest ]; then
	highest_version=$(jq -r '.highest_release' "$metadata")
	highest_sequence=$(jq -r '.highest_release_sequence' "$metadata")
	[ "$version" = "$highest_version" ] && [ "$release_sequence" -eq "$highest_sequence" ] \
		|| fail "release $version cannot be presented as latest; highest is $highest_version"
else
	[ "$version" = "$historical_version" ] || fail "historical install requested $historical_version, bundle is $version"
fi

signing_key_id=$(jq -r '.signing_key_id' "$manifest")
key_count=$(jq -r --arg id "$signing_key_id" --argjson sequence "$release_sequence" '
	[.primary_keys[] | select(
		.id == $id and
		.valid_from_release_sequence <= $sequence and
		(.valid_through_release_sequence == null or .valid_through_release_sequence >= $sequence)
	)] | length
' "$metadata")
[ "$key_count" -eq 1 ] || fail "no unique primary key authorizes release $version"
revoked=$(jq -r --arg id "$signing_key_id" '.primary_keys[] | select(.id == $id) | .revoked' "$metadata")
[ "$revoked" = false ] || fail "primary key $signing_key_id is revoked"
primary_name=$(jq -r --arg id "$signing_key_id" '.primary_keys[] | select(.id == $id) | .public_key' "$metadata")
primary_sha=$(jq -r --arg id "$signing_key_id" '.primary_keys[] | select(.id == $id) | .sha256' "$metadata")
safe_release_name "$primary_name" || fail 'unsafe primary public-key path'
primary_key="$root_dir/$primary_name"
[ -f "$primary_key" ] || fail "missing primary public key $primary_name"
[ "$(sha256_file "$primary_key")" = "$primary_sha" ] || fail 'primary public-key hash mismatch'

"$COSIGN_BIN" verify-blob --insecure-ignore-tlog \
	--key "$primary_key" --bundle "$manifest_signature" "$manifest" >/dev/null \
	|| fail 'release manifest signature invalid'

artifact_count=$(jq -r '.artifacts | length' "$manifest")
binary_count=0
sbom_count=0
image_count=0
chart_count=0
chart_digest_count=0
installer_count=0
oci_payload_count=0
image_payload_count=0
chart_payload_count=0
image_manifest_digest=
image_manifest_ref=
chart_image_digest=
chart_image_ref=
chart_manifest_digest=
chart_manifest_ref=
image_payload_digest=
image_payload_ref=
chart_payload_digest=
chart_payload_ref=
i=0
while [ "$i" -lt "$artifact_count" ]; do
	name=$(jq -r --argjson i "$i" '.artifacts[$i].name' "$manifest")
	kind=$(jq -r --argjson i "$i" '.artifacts[$i].kind' "$manifest")
	want_sha=$(jq -r --argjson i "$i" '.artifacts[$i].sha256' "$manifest")
	safe_release_name "$name" || fail "unsafe artifact path $name"
	case "$kind" in
		binary) binary_count=$((binary_count + 1)) ;;
		sbom) sbom_count=$((sbom_count + 1)) ;;
		image) image_count=$((image_count + 1)) ;;
		chart) chart_count=$((chart_count + 1)) ;;
		chart-digest) chart_digest_count=$((chart_digest_count + 1)) ;;
		installer) installer_count=$((installer_count + 1)) ;;
		oci-payload) oci_payload_count=$((oci_payload_count + 1)) ;;
		checksum) ;;
		*) fail "unsupported artifact kind $kind" ;;
	esac
	case "$want_sha" in
		*[!0-9a-f]* | "") fail "invalid SHA-256 for $name" ;;
	esac
	[ "${#want_sha}" -eq 64 ] || fail "invalid SHA-256 for $name"
	path="$bundle_dir/$name"
	[ -f "$path" ] || fail "missing artifact $name"
	[ "$(sha256_file "$path")" = "$want_sha" ] || fail "artifact hash mismatch: $name"
	artifact_signature="$path.sigstore.json"
	[ -f "$artifact_signature" ] || fail "missing artifact signature: $name"
	"$COSIGN_BIN" verify-blob --insecure-ignore-tlog \
		--key "$primary_key" --bundle "$artifact_signature" "$path" >/dev/null \
		|| fail "artifact signature invalid: $name"
	if [ "$kind" = image ]; then
		digest=$(jq -r --argjson i "$i" '.artifacts[$i].digest' "$manifest")
		image=$(jq -r --argjson i "$i" '.artifacts[$i].image' "$manifest")
		is_digest "$digest" || fail "invalid image digest for $name"
		[ -n "$image" ] && [ "$image" != null ] || fail "missing image identity for $name"
		[ "$(tr -d '\n' <"$path")" = "$digest" ] || fail "image digest mismatch: $name"
		image_manifest_digest=$digest
		image_manifest_ref=$image
	elif [ "$kind" = chart-digest ]; then
		digest=$(jq -r --argjson i "$i" '.artifacts[$i].digest' "$manifest")
		chart=$(jq -r --argjson i "$i" '.artifacts[$i].chart' "$manifest")
		is_digest "$digest" || fail "invalid chart digest for $name"
		[ -n "$chart" ] && [ "$chart" != null ] || fail "missing chart identity for $name"
		[ "$(tr -d '\n' <"$path")" = "$digest" ] || fail "chart digest mismatch: $name"
		chart_manifest_digest=$digest
		chart_manifest_ref=$chart
	elif [ "$kind" = chart ]; then
		command -v tar >/dev/null 2>&1 || fail 'tar is required to verify the Helm chart'
		chart_yaml=$(tar -xOf "$path" wenv/Chart.yaml) || fail "cannot read Chart.yaml from $name"
		values_yaml=$(tar -xOf "$path" wenv/values.yaml) || fail "cannot read values.yaml from $name"
		chart_version=$(printf '%s\n' "$chart_yaml" | awk '$1 == "version:" {print $2}')
		app_version=$(printf '%s\n' "$chart_yaml" | awk '$1 == "appVersion:" {print $2}')
		pinned_image=$(printf '%s\n' "$values_yaml" | awk '$1 == "digest:" {print $2}')
		pinned_image_ref=$(printf '%s\n' "$values_yaml" | awk '$1 == "repository:" {print $2}')
		[ "$chart_version" = "$version" ] || fail "chart version mismatch: $name"
		[ "$app_version" = "$version" ] || fail "chart appVersion mismatch: $name"
		expected_image=$(jq -r --argjson i "$i" '.artifacts[$i].image_digest' "$manifest")
		expected_image_ref=$(jq -r --argjson i "$i" '.artifacts[$i].image_repository' "$manifest")
		[ "$pinned_image" = "$expected_image" ] || fail "chart image digest mismatch: $name"
		[ "$pinned_image_ref" = "$expected_image_ref" ] || fail "chart image repository mismatch: $name"
		chart_image_digest=$expected_image
		chart_image_ref=$expected_image_ref
	elif [ "$kind" = oci-payload ]; then
		subject_kind=$(jq -r --argjson i "$i" '.artifacts[$i].subject_kind' "$manifest")
		subject=$(jq -r --argjson i "$i" '.artifacts[$i].subject' "$manifest")
		subject_ref=${subject%@*}
		subject_digest=${subject#*@}
		payload_ref=$(jq -r '.critical.identity["docker-reference"]' "$path")
		payload_digest=$(jq -r '.critical.image["docker-manifest-digest"]' "$path")
		payload_type=$(jq -r '.critical.type' "$path")
		[ "$payload_ref" = "$subject_ref" ] || fail "OCI payload identity mismatch: $name"
		[ "$payload_digest" = "$subject_digest" ] || fail "OCI payload digest mismatch: $name"
		[ "$payload_type" = 'cosign container image signature' ] || fail "OCI payload type mismatch: $name"
		case "$subject_kind" in
			image)
				image_payload_count=$((image_payload_count + 1))
				image_payload_digest=$subject_digest
				image_payload_ref=$subject_ref
				;;
			chart)
				chart_payload_count=$((chart_payload_count + 1))
				chart_payload_digest=$subject_digest
				chart_payload_ref=$subject_ref
				;;
		esac
		if [ "$verify_published" = true ]; then
			"$COSIGN_BIN" verify --insecure-ignore-tlog --key "$primary_key" "$subject" >/dev/null \
				|| fail "published OCI signature invalid: $subject"
		fi
	fi
	i=$((i + 1))
done

[ "$binary_count" -gt 0 ] || fail 'manifest contains no binary artifacts'
[ "$sbom_count" -gt 0 ] || fail 'manifest contains no SBOM artifact'
[ "$image_count" -eq 1 ] || fail 'manifest must contain exactly one image digest artifact'
[ "$chart_count" -eq 1 ] || fail 'manifest must contain exactly one Helm chart'
[ "$chart_digest_count" -eq 1 ] || fail 'manifest must contain exactly one chart digest artifact'
[ "$installer_count" -eq 1 ] || fail 'manifest must contain exactly one installer'
[ "$oci_payload_count" -eq 2 ] || fail 'manifest must contain image and chart OCI signing payloads'
[ "$image_payload_count" -eq 1 ] || fail 'manifest must contain exactly one image OCI signing payload'
[ "$chart_payload_count" -eq 1 ] || fail 'manifest must contain exactly one chart OCI signing payload'
[ "$image_manifest_digest" = "$chart_image_digest" ] \
	|| fail 'chart image digest does not match image manifest digest'
[ "$image_manifest_ref" = "$chart_image_ref" ] \
	|| fail 'chart image repository does not match image manifest identity'
[ "$image_manifest_digest" = "$image_payload_digest" ] \
	|| fail 'image OCI payload digest does not match image manifest digest'
[ "$image_manifest_ref" = "$image_payload_ref" ] \
	|| fail 'image OCI payload identity does not match image manifest identity'
[ "$chart_manifest_digest" = "$chart_payload_digest" ] \
	|| fail 'chart OCI payload digest does not match chart manifest digest'
[ "$chart_manifest_ref" = "$chart_payload_ref" ] \
	|| fail 'chart OCI payload identity does not match chart manifest identity'

write_state

printf 'verified release %s (%s)\n' "$version" "$mode"
