#!/bin/sh
set -eu

: "${COSIGN_BIN:=cosign}"

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-release-fixture.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

sign_blob() {
	key=$1
	payload=$2
	output=$3
	HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 NO_PROXY='' \
		COSIGN_PASSWORD=fixture-pass "$COSIGN_BIN" sign-blob --yes \
		--new-bundle-format=false --tlog-upload=false --use-signing-config=false \
		--key "$key" --bundle "$output" "$payload" >/dev/null
}

expect_reject() {
	label=$1
	expected=$2
	shift 2
	reject_log="$fixture_dir/reject.log"
	if "$@" >/dev/null 2>"$reject_log"; then
		printf 'release fixture failed: %s was accepted\n' "$label" >&2
		exit 1
	fi
	grep -F "$expected" "$reject_log" >/dev/null || {
		printf 'release fixture failed: %s rejected for unexpected reason\n' "$label" >&2
		cat "$reject_log" >&2
		exit 1
	}
	printf 'release fixture: %s refused\n' "$label"
}

# Negative fixtures deliberately recovery-authorize a contradictory manifest so
# verification reaches the narrower digest, chart, and key-window assertions.
rebind_negative_metadata() {
	manifest=$1
	input=$2
	output=$3
	manifest_version=$(jq -r '.version' "$manifest")
	manifest_sha=$(sha256_file "$manifest")
	jq --arg version "$manifest_version" --arg manifest_sha "$manifest_sha" '
		.sequence += 1 |
		.event = {type: "release", signed_by: .recovery.id} |
		(.releases[] | select(.version == $version)).manifest_sha256 = $manifest_sha
		' "$input" >"$output"
	sign_blob "$trust_dir/recovery.key" "$output" "$output.sigstore.json"
}

restore_bundle_file() {
	cp "$fixture_dir/bundle-v1/$1" "$bundle_dir/$1"
}

expect_chart_archive_reject() {
	label=$1
	expected=$2
	stem=$3
	chart_name=hikyo-0.1.0.tgz
	tmp_manifest="$fixture_dir/manifest-$stem.json"
	negative_metadata="$fixture_dir/$stem-metadata.json"

	tar -czf "$bundle_dir/$chart_name" -C "$fixture_dir/chart" hikyo
	sign_blob "$trust_dir/primary-1.key" "$bundle_dir/$chart_name" \
		"$bundle_dir/$chart_name.sigstore.json"
	jq --arg sha "$(sha256_file "$bundle_dir/$chart_name")" \
		'(.artifacts[] | select(.kind == "chart")).sha256 = $sha' \
		"$bundle_dir/release-manifest.json" >"$tmp_manifest"
	mv "$tmp_manifest" "$bundle_dir/release-manifest.json"
	sign_blob "$trust_dir/primary-1.key" "$bundle_dir/release-manifest.json" \
		"$bundle_dir/release-manifest.sigstore.json"
	rebind_negative_metadata "$bundle_dir/release-manifest.json" "$trust_dir/metadata.json" \
		"$negative_metadata"
	expect_reject "$label" "$expected" "$(dirname "$0")/verify-bundle.sh" \
		--root "$trust_dir/root.json" --metadata "$negative_metadata" \
		--metadata-signature "$negative_metadata.sigstore.json" \
		--bundle "$bundle_dir" --state "$fixture_dir/$stem-state.json" --latest
	restore_bundle_file "$chart_name"
	restore_bundle_file "$chart_name.sigstore.json"
	restore_bundle_file release-manifest.json
	restore_bundle_file release-manifest.sigstore.json
}

trust_dir="$fixture_dir/trust"
bundle_dir="$fixture_dir/bundle"
state="$fixture_dir/verification-state.json"
mkdir -p "$trust_dir" "$bundle_dir"

COSIGN_PASSWORD=fixture-pass "$COSIGN_BIN" generate-key-pair --output-key-prefix "$trust_dir/recovery" >/dev/null
COSIGN_PASSWORD=fixture-pass "$COSIGN_BIN" generate-key-pair --output-key-prefix "$trust_dir/primary-1" >/dev/null

recovery_sha=$(sha256_file "$trust_dir/recovery.pub")
primary_sha=$(sha256_file "$trust_dir/primary-1.pub")

jq -n \
	--arg recovery_sha "$recovery_sha" \
	--arg primary_sha "$primary_sha" \
	'{
		schema: "hikyo.dev/trust-root/v1",
		recovery: {id: "recovery-1", public_key: "recovery.pub", sha256: $recovery_sha},
		bootstrap_primary: {id: "primary-1", public_key: "primary-1.pub", sha256: $primary_sha}
	}' >"$trust_dir/root.json"

jq -n \
	--arg recovery_sha "$recovery_sha" \
	--arg primary_sha "$primary_sha" '
	{
		schema: "hikyo.dev/trust-metadata/v1",
		sequence: 1,
		highest_release: null,
		highest_release_sequence: null,
		recovery: {id: "recovery-1", sha256: $recovery_sha},
		event: {type: "bootstrap", signed_by: "recovery-1"},
		primary_keys: [{
			id: "primary-1", public_key: "primary-1.pub", sha256: $primary_sha,
			valid_from_release_sequence: 1, valid_through_release_sequence: null,
			revoked: false
		}],
		releases: [],
		pending_release: {version: "0.1.0", sequence: 1, manifest_sha256: ("0" * 64)}
	}' >"$trust_dir/bootstrap-metadata.json"
sign_blob "$trust_dir/recovery.key" "$trust_dir/bootstrap-metadata.json" \
	"$trust_dir/bootstrap-metadata.sigstore.json"
jq '.sequence = 2' "$trust_dir/bootstrap-metadata.json" \
	>"$trust_dir/bootstrap-wrong-sequence.json"
sign_blob "$trust_dir/recovery.key" "$trust_dir/bootstrap-wrong-sequence.json" \
	"$trust_dir/bootstrap-wrong-sequence.sigstore.json"
expect_reject 'bootstrap metadata with a noninitial trust sequence' 'invalid trust metadata' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" \
	--metadata "$trust_dir/bootstrap-wrong-sequence.json" \
	--metadata-signature "$trust_dir/bootstrap-wrong-sequence.sigstore.json" \
	--state "$fixture_dir/bootstrap-wrong-sequence-state.json" --trust-only
"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" \
	--metadata "$trust_dir/bootstrap-metadata.json" \
	--metadata-signature "$trust_dir/bootstrap-metadata.sigstore.json" \
	--state "$state" --trust-only >/dev/null
jq -e '
	.trust_sequence == 1 and .highest_release == null and
	.highest_release_sequence == null
	' "$state" >/dev/null
printf 'release fixture: first-release bootstrap trust accepted without claiming latest\n'

jq -n \
	--arg recovery_sha "$recovery_sha" \
	--arg primary_sha "$primary_sha" \
	'{
		schema: "hikyo.dev/trust-metadata/v1",
		sequence: 2,
		highest_release: "0.1.0",
		highest_release_sequence: 1,
		recovery: {id: "recovery-1", sha256: $recovery_sha},
		event: {type: "release", signed_by: "recovery-1"},
		primary_keys: [{
			id: "primary-1", public_key: "primary-1.pub", sha256: $primary_sha,
			valid_from_release_sequence: 1, valid_through_release_sequence: null,
			revoked: false
		}],
		releases: [{version: "0.1.0", sequence: 1, manifest_sha256: ("0" * 64)}]
	}' >"$trust_dir/metadata.json"

printf 'fixture binary\n' >"$bundle_dir/hikyo_Linux_arm64.tar.gz"
candidate_commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
jq -n --arg commit "$candidate_commit" '{
	schema: "hikyo.dev/release-binaries/v1",
	source_commit: $commit,
	version: "0.1.0",
	producer: {
		name: "goreleaser",
		build_id: "hikyo",
		config: ".goreleaser.yaml",
		config_sha256: ("a" * 64)
	},
	packages: ["amd64", "arm64"] | map({
		goos: "linux",
		goarch: .,
		archive_input: {build_id: "hikyo", sha256: ("b" * 64)},
		oci_input: {path: ("image-root/" + . + "/hikyo"), sha256: ("b" * 64)}
	})
}' >"$bundle_dir/binary-provenance.json"
printf '{"spdxVersion":"SPDX-2.3"}\n' >"$bundle_dir/hikyo-source.spdx.json"
printf 'sha256:%064d\n' 1 >"$bundle_dir/image-index.digest"
printf 'sha256:%064d\n' 2 >"$bundle_dir/chart-index.digest"
printf '#!/bin/sh\nprintf "fixture installer\\n"\n' >"$bundle_dir/install.sh"
printf '{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key_id":"primary-1","public_key":"primary-1.pub","sequence":1,"version":"0.1.0"}\n' \
	>"$bundle_dir/release-candidate.json"
mkdir -p "$fixture_dir/chart/hikyo"
printf 'name: hikyo\nversion: 0.1.0\nappVersion: 0.1.0\n' >"$fixture_dir/chart/hikyo/Chart.yaml"
printf 'image:\n  repository: ghcr.io/hikyo-org/hikyo\n  digest: sha256:%064d\n' 1 \
	>"$fixture_dir/chart/hikyo/values.yaml"
tar -czf "$bundle_dir/hikyo-0.1.0.tgz" -C "$fixture_dir/chart" hikyo

binary_sha=$(sha256_file "$bundle_dir/hikyo_Linux_arm64.tar.gz")
binary_provenance_sha=$(sha256_file "$bundle_dir/binary-provenance.json")
sbom_sha=$(sha256_file "$bundle_dir/hikyo-source.spdx.json")
image_file_sha=$(sha256_file "$bundle_dir/image-index.digest")
image_digest=$(tr -d '\n' <"$bundle_dir/image-index.digest")
chart_file_sha=$(sha256_file "$bundle_dir/hikyo-0.1.0.tgz")
chart_digest_file_sha=$(sha256_file "$bundle_dir/chart-index.digest")
chart_digest=$(tr -d '\n' <"$bundle_dir/chart-index.digest")
installer_sha=$(sha256_file "$bundle_dir/install.sh")
candidate_sha=$(sha256_file "$bundle_dir/release-candidate.json")
jq -n --arg digest "$image_digest" '{critical:{identity:{"docker-reference":"ghcr.io/hikyo-org/hikyo"},image:{"docker-manifest-digest":$digest},type:"cosign container image signature"},optional:null}' \
	>"$bundle_dir/image-index.oci-payload.json"
jq -n --arg digest "$chart_digest" '{critical:{identity:{"docker-reference":"ghcr.io/hikyo-org/charts/hikyo"},image:{"docker-manifest-digest":$digest},type:"cosign container image signature"},optional:null}' \
	>"$bundle_dir/chart-index.oci-payload.json"
image_payload_sha=$(sha256_file "$bundle_dir/image-index.oci-payload.json")
chart_payload_sha=$(sha256_file "$bundle_dir/chart-index.oci-payload.json")

jq -n \
	--arg binary_sha "$binary_sha" \
	--arg binary_provenance_sha "$binary_provenance_sha" \
	--arg sbom_sha "$sbom_sha" \
	--arg image_file_sha "$image_file_sha" \
	--arg image_digest "$image_digest" \
	--arg chart_file_sha "$chart_file_sha" \
	--arg chart_digest_file_sha "$chart_digest_file_sha" \
	--arg chart_digest "$chart_digest" \
	--arg installer_sha "$installer_sha" \
	--arg candidate_sha "$candidate_sha" \
	--arg image_payload_sha "$image_payload_sha" \
	--arg chart_payload_sha "$chart_payload_sha" \
	'{
		schema: "hikyo.dev/release-manifest/v1",
		version: "0.1.0",
		tag: "v0.1.0",
		source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		release_sequence: 1,
		signing_key_id: "primary-1",
		artifacts: [
			{name: "release-candidate.json", kind: "release-candidate", sha256: $candidate_sha},
			{name: "hikyo_Linux_arm64.tar.gz", kind: "binary", sha256: $binary_sha},
			{name: "binary-provenance.json", kind: "binary-provenance", sha256: $binary_provenance_sha},
			{name: "hikyo-source.spdx.json", kind: "sbom", sha256: $sbom_sha},
			{name: "image-index.digest", kind: "image", sha256: $image_file_sha, digest: $image_digest, image: "ghcr.io/hikyo-org/hikyo", tag: "0.1.0"},
			{name: "hikyo-0.1.0.tgz", kind: "chart", sha256: $chart_file_sha, chart_version: "0.1.0", app_version: "0.1.0", image_repository: "ghcr.io/hikyo-org/hikyo", image_digest: $image_digest},
			{name: "chart-index.digest", kind: "chart-digest", sha256: $chart_digest_file_sha, digest: $chart_digest, chart: "ghcr.io/hikyo-org/charts/hikyo"},
			{name: "install.sh", kind: "installer", sha256: $installer_sha},
			{name: "image-index.oci-payload.json", kind: "oci-payload", sha256: $image_payload_sha, subject_kind: "image", subject: ("ghcr.io/hikyo-org/hikyo@" + $image_digest), digest: $image_digest},
			{name: "chart-index.oci-payload.json", kind: "oci-payload", sha256: $chart_payload_sha, subject_kind: "chart", subject: ("ghcr.io/hikyo-org/charts/hikyo@" + $chart_digest), digest: $chart_digest}
		]
	}' >"$bundle_dir/release-manifest.json"

manifest_sha=$(sha256_file "$bundle_dir/release-manifest.json")
jq --arg manifest_sha "$manifest_sha" \
	'(.releases[] | select(.version == "0.1.0")).manifest_sha256 = $manifest_sha' \
	"$trust_dir/metadata.json" >"$trust_dir/metadata-bound.json"
mv "$trust_dir/metadata-bound.json" "$trust_dir/metadata.json"
sign_blob "$trust_dir/recovery.key" "$trust_dir/metadata.json" "$trust_dir/metadata.sigstore.json"
jq -e '.base64Signature | type == "string" and length > 0' "$trust_dir/metadata.sigstore.json" >/dev/null

HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 NO_PROXY='' \
	COSIGN_PASSWORD=fixture-pass "$(dirname "$0")/sign-bundle.sh" \
	"$bundle_dir" "$trust_dir/primary-1.key" "$trust_dir/metadata.json" >/dev/null
[ -s "$bundle_dir/image-index.oci-payload.json.signature" ]
[ -s "$bundle_dir/chart-index.oci-payload.json.signature" ]
[ "$(tr -d '\n' <"$bundle_dir/image-index.oci-payload.json.signature")" = \
	"$(jq -r '.base64Signature' "$bundle_dir/image-index.oci-payload.json.sigstore.json")" ]
[ "$(tr -d '\n' <"$bundle_dir/chart-index.oci-payload.json.signature")" = \
	"$(jq -r '.base64Signature' "$bundle_dir/chart-index.oci-payload.json.sigstore.json")" ]

"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" \
	--metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" \
	--bundle "$bundle_dir" \
	--state "$state" \
	--latest

printf 'release fixture: valid chain accepted\n'

# Keep blob verification real, but replace registry access with a recorder so CI
# proves --published invokes cosign for both exact signed OCI subjects.
# shellcheck disable=SC2016
printf '#!/bin/sh\nif [ "$1" = verify ]; then\n  shift\n  for arg do case "$arg" in *@sha256:*) printf "%%s\\n" "$arg" >>"$COSIGN_VERIFY_LOG" ;; esac; done\n  exit 0\nfi\nexec "$COSIGN_REAL" "$@"\n' >"$fixture_dir/cosign-published"
chmod +x "$fixture_dir/cosign-published"
: >"$fixture_dir/published.log"
export COSIGN_REAL="$COSIGN_BIN"
export COSIGN_VERIFY_LOG="$fixture_dir/published.log"
COSIGN_BIN="$fixture_dir/cosign-published" "$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" --bundle "$bundle_dir" \
	--state "$state" --published --latest >/dev/null
grep -Fx "ghcr.io/hikyo-org/hikyo@$image_digest" "$fixture_dir/published.log" >/dev/null
grep -Fx "ghcr.io/hikyo-org/charts/hikyo@$chart_digest" "$fixture_dir/published.log" >/dev/null
[ "$(wc -l <"$fixture_dir/published.log" | tr -d ' ')" -eq 2 ]
printf 'release fixture: published image and chart subjects verified individually\n'

# Blob verification stays real; registry mutations are recorded so the
# networked half of the ceremony proves exact attach and verify arguments.
# shellcheck disable=SC2016
printf '#!/bin/sh\ncase "$1" in\n  attach) action=attach ;;\n  verify) action=verify ;;\n  *) exec "$COSIGN_REAL" "$@" ;;\nesac\nfor arg do subject=$arg; done\nprintf "%%s %%s\\n" "$action" "$subject" >>"$COSIGN_PUBLISH_LOG"\n' \
	>"$fixture_dir/cosign-publish"
chmod +x "$fixture_dir/cosign-publish"
: >"$fixture_dir/publish.log"
export COSIGN_PUBLISH_LOG="$fixture_dir/publish.log"
COSIGN_BIN="$fixture_dir/cosign-publish" "$(dirname "$0")/publish-oci-signatures.sh" \
	"$bundle_dir" "$trust_dir/root.json" "$trust_dir/metadata.json" \
	"$trust_dir/metadata.sigstore.json" >/dev/null
grep -Fx "attach ghcr.io/hikyo-org/hikyo@$image_digest" "$fixture_dir/publish.log" >/dev/null
grep -Fx "verify ghcr.io/hikyo-org/hikyo@$image_digest" "$fixture_dir/publish.log" >/dev/null
grep -Fx "attach ghcr.io/hikyo-org/charts/hikyo@$chart_digest" "$fixture_dir/publish.log" >/dev/null
grep -Fx "verify ghcr.io/hikyo-org/charts/hikyo@$chart_digest" "$fixture_dir/publish.log" >/dev/null
[ "$(wc -l <"$fixture_dir/publish.log" | tr -d ' ')" -eq 4 ]
printf 'release fixture: OCI signatures attached and verified for exact subjects\n'

cp -R "$bundle_dir" "$fixture_dir/bundle-v1"

printf ' ' >>"$bundle_dir/release-candidate.json"
expect_reject 'tampered release candidate' 'release-candidate.json hash mismatch' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" \
	--bundle "$bundle_dir" --state "$state" --latest
restore_bundle_file release-candidate.json

jq '.source_commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
	"$bundle_dir/binary-provenance.json" >"$fixture_dir/wrong-binary-provenance.json"
mv "$fixture_dir/wrong-binary-provenance.json" "$bundle_dir/binary-provenance.json"
sign_blob "$trust_dir/primary-1.key" "$bundle_dir/binary-provenance.json" \
	"$bundle_dir/binary-provenance.json.sigstore.json"
jq --arg sha "$(sha256_file "$bundle_dir/binary-provenance.json")" \
	'(.artifacts[] | select(.kind == "binary-provenance")).sha256 = $sha' \
	"$bundle_dir/release-manifest.json" >"$fixture_dir/manifest-wrong-binary-provenance.json"
mv "$fixture_dir/manifest-wrong-binary-provenance.json" "$bundle_dir/release-manifest.json"
sign_blob "$trust_dir/primary-1.key" "$bundle_dir/release-manifest.json" \
	"$bundle_dir/release-manifest.sigstore.json"
rebind_negative_metadata "$bundle_dir/release-manifest.json" "$trust_dir/metadata.json" \
	"$fixture_dir/wrong-binary-provenance-metadata.json"
expect_reject 'binary provenance for a different candidate' 'invalid binary provenance' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" \
	--metadata "$fixture_dir/wrong-binary-provenance-metadata.json" \
	--metadata-signature "$fixture_dir/wrong-binary-provenance-metadata.json.sigstore.json" \
	--bundle "$bundle_dir" --state "$state" --latest
restore_bundle_file binary-provenance.json
restore_bundle_file binary-provenance.json.sigstore.json
restore_bundle_file release-manifest.json
restore_bundle_file release-manifest.sigstore.json

printf 'tampered\n' >>"$bundle_dir/hikyo_Linux_arm64.tar.gz"
expect_reject 'tampered artifact' 'artifact hash mismatch' "$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" --bundle "$bundle_dir" --state "$state" --latest
cp "$fixture_dir/bundle-v1/hikyo_Linux_arm64.tar.gz" "$bundle_dir/hikyo_Linux_arm64.tar.gz"

printf 'sha256:%064d\n' 3 >"$bundle_dir/image-index.digest"
sign_blob "$trust_dir/primary-1.key" "$bundle_dir/image-index.digest" "$bundle_dir/image-index.digest.sigstore.json"
jq --arg sha "$(sha256_file "$bundle_dir/image-index.digest")" \
	'(.artifacts[] | select(.kind == "image")).sha256 = $sha' \
	"$bundle_dir/release-manifest.json" >"$fixture_dir/manifest-wrong-digest.json"
mv "$fixture_dir/manifest-wrong-digest.json" "$bundle_dir/release-manifest.json"
sign_blob "$trust_dir/primary-1.key" "$bundle_dir/release-manifest.json" \
	"$bundle_dir/release-manifest.sigstore.json"
rebind_negative_metadata "$bundle_dir/release-manifest.json" "$trust_dir/metadata.json" \
	"$fixture_dir/wrong-digest-metadata.json"
expect_reject 'valid signature over wrong presented image digest' 'image digest mismatch: image-index.digest' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$fixture_dir/wrong-digest-metadata.json" \
	--metadata-signature "$fixture_dir/wrong-digest-metadata.json.sigstore.json" \
	--bundle "$bundle_dir" --state "$fixture_dir/wrong-digest-state.json" --latest
cp "$fixture_dir/bundle-v1/image-index.digest" "$bundle_dir/image-index.digest"
cp "$fixture_dir/bundle-v1/image-index.digest.sigstore.json" "$bundle_dir/image-index.digest.sigstore.json"
cp "$fixture_dir/bundle-v1/release-manifest.json" "$bundle_dir/release-manifest.json"
cp "$fixture_dir/bundle-v1/release-manifest.sigstore.json" "$bundle_dir/release-manifest.sigstore.json"

wrong_payload_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333
jq --arg digest "$wrong_payload_digest" \
	'.critical.image["docker-manifest-digest"] = $digest' \
	"$bundle_dir/image-index.oci-payload.json" >"$fixture_dir/image-payload-wrong-digest.json"
mv "$fixture_dir/image-payload-wrong-digest.json" "$bundle_dir/image-index.oci-payload.json"
sign_blob "$trust_dir/primary-1.key" "$bundle_dir/image-index.oci-payload.json" \
	"$bundle_dir/image-index.oci-payload.json.sigstore.json"
jq --arg digest "$wrong_payload_digest" \
	--arg sha "$(sha256_file "$bundle_dir/image-index.oci-payload.json")" '
	(.artifacts[] | select(.name == "image-index.oci-payload.json")) |= (
		.sha256 = $sha | .digest = $digest |
		.subject = ("ghcr.io/hikyo-org/hikyo@" + $digest)
	)' "$bundle_dir/release-manifest.json" >"$fixture_dir/manifest-cross-digest.json"
mv "$fixture_dir/manifest-cross-digest.json" "$bundle_dir/release-manifest.json"
sign_blob "$trust_dir/primary-1.key" "$bundle_dir/release-manifest.json" \
	"$bundle_dir/release-manifest.sigstore.json"
rebind_negative_metadata "$bundle_dir/release-manifest.json" "$trust_dir/metadata.json" \
	"$fixture_dir/cross-digest-metadata.json"
expect_reject 'self-consistent but cross-bound image digest mismatch' \
	'image OCI payload digest does not match image manifest digest' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$fixture_dir/cross-digest-metadata.json" \
	--metadata-signature "$fixture_dir/cross-digest-metadata.json.sigstore.json" \
	--bundle "$bundle_dir" --state "$fixture_dir/cross-digest-state.json" --latest
cp "$fixture_dir/bundle-v1/image-index.oci-payload.json" "$bundle_dir/image-index.oci-payload.json"
cp "$fixture_dir/bundle-v1/image-index.oci-payload.json.sigstore.json" \
	"$bundle_dir/image-index.oci-payload.json.sigstore.json"
cp "$fixture_dir/bundle-v1/release-manifest.json" "$bundle_dir/release-manifest.json"
cp "$fixture_dir/bundle-v1/release-manifest.sigstore.json" "$bundle_dir/release-manifest.sigstore.json"

printf 'name: hikyo\nversion: 9.9.9\nappVersion: 0.1.0\n' >"$fixture_dir/chart/hikyo/Chart.yaml"
expect_chart_archive_reject 'chart version contradictory to signed release version' \
	'chart version mismatch: hikyo-0.1.0.tgz' wrong-chart

printf 'name: hikyo\nversion: 0.1.0\nappVersion: 0.1.0\n' >"$fixture_dir/chart/hikyo/Chart.yaml"
printf 'image:\n  repository: ghcr.io/hikyo-org/hikyo\n  digest: sha256:%064d\n' 3 \
	>"$fixture_dir/chart/hikyo/values.yaml"
expect_chart_archive_reject 'chart pins image digest outside signed manifest' \
	'chart image digest mismatch: hikyo-0.1.0.tgz' wrong-chart-image

printf 'image:\n  repository: ghcr.io/attacker/hikyo\n  digest: sha256:%064d\n' 1 \
	>"$fixture_dir/chart/hikyo/values.yaml"
expect_chart_archive_reject 'chart pins image repository outside signed manifest' \
	'chart image repository mismatch: hikyo-0.1.0.tgz' wrong-chart-repository

jq '.critical.identity["docker-reference"] = "ghcr.io/attacker/charts/hikyo"' \
	"$bundle_dir/chart-index.oci-payload.json" >"$fixture_dir/chart-payload-wrong-identity.json"
mv "$fixture_dir/chart-payload-wrong-identity.json" "$bundle_dir/chart-index.oci-payload.json"
sign_blob "$trust_dir/primary-1.key" "$bundle_dir/chart-index.oci-payload.json" \
	"$bundle_dir/chart-index.oci-payload.json.sigstore.json"
jq --arg sha "$(sha256_file "$bundle_dir/chart-index.oci-payload.json")" \
	--arg subject "ghcr.io/attacker/charts/hikyo@$chart_digest" \
	'(.artifacts[] | select(.name == "chart-index.oci-payload.json")) |=
		(.sha256 = $sha | .subject = $subject)' \
	"$bundle_dir/release-manifest.json" >"$fixture_dir/manifest-wrong-chart-payload.json"
mv "$fixture_dir/manifest-wrong-chart-payload.json" "$bundle_dir/release-manifest.json"
sign_blob "$trust_dir/primary-1.key" "$bundle_dir/release-manifest.json" \
	"$bundle_dir/release-manifest.sigstore.json"
rebind_negative_metadata "$bundle_dir/release-manifest.json" "$trust_dir/metadata.json" \
	"$fixture_dir/wrong-chart-payload-metadata.json"
expect_reject 'chart OCI payload names different repository' \
	'chart OCI payload identity does not match chart manifest identity' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$fixture_dir/wrong-chart-payload-metadata.json" \
	--metadata-signature "$fixture_dir/wrong-chart-payload-metadata.json.sigstore.json" \
	--bundle "$bundle_dir" --state "$fixture_dir/wrong-chart-payload-state.json" --latest
restore_bundle_file chart-index.oci-payload.json
restore_bundle_file chart-index.oci-payload.json.sigstore.json
restore_bundle_file release-manifest.json
restore_bundle_file release-manifest.sigstore.json
printf 'image:\n  repository: ghcr.io/hikyo-org/hikyo\n  digest: sha256:%064d\n' 1 \
	>"$fixture_dir/chart/hikyo/values.yaml"

COSIGN_PASSWORD=fixture-pass "$COSIGN_BIN" generate-key-pair --output-key-prefix "$trust_dir/primary-2" >/dev/null
primary_2_sha=$(sha256_file "$trust_dir/primary-2.pub")
cp "$trust_dir/metadata.json" "$trust_dir/metadata-v1.json"
cp "$trust_dir/metadata.sigstore.json" "$trust_dir/metadata-v1.sigstore.json"
jq \
	--arg primary_2_sha "$primary_2_sha" '
	.sequence = 3 |
	.event = {type: "rotation", signed_by: "recovery-1"} |
	.primary_keys[0].valid_through_release_sequence = 1 |
	.primary_keys += [{
		id: "primary-2", public_key: "primary-2.pub", sha256: $primary_2_sha,
		valid_from_release_sequence: 2, valid_through_release_sequence: null,
		revoked: false
	}] |
	.pending_release = {version: "0.2.0", sequence: 2, manifest_sha256: ("0" * 64)}
	' "$trust_dir/metadata-v1.json" >"$trust_dir/metadata.json"
sign_blob "$trust_dir/recovery.key" "$trust_dir/metadata.json" "$trust_dir/metadata.sigstore.json"
"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" --bundle "$fixture_dir/bundle-v1" \
	--state "$state" --latest >/dev/null
printf 'release fixture: current release remains installable while successor is pending\n'

cp -R "$fixture_dir/bundle-v1" "$fixture_dir/bundle-v2"
rm "$fixture_dir/bundle-v2/hikyo-0.1.0.tgz" "$fixture_dir/bundle-v2/hikyo-0.1.0.tgz.sigstore.json"
printf '{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key_id":"primary-2","public_key":"primary-2.pub","sequence":2,"version":"0.2.0"}\n' \
	>"$fixture_dir/bundle-v2/release-candidate.json"
candidate_v2_sha=$(sha256_file "$fixture_dir/bundle-v2/release-candidate.json")
jq '.version = "0.2.0"' "$fixture_dir/bundle-v2/binary-provenance.json" \
	>"$fixture_dir/binary-provenance-v2.json"
mv "$fixture_dir/binary-provenance-v2.json" "$fixture_dir/bundle-v2/binary-provenance.json"
binary_provenance_v2_sha=$(sha256_file "$fixture_dir/bundle-v2/binary-provenance.json")
printf 'name: hikyo\nversion: 0.2.0\nappVersion: 0.2.0\n' >"$fixture_dir/chart/hikyo/Chart.yaml"
tar -czf "$fixture_dir/bundle-v2/hikyo-0.2.0.tgz" -C "$fixture_dir/chart" hikyo
chart_v2_sha=$(sha256_file "$fixture_dir/bundle-v2/hikyo-0.2.0.tgz")
jq --arg chart_v2_sha "$chart_v2_sha" \
	--arg candidate_v2_sha "$candidate_v2_sha" \
	--arg binary_provenance_v2_sha "$binary_provenance_v2_sha" '
	.version = "0.2.0" |
	.tag = "v0.2.0" |
	.release_sequence = 2 |
	.signing_key_id = "primary-2" |
	(.artifacts[] | select(.kind == "release-candidate")).sha256 = $candidate_v2_sha |
	(.artifacts[] | select(.kind == "binary-provenance")).sha256 = $binary_provenance_v2_sha |
	(.artifacts[] | select(.kind == "image")).tag = "0.2.0" |
	(.artifacts[] | select(.kind == "chart")) |= (
		.name = "hikyo-0.2.0.tgz" |
		.sha256 = $chart_v2_sha |
		.chart_version = "0.2.0" |
		.app_version = "0.2.0"
	)
	' "$fixture_dir/bundle-v1/release-manifest.json" >"$fixture_dir/bundle-v2/release-manifest.json"
"$(dirname "$0")/bind-manifest.sh" "$fixture_dir/bundle-v2/release-manifest.json" \
	"$trust_dir/metadata.json" "$trust_dir/metadata-bound.json" >/dev/null
mv "$trust_dir/metadata-bound.json" "$trust_dir/metadata.json"
sign_blob "$trust_dir/recovery.key" "$trust_dir/metadata.json" "$trust_dir/metadata.sigstore.json"

expect_reject 'downgrade presented as latest' 'cannot be presented as latest' "$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" --bundle "$fixture_dir/bundle-v1" --state "$state" --latest
"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" --bundle "$fixture_dir/bundle-v1" \
	--state "$state" --historical 0.1.0 >/dev/null

expect_reject 'trust metadata rollback' 'trust metadata rollback refused' "$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata-v1.json" \
	--metadata-signature "$trust_dir/metadata-v1.sigstore.json" --bundle "$fixture_dir/bundle-v1" \
	--state "$state" --latest

cp "$trust_dir/metadata.json" "$trust_dir/metadata-primary-authorized.json"
sign_blob "$trust_dir/primary-1.key" "$trust_dir/metadata-primary-authorized.json" \
	"$trust_dir/metadata-primary-authorized.sigstore.json"
expect_reject 'primary-signed trust-root update' 'trust metadata is not signed by pinned recovery root' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata-primary-authorized.json" \
	--metadata-signature "$trust_dir/metadata-primary-authorized.sigstore.json" \
	--bundle "$fixture_dir/bundle-v1" --state "$state" --historical 0.1.0

HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 NO_PROXY='' \
	COSIGN_PASSWORD=fixture-pass "$(dirname "$0")/sign-bundle.sh" \
	"$fixture_dir/bundle-v2" "$trust_dir/primary-2.key" "$trust_dir/metadata.json" >/dev/null
"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" --bundle "$fixture_dir/bundle-v2" \
	--state "$state" --latest >/dev/null
printf 'release fixture: recovery-authorized primary rotation accepted\n'

cp -R "$fixture_dir/bundle-v2" "$fixture_dir/bundle-v2-wrong-private"
expect_reject 'wrong private key for candidate' 'private key does not match release candidate' \
	env HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 \
	ALL_PROXY=http://127.0.0.1:9 NO_PROXY='' COSIGN_PASSWORD=fixture-pass \
	"$(dirname "$0")/sign-bundle.sh" "$fixture_dir/bundle-v2-wrong-private" \
	"$trust_dir/primary-1.key" "$trust_dir/metadata.json"

cp -R "$fixture_dir/bundle-v2" "$fixture_dir/bundle-v2-superseded"
printf '{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key_id":"primary-1","public_key":"primary-1.pub","sequence":2,"version":"0.2.0"}\n' \
	>"$fixture_dir/bundle-v2-superseded/release-candidate.json"
superseded_candidate_sha=$(sha256_file "$fixture_dir/bundle-v2-superseded/release-candidate.json")
jq --arg candidate_sha "$superseded_candidate_sha" '
	.signing_key_id = "primary-1" |
	(.artifacts[] | select(.kind == "release-candidate")).sha256 = $candidate_sha
	' "$fixture_dir/bundle-v2/release-manifest.json" \
	>"$fixture_dir/bundle-v2-superseded/release-manifest.json"
sign_blob "$trust_dir/primary-1.key" \
	"$fixture_dir/bundle-v2-superseded/release-candidate.json" \
	"$fixture_dir/bundle-v2-superseded/release-candidate.json.sigstore.json"
sign_blob "$trust_dir/primary-1.key" "$fixture_dir/bundle-v2-superseded/release-manifest.json" \
	"$fixture_dir/bundle-v2-superseded/release-manifest.sigstore.json"
rebind_negative_metadata "$fixture_dir/bundle-v2-superseded/release-manifest.json" \
	"$trust_dir/metadata.json" "$fixture_dir/superseded-metadata.json"
expect_reject 'superseded primary past release cutoff' 'record does not match trust metadata' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$fixture_dir/superseded-metadata.json" \
	--metadata-signature "$fixture_dir/superseded-metadata.json.sigstore.json" \
	--bundle "$fixture_dir/bundle-v2-superseded" \
	--state "$fixture_dir/superseded-state.json" --latest
expect_reject 'OCI publication with superseded candidate key' \
	'bundle is not candidate-authorized' \
	env COSIGN_BIN="$fixture_dir/cosign-publish" \
	"$(dirname "$0")/publish-oci-signatures.sh" \
	"$fixture_dir/bundle-v2-superseded" "$trust_dir/root.json" \
	"$fixture_dir/superseded-metadata.json" \
	"$fixture_dir/superseded-metadata.json.sigstore.json"

cp "$trust_dir/metadata.json" "$trust_dir/metadata-v4.json"
jq '
	.sequence = 5 |
	.event = {type: "revocation", signed_by: "recovery-1"} |
	.primary_keys[0].revoked = true
	' "$trust_dir/metadata-v4.json" >"$trust_dir/metadata.json"
sign_blob "$trust_dir/recovery.key" "$trust_dir/metadata.json" "$trust_dir/metadata.sigstore.json"
expect_reject 'revoked primary on formerly valid release' 'primary key is revoked' \
	"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" --bundle "$fixture_dir/bundle-v1" \
	--state "$state" --historical 0.1.0
"$(dirname "$0")/verify-bundle.sh" \
	--root "$trust_dir/root.json" --metadata "$trust_dir/metadata.json" \
	--metadata-signature "$trust_dir/metadata.sigstore.json" --bundle "$fixture_dir/bundle-v2" \
	--state "$state" --latest >/dev/null
printf 'release fixture: distinct revocation preserves unrevoked current key\n'
