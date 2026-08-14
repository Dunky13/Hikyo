#!/bin/sh
set -eu

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-manifest-fixture.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
dist="$fixture_dir/dist"
mkdir -p "$dist"

printf 'binary\n' >"$dist/hikyo_0.1.0_Linux_arm64.tar.gz"
printf 'binary\n' >"$dist/hikyo_0.1.0_Windows_arm64.zip"
printf 'checksums\n' >"$dist/checksums.txt"
printf '{"spdxVersion":"SPDX-2.3"}\n' >"$dist/hikyo-source.spdx.json"
printf '{"spdxVersion":"SPDX-2.3"}\n' >"$dist/hikyo-image.spdx.json"
printf 'installer\n' >"$dist/install.sh"
printf '{"critical":{"identity":{"docker-reference":"ghcr.io/hikyo-org/hikyo"},"image":{"docker-manifest-digest":"sha256:%064d"}}}\n' 1 >"$dist/image-index.oci-payload.json"
printf '{"critical":{"identity":{"docker-reference":"ghcr.io/hikyo-org/charts/hikyo"},"image":{"docker-manifest-digest":"sha256:%064d"}}}\n' 2 >"$dist/chart-index.oci-payload.json"
mkdir -p "$fixture_dir/hikyo"
printf 'name: hikyo\nversion: 0.1.0\nappVersion: 0.1.0\n' >"$fixture_dir/hikyo/Chart.yaml"
printf 'image:\n  digest: sha256:%064d\n' 1 >"$fixture_dir/hikyo/values.yaml"
tar -czf "$dist/hikyo-0.1.0.tgz" -C "$fixture_dir" hikyo
printf '{"releases":[{"version":"0.1.0","sequence":7}]}\n' >"$fixture_dir/metadata.json"

"$(dirname "$0")/create-manifest.sh" \
	0.1.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa primary-1 ghcr.io/hikyo-org/hikyo \
	sha256:1111111111111111111111111111111111111111111111111111111111111111 \
	ghcr.io/hikyo-org/charts/hikyo \
	sha256:2222222222222222222222222222222222222222222222222222222222222222 \
	"$dist" "$fixture_dir/metadata.json" >/dev/null

jq -e '
	.version == "0.1.0" and
	.tag == "v0.1.0" and
	.release_sequence == 7 and
	([.artifacts[] | select(.kind == "binary")] | length) == 2 and
	([.artifacts[] | select(.kind == "sbom")] | length) == 2 and
	([.artifacts[] | select(.kind == "checksum")] | length) == 1 and
	([.artifacts[] | select(.kind == "image")] | length) == 1 and
	([.artifacts[] | select(.kind == "image")][0].tag == "0.1.0") and
	([.artifacts[] | select(.kind == "chart")] | length) == 1 and
	([.artifacts[] | select(.kind == "chart-digest")] | length) == 1 and
	([.artifacts[] | select(.kind == "installer")] | length) == 1 and
	([.artifacts[] | select(.kind == "oci-payload")] | length) == 2 and
	([.artifacts[] | select(.kind == "chart")][0] |
		.chart_version == "0.1.0" and .app_version == "0.1.0" and
		.image_repository == "ghcr.io/hikyo-org/hikyo" and
		.image_digest == "sha256:1111111111111111111111111111111111111111111111111111111111111111")
' "$dist/release-manifest.json" >/dev/null

printf 'manifest fixture: complete artifact set recorded\n'
