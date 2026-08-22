#!/bin/sh
set -eu

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-image-root-fixture.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
dist="$fixture_dir/dist"
image_root="$fixture_dir/image-root"
config="$fixture_dir/goreleaser.yaml"
commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
version=0.0.0-snapshot-aaaaaaaa
mkdir -p "$dist/hikyo_linux_amd64_v1" "$dist/hikyo_linux_arm64_v8.0"
printf 'amd64 canonical binary\n' >"$dist/hikyo_linux_amd64_v1/hikyo"
printf 'arm64 canonical binary\n' >"$dist/hikyo_linux_arm64_v8.0/hikyo"
printf 'builds:\n  - id: hikyo\n' >"$config"
jq -n --arg commit "$commit" --arg version "$version" \
	'{commit: $commit, version: $version}' >"$dist/metadata.json"
jq -n \
	--arg amd64 "$dist/hikyo_linux_amd64_v1/hikyo" \
	--arg arm64 "$dist/hikyo_linux_arm64_v8.0/hikyo" \
	'[
		{name:"hikyo", path:$amd64, goos:"linux", goarch:"amd64", type:"Binary", extra:{ID:"hikyo"}},
		{name:"hikyo", path:$arm64, goos:"linux", goarch:"arm64", type:"Binary", extra:{ID:"hikyo"}}
	]' >"$dist/artifacts.json"

"$(dirname "$0")/prepare-image-root.sh" "$dist" "$image_root" "$commit" "$config" >/dev/null

cmp "$dist/hikyo_linux_amd64_v1/hikyo" "$image_root/amd64/hikyo"
cmp "$dist/hikyo_linux_arm64_v8.0/hikyo" "$image_root/arm64/hikyo"
config_sha=$(sha256sum "$config" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$config" | awk '{print $1}')
jq -e \
	--arg commit "$commit" \
	--arg version "$version" \
	--arg config_sha "$config_sha" '
	.schema == "hikyo.dev/release-binaries/v1" and
	.source_commit == $commit and
	.version == $version and
	.producer == {
		name: "goreleaser",
		build_id: "hikyo",
		config: ".goreleaser.yaml",
		config_sha256: $config_sha
	} and
	([.packages[] | select(
		.goos == "linux" and
		(.goarch == "amd64" or .goarch == "arm64") and
		.archive_input.sha256 == .oci_input.sha256
	)] | length) == 2
' "$dist/binary-provenance.json" >/dev/null

jq '.[1] = .[0] | .[1].path = (. [0].path + ".duplicate")' \
	"$dist/artifacts.json" >"$fixture_dir/duplicate.json"
cp "$dist/hikyo_linux_amd64_v1/hikyo" "$dist/hikyo_linux_amd64_v1/hikyo.duplicate"
cp "$fixture_dir/duplicate.json" "$dist/artifacts.json"
if "$(dirname "$0")/prepare-image-root.sh" "$dist" "$image_root" "$commit" "$config" \
	>"$fixture_dir/duplicate.out" 2>"$fixture_dir/duplicate.err"
then
	printf 'prepare image root fixture: duplicate architecture unexpectedly accepted\n' >&2
	exit 1
fi
grep -F 'expected exactly one GoReleaser binary for linux/amd64' "$fixture_dir/duplicate.err" >/dev/null

printf 'prepare image root fixture: canonical amd64/arm64 binaries and provenance verified\n'
