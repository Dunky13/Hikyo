#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
dist="$repo_root/dist"
[ -f "$dist/metadata.json" ] || {
	printf 'snapshot manifest fixture: run GoReleaser snapshot first\n' >&2
	exit 2
}

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/wenv-snapshot-manifest.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
version=$(jq -r '.version' "$dist/metadata.json")
commit=$(jq -r '.commit' "$dist/metadata.json")
for expected in \
	"wenv_${version}_Darwin_x86_64.tar.gz" \
	"wenv_${version}_Darwin_arm64.tar.gz" \
	"wenv_${version}_Linux_x86_64.tar.gz" \
	"wenv_${version}_Linux_arm64.tar.gz" \
	"wenv_${version}_Windows_x86_64.zip" \
	"wenv_${version}_Windows_arm64.zip"
do
	[ -f "$dist/$expected" ] || {
		printf 'snapshot manifest fixture: missing installer archive %s\n' "$expected" >&2
		exit 1
	}
done

case "$(uname -s):$(uname -m)" in
	Linux:x86_64 | Linux:amd64) native_archive="wenv_${version}_Linux_x86_64.tar.gz" ;;
	Linux:arm64 | Linux:aarch64) native_archive="wenv_${version}_Linux_arm64.tar.gz" ;;
	Darwin:x86_64) native_archive="wenv_${version}_Darwin_x86_64.tar.gz" ;;
	Darwin:arm64) native_archive="wenv_${version}_Darwin_arm64.tar.gz" ;;
	*) printf 'snapshot manifest fixture: unsupported native runner\n' >&2; exit 1 ;;
esac
mkdir -p "$fixture_dir/native"
tar -xzf "$dist/$native_archive" -C "$fixture_dir/native" wenv
native_version=$("$fixture_dir/native/wenv" version)
case "$native_version" in
	"wenv $version ("*) ;;
	*) printf 'snapshot manifest fixture: binary version does not match archive version\n' >&2; exit 1 ;;
esac
rm -f "$dist/artifacts.json" "$dist/config.yaml" "$dist/metadata.json"

printf '{"spdxVersion":"SPDX-2.3"}\n' >"$dist/wenv-source.spdx.json"
printf '{"spdxVersion":"SPDX-2.3"}\n' >"$dist/wenv-image.spdx.json"
printf '#!/bin/sh\nexit 0\n' >"$dist/install.sh"
image_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111
chart_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222
jq -n --arg digest "$image_digest" '{critical:{identity:{"docker-reference":"ghcr.io/dunky13/wenv"},image:{"docker-manifest-digest":$digest}}}' \
	>"$dist/image-index.oci-payload.json"
jq -n --arg digest "$chart_digest" '{critical:{identity:{"docker-reference":"ghcr.io/dunky13/charts/wenv"},image:{"docker-manifest-digest":$digest}}}' \
	>"$dist/chart-index.oci-payload.json"
mkdir -p "$fixture_dir/wenv"
printf 'name: wenv\nversion: %s\nappVersion: %s\n' "$version" "$version" >"$fixture_dir/wenv/Chart.yaml"
printf 'image:\n  digest: %s\n' "$image_digest" >"$fixture_dir/wenv/values.yaml"
tar -czf "$dist/wenv-$version.tgz" -C "$fixture_dir" wenv
printf '{"releases":[{"version":"%s","sequence":1}]}\n' "$version" >"$fixture_dir/trust-metadata.json"

"$script_dir/create-manifest.sh" "$version" "$commit" primary-1 \
	ghcr.io/dunky13/wenv "$image_digest" ghcr.io/dunky13/charts/wenv "$chart_digest" \
	"$dist" "$fixture_dir/trust-metadata.json" >/dev/null

jq -e '
	([.artifacts[] | select(.kind == "binary")] | length) == 6 and
	([.artifacts[] | select(.kind == "chart")] | length) == 1 and
	([.artifacts[] | select(.kind == "oci-payload")] | length) == 2
' "$dist/release-manifest.json" >/dev/null
printf 'snapshot manifest fixture: complete GoReleaser output classified\n'
