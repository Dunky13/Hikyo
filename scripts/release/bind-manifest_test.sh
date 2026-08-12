#!/bin/sh
set -eu

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-bind-manifest.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
printf '{"version":"0.1.0","release_sequence":7}\n' >"$fixture_dir/manifest.json"
printf '{"sequence":4,"highest_release":"0.0.9","highest_release_sequence":6,"recovery":{"id":"recovery-1"},"event":{"type":"rotation"},"releases":[{"version":"0.0.9","sequence":6,"manifest_sha256":"%064d"}],"pending_release":{"version":"0.1.0","sequence":7,"manifest_sha256":"%064d"}}\n' 1 0 \
	>"$fixture_dir/metadata.json"

"$(dirname "$0")/bind-manifest.sh" "$fixture_dir/manifest.json" \
	"$fixture_dir/metadata.json" "$fixture_dir/bound.json" >/dev/null
want=$(shasum -a 256 "$fixture_dir/manifest.json" | awk '{print $1}')
jq -e --arg want "$want" '
	.sequence == 5 and .event == {type: "release", signed_by: "recovery-1"} and
	.highest_release == "0.1.0" and .highest_release_sequence == 7 and
	.pending_release == null and .releases[1].manifest_sha256 == $want
	' "$fixture_dir/bound.json" >/dev/null
printf 'manifest binding fixture: recovery metadata binds exact release bytes\n'
