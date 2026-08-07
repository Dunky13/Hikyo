#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/../lib/release.sh"

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/wenv-installer-fixture.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
printf '{"root":"fixture"}\n' >"$fixture_dir/root.json"
printf '#!/bin/sh\nexit 0\n' >"$fixture_dir/verify.sh"

"$script_dir/render-installer.sh" 0.1.0 "$fixture_dir/root.json" \
	"$fixture_dir/verify.sh" "$fixture_dir/install.sh" >/dev/null

grep -F "version='0.1.0'" "$fixture_dir/install.sh" >/dev/null
grep -F "root_sha256='$(sha256_file "$fixture_dir/root.json")'" "$fixture_dir/install.sh" >/dev/null
grep -F "verifier_sha256='$(sha256_file "$fixture_dir/verify.sh")'" "$fixture_dir/install.sh" >/dev/null
grep -F "release_lib_sha256='$(sha256_file "$script_dir/../lib/release.sh")'" "$fixture_dir/install.sh" >/dev/null
grep -F "current_trust_url=\"https://raw.githubusercontent.com/\$repository/refs/heads/main\"" \
	"$fixture_dir/install.sh" >/dev/null
grep -F "download \"\$current_trust_url/release/trust/metadata.json\"" \
	"$fixture_dir/install.sh" >/dev/null
if grep -E '@(VERSION|ROOT_SHA256|VERIFIER_SHA256|RELEASE_LIB_SHA256)@' "$fixture_dir/install.sh" >/dev/null; then
	printf 'installer fixture failed: unresolved placeholder\n' >&2
	exit 1
fi

printf 'installer fixture: trust root and verifier pinned; current revocations fetched\n'
