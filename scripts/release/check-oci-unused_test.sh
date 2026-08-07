#!/bin/sh
set -eu

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/wenv-oci-guard.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
printf '#!/bin/sh\nprintf "manifest unknown\\n" >&2\nexit 1\n' >"$fixture_dir/missing"
printf '#!/bin/sh\nexit 0\n' >"$fixture_dir/found"
printf '#!/bin/sh\nprintf "unauthorized\\n" >&2\nexit 1\n' >"$fixture_dir/error"
chmod +x "$fixture_dir/missing" "$fixture_dir/found" "$fixture_dir/error"

DOCKER_BIN="$fixture_dir/missing" "$(dirname "$0")/check-oci-unused.sh" registry.example/wenv:0.1.0 >/dev/null
for fixture in found error; do
	if DOCKER_BIN="$fixture_dir/$fixture" \
		"$(dirname "$0")/check-oci-unused.sh" registry.example/wenv:0.1.0 >/dev/null 2>&1; then
		printf 'OCI guard fixture failed: %s accepted\n' "$fixture" >&2
		exit 1
	fi
done
printf 'OCI guard fixture: missing accepted; existing and inconclusive refused\n'
