#!/bin/sh
set -eu

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/wenv-tag-probe.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

printf '#!/bin/sh\nprintf "gh: Repository rule violations found for refs/tags/v-ruleset-probe (HTTP 422)\\n" >&2\nexit 1\n' >"$fixture_dir/deny-gh"
printf '#!/bin/sh\nexit 0\n' >"$fixture_dir/allow-gh"
printf '#!/bin/sh\nprintf "gh: authentication failed (HTTP 401)\\n" >&2\nexit 1\n' >"$fixture_dir/error-gh"
# The fixture resolves the probe tag to A and the replacement to B.
# shellcheck disable=SC2016
printf '#!/bin/sh\ncase "$2" in v-ruleset-probe*) printf "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n" ;; *) printf "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\\n" ;; esac\n' >"$fixture_dir/git"
chmod +x "$fixture_dir/deny-gh" "$fixture_dir/allow-gh" "$fixture_dir/error-gh"
chmod +x "$fixture_dir/git"

sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
PATH="$fixture_dir:$PATH" WENV_ALLOW_IMMUTABLE_TAG_PROBE=YES GH_BIN="$fixture_dir/deny-gh" \
	"$(dirname "$0")/probe-tag-move.sh" owner/repo v-ruleset-probe "$sha" >/dev/null

if PATH="$fixture_dir:$PATH" WENV_ALLOW_IMMUTABLE_TAG_PROBE=YES GH_BIN="$fixture_dir/allow-gh" \
	"$(dirname "$0")/probe-tag-move.sh" owner/repo v-ruleset-probe "$sha" >/dev/null 2>&1; then
	printf 'tag probe fixture failed: accepted mutation was treated as success\n' >&2
	exit 1
fi

if PATH="$fixture_dir:$PATH" WENV_ALLOW_IMMUTABLE_TAG_PROBE=YES GH_BIN="$fixture_dir/error-gh" \
	"$(dirname "$0")/probe-tag-move.sh" owner/repo v-ruleset-probe "$sha" >/dev/null 2>&1; then
	printf 'tag probe fixture failed: API failure was treated as ruleset proof\n' >&2
	exit 1
fi

printf 'tag probe fixture: ruleset denial passes; accepted move and API failure fail\n'
