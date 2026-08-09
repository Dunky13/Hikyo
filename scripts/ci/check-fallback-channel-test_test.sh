#!/bin/sh
set -eu

CDPATH=
repo_root=$(cd -- "$(dirname "$0")/../.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/wenv-fallback-channel.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

cat >"$fixture_dir/passed.json" <<'EOF'
{
  "schema": "wenv.dev/fallback-channel-test/v1",
  "address": "security@developwent.io",
  "status": "passed",
  "sent_at": "2026-08-01T10:00:00Z",
  "received_at": "2026-08-01T10:05:00Z",
  "message_id_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
EOF

WENV_FALLBACK_TEST_NOW=2026-08-09T00:00:00Z \
	"$repo_root/scripts/ci/check-fallback-channel-test.sh" \
	"$fixture_dir/passed.json" security@developwent.io

jq '.status = "pending"' "$fixture_dir/passed.json" >"$fixture_dir/pending.json"
if WENV_FALLBACK_TEST_NOW=2026-08-10T00:00:00Z \
	"$repo_root/scripts/ci/check-fallback-channel-test.sh" \
	"$fixture_dir/pending.json" security@developwent.io >/dev/null 2>&1; then
	printf 'fallback fixture failed: pending test was accepted\n' >&2
	exit 1
fi

jq '.sent_at = "2026-04-01T10:00:00Z" | .received_at = "2026-04-01T10:05:00Z"' \
	"$fixture_dir/passed.json" >"$fixture_dir/stale.json"
if WENV_FALLBACK_TEST_NOW=2026-08-09T00:00:00Z \
	"$repo_root/scripts/ci/check-fallback-channel-test.sh" \
	"$fixture_dir/stale.json" security@developwent.io >/dev/null 2>&1; then
	printf 'fallback fixture failed: stale test was accepted\n' >&2
	exit 1
fi

jq '.received_at = "2026-08-09T10:01:00Z"' \
	"$fixture_dir/passed.json" >"$fixture_dir/late.json"
if WENV_FALLBACK_TEST_NOW=2026-08-10T00:00:00Z \
	"$repo_root/scripts/ci/check-fallback-channel-test.sh" \
	"$fixture_dir/late.json" security@developwent.io >/dev/null 2>&1; then
	printf 'fallback fixture failed: receipt outside acknowledgement window was accepted\n' >&2
	exit 1
fi
