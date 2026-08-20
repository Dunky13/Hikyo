#!/bin/sh
set -eu

CDPATH=
script_dir=$(cd -- "$(dirname "$0")" && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-fuzz-issue.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

mkdir -p "$fixture_dir/artifact/internal/crypto/testdata/fuzz/FuzzParseHeader"
reproducer_hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
printf 'go test fuzz v1\n[]byte("bad")\n' \
	>"$fixture_dir/artifact/internal/crypto/testdata/fuzz/FuzzParseHeader/$reproducer_hash"
(cd "$fixture_dir/artifact" && zip -qr "$fixture_dir/reproducers.zip" .)

cat >"$fixture_dir/gh" <<'EOF'
#!/bin/sh
set -eu

case "$1:$2" in
	api:repos/*/actions/runs/*/artifacts*)
		if [ "${FAKE_NO_ARTIFACT:-0}" -eq 1 ]; then
			printf '{"artifacts":[]}\n'
		else
			printf '{"artifacts":[{"id":42,"name":"fuzz-reproducers-123-1","expired":false}]}\n'
		fi
		;;
	api:repos/*/actions/artifacts/42/zip)
		cat "${FAKE_ARTIFACT_ZIP:?}"
		;;
	issue:list)
		if [ "${FAKE_EXISTING_ISSUE:-0}" -eq 1 ]; then
			printf '77\n'
		fi
		;;
	issue:create | issue:comment | pr:comment)
		printf '%s\n' "$*" >>"${FAKE_GH_LOG:?}"
		while [ "$#" -gt 0 ]; do
			if [ "$1" = '--body-file' ]; then
				shift
				cp "$1" "${FAKE_ISSUE_BODY:?}"
				break
			fi
			shift
		done
		;;
	*)
		printf 'unexpected gh fixture invocation: %s\n' "$*" >&2
		exit 1
		;;
esac
EOF
chmod +x "$fixture_dir/gh"

run_reporter() {
	GH_BIN="$fixture_dir/gh" \
	GH_REPO=Hikyo-Org/Hikyo \
	FAKE_ARTIFACT_ZIP="${FAKE_ARTIFACT_ZIP_OVERRIDE:-$fixture_dir/reproducers.zip}" \
	FAKE_GH_LOG="$fixture_dir/gh.log" \
	FAKE_ISSUE_BODY="$fixture_dir/body.md" \
	FUZZ_ARTIFACT_RETRY_DELAY_SECONDS=0 \
	FUZZ_CLASSIFICATION="${FUZZ_CLASSIFICATION_OVERRIDE:-}" \
	"$script_dir/report-fuzz-finding.sh" \
		"$@"
}

head_sha=0123456789abcdef0123456789abcdef01234567
base_sha=abcdef0123456789abcdef0123456789abcdef01
run_url=https://github.com/Hikyo-Org/Hikyo/actions/runs/123
reproducer_path="internal/crypto/testdata/fuzz/FuzzParseHeader/$reproducer_hash"
related_classification=$(jq -cn --arg base "$base_sha" --arg path "$reproducer_path" \
	'{base_sha: $base, related: [$path], unrelated: []}')
unrelated_classification=$(jq -cn --arg base "$base_sha" --arg path "$reproducer_path" \
	'{base_sha: $base, related: [], unrelated: [$path]}')
FUZZ_CLASSIFICATION_OVERRIDE="$related_classification" \
	run_reporter 'PR #19' "$head_sha" "$run_url" 123 1 >/dev/null
unset FUZZ_CLASSIFICATION_OVERRIDE

grep -F 'pr comment 19' "$fixture_dir/gh.log" >/dev/null
grep -F -- '--edit-last --create-if-none' "$fixture_dir/gh.log" >/dev/null
grep -F 'match this PR' "$fixture_dir/body.md" >/dev/null
grep -F "go test -run='^FuzzParseHeader/$reproducer_hash\$' ./internal/crypto" \
	"$fixture_dir/body.md" >/dev/null
grep -F 'fuzz-reproducers-123-1' "$fixture_dir/body.md" >/dev/null

: >"$fixture_dir/gh.log"
FUZZ_CLASSIFICATION_OVERRIDE="$unrelated_classification" \
	run_reporter 'PR #19' "$head_sha" "$run_url" 123 1 >/dev/null
unset FUZZ_CLASSIFICATION_OVERRIDE
grep -F 'issue create' "$fixture_dir/gh.log" >/dev/null
grep -F 'pre-existing reproducible failure' "$fixture_dir/gh.log" >/dev/null
grep -F 'reproduce on the trusted base' "$fixture_dir/body.md" >/dev/null

: >"$fixture_dir/gh.log"
FAKE_EXISTING_ISSUE=1 FUZZ_CLASSIFICATION_OVERRIDE="$unrelated_classification" \
	run_reporter 'PR #19' "$head_sha" "$run_url" 123 1 >/dev/null
unset FAKE_EXISTING_ISSUE
unset FUZZ_CLASSIFICATION_OVERRIDE
grep -F 'issue comment 77' "$fixture_dir/gh.log" >/dev/null
if grep -F 'issue create' "$fixture_dir/gh.log" >/dev/null; then
	printf 'fuzz issue fixture failed: duplicate issue created\n' >&2
	exit 1
fi

: >"$fixture_dir/gh.log"
FAKE_NO_ARTIFACT=1 run_reporter main "$head_sha" "$run_url" 123 1 >/dev/null
unset FAKE_NO_ARTIFACT
if [ -s "$fixture_dir/gh.log" ]; then
	printf 'fuzz issue fixture failed: issue changed without a reproducer artifact\n' >&2
	exit 1
fi

if run_reporter 'PR #19 @maintainers' "$head_sha" "$run_url" 123 1 \
	>/dev/null 2>&1; then
	printf 'fuzz issue fixture failed: unsafe issue scope accepted\n' >&2
	exit 1
fi

mkdir -p "$fixture_dir/invalid-artifact"
printf 'not a corpus file\n' >"$fixture_dir/invalid-artifact/notes.md"
(cd "$fixture_dir/invalid-artifact" && zip -qr "$fixture_dir/invalid.zip" .)
if FAKE_ARTIFACT_ZIP_OVERRIDE="$fixture_dir/invalid.zip" run_reporter \
	'PR #19' "$head_sha" "$run_url" 123 1 >/dev/null 2>&1; then
	printf 'fuzz issue fixture failed: artifact without corpus files accepted\n' >&2
	exit 1
fi

printf 'fuzz reporter fixture: related PR comment, unrelated issue, dedup, and refusal paths passed\n'
