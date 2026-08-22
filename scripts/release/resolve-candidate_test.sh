#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-candidate-fixture.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
version=1.2.3

jq -n '
	{
		releases: [{version: "1.2.2", sequence: 6, manifest_sha256: ("1" * 64)}],
		pending_release: {version: "1.2.3", sequence: 7, manifest_sha256: ("0" * 64)},
		primary_keys: [
			{id: "primary-1", public_key: "primary-1.pub", sha256: ("a" * 64), valid_from_release_sequence: 1,
			 valid_through_release_sequence: 6, revoked: false},
			{id: "primary-2", public_key: "primary-2.pub", sha256: ("b" * 64), valid_from_release_sequence: 7,
			 valid_through_release_sequence: null, revoked: false}
		]
	}
' >"$fixture_dir/metadata.json"

expect_reject() {
	label=$1
	expected=$2
	metadata=$3
	if "$script_dir/resolve-candidate.sh" "$metadata" "$version" "$commit" \
		>"$fixture_dir/rejected.json" 2>"$fixture_dir/rejected.log"; then
		printf 'candidate fixture failed: %s was accepted\n' "$label" >&2
		exit 1
	fi
	grep -F "$expected" "$fixture_dir/rejected.log" >/dev/null || {
		printf 'candidate fixture failed: %s rejected for unexpected reason\n' "$label" >&2
		cat "$fixture_dir/rejected.log" >&2
		exit 1
	}
	printf 'candidate fixture: %s refused\n' "$label"
}

"$script_dir/resolve-candidate.sh" "$fixture_dir/metadata.json" "$version" "$commit" \
	>"$fixture_dir/candidate.json"
"$script_dir/resolve-candidate.sh" "$fixture_dir/metadata.json" "$version" "$commit" pending \
	>"$fixture_dir/pending-candidate.json"
cmp -s "$fixture_dir/candidate.json" "$fixture_dir/pending-candidate.json"
expected='{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key_id":"primary-2","public_key":"primary-2.pub","sequence":7,"version":"1.2.3"}'
[ "$(cat "$fixture_dir/candidate.json")" = "$expected" ] || {
	printf 'candidate fixture failed: output is not canonical\n' >&2
	exit 1
}
candidate_sha=$(shasum -a 256 "$fixture_dir/candidate.json" | awk '{print $1}')
"$script_dir/check-candidate.sh" "$fixture_dir/candidate.json" "$candidate_sha"
printf 'candidate fixture: pending release resolved canonically\n'

jq '.pending_release = {version: "9.9.9", sequence: 8, manifest_sha256: ("0" * 64)}' \
	"$fixture_dir/metadata.json" >"$fixture_dir/missing.json"
expect_reject 'missing release' 'release version is absent' "$fixture_dir/missing.json"

jq '.releases += [{version: "1.2.3", sequence: 5, manifest_sha256: ("2" * 64)}]' \
	"$fixture_dir/metadata.json" >"$fixture_dir/duplicate-version.json"
expect_reject 'duplicate release version' 'release version is duplicated' \
	"$fixture_dir/duplicate-version.json"

jq '.releases += [{version: "1.2.1", sequence: 7, manifest_sha256: ("2" * 64)}]' \
	"$fixture_dir/metadata.json" >"$fixture_dir/duplicate-sequence.json"
expect_reject 'duplicate release sequence' 'release sequence is duplicated' \
	"$fixture_dir/duplicate-sequence.json"

jq '.releases += [
	{version: "1.1.0", sequence: 4, manifest_sha256: ("2" * 64)},
	{version: "1.1.0", sequence: 5, manifest_sha256: ("3" * 64)}
]' "$fixture_dir/metadata.json" >"$fixture_dir/unrelated-duplicate-version.json"
expect_reject 'unrelated duplicate release version' 'release version is duplicated' \
	"$fixture_dir/unrelated-duplicate-version.json"

jq '.releases += [
	{version: "1.1.0", sequence: 4, manifest_sha256: ("2" * 64)},
	{version: "1.1.1", sequence: 4, manifest_sha256: ("3" * 64)}
]' "$fixture_dir/metadata.json" >"$fixture_dir/unrelated-duplicate-sequence.json"
expect_reject 'unrelated duplicate release sequence' 'release sequence is duplicated' \
	"$fixture_dir/unrelated-duplicate-sequence.json"

jq '.primary_keys += [{id: "overlap", public_key: "overlap.pub", sha256: ("c" * 64),
	valid_from_release_sequence: 7, valid_through_release_sequence: 8, revoked: false}]' \
	"$fixture_dir/metadata.json" >"$fixture_dir/overlap.json"
expect_reject 'overlapping primary intervals' 'primary-key intervals overlap' \
	"$fixture_dir/overlap.json"

jq '(.primary_keys[] | select(.id == "primary-2")).pending = true' \
	"$fixture_dir/metadata.json" >"$fixture_dir/pending-key.json"
expect_reject 'pending primary key' 'primary key is pending' "$fixture_dir/pending-key.json"

jq '(.primary_keys[] | select(.id == "primary-2")).revoked = true' \
	"$fixture_dir/metadata.json" >"$fixture_dir/revoked-key.json"
expect_reject 'revoked primary key' 'primary key is revoked' "$fixture_dir/revoked-key.json"

jq '(.primary_keys[] | select(.id == "primary-2")).valid_from_release_sequence = 8' \
	"$fixture_dir/metadata.json" >"$fixture_dir/out-of-interval.json"
expect_reject 'out-of-interval primary key' 'no primary key covers release sequence' \
	"$fixture_dir/out-of-interval.json"

"$script_dir/resolve-candidate.sh" "$fixture_dir/metadata.json" 1.2.2 "$commit" \
	>"$fixture_dir/boundary.json"
jq -e '.sequence == 6 and .key_id == "primary-1" and .public_key == "primary-1.pub"' \
	"$fixture_dir/boundary.json" >/dev/null
printf 'candidate fixture: inclusive interval boundary is deterministic\n'

jq 'del(.pending_release)' "$fixture_dir/metadata.json" >"$fixture_dir/finalized-only.json"
"$script_dir/resolve-candidate.sh" "$fixture_dir/finalized-only.json" 1.2.2 "$commit" \
	>"$fixture_dir/finalized-only-candidate.json"
cmp -s "$fixture_dir/boundary.json" "$fixture_dir/finalized-only-candidate.json"
printf 'candidate fixture: finalized-only metadata resolved\n'

if "$script_dir/resolve-candidate.sh" "$fixture_dir/metadata.json" 1.2.2 "$commit" pending \
	>/dev/null 2>"$fixture_dir/finalized.log"; then
	printf 'candidate fixture failed: finalized release was accepted as pending\n' >&2
	exit 1
fi
grep -F 'release is not a pending candidate' "$fixture_dir/finalized.log" >/dev/null
printf 'candidate fixture: finalized release refused as pending\n'

cp "$fixture_dir/candidate.json" "$fixture_dir/noncanonical.json"
printf ' ' >>"$fixture_dir/noncanonical.json"
noncanonical_sha=$(shasum -a 256 "$fixture_dir/noncanonical.json" | awk '{print $1}')
if "$script_dir/check-candidate.sh" "$fixture_dir/noncanonical.json" "$noncanonical_sha" \
	>/dev/null 2>"$fixture_dir/noncanonical.log"; then
	printf 'candidate fixture failed: noncanonical record was accepted\n' >&2
	exit 1
fi
grep -F 'record is not canonical JSON' "$fixture_dir/noncanonical.log" >/dev/null
printf 'candidate fixture: noncanonical record refused\n'

if "$script_dir/check-candidate.sh" "$fixture_dir/candidate.json" \
	bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
	>/dev/null 2>"$fixture_dir/tamper.log"; then
	printf 'candidate fixture failed: record hash mismatch was accepted\n' >&2
	exit 1
fi
grep -F 'record hash mismatch' "$fixture_dir/tamper.log" >/dev/null
printf 'candidate fixture: tampered record refused\n'
