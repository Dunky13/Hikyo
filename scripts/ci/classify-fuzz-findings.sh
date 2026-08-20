#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
	printf 'usage: %s ARTIFACT_ZIP BASE_SHA REPO_ROOT\n' "$0" >&2
	exit 2
fi

artifact_zip=$1
base_sha=$2
repo_root=$3
GO_BIN=${GO_BIN:-go}
JQ_BIN=${JQ_BIN:-jq}
UNZIP_BIN=${UNZIP_BIN:-unzip}

[ -f "$artifact_zip" ] || {
	printf 'fuzz classification: artifact ZIP not found\n' >&2
	exit 2
}
[ -d "$repo_root/.git" ] || [ -f "$repo_root/.git" ] || {
	printf 'fuzz classification: repository root is not a Git checkout\n' >&2
	exit 2
}
case "$base_sha" in
	*[!0-9a-f]* | '')
		printf 'fuzz classification: invalid base SHA\n' >&2
		exit 2
		;;
esac
[ "${#base_sha}" -eq 40 ] || {
	printf 'fuzz classification: base SHA must contain 40 hex characters\n' >&2
	exit 2
}

work_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hikyo-fuzz-classify.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
archive_entries="$work_dir/archive-entries"
valid_paths="$work_dir/valid-paths"
related_paths="$work_dir/related-paths"
unrelated_paths="$work_dir/unrelated-paths"
: >"$related_paths"
: >"$unrelated_paths"

"$UNZIP_BIN" -Z1 "$artifact_zip" >"$archive_entries"
awk '/^([A-Za-z0-9_][A-Za-z0-9._-]*\/)*testdata\/fuzz\/Fuzz[A-Za-z0-9_]+\/[0-9a-f]{64}$/ { print }' \
	"$archive_entries" | sort -u >"$valid_paths"

path_count=$(awk 'END { print NR }' "$valid_paths")
[ "$path_count" -gt 0 ] && [ "$path_count" -le 100 ] || {
	printf 'fuzz classification: expected 1-100 valid reproducers, got %s\n' \
		"$path_count" >&2
	exit 1
}

while IFS= read -r path; do
	target_and_hash=${path#*testdata/fuzz/}
	target=${target_and_hash%/*}
	case "$path" in
		testdata/fuzz/*)
			package_dir=.
			package=.
			;;
		*)
			package_dir=${path%/testdata/fuzz/*}
			package=./$package_dir
			;;
	esac

	# A target or package absent from the trusted base exists only because of
	# the PR, so its finding belongs on that PR without executing PR code here.
	if [ ! -d "$repo_root/$package_dir" ]; then
		printf '%s\n' "$path" >>"$related_paths"
		continue
	fi
	if ! listing=$(cd "$repo_root" && \
		"$GO_BIN" test -run='^$' -list="^${target}$" "$package" 2>&1); then
		printf 'fuzz classification: base target listing failed for %s; attributing to PR\n' \
			"$package" >&2
		printf '%s\n' "$path" >>"$related_paths"
		continue
	fi
	if ! printf '%s\n' "$listing" | grep -Fx "$target" >/dev/null; then
		printf '%s\n' "$path" >>"$related_paths"
		continue
	fi

	destination="$repo_root/$path"
	mkdir -p "$(dirname "$destination")"
	"$UNZIP_BIN" -p "$artifact_zip" "$path" >"$destination"
	if (cd "$repo_root" && "$GO_BIN" test -count=1 \
		-run="^${target_and_hash}\$" -timeout=30s "$package") >&2; then
		printf '%s\n' "$path" >>"$related_paths"
		printf 'fuzz classification: %s passes on base; PR-related\n' "$path" >&2
	else
		printf '%s\n' "$path" >>"$unrelated_paths"
		printf 'fuzz classification: %s also fails on base; independent issue\n' "$path" >&2
	fi
done <"$valid_paths"

related_json=$("$JQ_BIN" -Rsc 'split("\n") | map(select(length > 0))' "$related_paths")
unrelated_json=$("$JQ_BIN" -Rsc 'split("\n") | map(select(length > 0))' "$unrelated_paths")
"$JQ_BIN" -cn --arg base_sha "$base_sha" \
	--argjson related "$related_json" \
	--argjson unrelated "$unrelated_json" \
	"{base_sha: \$base_sha, related: \$related, unrelated: \$unrelated}"
