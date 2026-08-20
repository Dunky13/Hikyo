#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
	printf 'usage: %s SCOPE HEAD_SHA RUN_URL RUN_ID RUN_ATTEMPT\n' "$0" >&2
	exit 2
fi

scope=$1
head_sha=$2
run_url=$3
run_id=$4
run_attempt=$5
GH_BIN=${GH_BIN:-gh}
JQ_BIN=${JQ_BIN:-jq}
UNZIP_BIN=${UNZIP_BIN:-unzip}
retry_delay_seconds=${FUZZ_ARTIFACT_RETRY_DELAY_SECONDS:-2}

case "$scope" in
	main) ;;
	'PR #'*)
		pr_number=${scope#PR #}
		case "$pr_number" in
			*[!0-9]* | '' | 0*)
				printf 'fuzz issue: invalid scope %s\n' "$scope" >&2
				exit 2
				;;
		esac
		;;
	*)
		printf 'fuzz issue: invalid scope %s\n' "$scope" >&2
		exit 2
		;;
esac
case "$head_sha" in
	*[!0-9a-f]* | '')
		printf 'fuzz issue: invalid head SHA\n' >&2
		exit 2
		;;
esac
[ "${#head_sha}" -eq 40 ] || {
	printf 'fuzz issue: head SHA must contain 40 hex characters\n' >&2
	exit 2
}
for value in "$run_id" "$run_attempt"; do
	case "$value" in
		*[!0-9]* | '' | 0*)
			printf 'fuzz issue: invalid run identity\n' >&2
			exit 2
			;;
	esac
done
case "$retry_delay_seconds" in
	*[!0-9]* | '')
		printf 'fuzz issue: invalid artifact retry delay\n' >&2
		exit 2
		;;
esac
[ -n "${GH_REPO:-}" ] || {
	printf 'fuzz issue: GH_REPO is required\n' >&2
	exit 2
}
if ! printf '%s\n' "$GH_REPO" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'; then
	printf 'fuzz issue: invalid GH_REPO\n' >&2
	exit 2
fi
if [ "$run_url" != "https://github.com/$GH_REPO/actions/runs/$run_id" ]; then
	printf 'fuzz issue: invalid run URL\n' >&2
	exit 2
fi

artifact_name="fuzz-reproducers-$run_id-$run_attempt"
work_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hikyo-fuzz-issue.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
artifact_zip="$work_dir/reproducers.zip"
artifact_json="$work_dir/artifacts.json"

attempt=1
artifact_id=
while [ "$attempt" -le 5 ]; do
	"$GH_BIN" api "repos/$GH_REPO/actions/runs/$run_id/artifacts?per_page=100" >"$artifact_json"
	jq_filter="
		first(
			.artifacts[] |
			select(.name == \$name and .expired == false) |
			.id
		) // empty
	"
	artifact_id=$("$JQ_BIN" -r --arg name "$artifact_name" "$jq_filter" \
		"$artifact_json")
	[ -z "$artifact_id" ] || break
	[ "$attempt" -eq 5 ] || sleep "$retry_delay_seconds"
	attempt=$((attempt + 1))
done

if [ -z "$artifact_id" ]; then
printf 'fuzz report: no reproducer artifact named %s\n' "$artifact_name"
	exit 0
fi
case "$artifact_id" in
	*[!0-9]* | '')
		printf 'fuzz issue: artifact API returned an invalid ID\n' >&2
		exit 1
		;;
esac

"$GH_BIN" api "repos/$GH_REPO/actions/artifacts/$artifact_id/zip" >"$artifact_zip"

paths_file="$work_dir/paths"
archive_entries="$work_dir/archive-entries"
valid_paths="$work_dir/valid-paths"
"$UNZIP_BIN" -Z1 "$artifact_zip" >"$archive_entries"
awk '/^([A-Za-z0-9_][A-Za-z0-9._-]*\/)*testdata\/fuzz\/Fuzz[A-Za-z0-9_]+\/[0-9a-f]{64}$/ { print }' \
	"$archive_entries" >"$valid_paths"
sort -u "$valid_paths" >"$paths_file"

if [ ! -s "$paths_file" ]; then
	printf 'fuzz issue: artifact %s contained no valid Go fuzz reproducers\n' "$artifact_name" >&2
	exit 1
fi

path_count=$(awk 'END { print NR }' "$paths_file")
[ "$path_count" -le 100 ] || {
	printf 'fuzz issue: artifact contains too many reproducers (%s)\n' "$path_count" >&2
	exit 1
}

related_paths="$work_dir/related-paths"
unrelated_paths="$work_dir/unrelated-paths"
: >"$related_paths"
: >"$unrelated_paths"
classification_base=
classification_note=

if [ "$scope" = main ]; then
	cp "$paths_file" "$unrelated_paths"
elif [ -z "${FUZZ_CLASSIFICATION:-}" ]; then
	# Attribution failure must not create a potentially unrelated public issue.
	# Keep findings on the PR until the trusted base replay can classify them.
	cp "$paths_file" "$related_paths"
	classification_note='Base replay attribution was unavailable; treating these findings as PR-related.'
else
	classification_file="$work_dir/classification.json"
	printf '%s\n' "$FUZZ_CLASSIFICATION" >"$classification_file"
	if ! "$JQ_BIN" -e '
		type == "object" and
		(.base_sha | type == "string" and test("^[0-9a-f]{40}$")) and
		(.related | type == "array" and all(.[]; type == "string") and length == (unique | length)) and
		(.unrelated | type == "array" and all(.[]; type == "string") and length == (unique | length)) and
		([.related[], .unrelated[]] | length == (unique | length))
	' "$classification_file" >/dev/null; then
		printf 'fuzz report: invalid base-replay classification\n' >&2
		exit 1
	fi
	classification_base=$("$JQ_BIN" -r '.base_sha' "$classification_file")
	"$JQ_BIN" -r '.related[]' "$classification_file" | sort -u >"$related_paths"
	"$JQ_BIN" -r '.unrelated[]' "$classification_file" | sort -u >"$unrelated_paths"
	classified_paths="$work_dir/classified-paths"
	cat "$related_paths" "$unrelated_paths" | sort -u >"$classified_paths"
	if ! cmp -s "$paths_file" "$classified_paths"; then
		printf 'fuzz report: classification does not cover the artifact exactly\n' >&2
		exit 1
	fi
	classification_note="Trusted replay used PR base \`$classification_base\`."
fi

write_body() {
	selected_paths=$1
	body_file=$2
	intro=$3
	selected_count=$(awk 'END { print NR }' "$selected_paths")
	{
		printf '%s\n\n' "$intro"
		printf "Fuzz CI produced %s minimized reproducer(s) for commit \`%s\`.\n\n" \
			"$selected_count" "$head_sha"
		[ -z "$classification_note" ] || printf '%s\n\n' "$classification_note"
		printf -- '- Run: %s\n' "$run_url"
		printf -- "- Artifact: \`%s\` (retained for 30 days)\n\n" "$artifact_name"
		printf 'Download the artifact, extract it at the repository root, then run:\n\n'
		while IFS= read -r path; do
			target_and_hash=${path#*testdata/fuzz/}
			case "$path" in
				testdata/fuzz/*) package=. ;;
				*) package=./${path%/testdata/fuzz/*} ;;
			esac
			printf -- "- \`%s\`\n\n" "$path"
			printf '  ```sh\n'
			printf "  go test -run='^%s\$' %s\n" "$target_and_hash" "$package"
			printf '  ```\n\n'
		done <"$selected_paths"
		printf "Failure output and stack traces remain in the linked run log. Commit each reproducer with the fix so normal \`go test ./...\` prevents regression.\n"
	} >"$body_file"
}

if [ -s "$related_paths" ]; then
	pr_body="$work_dir/pr-comment.md"
	write_body "$related_paths" "$pr_body" \
		'<!-- hikyo-fuzz-findings -->
These findings do not reproduce on the trusted base (or target code is new), so they match this PR.'
	"$GH_BIN" pr comment "$pr_number" --body-file "$pr_body" \
		--edit-last --create-if-none
	printf 'fuzz report: added PR-related findings to PR #%s\n' "$pr_number"
fi

if [ -s "$unrelated_paths" ]; then
	issue_body="$work_dir/issue.md"
	case "$scope" in
		main)
			title='Fuzz CI found reproducible failure on main'
			intro="Fuzz CI found independently actionable failures on \`main\`."
			;;
		*)
			title='Fuzz CI found a pre-existing reproducible failure'
			intro="These findings also reproduce on the trusted base while testing $scope, so they are tracked independently."
			;;
	esac
	write_body "$unrelated_paths" "$issue_body" "$intro"
	issue_jq="map(select(.title == \"$title\"))[0].number // empty"
	issue_number=$("$GH_BIN" issue list --state open --search "$title in:title" \
		--json number,title --jq "$issue_jq")
	if [ -n "$issue_number" ]; then
		"$GH_BIN" issue comment "$issue_number" --body-file "$issue_body"
		printf 'fuzz report: added independent findings to issue #%s\n' "$issue_number"
	else
		"$GH_BIN" issue create --title "$title" --label bug --body-file "$issue_body"
	fi
fi
