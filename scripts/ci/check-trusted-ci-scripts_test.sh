#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
workflow="$script_dir/../../.github/workflows/ci.yml"
controller="$script_dir/../../.github/workflows/ci-control.yml"
# Out-of-band fuzz reporting moved to its own trusted base-context workflow
# (#189): ci.yml / ci-control.yml execute untrusted PR code and hold no
# issue/PR write, while fuzz-report.yml runs on workflow_run completion in the
# base context and is the sole holder of write authority.
reporter="$script_dir/../../.github/workflows/fuzz-report.yml"

require_line() {
	file=$1
	expected=$2
	if ! grep -F -- "$expected" "$file" >/dev/null; then
		printf 'trusted CI scripts fixture failed: missing %s in %s\n' "$expected" "$(basename "$file")" >&2
		exit 1
	fi
}

# The reusable validation graph runs untrusted PR code through base-controlled
# trusted scripts (fetched at BASE_SHA) and uploads the fuzz reproducers as an
# artifact the trusted reporter re-validates.
require_line "$workflow" "git show \"\$BASE_SHA:scripts/ci/classify-changed-paths.sh\" >\"\$trusted_classifier\""
require_line "$workflow" "git show \"\$BASE_SHA:scripts/ci/ci-job-registry.json\" >\"\$trusted_registry\""
require_line "$workflow" "CI_JOB_REGISTRY=\"\$trusted_registry\" \"\$trusted_classifier\" --files"
require_line "$workflow" "git show \"\$BASE_SHA:scripts/ci/check-required-jobs.sh\" >\"\$trusted_checker\""
require_line "$workflow" "CI_JOB_REGISTRY=\"\$trusted_registry\" \"\$trusted_checker\" --supports-plan-v2"
require_line "$workflow" "CI_JOB_REGISTRY=\"\$trusted_registry\" \"\$trusted_checker\" \"\$GITHUB_EVENT_NAME\" \"\$NEEDS_JSON\" \"\$PLAN_JSON\""
require_line "$workflow" "git show \"\$BASE_SHA:scripts/ci/analysis-shards-go/main.go\" >\"\$trusted_planner\""
require_line "$workflow" 'name: Upload shard fuzz reproducers'
require_line "$workflow" 'name: Download shard fuzz reproducers'
require_line "$workflow" 'name: Upload minimized fuzz reproducers'
require_line "$workflow" "-fuzztime=100000x -timeout=2m"
# Workflow shell variables below are literal fixture text.
# shellcheck disable=SC2016
require_line "$workflow" 'echo "$shellcheck_dir" >>"$GITHUB_PATH"'
# GitHub expressions below are literal fixture text.
# shellcheck disable=SC2016
require_line "$workflow" 'FUZZ_SHARD_RESULT: ${{ needs.fuzz_shard.result }}'
# shellcheck disable=SC2016
require_line "$workflow" 'RACE_SHARD_RESULT: ${{ needs.race_shard.result }}'

download_block=$(sed -n \
	'/name: Download shard fuzz reproducers/,/name: Find merged fuzz reproducers/p' \
	"$workflow")
if printf '%s\n' "$download_block" | grep -F 'continue-on-error: true' >/dev/null; then
	printf 'trusted CI scripts fixture failed: shard artifact download errors are suppressed\n' >&2
	exit 1
fi

if grep -Eq '^[[:space:]]+pull_request:' "$workflow"; then
	printf 'trusted CI scripts fixture failed: direct pull-request trigger is enabled\n' >&2
	exit 1
fi
if ! grep -F 'pull_request_target:' "$controller" >/dev/null ||
	! grep -F 'uses: ./.github/workflows/ci.yml' "$controller" >/dev/null; then
	printf 'trusted CI scripts fixture failed: base-controlled entrypoint is missing\n' >&2
	exit 1
fi

# The untrusted validation graph (ci.yml, ci-control.yml) holds NO issue/PR write
# anywhere: executing attacker-influenced PR code must never reach a write token.
if grep -Eq '(issues|pull-requests): write' "$workflow" ||
	grep -Eq '(issues|pull-requests): write' "$controller"; then
	printf 'trusted CI scripts fixture failed: untrusted validation graph received issue/PR writes\n' >&2
	exit 1
fi

# The trusted reporter runs out of band on workflow_run completion, never as a
# direct pull_request(_target) job, and binds PR identity ONLY to GitHub-owned
# workflow_run metadata — never to an artifact an untrusted PR job could forge.
if ! grep -Eq '^  workflow_run:' "$reporter"; then
	printf 'trusted CI scripts fixture failed: reporter is not a workflow_run job\n' >&2
	exit 1
fi
if grep -Eq '^[[:space:]]+pull_request(_target)?:' "$reporter"; then
	printf 'trusted CI scripts fixture failed: reporter carries a direct pull-request trigger\n' >&2
	exit 1
fi
require_line "$reporter" 'github.event.workflow_run.pull_requests'

# The read-only classify job replays untrusted reproducers against the trusted
# base and holds no write; only the report jobs hold write. report-pr routes a
# PR finding (issues + PR write), report-main opens a repository issue for a main
# push (issues write). Both post through the base-controlled trusted script.
classify_block=$(sed -n '/^  classify:/,/^  report-pr:/p' "$reporter")
report_pr_block=$(sed -n '/^  report-pr:/,/^  report-main:/p' "$reporter")
report_main_block=$(sed -n '/^  report-main:/,$p' "$reporter")
if printf '%s\n' "$classify_block" | grep -Eq '(issues|pull-requests): write'; then
	printf 'trusted CI scripts fixture failed: read-only classify job received issue/PR writes\n' >&2
	exit 1
fi
if ! printf '%s\n' "$report_pr_block" | grep -F 'issues: write' >/dev/null ||
	! printf '%s\n' "$report_pr_block" | grep -F 'pull-requests: write' >/dev/null ||
	! printf '%s\n' "$report_pr_block" | grep -F './scripts/ci/report-fuzz-finding.sh "PR #' >/dev/null; then
	printf 'trusted CI scripts fixture failed: trusted PR fuzz reporter is missing\n' >&2
	exit 1
fi
if ! printf '%s\n' "$report_main_block" | grep -F 'issues: write' >/dev/null ||
	! printf '%s\n' "$report_main_block" | grep -F './scripts/ci/report-fuzz-finding.sh main' >/dev/null; then
	printf 'trusted CI scripts fixture failed: trusted main fuzz reporter is missing\n' >&2
	exit 1
fi

printf 'trusted CI scripts fixture: untrusted validation graph holds no writes; the out-of-band reporter owns PR binding and issue writes\n'
