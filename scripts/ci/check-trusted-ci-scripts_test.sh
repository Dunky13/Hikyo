#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
workflow="$script_dir/../../.github/workflows/ci.yml"
controller="$script_dir/../../.github/workflows/ci-control.yml"

require_workflow_line() {
	expected=$1
	if ! grep -F -- "$expected" "$workflow" >/dev/null; then
		printf 'trusted CI scripts fixture failed: missing %s\n' "$expected" >&2
		exit 1
	fi
}

require_workflow_line "git show \"\$BASE_SHA:scripts/ci/classify-changed-paths.sh\" >\"\$trusted_classifier\""
require_workflow_line "\"\$trusted_classifier\" --files"
require_workflow_line "git show \"\$BASE_SHA:scripts/ci/check-required-jobs.sh\" >\"\$trusted_checker\""
require_workflow_line "\"\$trusted_checker\" \"\$GITHUB_EVENT_NAME\" \"\$NEEDS_JSON\" \"\$PLAN_JSON\""
require_workflow_line 'name: Upload minimized fuzz reproducers'
require_workflow_line './scripts/ci/report-fuzz-finding.sh main'

if grep -Eq '^[[:space:]]+pull_request:' "$workflow"; then
	printf 'trusted CI scripts fixture failed: direct pull-request trigger is enabled\n' >&2
	exit 1
fi
if ! grep -F 'pull_request_target:' "$controller" >/dev/null ||
	! grep -F 'uses: ./.github/workflows/ci.yml' "$controller" >/dev/null; then
	printf 'trusted CI scripts fixture failed: base-controlled entrypoint is missing\n' >&2
	exit 1
fi
validation_block=$(sed -n '/^  validation:/,/^  classify-fuzz-findings:/p' "$controller")
classification_block=$(sed -n '/^  classify-fuzz-findings:/,/^  report-fuzz-failure:/p' "$controller")
reporter_block=$(sed -n '/^  report-fuzz-failure:/,/^  ci-required:/p' "$controller")
fuzz_block=$(sed -n '/^  fuzz:/,/^  report-main-fuzz-failure:/p' "$workflow")
main_reporter_block=$(sed -n '/^  report-main-fuzz-failure:/,/^  headline-guarantee:/p' "$workflow")
if printf '%s\n' "$validation_block" | grep -E '(issues|pull-requests): write' >/dev/null ||
	printf '%s\n' "$classification_block" | grep -E '(issues|pull-requests): write' >/dev/null ||
	printf '%s\n' "$fuzz_block" | grep -E '(issues|pull-requests): write' >/dev/null; then
	printf 'trusted CI scripts fixture failed: untrusted validation received issue writes\n' >&2
	exit 1
fi
if ! grep -F "ref: \${{ github.event.pull_request.base.sha }}" "$controller" >/dev/null ||
	! printf '%s\n' "$reporter_block" | grep -F 'issues: write' >/dev/null ||
	! printf '%s\n' "$reporter_block" | grep -F 'pull-requests: write' >/dev/null ||
	! printf '%s\n' "$main_reporter_block" | grep -F 'issues: write' >/dev/null ||
	! grep -F "FUZZ_CLASSIFICATION: \${{ needs.classify-fuzz-findings.outputs.classification }}" "$controller" >/dev/null ||
	! grep -F "./scripts/ci/report-fuzz-finding.sh \"PR #\${{ github.event.pull_request.number }}\"" "$controller" >/dev/null; then
	printf 'trusted CI scripts fixture failed: trusted fuzz reporter is missing\n' >&2
	exit 1
fi

printf 'trusted CI scripts fixture: base workflow owns PR orchestration, gate logic, and issue writes\n'
