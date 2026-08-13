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

if grep -Eq '^[[:space:]]+pull_request:' "$workflow"; then
	printf 'trusted CI scripts fixture failed: direct pull-request trigger is enabled\n' >&2
	exit 1
fi
if ! grep -F 'pull_request_target:' "$controller" >/dev/null ||
	! grep -F 'uses: ./.github/workflows/ci.yml' "$controller" >/dev/null; then
	printf 'trusted CI scripts fixture failed: base-controlled entrypoint is missing\n' >&2
	exit 1
fi

printf 'trusted CI scripts fixture: base workflow owns PR orchestration and gate logic\n'
