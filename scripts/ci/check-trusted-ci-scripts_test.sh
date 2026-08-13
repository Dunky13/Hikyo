#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
workflow="$script_dir/../../.github/workflows/ci.yml"

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

printf 'trusted CI scripts fixture: pull requests execute base-revision gate logic\n'
