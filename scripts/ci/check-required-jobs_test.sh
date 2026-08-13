#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
checker="$script_dir/check-required-jobs.sh"

if ! "$checker" --supports-plan-v1; then
	printf 'required-jobs fixture failed: plan-v1 capability was not reported\n' >&2
	exit 1
fi

expect_accept() {
	label=$1
	event=$2
	results=$3
	plan=$4
	if ! "$checker" "$event" "$results" "$plan" >/dev/null; then
		printf 'required-jobs fixture failed: %s was rejected\n' "$label" >&2
		exit 1
	fi
}

expect_reject() {
	label=$1
	event=$2
	results=$3
	plan=$4
	if "$checker" "$event" "$results" "$plan" >/dev/null 2>&1; then
		printf 'required-jobs fixture failed: %s was accepted\n' "$label" >&2
		exit 1
	fi
}

all_plan='{
	"client":true,
	"docs":true,
	"generated":true,
	"headline_guarantee":true,
	"lint":true,
	"release_snapshot":true,
	"supply_chain_checks":true,
	"test":true,
	"web":true
}'

all_success='{
	"changes":{"result":"success"},
	"client":{"result":"success"},
	"dco":{"result":"success"},
	"docs":{"result":"success"},
	"generated":{"result":"success"},
	"headline-guarantee":{"result":"success"},
	"lint":{"result":"success"},
	"release-snapshot":{"result":"success"},
	"supply-chain-checks":{"result":"success"},
	"test":{"result":"success"},
	"web":{"result":"success"}
}'

docs_plan=$(printf '%s' "$all_plan" | jq 'map_values(false) | .docs = true')
docs_success=$(printf '%s' "$all_success" | jq '
	.client.result = "skipped" |
	.generated.result = "skipped" |
	.["headline-guarantee"].result = "skipped" |
	.lint.result = "skipped" |
	.["release-snapshot"].result = "skipped" |
	.["supply-chain-checks"].result = "skipped" |
	.test.result = "skipped" |
	.web.result = "skipped"
')

expect_accept 'successful full pull request' pull_request "$all_success" "$all_plan"
expect_accept 'successful docs-only pull request' pull_request "$docs_success" "$docs_plan"
expect_accept 'main push with skipped DCO' push \
	"$(printf '%s' "$all_success" | jq '.dco.result = "skipped"')" "$all_plan"

for result in failure cancelled skipped; do
	expect_reject "selected client with $result result" pull_request \
		"$(printf '%s' "$all_success" | jq --arg result "$result" '.client.result = $result')" \
		"$all_plan"
done

expect_reject 'unselected web job unexpectedly ran' pull_request \
	"$(printf '%s' "$docs_success" | jq '.web.result = "success"')" "$docs_plan"
expect_reject 'unselected web job failed instead of skipping' pull_request \
	"$(printf '%s' "$docs_success" | jq '.web.result = "failure"')" "$docs_plan"
expect_reject 'main push used a selective plan' push \
	"$(printf '%s' "$docs_success" | jq '.dco.result = "skipped"')" "$docs_plan"
expect_reject 'classifier failed' pull_request \
	"$(printf '%s' "$all_success" | jq '.changes.result = "failure"')" "$all_plan"
expect_reject 'failed DCO' pull_request \
	"$(printf '%s' "$all_success" | jq '.dco.result = "failure"')" "$all_plan"
expect_reject 'unsupported event' workflow_dispatch "$all_success" "$all_plan"
expect_reject 'empty job set' pull_request '{}' "$all_plan"
expect_reject 'missing required job' pull_request \
	"$(printf '%s' "$all_success" | jq 'del(.web)')" "$all_plan"
expect_reject 'unknown job' pull_request \
	"$(printf '%s' "$all_success" | jq '.unexpected.result = "success"')" "$all_plan"
expect_reject 'malformed results' pull_request 'not-json' "$all_plan"
expect_reject 'missing plan entry' pull_request "$all_success" \
	"$(printf '%s' "$all_plan" | jq 'del(.web)')"
expect_reject 'unknown plan entry' pull_request "$all_success" \
	"$(printf '%s' "$all_plan" | jq '.unexpected = true')"
expect_reject 'non-boolean plan entry' pull_request "$all_success" \
	"$(printf '%s' "$all_plan" | jq '.web = "true"')"
expect_reject 'malformed plan' pull_request "$all_success" 'not-json'

printf 'required-jobs fixture: planned success/skip accepted; drift and failures refused\n'
