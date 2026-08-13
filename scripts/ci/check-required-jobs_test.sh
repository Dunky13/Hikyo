#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
checker="$script_dir/check-required-jobs.sh"

expect_accept() {
	label=$1
	event=$2
	results=$3
	if ! "$checker" "$event" "$results" >/dev/null; then
		printf 'required-jobs fixture failed: %s was rejected\n' "$label" >&2
		exit 1
	fi
}

expect_reject() {
	label=$1
	event=$2
	results=$3
	if "$checker" "$event" "$results" >/dev/null 2>&1; then
		printf 'required-jobs fixture failed: %s was accepted\n' "$label" >&2
		exit 1
	fi
}

all_success='{
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

expect_accept 'successful pull request' pull_request "$all_success"
expect_accept 'main push with skipped DCO' push \
	"$(printf '%s' "$all_success" | jq '.dco.result = "skipped"')"

for result in failure cancelled skipped; do
	expect_reject "pull request with $result client" pull_request \
		"$(printf '%s' "$all_success" | jq --arg result "$result" '.client.result = $result')"
done

expect_reject 'main push with skipped validation' push \
	"$(printf '%s' "$all_success" | jq '.web.result = "skipped" | .dco.result = "skipped"')"
expect_reject 'main push with failed DCO' push \
	"$(printf '%s' "$all_success" | jq '.dco.result = "failure"')"
expect_reject 'unsupported event' workflow_dispatch "$all_success"
expect_reject 'empty job set' pull_request '{}'
expect_reject 'missing required job' pull_request \
	"$(printf '%s' "$all_success" | jq 'del(.web)')"
expect_reject 'unknown job' pull_request \
	"$(printf '%s' "$all_success" | jq '.unexpected.result = "success"')"
expect_reject 'malformed results' pull_request 'not-json'

printf 'required-jobs fixture: success accepted; failure, cancellation, and skip refused\n'
