#!/bin/sh
set -eu

if [ "$#" -eq 1 ] && [ "$1" = "--supports-plan-v1" ]; then
	exit 0
fi

if [ "$#" -ne 3 ]; then
	printf 'usage: %s EVENT NEEDS_JSON PLAN_JSON\n' "$0" >&2
	exit 2
fi

event=$1
results=$2
plan=$3
expected_results='["changes","client","dco","docs","generated","headline-guarantee","lint","release-snapshot","supply-chain-checks","test","web"]'
expected_plan='["client","docs","generated","headline_guarantee","lint","release_snapshot","supply_chain_checks","test","web"]'

case "$event" in
	pull_request | pull_request_target | push) ;;
	*)
		printf 'required jobs: unsupported event %s\n' "$event" >&2
		exit 2
		;;
esac

if ! jq -en \
	--arg event "$event" \
	--argjson results "$results" \
	--argjson plan "$plan" \
	--argjson expected_results "$expected_results" \
	--argjson expected_plan "$expected_plan" '
	def result_key: gsub("_"; "-");

	($results | type == "object" and (keys == ($expected_results | sort))) and
	($plan | type == "object" and (keys == ($expected_plan | sort)) and
		all(.[]; type == "boolean")) and
	($results.changes.result == "success") and
	(if $event == "push" then
		$results.dco.result == "skipped" and
		all($plan[]; . == true)
	else
		$results.dco.result == "success"
	end) and
	all($plan | to_entries[];
		. as $entry |
		$results[($entry.key | result_key)].result ==
			(if $entry.value then "success" else "skipped" end)
	)
' >/dev/null; then
	printf 'required jobs: validation results did not match the change plan\n' >&2
	printf '%s\n' "$results" | jq -r --argjson plan "$plan" '
		def result_key: gsub("_"; "-");
		$plan | to_entries[] |
		. as $entry |
		($entry.key | result_key) as $job |
		(if $entry.value then "success" else "skipped" end) as $expected |
		select($results[$job].result != $expected) |
		"  \($job): expected \($expected), got \($results[$job].result // "missing")"
	' --argjson results "$results" >&2 2>/dev/null || true
	exit 1
fi

printf 'required jobs: planned validation passed\n'
