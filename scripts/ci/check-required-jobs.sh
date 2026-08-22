#!/bin/sh
set -eu

if [ "$#" -eq 1 ] && [ "$1" = "--supports-plan-v2" ]; then
	exit 0
fi

if [ "$#" -ne 3 ]; then
	printf 'usage: %s EVENT NEEDS_JSON PLAN_JSON\n' "$0" >&2
	exit 2
fi

event=$1
results=$2
plan=$3
script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
registry_path=${CI_JOB_REGISTRY:-$script_dir/ci-job-registry.json}
if ! registry=$(jq -ce '
	select(.version == 2) |
	select(.path_classes.full | type == "array" and length > 0) |
	select(.jobs | type == "object" and length > 0)
' "$registry_path"); then
	printf 'required jobs: invalid CI job registry %s\n' "$registry_path" >&2
	exit 1
fi

case "$event" in
	pull_request | pull_request_target | push) ;;
	*)
		printf 'required jobs: unsupported event %s\n' "$event" >&2
		exit 2
		;;
esac

if ! validation=$(jq -cn \
	--arg event "$event" \
	--argjson results "$results" \
	--argjson plan "$plan" \
	--argjson registry "$registry" '
	def direct_gate:
		.required_gate == "always" or
		.required_gate == "pull-request" or
		.required_gate == "planned";
	def should_run($rule):
		if $rule.required_gate == "always" then true
		elif $rule.required_gate == "pull-request" then $event != "push"
		elif $rule.required_gate == "planned" then
			any($rule.plan_jobs[]; $plan[.] == true)
		else false
		end;

	([$registry.jobs | to_entries[] | select(.value | direct_gate) | .key] | sort) as $expected_results |
	($registry.path_classes.full | sort) as $expected_plan |
	(if ($results | type) == "object" then
		($results | keys) == $expected_results
	else false end) as $results_shape |
	(if ($plan | type) == "object" then
		($plan | keys) == $expected_plan and all($plan[]; type == "boolean")
	else false end) as $plan_shape |
	(if $results_shape and $plan_shape then
		[$registry.jobs | to_entries[] | select(.value | direct_gate) |
			. as $entry |
			(if should_run($entry.value) then "success" else "skipped" end) as $expected |
			select($results[$entry.key].result != $expected) |
			{job: $entry.key, expected: $expected, actual: ($results[$entry.key].result // "missing")}]
	else [] end) as $mismatches |
	{
		valid: (
			$results_shape and
			$plan_shape and
			(if $event == "push" then all($plan[]; . == true) else true end) and
			($mismatches | length == 0)
		),
		mismatches: $mismatches
	}
'); then
	printf 'required jobs: validation inputs were not valid JSON\n' >&2
	exit 1
fi

if ! printf '%s\n' "$validation" | jq -e '.valid == true' >/dev/null; then
	printf 'required jobs: validation results did not match the change plan\n' >&2
	printf '%s\n' "$validation" | jq -r \
		'.mismatches[] | "  \(.job): expected \(.expected), got \(.actual)"' >&2
	exit 1
fi

printf 'required jobs: planned validation passed\n'
