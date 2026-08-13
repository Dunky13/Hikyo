#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s EVENT NEEDS_JSON\n' "$0" >&2
	exit 2
fi

event=$1
results=$2
expected='["client","dco","docs","generated","headline-guarantee","lint","release-snapshot","supply-chain-checks","test","web"]'

case "$event" in
	pull_request)
		allowed='all(to_entries[]; .value.result == "success")'
		;;
	push)
		allowed='all(to_entries[];
			.value.result == "success" or
			(.key == "dco" and .value.result == "skipped")
		)'
		;;
	*)
		printf 'required jobs: unsupported event %s\n' "$event" >&2
		exit 2
		;;
esac

if ! printf '%s\n' "$results" | jq -e --argjson expected "$expected" \
	"type == \"object\" and (keys == (\$expected | sort)) and ($allowed)" >/dev/null; then
	printf 'required jobs: one or more jobs did not succeed\n' >&2
	printf '%s\n' "$results" | jq -r \
		'to_entries[] | select(.value.result != "success") | "  \(.key): \(.value.result)"' \
		>&2 2>/dev/null || true
	exit 1
fi

printf 'required jobs: all validation jobs passed\n'
