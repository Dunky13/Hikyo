#!/bin/sh
# Shell variables below are literal fixture text.
# shellcheck disable=SC2016
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
probe="$script_dir/no-egress.sh"

fail() {
	printf 'no-egress lifecycle fixture failed: %s\n' "$1" >&2
	exit 1
}

grep -F -- 'strace --kill-on-exit -f' "$probe" >/dev/null ||
	fail 'strace does not own tracee cleanup when the tracer exits'
grep -F -- 'kill -KILL "$child"' "$probe" >/dev/null ||
	fail 'the probe does not stop the tracer by its exact PID'
if grep -Eq 'kill[[:space:]][^#]*"?-\$\{?[[:alnum:]_]+' "$probe"; then
	fail 'the probe can signal an inherited process group'
fi
if grep -Eq '^[[:space:]]*pgid=' "$probe"; then
	fail 'the probe still derives a process group for teardown'
fi

printf 'no-egress lifecycle fixture: tracer-owned cleanup cannot signal the runner process group\n'
