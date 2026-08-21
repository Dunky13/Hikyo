#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
	printf 'usage: %s actionlint|govulncheck [arguments...]\n' "$0" >&2
	exit 2
fi

tool=$1
shift

case "$tool" in
actionlint)
	module=github.com/rhysd/actionlint
	package=$module/cmd/actionlint
	;;
govulncheck)
	module=golang.org/x/vuln
	package=$module/cmd/govulncheck
	;;
*)
	printf 'unknown Go CI tool: %s\n' "$tool" >&2
	exit 2
	;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
manifest=$script_dir/go-tool-modules.txt
version=$(awk -F '@' -v module="$module" '$1 == module { print $2 }' "$manifest")

if [ -z "$version" ] || [ "$(printf '%s\n' "$version" | wc -l | tr -d ' ')" -ne 1 ]; then
	printf 'expected exactly one version for %s in %s\n' "$module" "$manifest" >&2
	exit 1
fi

exec go run "$package@$version" "$@"
