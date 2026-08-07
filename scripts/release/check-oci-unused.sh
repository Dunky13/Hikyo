#!/bin/sh
set -eu

: "${DOCKER_BIN:=docker}"

[ "$#" -eq 1 ] || { printf 'usage: %s OCI_TAG\n' "$0" >&2; exit 2; }
tag=$1
error_file=$(mktemp "${TMPDIR:-/tmp}/wenv-oci-lookup.XXXXXX")
trap 'rm -f "$error_file"' EXIT HUP INT TERM

if "$DOCKER_BIN" manifest inspect "$tag" >/dev/null 2>"$error_file"; then
	printf 'OCI release guard: %s already exists\n' "$tag" >&2
	exit 1
fi
if grep -Eiq 'manifest unknown|no such manifest|not found' "$error_file"; then
	printf 'OCI release guard: %s is unused\n' "$tag"
	exit 0
fi

printf 'OCI release guard: cannot prove %s is unused: %s\n' \
	"$tag" "$(tr '\n' ' ' <"$error_file")" >&2
exit 1
