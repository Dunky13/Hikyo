#!/bin/sh
set -eu

: "${ImageOS:?GitHub runner ImageOS is required}"
: "${GITHUB_OUTPUT:?GitHub step output file is required}"

printf 'value=%s\n' "$ImageOS" >>"$GITHUB_OUTPUT"
