#!/bin/sh
set -eu

verify=false
case "$#:$*" in
	0:) ;;
	1:--verify) verify=true ;;
	*) printf 'usage: %s [--verify]\n' "$0" >&2; exit 2 ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
cd "$repo_root/web"

pnpm --dir ../clients/ts install --frozen-lockfile
pnpm install --frozen-lockfile
if [ "$verify" = true ]; then
	pnpm run typecheck
	pnpm run test
fi
pnpm run build
