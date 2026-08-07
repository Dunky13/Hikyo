#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	printf 'usage: %s BASE HEAD [REPOSITORY]\n' "$0" >&2
	exit 2
fi

base=$1
head=$2
repo=${3:-.}

git -C "$repo" rev-parse --verify "$base^{commit}" >/dev/null 2>&1 \
	|| { printf 'DCO check: invalid base %s\n' "$base" >&2; exit 2; }
git -C "$repo" rev-parse --verify "$head^{commit}" >/dev/null 2>&1 \
	|| { printf 'DCO check: invalid head %s\n' "$head" >&2; exit 2; }
base=$(git -C "$repo" merge-base "$base" "$head") \
	|| { printf 'DCO check: base and head have no merge base\n' >&2; exit 2; }

commits=$(git -C "$repo" rev-list --no-merges --reverse "$base..$head")
[ -n "$commits" ] || { printf 'DCO check: empty commit range\n' >&2; exit 2; }

failed=0
for commit in $commits; do
	identity=$(git -C "$repo" show -s --format='%an <%ae>' "$commit")
	trailers=$(git -C "$repo" show -s --format='%B' "$commit" | git -C "$repo" interpret-trailers --parse)
	if ! printf '%s\n' "$trailers" | grep -F -i -x "Signed-off-by: $identity" >/dev/null; then
		printf 'DCO check: %s missing Signed-off-by: %s\n' "$commit" "$identity" >&2
		failed=1
	fi
done

[ "$failed" -eq 0 ] || exit 1
printf 'DCO check: %s commits signed\n' "$(printf '%s\n' "$commits" | wc -l | tr -d ' ')"
