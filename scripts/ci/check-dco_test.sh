#!/bin/sh
set -eu

repo=$(mktemp -d "${TMPDIR:-/tmp}/wenv-dco-fixture.XXXXXX")
trap 'rm -rf "$repo"' EXIT HUP INT TERM

git -C "$repo" init -q
git -C "$repo" config user.name 'Fixture Author'
git -C "$repo" config user.email 'fixture@example.com'

printf 'base\n' >"$repo/file"
git -C "$repo" add file
git -C "$repo" commit -q -s -m base
base=$(git -C "$repo" rev-parse HEAD)

printf 'signed\n' >>"$repo/file"
git -C "$repo" commit -q -s -am signed
signed=$(git -C "$repo" rev-parse HEAD)
"$(dirname "$0")/check-dco.sh" "$base" "$signed" "$repo"

git -C "$repo" branch topic "$signed"
git -C "$repo" switch -q --detach "$base"
printf 'advanced main\n' >"$repo/main-only"
git -C "$repo" add main-only
git -C "$repo" commit -q -s -m 'advance main'
advanced_base=$(git -C "$repo" rev-parse HEAD)
"$(dirname "$0")/check-dco.sh" "$advanced_base" "$signed" "$repo" >/dev/null
git -C "$repo" switch -q topic

git -C "$repo" merge -q --no-ff --no-edit "$advanced_base"
merged=$(git -C "$repo" rev-parse HEAD)
"$(dirname "$0")/check-dco.sh" "$advanced_base" "$merged" "$repo" >/dev/null

printf 'unsigned\n' >>"$repo/file"
git -C "$repo" commit -q -am unsigned
unsigned=$(git -C "$repo" rev-parse HEAD)
if "$(dirname "$0")/check-dco.sh" "$signed" "$unsigned" "$repo" >/dev/null 2>&1; then
	printf 'DCO fixture failed: unsigned commit accepted\n' >&2
	exit 1
fi

printf 'DCO fixture: signed, behind-base, and merge commits accepted; unsigned refused\n'
