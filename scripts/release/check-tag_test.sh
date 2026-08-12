#!/bin/sh
set -eu

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-tag-guard.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
remote="$fixture_dir/origin.git"
repo="$fixture_dir/repo"
git init -q --bare "$remote"
git clone -q "$remote" "$repo"
git -C "$repo" config user.name 'Fixture Author'
git -C "$repo" config user.email 'fixture@example.com'
printf 'release\n' >"$repo/file"
git -C "$repo" add file
git -C "$repo" commit -q -s -m release
git -C "$repo" branch -M main
git -C "$repo" tag -a v0.1.0 -m v0.1.0
git -C "$repo" push -q origin main v0.1.0
tag_object=$(git -C "$repo" rev-parse v0.1.0)

printf '#!/bin/sh\nprintf "gh: Not Found (HTTP 404)\\n" >&2\nexit 1\n' >"$fixture_dir/gh-404"
printf '#!/bin/sh\nprintf "gh: authentication failed (HTTP 401)\\n" >&2\nexit 1\n' >"$fixture_dir/gh-401"
printf '#!/bin/sh\nexit 0\n' >"$fixture_dir/gh-found"
chmod +x "$fixture_dir/gh-404" "$fixture_dir/gh-401" "$fixture_dir/gh-found"

(
	cd "$repo"
	GH_BIN="$fixture_dir/gh-404" "$OLDPWD/scripts/release/check-tag.sh" owner/repo v0.1.0 "$tag_object" >/dev/null
)
for gh_fixture in gh-401 gh-found; do
	if (
		cd "$repo"
		GH_BIN="$fixture_dir/$gh_fixture" "$OLDPWD/scripts/release/check-tag.sh" owner/repo v0.1.0 "$tag_object" >/dev/null 2>&1
	); then
		printf 'tag guard fixture failed: %s accepted\n' "$gh_fixture" >&2
		exit 1
	fi
done

printf 'tag guard fixture: annotated tag accepted; used tag and API failure refused\n'
