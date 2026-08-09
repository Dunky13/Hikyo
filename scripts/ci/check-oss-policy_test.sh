#!/bin/sh
set -eu

CDPATH=
repo_root=$(cd -- "$(dirname "$0")/../.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/wenv-oss-policy.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

"$repo_root/scripts/ci/check-oss-policy.sh" "$repo_root" "$repo_root/docs/site/dist"

mkdir -p "$fixture_dir/site/.well-known"
for path in README.md GOVERNANCE.md TRADEMARK.md CONTRIBUTING.md LICENSE; do
	cp "$repo_root/$path" "$fixture_dir/$path"
done

if "$repo_root/scripts/ci/check-oss-policy.sh" "$fixture_dir" "$fixture_dir/site" >/dev/null 2>&1; then
	printf 'OSS policy fixture failed: missing SECURITY.md was accepted\n' >&2
	exit 1
fi

cp "$repo_root/SECURITY.md" "$fixture_dir/SECURITY.md"
mkdir -p "$fixture_dir/docs/site/public/.well-known"
cp "$repo_root/docs/site/public/.well-known/security.txt" \
	"$fixture_dir/docs/site/public/.well-known/security.txt"

if "$repo_root/scripts/ci/check-oss-policy.sh" "$fixture_dir" "$fixture_dir/site" >/dev/null 2>&1; then
	printf 'OSS policy fixture failed: missing SUPPORT.md was accepted\n' >&2
	exit 1
fi

cp "$repo_root/SUPPORT.md" "$fixture_dir/SUPPORT.md"

if "$repo_root/scripts/ci/check-oss-policy.sh" "$fixture_dir" "$fixture_dir/site" >/dev/null 2>&1; then
	printf 'OSS policy fixture failed: unserved O4-O6 policy pages were accepted\n' >&2
	exit 1
fi
