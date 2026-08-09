#!/bin/sh
set -eu

CDPATH=
repo_root=$(cd -- "$(dirname "$0")/../.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/wenv-oss-policy.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

"$repo_root/scripts/ci/check-oss-policy.sh" "$repo_root" "$repo_root/docs/site/dist"

mkdir -p "$fixture_dir/site/.well-known"
mkdir -p "$fixture_dir/release/repository"
mkdir -p "$fixture_dir/.github/ISSUE_TEMPLATE" "$fixture_dir/.github/workflows"
for path in README.md GOVERNANCE.md TRADEMARK.md CONTRIBUTING.md LICENSE; do
	cp "$repo_root/$path" "$fixture_dir/$path"
done
cp "$repo_root/release/repository/main-ci-gate.json" \
	"$fixture_dir/release/repository/main-ci-gate.json"
cp "$repo_root/release/repository/fallback-channel-test.json" \
	"$fixture_dir/release/repository/fallback-channel-test.json"
cp "$repo_root/.github/ISSUE_TEMPLATE/config.yml" \
	"$fixture_dir/.github/ISSUE_TEMPLATE/config.yml"
cp "$repo_root/.github/workflows/security-channel.yml" \
	"$fixture_dir/.github/workflows/security-channel.yml"

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

cp -R "$repo_root/docs/site/dist/." "$fixture_dir/site/"
sed 's/^Expires:.*/Expires: 2000-08-09T00:00:00Z/' \
	"$fixture_dir/docs/site/public/.well-known/security.txt" \
	>"$fixture_dir/security-expired.txt"
mv "$fixture_dir/security-expired.txt" \
	"$fixture_dir/docs/site/public/.well-known/security.txt"
cp "$fixture_dir/docs/site/public/.well-known/security.txt" \
	"$fixture_dir/site/.well-known/security.txt"

if "$repo_root/scripts/ci/check-oss-policy.sh" "$fixture_dir" "$fixture_dir/site" >/dev/null 2>&1; then
	printf 'OSS policy fixture failed: elapsed source security.txt expiry was accepted\n' >&2
	exit 1
fi

cp "$repo_root/docs/site/public/.well-known/security.txt" \
	"$fixture_dir/docs/site/public/.well-known/security.txt"
cp "$fixture_dir/docs/site/public/.well-known/security.txt" \
	"$fixture_dir/site/.well-known/security.txt"
sed 's#Dunky13/wenv/security/advisories/new#wrong/repository/security/advisories/new#' \
	"$fixture_dir/.github/ISSUE_TEMPLATE/config.yml" \
	>"$fixture_dir/config-wrong.yml"
mv "$fixture_dir/config-wrong.yml" "$fixture_dir/.github/ISSUE_TEMPLATE/config.yml"

if "$repo_root/scripts/ci/check-oss-policy.sh" "$fixture_dir" "$fixture_dir/site" >/dev/null 2>&1; then
	printf 'OSS policy fixture failed: misrouted issue-chooser PVR link was accepted\n' >&2
	exit 1
fi

cp "$repo_root/.github/ISSUE_TEMPLATE/config.yml" \
	"$fixture_dir/.github/ISSUE_TEMPLATE/config.yml"
sed '/issues: write/d' "$fixture_dir/.github/workflows/security-channel.yml" \
	>"$fixture_dir/security-channel-unprivileged.yml"
mv "$fixture_dir/security-channel-unprivileged.yml" \
	"$fixture_dir/.github/workflows/security-channel.yml"

if "$repo_root/scripts/ci/check-oss-policy.sh" "$fixture_dir" "$fixture_dir/site" >/dev/null 2>&1; then
	printf 'OSS policy fixture failed: silent fallback-channel failure was accepted\n' >&2
	exit 1
fi
