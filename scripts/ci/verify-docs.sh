#!/bin/sh
set -eu

CDPATH=
repo_root=$(cd -- "$(dirname "$0")/../.." && pwd)
package_manager=$(node -p 'require(process.argv[1]).packageManager' \
	"$repo_root/docs/site/package.json")

case "$package_manager" in
	pnpm@*) ;;
	*)
		printf 'docs verification: expected a pinned pnpm packageManager, got %s\n' \
			"$package_manager" >&2
		exit 1
		;;
esac

corepack enable
corepack install --global "$package_manager"
pnpm --dir "$repo_root/docs/site" install --frozen-lockfile
node "$repo_root/scripts/ci/check-doc-status.mjs" --check --root "$repo_root"
"$repo_root/scripts/ci/check-doc-status_test.sh"
pnpm --dir "$repo_root/docs/site" peers check
if [ -n "${CI:-}" ]; then
	pnpm --dir "$repo_root/docs/site" exec playwright install --with-deps chromium
fi
pnpm --dir "$repo_root/docs/site" run verify
"$repo_root/scripts/ci/check-oss-policy_test.sh"
"$repo_root/scripts/ci/check-docs-live_test.sh"
"$repo_root/scripts/ci/check-fallback-channel-test_test.sh"
