#!/bin/sh
set -eu

CDPATH=
repo_root=$(cd -- "$(dirname "$0")/../.." && pwd)

corepack enable
pnpm --dir "$repo_root/docs/site" install --frozen-lockfile
pnpm --dir "$repo_root/docs/site" peers check
pnpm --dir "$repo_root/docs/site" run verify
"$repo_root/scripts/ci/check-oss-policy_test.sh"
"$repo_root/scripts/ci/check-docs-live_test.sh"
