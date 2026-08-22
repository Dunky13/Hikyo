#!/bin/sh
# GitHub expressions below are literal fixture text.
# shellcheck disable=SC2016
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
workflow="$repo_root/.github/workflows/ci.yml"
fixture="$repo_root/web/e2e/fixtures/instance.ts"
spa_builder="$repo_root/scripts/ci/build-spa.sh"

fail() {
	printf 'build artifact reuse fixture failed: %s\n' "$1" >&2
	exit 1
}

require_line() {
	file=$1
	expected=$2
	grep -F -- "$expected" "$file" >/dev/null ||
		fail "missing $expected in $(basename "$file")"
}

app_block=$(sed -n '/^  app-build:/,/^  release-snapshot:/p' "$workflow")
release_block=$(sed -n '/^  release-snapshot:/,/^  generated:/p' "$workflow")
web_block=$(sed -n '/^  web:/,/^  test:/p' "$workflow")

[ -n "$app_block" ] || fail 'app-build job is missing'
printf '%s\n' "$app_block" | grep -F 'run: ./scripts/ci/build-spa.sh --verify' >/dev/null ||
	fail 'app-build does not verify and build the SPA through the shared script'
printf '%s\n' "$app_block" | grep -F 'go build -tags ui -o ci-artifacts/hikyo-ui ./cmd/hikyo' >/dev/null ||
	fail 'app-build does not produce the release-shaped CI binary'
printf '%s\n' "$app_block" | grep -F 'name: hikyo-app-${{ github.run_id }}-${{ github.run_attempt }}' >/dev/null ||
	fail 'app-build artifact is not scoped to this run attempt'

printf '%s\n' "$web_block" | grep -F 'needs: [changes, app-build]' >/dev/null ||
	fail 'web does not depend on app-build'
printf '%s\n' "$web_block" | grep -F 'name: hikyo-app-${{ github.run_id }}-${{ github.run_attempt }}' >/dev/null ||
	fail 'web does not consume the exact app-build artifact'
printf '%s\n' "$web_block" | grep -F 'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1' >/dev/null ||
	fail 'web does not use the repository-pinned download-artifact action'
printf '%s\n' "$web_block" | grep -F 'run: chmod +x ci-artifacts/hikyo-ui' >/dev/null ||
	fail 'web does not restore execute permission after artifact download'

if printf '%s\n' "$web_block" |
	grep -E 'pnpm run (typecheck|test|build)|pnpm build' >/dev/null; then
	fail 'a browser shard repeats app-build frontend work'
fi
printf '%s\n' "$release_block" | grep -F 'needs: changes' >/dev/null ||
	fail 'release snapshot is serialized behind app-build'
printf '%s\n' "$release_block" | grep -F 'run: ./scripts/ci/build-spa.sh' >/dev/null ||
	fail 'parallel release snapshot does not build its embedded SPA through the shared script'

require_line "$spa_builder" 'cd "$repo_root/web"'
require_line "$spa_builder" 'pnpm --dir ../clients/ts install --frozen-lockfile'
require_line "$spa_builder" 'pnpm install --frozen-lockfile'
require_line "$spa_builder" 'pnpm run typecheck'
require_line "$spa_builder" 'pnpm run test'
require_line "$spa_builder" 'pnpm run build'

require_line "$workflow" 'name: Upload unsigned development snapshot'
upload_block=$(sed -n \
	'/name: Upload unsigned development snapshot/,/name: Save release-snapshot Go cache/p' \
	"$workflow")
printf '%s\n' "$upload_block" | grep -F "if: github.event_name == 'push' && github.ref == 'refs/heads/main'" >/dev/null ||
	fail 'development snapshot upload is not guarded on trusted main'
for expected in \
	'name: hikyo-development-${{ github.sha }}' \
	'dist/hikyo_*_Darwin_*.tar.gz' \
	'dist/hikyo_*_Linux_*.tar.gz' \
	'dist/hikyo_*_Windows_*.zip' \
	'dist/checksums.txt' \
	'dist/DEVELOPMENT-SNAPSHOT.txt' \
	'retention-days: 14'
do
	printf '%s\n' "$upload_block" | grep -F "$expected" >/dev/null ||
		fail "development snapshot upload is missing $expected"
done
validate_line=$(grep -nF 'name: Classify complete snapshot manifest' "$workflow" | cut -d: -f1)
upload_line=$(grep -nF 'name: Upload unsigned development snapshot' "$workflow" | cut -d: -f1)
[ -n "$validate_line" ] && [ "$validate_line" -lt "$upload_line" ] ||
	fail 'development snapshot is uploaded before non-mutating manifest validation'
require_line "$fixture" "process.env.HIKYO_E2E_BINARY"

if grep -Eq 'gh release|action-gh-release' "$workflow"; then
	fail 'ordinary CI publishes a GitHub Release and bypasses the signing ceremony'
fi

printf 'build artifact reuse fixture: one app build feeds browser shards while release downloads stay parallel\n'
