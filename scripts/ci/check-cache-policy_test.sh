#!/bin/sh
# GitHub expressions and embedded shell snippets below are literal fixture text.
# shellcheck disable=SC2016
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
workflow="$repo_root/.github/workflows/ci.yml"
workflows_dir="$repo_root/.github/workflows"
tool_modules="$repo_root/scripts/ci/go-tool-modules.txt"

fail() {
	printf 'cache policy fixture failed: %s\n' "$1" >&2
	exit 1
}

require_line() {
	file=$1
	expected=$2
	grep -F -- "$expected" "$file" >/dev/null ||
		fail "missing $expected in $(basename "$file")"
}

set --
for candidate in "$workflows_dir"/*.yml "$workflows_dir"/*.yaml; do
	[ -f "$candidate" ] || continue
	set -- "$@" "$candidate"
done
[ "$#" -gt 0 ] || fail 'no GitHub workflow files found'

# Hikyo deliberately uses the free GitHub-hosted pool. Keep runner placement
# reviewable instead of allowing a third-party label to return unnoticed.
for file in "$@"; do
	if grep -iE 'blacksmith|buildjet|self-hosted' "$file" >/dev/null; then
		fail "non-GitHub runner reference in $(basename "$file")"
	fi
	if grep -E '^[[:space:]]+runs-on:' "$file" |
		grep -Fv 'runs-on: ubuntu-latest' >/dev/null; then
		fail "runner other than ubuntu-latest in $(basename "$file")"
	fi
done

# Run IDs make every immutable Actions cache an exact miss and force a fresh
# archive upload. Artifact and concurrency names may still use run IDs.
if grep -E '^[[:space:]]+key: go-.*github\.(run_id|run_attempt)' \
	"$@" >/dev/null; then
	fail 'Go cache key contains a run ID or run attempt'
fi

# Validate every cache reader by policy rather than mirroring a fixed reader
# count or every job name. A newly added reader is covered automatically.
grep -F 'path: ~/go/pkg/mod' "$@" >/dev/null || fail 'no Go module cache reader found'
grep -F 'path: ~/.cache/go-build' "$@" >/dev/null || fail 'no Go build cache reader found'
for file in "$@"; do
	awk '
		function validate() {
			if (index(block, "actions/cache/restore@") == 0) return
			if (index(block, "path: ~/go/pkg/mod") > 0) {
				if (index(block, "key: go-mod-v2-${{ runner.os }}-${{ hashFiles(\047go.mod\047, \047go.sum\047, \047scripts/ci/go-tool-modules.txt\047) }}") == 0 ||
					index(block, "restore-keys: go-mod-v2-${{ runner.os }}-") == 0) bad = 1
			}
			if (index(block, "path: ~/.cache/go-build") > 0) {
				if (index(block, "key: go-") == 0 ||
					index(block, "-v2-") == 0 ||
					index(block, "${{ runner.os }}") == 0 ||
					index(block, "${{ runner.arch }}") == 0 ||
					index(block, "${{ steps.runner-cache-abi.outputs.value }}") == 0 ||
					index(block, "hashFiles(\047go.mod\047, \047go.sum\047") == 0 ||
					index(block, "restore-keys:") == 0) bad = 1
			}
		}
		/^[[:space:]]+- name:/ { validate(); block = "" }
		{ block = block $0 "\n" }
		END { validate(); if (bad) exit 1 }
	' "$file" || fail "incompatible Go cache reader in $(basename "$file")"
done

require_line "$tool_modules" 'github.com/rhysd/actionlint@v1.7.12'
require_line "$tool_modules" 'golang.org/x/vuln@v1.7.0'
require_line "$workflow" 'done < "$GITHUB_WORKSPACE/scripts/ci/go-tool-modules.txt"'
require_line "$workflow" 'go mod download all'
require_line "$workflow" 'run: ./scripts/ci/run-go-tool.sh actionlint'
require_line "$workflow" './scripts/ci/run-go-tool.sh govulncheck -mode=binary'
require_line "$workflow" 'run: ./scripts/ci/export-runner-cache-abi.sh'
require_line "$workflow" 'id: fuzz-cache-generation'
require_line "$workflow" 'run: echo "value=$(date -u +%G-W%V)" >>"$GITHUB_OUTPUT"'
grep -F 'key: go-fuzz-v2-' "$workflow" |
	grep -F 'steps.fuzz-cache-generation.outputs.value' >/dev/null ||
	fail 'fuzz cache does not rotate by weekly generation'
grep -F 'key: go-release-snapshot-v2-' "$workflow" |
	grep -F "hashFiles('go.mod', 'go.sum', '.goreleaser.yaml')" >/dev/null ||
	fail 'release-snapshot cache does not include GoReleaser configuration'
require_line "$repo_root/.github/workflows/race-isolation.yml" 'name: Restore race Go cache'

# Every cache writer must be trusted-main-only and must skip an upload after an
# exact hit. This covers Go, module, and Playwright writers alike.
for file in "$@"; do
	awk \
		-v main_guard="github.event_name == 'push' && github.ref == 'refs/heads/main'" \
		-v hit_guard="outputs.cache-hit != 'true'" '
		/^[[:space:]]+- name:/ { block = "" }
		{ block = block $0 "\n" }
		/actions\/cache\/save@/ {
			if (index(block, main_guard) == 0 || index(block, hit_guard) == 0) {
				bad = 1
			}
		}
		END {
			if (bad) exit 1
		}
	' "$file" || fail "cache writer without trusted-main exact-miss guard in $(basename "$file")"
done

printf 'cache policy fixture: GitHub runners, stable Go keys, and trusted exact-miss writers verified\n'
