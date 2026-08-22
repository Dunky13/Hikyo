#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
planner=$repo_root/scripts/ci/analysis-shards
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-analysis-shards.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

mkdir -p \
	"$fixture_dir/extra" \
	"$fixture_dir/internal/crypto" \
	"$fixture_dir/internal/isolation" \
	"$fixture_dir/internal/service" \
	"$fixture_dir/internal/store"

printf '%s\n' 'module example.com/shards' 'go 1.26.6' >"$fixture_dir/go.mod"

for package in extra internal/crypto internal/isolation internal/service internal/store; do
	package_name=${package##*/}
	printf 'package %s\n' "$package_name" >"$fixture_dir/$package/$package_name.go"
done

cat >"$fixture_dir/extra/extra_test.go" <<'EOF'
package extra

import "testing"

func FuzzAuto(f *testing.F) { f.Fuzz(func(*testing.T, []byte) {}) }
EOF

cat >"$fixture_dir/internal/crypto/crypto_test.go" <<'EOF'
package crypto

import "testing"

func FuzzOpen(f *testing.F)  { f.Fuzz(func(*testing.T, []byte) {}) }
func FuzzParse(f *testing.F) { f.Fuzz(func(*testing.T, []byte) {}) }
EOF

cat >"$fixture_dir/internal/isolation/isolation_test.go" <<'EOF'
package isolation

import "testing"

func FuzzIsolation(f *testing.F) { f.Fuzz(func(*testing.T, []byte) {}) }
EOF

cat >"$fixture_dir/internal/service/service_test.go" <<'EOF'
package service

import "testing"

func FuzzService(f *testing.F) { f.Fuzz(func(*testing.T, []byte) {}) }
EOF

race_actual=$fixture_dir/race-actual
fuzz_actual=$fixture_dir/fuzz-actual
: >"$race_actual"
: >"$fuzz_actual"

shard=0
while [ "$shard" -lt 3 ]; do
	"$planner" race --root "$fixture_dir" --shard "$shard" --shards 3 |
		awk -v shard="$shard" '{ print shard "\t" $0 }' >>"$race_actual"
	"$planner" fuzz --root "$fixture_dir" --shard "$shard" --shards 3 |
		awk -v shard="$shard" '{ print shard "\t" $0 }' >>"$fuzz_actual"
	shard=$((shard + 1))
done

if [ -n "$(cut -f2 "$race_actual" | sort | uniq -d)" ]; then
	printf 'analysis shard fixture failed: race package assigned more than once\n' >&2
	exit 1
fi
if [ -n "$(cut -f2- "$fuzz_actual" | sort | uniq -d)" ]; then
	printf 'analysis shard fixture failed: fuzz target assigned more than once\n' >&2
	exit 1
fi

cut -f2 "$race_actual" | sort >"$fixture_dir/race-packages"
cat >"$fixture_dir/race-expected" <<'EOF'
example.com/shards/extra
example.com/shards/internal/crypto
example.com/shards/internal/service
example.com/shards/internal/store
EOF
cmp "$fixture_dir/race-expected" "$fixture_dir/race-packages"

cut -f2- "$fuzz_actual" | sort >"$fixture_dir/fuzz-targets"
cat >"$fixture_dir/fuzz-expected" <<'EOF'
example.com/shards/extra	FuzzAuto
example.com/shards/internal/crypto	FuzzOpen
example.com/shards/internal/crypto	FuzzParse
example.com/shards/internal/isolation	FuzzIsolation
example.com/shards/internal/service	FuzzService
EOF
cmp "$fixture_dir/fuzz-expected" "$fixture_dir/fuzz-targets"

crypto_shards=$(awk -F '\t' '$2 == "example.com/shards/internal/crypto" { print $1 }' \
	"$fuzz_actual" | sort -u | wc -l | tr -d ' ')
[ "$crypto_shards" -eq 1 ] || {
	printf 'analysis shard fixture failed: one package was split across fuzz shards\n' >&2
	exit 1
}

if "$planner" race --root "$fixture_dir" --shard 3 --shards 3 >/dev/null 2>&1; then
	printf 'analysis shard fixture failed: out-of-range shard accepted\n' >&2
	exit 1
fi

printf 'analysis shard fixture: complete, disjoint race packages and fuzz targets passed\n'
