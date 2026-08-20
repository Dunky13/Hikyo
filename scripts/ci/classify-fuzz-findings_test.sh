#!/bin/sh
set -eu

CDPATH=
script_dir=$(cd -- "$(dirname "$0")" && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-fuzz-classify.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM
repo="$fixture_dir/repo"
artifact="$fixture_dir/artifact"
mkdir -p "$repo/.git" \
	"$repo/internal/related" \
	"$repo/internal/unrelated" \
	"$artifact/internal/related/testdata/fuzz/FuzzRelated" \
	"$artifact/internal/unrelated/testdata/fuzz/FuzzUnrelated" \
	"$artifact/internal/new/testdata/fuzz/FuzzNew"

hash_related=1111111111111111111111111111111111111111111111111111111111111111
hash_unrelated=2222222222222222222222222222222222222222222222222222222222222222
hash_new=3333333333333333333333333333333333333333333333333333333333333333
printf 'go test fuzz v1\n[]byte("related")\n' \
	>"$artifact/internal/related/testdata/fuzz/FuzzRelated/$hash_related"
printf 'go test fuzz v1\n[]byte("unrelated")\n' \
	>"$artifact/internal/unrelated/testdata/fuzz/FuzzUnrelated/$hash_unrelated"
printf 'go test fuzz v1\n[]byte("new")\n' \
	>"$artifact/internal/new/testdata/fuzz/FuzzNew/$hash_new"
(cd "$artifact" && zip -qr "$fixture_dir/reproducers.zip" .)

cat >"$fixture_dir/go" <<'EOF'
#!/bin/sh
set -eu
arguments=$*
case "$arguments" in
	*-list=\^FuzzRelated\$*) printf 'FuzzRelated\n' ;;
	*-list=\^FuzzUnrelated\$*) printf 'FuzzUnrelated\n' ;;
	*-run=\^FuzzRelated/*) exit 0 ;;
	*-run=\^FuzzUnrelated/*) exit 1 ;;
	*)
		printf 'unexpected Go fixture invocation: %s\n' "$arguments" >&2
		exit 2
		;;
esac
EOF
chmod +x "$fixture_dir/go"

base_sha=0123456789abcdef0123456789abcdef01234567
classification=$(GO_BIN="$fixture_dir/go" \
	"$script_dir/classify-fuzz-findings.sh" \
	"$fixture_dir/reproducers.zip" "$base_sha" "$repo")
json=$classification

printf '%s\n' "$json" | jq -e --arg path \
	"internal/related/testdata/fuzz/FuzzRelated/$hash_related" \
	'.related | index($path) != null' >/dev/null
printf '%s\n' "$json" | jq -e --arg path \
	"internal/unrelated/testdata/fuzz/FuzzUnrelated/$hash_unrelated" \
	'.unrelated == [$path]' >/dev/null
printf '%s\n' "$json" | jq -e --arg path \
	"internal/new/testdata/fuzz/FuzzNew/$hash_new" \
	'.related | index($path) != null' >/dev/null

printf 'fuzz classification fixture: base-pass/new findings related; base-fail finding unrelated\n'
