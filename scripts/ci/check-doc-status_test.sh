#!/bin/sh
set -eu

CDPATH=
repo_root=$(cd -- "$(dirname "$0")/../.." && pwd)
checker="$repo_root/scripts/ci/check-doc-status.mjs"
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-doc-status.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

make_fixture() {
	root=$1
	mkdir -p "$root/docs/status" "$root/docs/spec" "$root/docs/adr" "$root/docs/handoff"
	cat >"$root/docs/status/ledger.json" <<'EOF'
{
  "schema": "hikyo.dev/implementation-status/v1",
  "entries": [
    {
      "id": "CAP-DOCS-SITE",
      "kind": "capability",
      "title": "Documentation site",
      "status": "implemented",
      "implemented": "Canonical documentation and governance site",
      "evidence": [
        { "label": "#78 handoff", "path": "docs/handoff/78-docs-governance.md" }
      ]
    },
    {
      "id": "OBL-DOCS-SITE",
      "kind": "obligation",
      "title": "Publish the documentation site for 1.0",
      "status": "implemented",
      "summary": "Documentation site is implemented.",
      "source": "docs/spec/open-items.md",
      "blocks": "CAP-DOCS-SITE",
      "evidence": [
        { "label": "#78 handoff", "path": "docs/handoff/78-docs-governance.md" }
      ]
    }
  ]
}
EOF
	cat >"$root/docs/spec/open-items.md" <<'EOF'
# Post-spec obligations

- <a id="obl-docs-site"></a>`OBL-DOCS-SITE` — Publish the documentation site for 1.0.
EOF
	cat >"$root/docs/handoff/78-docs-governance.md" <<'EOF'
# Historical evidence
EOF
	cat >"$root/README.md" <<'EOF'
# Fixture

<!-- implementation-status:start -->
<!-- implementation-status:end -->
EOF
	node "$checker" --write --root "$root"
}

expect_reject() {
	label=$1
	root=$2
	if node "$checker" --check --root "$root" >/dev/null 2>&1; then
		printf 'documentation status fixture failed: %s was accepted\n' "$label" >&2
		exit 1
	fi
	printf 'documentation status fixture: refused %s\n' "$label"
}

valid="$fixture_dir/valid"
make_fixture "$valid"
node "$checker" --check --root "$valid"

contradiction="$fixture_dir/contradiction"
cp -R "$valid" "$contradiction"
sed 's/Fully implemented/Not started/' "$contradiction/README.md" \
	>"$contradiction/README-stale.md"
mv "$contradiction/README-stale.md" "$contradiction/README.md"
expect_reject 'contradictory generated summary' "$contradiction"

stale_ledger="$fixture_dir/stale-ledger"
cp -R "$valid" "$stale_ledger"
sed '/"id": "OBL-DOCS-SITE"/,/^[[:space:]]*}/ s/"status": "implemented"/"status": "open"/' \
	"$stale_ledger/docs/status/ledger.json" >"$stale_ledger/ledger-stale.json"
mv "$stale_ledger/ledger-stale.json" "$stale_ledger/docs/status/ledger.json"
expect_reject 'implemented capability with open obligation' "$stale_ledger"

unclassified_open="$fixture_dir/unclassified-open"
cp -R "$valid" "$unclassified_open"
sed -e '/"id": "OBL-DOCS-SITE"/,/^[[:space:]]*}/ s/"status": "implemented"/"status": "open"/' \
	-e '/"blocks": "CAP-DOCS-SITE"/d' \
	"$unclassified_open/docs/status/ledger.json" >"$unclassified_open/ledger-open.json"
mv "$unclassified_open/ledger-open.json" "$unclassified_open/docs/status/ledger.json"
expect_reject 'open obligation without blocking disposition' "$unclassified_open"

orphan="$fixture_dir/orphan"
cp -R "$valid" "$orphan"
sed 's|"entries": \[|"entries": [{"id":"OBL-ORPHAN","kind":"obligation","title":"Unreferenced obligation","status":"open","summary":"Orphan.","source":"docs/spec/open-items.md","nonBlocking":"Fixture orphan.","evidence":[{"label":"evidence","path":"docs/handoff/78-docs-governance.md"}]},|' \
	"$orphan/docs/status/ledger.json" >"$orphan/ledger-orphan.json"
mv "$orphan/ledger-orphan.json" "$orphan/docs/status/ledger.json"
expect_reject 'orphan ledger ID' "$orphan"

unknown="$fixture_dir/unknown"
cp -R "$valid" "$unknown"
printf "\n- \`OBL-UNKNOWN\` — Unknown obligation.\n" >>"$unknown/docs/spec/open-items.md"
expect_reject 'unknown obligation ID' "$unknown"

missing_evidence="$fixture_dir/missing-evidence"
cp -R "$valid" "$missing_evidence"
rm "$missing_evidence/docs/handoff/78-docs-governance.md"
expect_reject 'missing evidence' "$missing_evidence"

stale_open="$fixture_dir/stale-open"
cp -R "$valid" "$stale_open"
printf '\n**Status:** deferred\n' >>"$stale_open/docs/spec/open-items.md"
expect_reject 'mutable status in immutable obligations' "$stale_open"

spec_checkbox="$fixture_dir/spec-checkbox"
cp -R "$valid" "$spec_checkbox"
mkdir -p "$spec_checkbox/docs/adr"
printf '%s\n' '# Immutable ADR' '- [ ] Mutable implementation task' \
	>"$spec_checkbox/docs/adr/immutable.md"
expect_reject 'mutable ADR/spec checkbox' "$spec_checkbox"

printf 'documentation status fixture: valid ledger accepted; contradictions, unresolved disposition, orphan, unknown ID, missing evidence, and mutable spec status refused\n'
