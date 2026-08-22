#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s REPOSITORY_ROOT SITE_ROOT\n' "$0" >&2
	exit 2
fi

repo_root=$1
site_root=$2
NODE_BIN=${NODE_BIN:-node}

require_file() {
	[ -f "$1" ] || {
		printf 'OSS policy gate: missing %s\n' "$1" >&2
		exit 1
	}
}

require_text() {
	file=$1
	text=$2
	grep -F -- "$text" "$file" >/dev/null || {
		printf 'OSS policy gate: %s is missing locked text: %s\n' "$file" "$text" >&2
		exit 1
	}
}

reject_text() {
	file=$1
	text=$2
	if grep -F -- "$text" "$file" >/dev/null; then
		printf 'OSS policy gate: %s contains forbidden generated text: %s\n' "$file" "$text" >&2
		exit 1
	fi
}

for path in README.md GOVERNANCE.md TRADEMARK.md CONTRIBUTING.md SECURITY.md SUPPORT.md LICENSE; do
	require_file "$repo_root/$path"
done

issue_chooser="$repo_root/.github/ISSUE_TEMPLATE/config.yml"
require_file "$issue_chooser"
require_text "$issue_chooser" 'https://github.com/Hikyo-Org/Hikyo/security/advisories/new'
require_text "$issue_chooser" 'Do not report vulnerabilities in public issues.'

security_channel_workflow="$repo_root/.github/workflows/security-channel.yml"
require_file "$security_channel_workflow"
require_text "$security_channel_workflow" 'issues: write'
require_text "$security_channel_workflow" 'if: failure()'
require_text "$security_channel_workflow" 'Fallback security channel health check failed'

main_gate="$repo_root/release/repository/main-ci-gate.json"
require_file "$main_gate"
require_text "$main_gate" '{"context": "ci-required"}'

license_sha=$(sha256sum "$repo_root/LICENSE" | awk '{print $1}')
[ "$license_sha" = '3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04' ] || {
	printf 'OSS policy gate: LICENSE is not the exact MPL-2.0 text\n' >&2
	exit 1
}
require_text "$repo_root/LICENSE" 'Mozilla Public License Version 2.0'
require_text "$repo_root/LICENSE" 'Exhibit B - "Incompatible With Secondary Licenses" Notice'

pledge='Every capability required to run Hikyo in production is and will remain open'
require_text "$repo_root/README.md" "$pledge"
require_text "$repo_root/README.md" 'directory and there will never be one.'
require_text "$repo_root/GOVERNANCE.md" "$pledge"
require_text "$repo_root/GOVERNANCE.md" '## Amendment procedure'
require_text "$repo_root/GOVERNANCE.md" 'may be amended only by reopening its originating ticket'
require_text "$repo_root/GOVERNANCE.md" 'Twelve consecutive months without maintainer response'
require_text "$repo_root/GOVERNANCE.md" 'benevolent dictator for life (BDFL)'
require_text "$repo_root/TRADEMARK.md" 'Permission is required to offer a hosted or packaged service under the Hikyo'
require_text "$repo_root/TRADEMARK.md" 'does not limit the code freedoms granted by the Mozilla Public License 2.0.'
require_text "$repo_root/CONTRIBUTING.md" 'Every commit in a pull request must carry a Developer Certificate of Origin'
require_text "$repo_root/SECURITY.md" 'Do not report vulnerabilities in public issues.'
require_text "$repo_root/SECURITY.md" 'security@developwent.io'
require_text "$repo_root/SECURITY.md" 'acknowledged within 7 days'
require_text "$repo_root/SECURITY.md" 'critical: 14 days;'
require_text "$repo_root/SECURITY.md" 'high: 30 days;'
require_text "$repo_root/SECURITY.md" 'medium or low: the next scheduled release.'
require_text "$repo_root/SECURITY.md" 'The default embargo is 90 days from the report itself.'
require_text "$repo_root/SECURITY.md" 'The clock never waits on'
require_text "$repo_root/SECURITY.md" 'Active exploitation'
require_text "$repo_root/SECURITY.md" 'it never extends the embargo.'
require_text "$repo_root/SECURITY.md" 'beyond 90 days requires mutual agreement'
require_text "$repo_root/SECURITY.md" '| Latest patch release of the latest minor | Yes |'
require_text "$repo_root/SECURITY.md" '| All older stable releases | No |'
require_text "$repo_root/SECURITY.md" '| Prereleases | No |'
require_text "$repo_root/GOVERNANCE.md" 'Organization-wide'
require_text "$repo_root/GOVERNANCE.md" 'OBL-REPOSITORY-TRANSFER'
require_text "$repo_root/GOVERNANCE.md" 'implementation-status ledger'
require_text "$repo_root/GOVERNANCE.md" 'historical handoff'
reject_text "$repo_root/GOVERNANCE.md" '2FA enforcement remains pending'

security_txt="$repo_root/docs/site/public/.well-known/security.txt"
require_file "$security_txt"
favicon="$repo_root/docs/site/public/favicon-hikyo-48.png"
touch_icon="$repo_root/docs/site/public/apple-touch-icon.png"
require_file "$favicon"
require_file "$touch_icon"
require_text "$security_txt" 'Contact: https://github.com/Hikyo-Org/Hikyo/security/advisories/new'
require_text "$security_txt" 'Contact: mailto:security@developwent.io'
require_text "$security_txt" 'Expires:'
require_text "$security_txt" 'Canonical: https://hikyo.app/.well-known/security.txt'
source_expires=$(awk -F ': ' '$1 == "Expires" {print $2}' "$security_txt")
"$NODE_BIN" -e '
const expiry = Date.parse(process.argv[1]);
if (!Number.isFinite(expiry) || expiry <= Date.now()) process.exit(1);
' "$source_expires" || {
	printf 'OSS policy gate: source security.txt expiry is invalid or elapsed\n' >&2
	exit 1
}

fallback_evidence="$repo_root/release/repository/fallback-channel-test.json"
require_file "$fallback_evidence"
require_text "$fallback_evidence" '"address": "security@developwent.io"'

require_text "$repo_root/SUPPORT.md" 'Hikyo supports exactly one version: the latest patch release of the latest minor'
require_text "$repo_root/SUPPORT.md" 'end-of-life on the same day a new minor is released'
require_text "$repo_root/SUPPORT.md" 'Hikyo does not maintain backport branches.'
require_text "$repo_root/SUPPORT.md" 'Prereleases are never supported.'

for path in \
	.well-known/security.txt \
	api/search.json \
	index.html \
	security/index.html \
	support/index.html \
	governance/index.html \
	implementation-status/index.html \
	trademark/index.html \
	contributing/index.html \
	license/index.html; do
	require_file "$site_root/$path"
done

docs_meta="$repo_root/docs/site/src/content/docs/docs/meta.json"
require_file "$docs_meta"
docs_pages=$(
	"$NODE_BIN" -e '
const fs = require("node:fs");
const meta = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
for (const page of meta.pages) {
  if (page.startsWith("---")) continue;
  console.log(page === "index" ? "docs/index.html" : "docs/" + page + "/index.html");
}
' "$docs_meta"
)
while IFS= read -r path; do
	require_file "$site_root/$path"
done <<EOF
$docs_pages
EOF

require_text "$site_root/index.html" 'Every value is explicit'
require_text "$site_root/index.html" 'Mozilla Public License 2.0'
require_text "$site_root/index.html" '<link rel="canonical" href="https://hikyo.app/">'
require_text "$site_root/index.html" '<link rel="icon" type="image/png" sizes="48x48" href="/favicon-hikyo-48.png">'
require_text "$site_root/index.html" '<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">'
require_text "$site_root/index.html" 'href="/docs/"'
reject_text "$site_root/index.html" 'href="/hikyo/'
reject_text "$site_root/index.html" 'validated, inherited secrets'
reject_text "$site_root/index.html" 'MIT licensed'

require_text "$site_root/docs/index.html" 'Getting started'
require_text "$site_root/docs/index.html" '<link rel="icon" type="image/png" sizes="48x48" href="/favicon-hikyo-48.png">'
require_text "$site_root/docs/index.html" '<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">'
require_text "$site_root/docs/index.html" 'href="/docs/getting-started/"'
require_text "$site_root/docs/index.html" 'href="/docs/installation/"'
reject_text "$site_root/docs/index.html" 'href="/hikyo/'
require_text "$site_root/docs/getting-started/index.html" 'Build Hikyo from source'
require_text "$site_root/docs/getting-started/index.html" 'authority is single-use'
require_text "$site_root/docs/installation/index.html" 'has no published stable release yet'
require_text "$site_root/docs/build-from-source/index.html" 'frozen lockfiles prevent dependency resolution'
require_text "$site_root/docs/first-project/index.html" 'Changing your own grants revokes your current session'
require_text "$site_root/docs/core-concepts/index.html" 'Values do not inherit'
require_text "$site_root/docs/self-hosting/index.html" 'Production startup is fail-closed'

cmp "$security_txt" "$site_root/.well-known/security.txt" >/dev/null || {
	printf 'OSS policy gate: served security.txt differs from its canonical source\n' >&2
	exit 1
}
cmp "$favicon" "$site_root/favicon-hikyo-48.png" >/dev/null || {
	printf 'OSS policy gate: served favicon differs from its canonical source\n' >&2
	exit 1
}
cmp "$touch_icon" "$site_root/apple-touch-icon.png" >/dev/null || {
	printf 'OSS policy gate: served touch icon differs from its canonical source\n' >&2
	exit 1
}

require_text "$site_root/security/index.html" 'The default embargo is 90 days from the report itself.'
require_text "$site_root/security/index.html" 'security@developwent.io'
require_text "$site_root/security/index.html" 'Latest patch release of the latest minor'
require_text "$site_root/security/index.html" 'All older stable releases'
require_text "$site_root/support/index.html" 'Hikyo supports exactly one version'
require_text "$site_root/support/index.html" 'end-of-life on the same day a new minor is released'
require_text "$site_root/support/index.html" 'Hikyo does not maintain backport branches.'
require_text "$site_root/governance/index.html" 'may be amended only by reopening its originating ticket'
require_text "$site_root/governance/index.html" 'Twelve consecutive months without maintainer response'
require_text "$site_root/trademark/index.html" 'Permission is required to offer a hosted or packaged service'
require_text "$site_root/contributing/index.html" 'Developer Certificate of Origin'
require_text "$site_root/license/index.html" 'Mozilla Public License Version 2.0'
require_text "$site_root/security/index.html" 'href="/support/"'
require_text "$site_root/support/index.html" 'href="/security/"'
reject_text "$site_root/security/index.html" 'href="./SUPPORT.md"'
reject_text "$site_root/support/index.html" 'href="./SECURITY.md"'
reject_text "$site_root/trademark/index.html" 'href="./SECURITY.md"'
reject_text "$site_root/contributing/index.html" 'href="./SECURITY.md"'

if grep -R -F --include='*.html' '="/hikyo/' "$site_root" >/dev/null; then
	printf 'OSS policy gate: served site contains stale /hikyo/ URLs\n' >&2
	exit 1
fi

printf 'OSS policy gate: O4-O6 source and served-site assertions passed\n'
