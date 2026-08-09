#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s REPOSITORY_ROOT SITE_ROOT\n' "$0" >&2
	exit 2
fi

repo_root=$1
site_root=$2

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

main_gate="$repo_root/release/repository/main-ci-gate.json"
require_file "$main_gate"
require_text "$main_gate" '{"context": "docs"}'

license_sha=$(sha256sum "$repo_root/LICENSE" | awk '{print $1}')
[ "$license_sha" = '3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04' ] || {
	printf 'OSS policy gate: LICENSE is not the exact MPL-2.0 text\n' >&2
	exit 1
}

pledge='Every capability required to run Wenv in production is and will remain open'
require_text "$repo_root/README.md" "$pledge"
require_text "$repo_root/README.md" 'directory and there will never be one.'
require_text "$repo_root/GOVERNANCE.md" "$pledge"
require_text "$repo_root/GOVERNANCE.md" '## Amendment procedure'
require_text "$repo_root/GOVERNANCE.md" 'may be amended only by reopening its originating ticket'
require_text "$repo_root/GOVERNANCE.md" 'Twelve consecutive months without maintainer response'
require_text "$repo_root/GOVERNANCE.md" 'benevolent dictator for life (BDFL)'
require_text "$repo_root/TRADEMARK.md" 'Permission is required to offer a hosted or packaged service under the Wenv'
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

security_txt="$repo_root/docs/site/public/.well-known/security.txt"
require_file "$security_txt"
require_text "$security_txt" 'Contact: https://github.com/Dunky13/wenv/security/advisories/new'
require_text "$security_txt" 'Contact: mailto:security@developwent.io'
require_text "$security_txt" 'Expires: 2027-08-09T00:00:00Z'
require_text "$security_txt" 'Canonical: https://dunky13.github.io/wenv/.well-known/security.txt'

require_text "$repo_root/SUPPORT.md" 'Wenv supports exactly one version: the latest patch release of the latest minor'
require_text "$repo_root/SUPPORT.md" 'end-of-life on the same day a new minor is released'
require_text "$repo_root/SUPPORT.md" 'Wenv does not maintain backport branches.'
require_text "$repo_root/SUPPORT.md" 'Prereleases are never supported.'

for path in \
	.well-known/security.txt \
	security/index.html \
	support/index.html \
	governance/index.html \
	trademark/index.html \
	contributing/index.html \
	license/index.html; do
	require_file "$site_root/$path"
done

cmp "$security_txt" "$site_root/.well-known/security.txt" >/dev/null || {
	printf 'OSS policy gate: served security.txt differs from its canonical source\n' >&2
	exit 1
}

require_text "$site_root/security/index.html" 'The default embargo is 90 days from the report itself.'
require_text "$site_root/security/index.html" 'security@developwent.io'
require_text "$site_root/support/index.html" 'Wenv supports exactly one version'
require_text "$site_root/support/index.html" 'end-of-life on the same day a new minor is released'
require_text "$site_root/support/index.html" 'Wenv does not maintain backport branches.'
require_text "$site_root/governance/index.html" 'may be amended only by reopening its originating ticket'
require_text "$site_root/governance/index.html" 'Twelve consecutive months without maintainer response'
require_text "$site_root/trademark/index.html" 'Permission is required to offer a hosted or packaged service'
require_text "$site_root/contributing/index.html" 'Developer Certificate of Origin'
require_text "$site_root/license/index.html" 'Mozilla Public License Version 2.0'
require_text "$site_root/security/index.html" 'href="/wenv/support/"'
require_text "$site_root/support/index.html" 'href="/wenv/security/"'
reject_text "$site_root/security/index.html" 'href="./SUPPORT.md"'
reject_text "$site_root/support/index.html" 'href="./SECURITY.md"'
reject_text "$site_root/trademark/index.html" 'href="./SECURITY.md"'
reject_text "$site_root/contributing/index.html" 'href="./SECURITY.md"'

printf 'OSS policy gate: O4-O6 source and served-site assertions passed\n'
