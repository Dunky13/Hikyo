#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s DOCS_ORIGIN FALLBACK_EMAIL\n' "$0" >&2
	exit 2
fi

docs_origin=${1%/}
fallback_email=$2
CURL_BIN=${CURL_BIN:-curl}
JQ_BIN=${JQ_BIN:-jq}
NODE_BIN=${NODE_BIN:-node}

case "$docs_origin" in
	https://*) ;;
	*)
		printf 'live docs gate: DOCS_ORIGIN must use HTTPS\n' >&2
		exit 2
		;;
esac

case "$fallback_email" in
	*@*.*) ;;
	*)
		printf 'live docs gate: invalid fallback email\n' >&2
		exit 2
		;;
esac

fallback_domain=${fallback_email#*@}
case "$fallback_domain" in
	*[!A-Za-z0-9.-]* | .* | *.)
		printf 'live docs gate: invalid fallback domain\n' >&2
		exit 2
		;;
esac

fetch() {
	"$CURL_BIN" --fail --location --silent --show-error \
		--proto '=https' --tlsv1.2 --max-time 20 "$1"
}

require_response_text() {
	response=$1
	want=$2
	printf '%s\n' "$response" | grep -F -- "$want" >/dev/null || {
		printf 'live docs gate: %s is missing from served response\n' "$want" >&2
		exit 1
	}
}

security_txt=$(fetch "$docs_origin/.well-known/security.txt")
require_response_text "$security_txt" 'Contact: https://github.com/Dunky13/hikyo/security/advisories/new'
require_response_text "$security_txt" "Contact: mailto:$fallback_email"
require_response_text "$security_txt" "Canonical: $docs_origin/.well-known/security.txt"
expires=$(printf '%s\n' "$security_txt" | awk -F ': ' '$1 == "Expires" {print $2}')
[ -n "$expires" ] || {
	printf 'live docs gate: security.txt has no expiry\n' >&2
	exit 1
}
"$NODE_BIN" -e '
const expiry = Date.parse(process.argv[1]);
if (!Number.isFinite(expiry) || expiry <= Date.now()) process.exit(1);
' "$expires" || {
	printf 'live docs gate: security.txt expiry is invalid or elapsed\n' >&2
	exit 1
}

security_page=$(fetch "$docs_origin/security/")
require_response_text "$security_page" 'The default embargo is 90 days from the report itself.'

support_page=$(fetch "$docs_origin/support/")
require_response_text "$support_page" 'Hikyo supports exactly one version'

governance_page=$(fetch "$docs_origin/governance/")
require_response_text "$governance_page" 'may be amended only by reopening its originating ticket'
require_response_text "$governance_page" 'Twelve consecutive months without maintainer response'

trademark_page=$(fetch "$docs_origin/trademark/")
require_response_text "$trademark_page" 'Permission is required to offer a hosted or packaged service'

contributing_page=$(fetch "$docs_origin/contributing/")
require_response_text "$contributing_page" 'Developer Certificate of Origin'

license_page=$(fetch "$docs_origin/license/")
require_response_text "$license_page" 'Mozilla Public License Version 2.0'

mx_response=$("$CURL_BIN" --fail --location --silent --show-error \
	--proto '=https' --tlsv1.2 --max-time 20 \
	--header 'Accept: application/dns-json' \
	"https://cloudflare-dns.com/dns-query?name=$fallback_domain&type=MX")

printf '%s\n' "$mx_response" | "$JQ_BIN" -e \
	'.Status == 0 and any(.Answer[]?; .type == 15 and (.data | length > 0))' >/dev/null || {
	printf 'live docs gate: fallback domain %s has no reachable MX route\n' "$fallback_domain" >&2
	exit 1
}

printf 'live docs gate: security.txt, all policy pages, and fallback MX route passed\n'
