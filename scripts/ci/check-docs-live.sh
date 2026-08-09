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
require_response_text "$security_txt" 'Contact: https://github.com/Dunky13/wenv/security/advisories/new'
require_response_text "$security_txt" "Contact: mailto:$fallback_email"
require_response_text "$security_txt" "Canonical: $docs_origin/.well-known/security.txt"

security_page=$(fetch "$docs_origin/security/")
require_response_text "$security_page" 'The default embargo is 90 days from the report itself.'

support_page=$(fetch "$docs_origin/support/")
require_response_text "$support_page" 'Wenv supports exactly one version'

mx_response=$("$CURL_BIN" --fail --location --silent --show-error \
	--proto '=https' --tlsv1.2 --max-time 20 \
	--header 'Accept: application/dns-json' \
	"https://cloudflare-dns.com/dns-query?name=$fallback_domain&type=MX")

printf '%s\n' "$mx_response" | "$JQ_BIN" -e \
	'.Status == 0 and any(.Answer[]?; .type == 15 and (.data | length > 0))' >/dev/null || {
	printf 'live docs gate: fallback domain %s has no reachable MX route\n' "$fallback_domain" >&2
	exit 1
}

printf 'live docs gate: security.txt, policy pages, and fallback MX route passed\n'
