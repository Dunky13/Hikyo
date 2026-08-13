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
docs_cache_bust=${DOCS_CACHE_BUST:-}

case "$docs_origin" in
	https://*) ;;
	*)
		printf 'live docs gate: DOCS_ORIGIN must use HTTPS\n' >&2
		exit 2
		;;
esac

case "$docs_cache_bust" in
	*[!A-Za-z0-9._-]*)
		printf 'live docs gate: DOCS_CACHE_BUST contains unsafe URL characters\n' >&2
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

reject_response_text() {
	response=$1
	forbidden=$2
	if printf '%s\n' "$response" | grep -F -- "$forbidden" >/dev/null; then
		printf 'live docs gate: served response contains stale text: %s\n' \
			"$forbidden" >&2
		exit 1
	fi
}

extract_asset_path() {
	response=$1
	kind=$2
	case "$kind" in
		stylesheet)
			path=$(printf '%s\n' "$response" | \
				grep -o 'href="/_astro/[^"]*\.css"' | head -n 1 | \
				sed 's/^href="//; s/"$//')
			;;
		module)
			path=$(printf '%s\n' "$response" | \
				grep -E -o '(src|component-url|renderer-url)="/_astro/[^"]*\.js"' | \
				head -n 1 | sed 's/^[^=]*="//; s/"$//')
			;;
		*)
			printf 'live docs gate: unsupported asset kind: %s\n' "$kind" >&2
			exit 2
			;;
	esac
	[ -n "$path" ] || {
		printf 'live docs gate: served page has no root-hosted %s asset\n' "$kind" >&2
		exit 1
	}
	printf '%s\n' "$path"
}

require_asset() {
	asset_path=$1
	kind=$2
	case "$asset_path" in
		/_astro/*) ;;
		*)
			printf 'live docs gate: asset is not same-origin: %s\n' "$asset_path" >&2
			exit 1
			;;
	esac
	content_type=$("$CURL_BIN" --fail --location --silent --show-error \
		--proto '=https' --tlsv1.2 --max-time 20 --output /dev/null \
		--write-out '%{content_type}' "$docs_origin$asset_path")
	case "$kind:$content_type" in
		stylesheet:text/css* | module:application/javascript* | module:text/javascript*) ;;
		*)
			printf 'live docs gate: %s returned unexpected content type: %s\n' \
				"$asset_path" "$content_type" >&2
			exit 1
			;;
	esac
}

landing_url="$docs_origin/"
docs_url="$docs_origin/docs/"
if [ -n "$docs_cache_bust" ]; then
	landing_url="${landing_url}?deployment=$docs_cache_bust"
	docs_url="${docs_url}?deployment=$docs_cache_bust"
fi

landing_page=$(fetch "$landing_url")
require_response_text "$landing_page" '<title>Hikyo'
reject_response_text "$landing_page" '="/hikyo/'
landing_stylesheet=$(extract_asset_path "$landing_page" stylesheet)
landing_module=$(extract_asset_path "$landing_page" module)
require_asset "$landing_stylesheet" stylesheet
require_asset "$landing_module" module

docs_page=$(fetch "$docs_url")
require_response_text "$docs_page" '<title>Hikyo documentation'
reject_response_text "$docs_page" '="/hikyo/'
docs_stylesheet=$(extract_asset_path "$docs_page" stylesheet)
docs_module=$(extract_asset_path "$docs_page" module)
require_asset "$docs_stylesheet" stylesheet
require_asset "$docs_module" module

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

printf 'live docs gate: root assets, docs assets, policy pages, security.txt, and fallback MX passed\n'
