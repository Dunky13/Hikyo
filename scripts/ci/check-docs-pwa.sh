#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s REPOSITORY_ROOT SITE_ROOT\n' "$0" >&2
	exit 2
fi

repo_root=$1
site_root=$2
JQ_BIN=${JQ_BIN:-jq}

require_file() {
	[ -f "$1" ] || {
		printf 'docs PWA gate: missing %s\n' "$1" >&2
		exit 1
	}
}

require_text() {
	file=$1
	text=$2
	grep -F -- "$text" "$file" >/dev/null || {
		printf 'docs PWA gate: %s is missing %s\n' "$file" "$text" >&2
		exit 1
	}
}

for path in manifest.webmanifest pwa-192x192.png pwa-512x512.png; do
	require_file "$repo_root/docs/site/public/$path"
	require_file "$site_root/$path"
	cmp "$repo_root/docs/site/public/$path" "$site_root/$path" >/dev/null || {
		printf 'docs PWA gate: served %s differs from its source\n' "$path" >&2
		exit 1
	}
done

require_file "$site_root/sw.js"
"$JQ_BIN" -e '
  .id == "/" and
  .name == "Hikyo — fully open secrets and configuration" and
  .short_name == "Hikyo" and
  .start_url == "/" and
  .scope == "/" and
  .display == "standalone" and
  .theme_color == "#1b2225" and
  any(.icons[]; .src == "/pwa-192x192.png" and .sizes == "192x192" and .type == "image/png") and
  any(.icons[]; .src == "/pwa-512x512.png" and .sizes == "512x512" and .type == "image/png")
' "$site_root/manifest.webmanifest" >/dev/null || {
	printf 'docs PWA gate: manifest is incomplete or invalid\n' >&2
	exit 1
}

for page in index.html docs/index.html; do
	require_text "$site_root/$page" '<link rel="manifest" href="/manifest.webmanifest">'
	require_text "$site_root/$page" 'navigator.serviceWorker.register'
	require_text "$site_root/$page" '/sw.js'
done

for cached_path in \
	index.html \
	docs/index.html \
	docs/getting-started/index.html \
	manifest.webmanifest \
	pwa-512x512.png; do
	require_text "$site_root/sw.js" "$cached_path"
done

for prototype_family in \
	app-chrome \
	env-matrix \
	landing-opus-4.8 \
	landing-opus-5 \
	machine-access \
	reveal-edit \
	revision-history; do
	require_file "$site_root/prototypes/$prototype_family/index.html"
done
require_file "$site_root/prototypes/index.html"

prototype_pngs=$(find "$site_root/prototypes" -type f -name '*.png' -print)
if [ -n "$prototype_pngs" ]; then
	printf 'docs PWA gate: prototype screenshots must not be published\n%s\n' \
		"$prototype_pngs" >&2
	exit 1
fi

if grep -F -- 'prototypes/' "$site_root/sw.js" >/dev/null; then
	printf 'docs PWA gate: prototype assets must not be precached\n' >&2
	exit 1
fi

legacy_matches=$(grep -R -n -i -E --include='*.html' \
	'wenv|envweave|(^|[^[:alnum:]])ew_' "$site_root/prototypes" 2>/dev/null |
	grep -F -v -- 'wenv/change-token/v1' || true)
if [ -n "$legacy_matches" ]; then
	printf 'docs PWA gate: prototype HTML contains legacy product identity\n%s\n' \
		"$legacy_matches" >&2
	exit 1
fi

private_matches=$(grep -R -n -i -E --include='*.html' \
	'(^|[^[:alnum:]_])marc([^[:alnum:]_]|$)|([[:alnum:]_-]+\.)*went\.io|went-io|projects/dbugit|dbugit|pi-cluster|tail-net|adhd-kanban|poketracker|initiative-tracker|dunky13|id:.homelab.' \
	"$site_root/prototypes" 2>/dev/null || true)
if [ -n "$private_matches" ]; then
	printf 'docs PWA gate: prototype HTML contains personal or internal coordinates\n%s\n' \
		"$private_matches" >&2
	exit 1
fi

remote_font_matches=$(grep -R -n -E --include='*.html' \
	'fonts\.googleapis\.com|fonts\.gstatic\.com' \
	"$site_root/prototypes" 2>/dev/null || true)
if [ -n "$remote_font_matches" ]; then
	printf 'docs PWA gate: prototype HTML loads remote Google Fonts\n%s\n' \
		"$remote_font_matches" >&2
	exit 1
fi

unsafe_dom_matches=$(grep -R -n -E --include='*.html' \
	"(blastsub|sidevarlabel)[^;]*\.innerHTML[[:space:]]*=" \
	"$site_root/prototypes/app-chrome" 2>/dev/null || true)
if [ -n "$unsafe_dom_matches" ]; then
	printf 'docs PWA gate: prototype HTML reinterprets DOM-derived text as HTML\n%s\n' \
		"$unsafe_dom_matches" >&2
	exit 1
fi

stale_license_matches=$(grep -R -n -E --include='*.html' \
	'AGPL|MIT licensed' \
	"$site_root/prototypes" 2>/dev/null || true)
if [ -n "$stale_license_matches" ]; then
	printf 'docs PWA gate: prototype HTML contains stale license claims\n%s\n' \
		"$stale_license_matches" >&2
	exit 1
fi

printf 'docs PWA gate: manifest, sanitized prototypes, registration, icons, and offline precache passed\n'
