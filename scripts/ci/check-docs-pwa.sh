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

printf 'docs PWA gate: manifest, registration, icons, and offline precache passed\n'
