#!/bin/sh
set -eu

CDPATH=
repo_root=$(cd -- "$(dirname "$0")/../.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-docs-live.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

cat >"$fixture_dir/curl" <<'EOF'
#!/bin/sh
write_content_type=0
for argument do
	if [ "$argument" = '%{content_type}' ]; then
		write_content_type=1
	fi
	url=$argument
done
case "$url" in
	https://hikyo.app/ | https://hikyo.app/\?*)
		stale_base=${FAKE_STALE_BASE:-0}
		if [ "${FAKE_STALE_ONCE:-0}" -eq 1 ] && \
			[ ! -f "${FAKE_STALE_MARKER:?}" ]; then
			: >"$FAKE_STALE_MARKER"
			stale_base=1
		fi
		if [ "$stale_base" -eq 1 ]; then
			base=/hikyo
		else
			base=
		fi
		printf '<title>Hikyo</title><link rel="manifest" href="/manifest.webmanifest"><link rel="stylesheet" href="%s/_astro/landing.css"><script>navigator.serviceWorker.register("/sw.js")</script><script type="module" src="%s/_astro/landing.js"></script>\n' \
			"$base" "$base"
		;;
	*/docs/ | */docs/\?*)
		if [ "${FAKE_STALE_BASE:-0}" -eq 1 ]; then
			base=/hikyo
		else
			base=
		fi
		printf '<title>Hikyo documentation</title><link rel="stylesheet" href="%s/_astro/docs.css"><astro-island component-url="%s/_astro/docs.js" renderer-url="%s/_astro/client.js"></astro-island>\n' \
			"$base" "$base" "$base"
		;;
	*/_astro/*.css)
		if [ "$write_content_type" -eq 1 ]; then
			if [ "${FAKE_BAD_ASSET_TYPE:-0}" -eq 1 ]; then
				printf '%s' 'text/html; charset=utf-8'
			else
				printf '%s' 'text/css; charset=utf-8'
			fi
		else
			printf '%s\n' 'fixture stylesheet'
		fi
		;;
	*/_astro/*.js)
		if [ "$write_content_type" -eq 1 ]; then
			printf '%s' 'application/javascript; charset=utf-8'
		else
			printf '%s\n' 'fixture module'
		fi
		;;
	*/manifest.webmanifest)
		if [ "${FAKE_STALE_PWA:-0}" -eq 1 ]; then
			scope=/stale/
		else
			scope=/
		fi
		printf '{"id":"/","start_url":"/","scope":"%s","display":"standalone","icons":[{"src":"/pwa-192x192.png","sizes":"192x192"},{"src":"/pwa-512x512.png","sizes":"512x512"}]}\n' "$scope"
		;;
	*/sw.js)
		printf '%s\n' 'docs/getting-started/index.html pwa-512x512.png'
		;;
	*/pwa-192x192.png | */pwa-512x512.png)
		if [ "$write_content_type" -eq 1 ]; then
			printf '%s' 'image/png'
		else
			printf '%s\n' 'fixture PNG'
		fi
		;;
	*/.well-known/security.txt)
		if [ "${FAKE_EXPIRED:-0}" -eq 1 ]; then
			expires=2000-08-09T00:00:00Z
		else
			expires=2099-08-09T00:00:00Z
		fi
		printf '%s\n' \
			'Contact: https://github.com/Hikyo-Org/Hikyo/security/advisories/new' \
			'Contact: mailto:security@developwent.io' \
			"Expires: $expires" \
			'Canonical: https://hikyo.app/.well-known/security.txt'
		;;
	*/security/)
		printf '%s\n' 'The default embargo is 90 days from the report itself.'
		;;
	*/support/)
		printf '%s\n' 'Hikyo supports exactly one version: latest only.'
		;;
	*/governance/)
		if [ "${FAKE_STALE_GOVERNANCE:-0}" -eq 1 ]; then
			printf '%s\n' 'stale governance page'
		else
			printf '%s\n' \
				'may be amended only by reopening its originating ticket' \
				'Twelve consecutive months without maintainer response'
		fi
		;;
	*/trademark/)
		printf '%s\n' 'Permission is required to offer a hosted or packaged service'
		;;
	*/contributing/)
		printf '%s\n' 'Developer Certificate of Origin'
		;;
	*/license/)
		printf '%s\n' 'Mozilla Public License Version 2.0'
		;;
	*cloudflare-dns.com*)
		if [ "${FAKE_NO_MX:-0}" -eq 1 ]; then
			printf '%s\n' '{"Status":0,"Answer":[]}'
		else
			printf '%s\n' '{"Status":0,"Answer":[{"type":15,"data":"1 aspmx.l.google.com."}]}'
		fi
		;;
	*)
		printf 'unexpected fixture URL: %s\n' "$url" >&2
		exit 1
		;;
esac
EOF
chmod +x "$fixture_dir/curl"

CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io

if FAKE_NO_MX=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: fallback domain without MX was accepted\n' >&2
	exit 1
fi

if FAKE_EXPIRED=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: elapsed security.txt expiry was accepted\n' >&2
	exit 1
fi

if FAKE_STALE_GOVERNANCE=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: stale served governance was accepted\n' >&2
	exit 1
fi

if FAKE_STALE_BASE=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: stale /hikyo/ assets were accepted\n' >&2
	exit 1
fi

if FAKE_BAD_ASSET_TYPE=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: HTML stylesheet response was accepted\n' >&2
	exit 1
fi

if FAKE_STALE_PWA=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: stale PWA manifest was accepted\n' >&2
	exit 1
fi

if ! FAKE_STALE_ONCE=1 FAKE_STALE_MARKER="$fixture_dir/stale-once" \
	DOCS_ATTEMPTS=2 DOCS_RETRY_DELAY_SECONDS=0 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: transient stale deployment was not retried\n' >&2
	exit 1
fi

if FAKE_STALE_BASE=1 DOCS_ATTEMPTS=2 DOCS_RETRY_DELAY_SECONDS=0 \
	CURL_BIN="$fixture_dir/curl" "$repo_root/scripts/ci/check-docs-live.sh" \
	https://hikyo.app security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: persistent stale deployment was accepted\n' >&2
	exit 1
fi
