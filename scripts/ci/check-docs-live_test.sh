#!/bin/sh
set -eu

CDPATH=
repo_root=$(cd -- "$(dirname "$0")/../.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-docs-live.XXXXXX")
trap 'rm -rf "$fixture_dir"' EXIT HUP INT TERM

cat >"$fixture_dir/curl" <<'EOF'
#!/bin/sh
for argument do
	url=$argument
done
case "$url" in
	*/.well-known/security.txt)
		if [ "${FAKE_EXPIRED:-0}" -eq 1 ]; then
			expires=2000-08-09T00:00:00Z
		else
			expires=2099-08-09T00:00:00Z
		fi
		printf '%s\n' \
			'Contact: https://github.com/Dunky13/hikyo/security/advisories/new' \
			'Contact: mailto:security@developwent.io' \
			"Expires: $expires" \
			'Canonical: https://dunky13.github.io/hikyo/.well-known/security.txt'
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
	https://dunky13.github.io/hikyo security@developwent.io

if FAKE_NO_MX=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://dunky13.github.io/hikyo security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: fallback domain without MX was accepted\n' >&2
	exit 1
fi

if FAKE_EXPIRED=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://dunky13.github.io/hikyo security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: elapsed security.txt expiry was accepted\n' >&2
	exit 1
fi

if FAKE_STALE_GOVERNANCE=1 CURL_BIN="$fixture_dir/curl" \
	"$repo_root/scripts/ci/check-docs-live.sh" \
	https://dunky13.github.io/hikyo security@developwent.io >/dev/null 2>&1; then
	printf 'live docs fixture failed: stale served governance was accepted\n' >&2
	exit 1
fi
