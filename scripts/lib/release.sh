#!/bin/sh

# Shared release input validation. Callers remain fail-closed and decide how to
# report invalid values; these helpers only return success or failure.
sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

is_semver() {
	printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$'
}

is_full_sha() {
	printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{40}$'
}

is_digest() {
	printf '%s\n' "$1" | grep -Eq '^sha256:[0-9a-f]{64}$'
}

safe_release_name() {
	case "$1" in
		'' | */* | *..*) return 1 ;;
		*) return 0 ;;
	esac
}
