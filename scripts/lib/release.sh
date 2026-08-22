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

validate_binary_provenance() {
	[ "$#" -eq 3 ] || return 2
	[ -f "$1" ] || return 1

	jq -e --arg commit "$2" --arg version "$3" '
		.schema == "hikyo.dev/release-binaries/v1" and
		.source_commit == $commit and
		.version == $version and
		.producer.name == "goreleaser" and
		.producer.build_id == "hikyo" and
		.producer.config == ".goreleaser.yaml" and
		(.producer.config_sha256 | test("^[0-9a-f]{64}$")) and
		([.packages[].goarch] | sort) == ["amd64", "arm64"] and
		all(.packages[];
			.goos == "linux" and
			.archive_input.build_id == "hikyo" and
			(.archive_input.sha256 | test("^[0-9a-f]{64}$")) and
			.archive_input.sha256 == .oci_input.sha256 and
			.oci_input.path == ("image-root/" + .goarch + "/hikyo")
		)
	' "$1" >/dev/null
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
