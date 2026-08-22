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

validate_release_candidate_record() (
	record=$1
	[ -f "$record" ] || {
		printf 'candidate: record is absent\n' >&2
		return 1
	}
	jq -e '
		type == "object" and
		(keys == ["commit", "key_id", "public_key", "sequence", "version"]) and
		(.version | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][0-9A-Za-z.-]+)?$")) and
		(.sequence | type == "number" and . >= 1 and floor == .) and
		(.commit | type == "string" and test("^[0-9a-f]{40}$")) and
		(.key_id | type == "string" and length > 0) and
		(.public_key | type == "string" and length > 0)
	' "$record" >/dev/null || {
		printf 'candidate: invalid record\n' >&2
		return 1
	}
	candidate_public_key=$(jq -r '.public_key' "$record")
	safe_release_name "$candidate_public_key" || {
		printf 'candidate: unsafe public-key path\n' >&2
		return 1
	}
	candidate_canonical=$(mktemp "${TMPDIR:-/tmp}/hikyo-candidate-canonical.XXXXXX")
	if ! jq -e -cS . "$record" >"$candidate_canonical"; then
		rm -f "$candidate_canonical"
		printf 'candidate: invalid record\n' >&2
		return 1
	fi
	if ! cmp -s "$record" "$candidate_canonical"; then
		rm -f "$candidate_canonical"
		printf 'candidate: record is not canonical JSON\n' >&2
		return 1
	fi
	rm -f "$candidate_canonical"
)

check_release_candidate_hash() (
	record=$1
	expected_sha=$2
	case "$expected_sha" in
		*[!0-9a-f]* | '')
			printf 'candidate: invalid expected SHA-256\n' >&2
			return 1
			;;
	esac
	[ "${#expected_sha}" -eq 64 ] || {
		printf 'candidate: invalid expected SHA-256\n' >&2
		return 1
	}
	[ -f "$record" ] || {
		printf 'candidate: record is absent\n' >&2
		return 1
	}
	[ "$(sha256_file "$record")" = "$expected_sha" ] || {
		printf 'candidate: record hash mismatch\n' >&2
		return 1
	}
	validate_release_candidate_record "$record"
)

validate_release_candidate_metadata() (
	metadata=$1
	[ -f "$metadata" ] || {
		printf 'candidate: trust metadata is absent\n' >&2
		return 1
	}
	jq -e '
		type == "object" and
		(.releases | type == "array") and
		(.primary_keys | type == "array" and length > 0) and
		(.pending_release == null or
			((.pending_release | type == "object") and
			 (.pending_release.manifest_sha256 == ("0" * 64)))) and
		all([.releases[]?, (.pending_release? // empty)][];
			(.version | type == "string") and
			(.sequence | type == "number" and . >= 1 and floor == .) and
			(.manifest_sha256 | type == "string" and test("^[0-9a-f]{64}$"))) and
		all(.primary_keys[]; . as $key |
			($key.id | type == "string" and length > 0) and
			($key.public_key | type == "string" and length > 0) and
			($key.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
			($key.valid_from_release_sequence | type == "number" and . >= 1 and floor == .) and
			($key.valid_through_release_sequence == null or
				($key.valid_through_release_sequence | type == "number" and
				 . >= $key.valid_from_release_sequence and floor == .)) and
			($key.revoked | type == "boolean") and
			($key.pending == null or ($key.pending | type == "boolean"))) and
		([.primary_keys[].id] | unique | length) == (.primary_keys | length) and
		([.primary_keys[].public_key] | unique | length) == (.primary_keys | length)
	' "$metadata" >/dev/null || {
		printf 'candidate: invalid trust metadata\n' >&2
		return 1
	}
)

select_release_candidate() (
	metadata=$1
	version=$2
	validate_release_candidate_metadata "$metadata" || return 1
	is_semver "$version" || {
		printf 'candidate: invalid release version\n' >&2
		return 1
	}
	releases=$(jq -c '[.releases[]?, .pending_release?] | map(select(. != null))' "$metadata")
	release_count=$(printf '%s\n' "$releases" | jq -r 'length')
	unique_version_count=$(printf '%s\n' "$releases" | jq -r '[.[].version] | unique | length')
	[ "$release_count" -eq "$unique_version_count" ] || {
		printf 'candidate: release version is duplicated\n' >&2
		return 1
	}
	unique_sequence_count=$(printf '%s\n' "$releases" | jq -r '[.[].sequence] | unique | length')
	[ "$release_count" -eq "$unique_sequence_count" ] || {
		printf 'candidate: release sequence is duplicated\n' >&2
		return 1
	}
	version_matches=$(printf '%s\n' "$releases" | jq -r --arg version "$version" \
		'[.[] | select(.version == $version)] | length')
	[ "$version_matches" -gt 0 ] || {
		printf 'candidate: release version is absent\n' >&2
		return 1
	}
	release_sequence=$(printf '%s\n' "$releases" | jq -r --arg version "$version" \
		'.[] | select(.version == $version) | .sequence')
	interval_keys=$(jq -c --argjson sequence "$release_sequence" '
		[.primary_keys[] | select(
			.valid_from_release_sequence <= $sequence and
			(.valid_through_release_sequence == null or
			 .valid_through_release_sequence >= $sequence)
		)]
	' "$metadata")
	interval_count=$(printf '%s\n' "$interval_keys" | jq -r 'length')
	[ "$interval_count" -gt 0 ] || {
		printf 'candidate: no primary key covers release sequence\n' >&2
		return 1
	}
	[ "$interval_count" -eq 1 ] || {
		printf 'candidate: primary-key intervals overlap\n' >&2
		return 1
	}
	key_pending=$(printf '%s\n' "$interval_keys" | jq -r '.[0].pending // false')
	[ "$key_pending" = false ] || {
		printf 'candidate: primary key is pending\n' >&2
		return 1
	}
	key_revoked=$(printf '%s\n' "$interval_keys" | jq -r '.[0].revoked')
	[ "$key_revoked" = false ] || {
		printf 'candidate: primary key is revoked\n' >&2
		return 1
	}
	key_id=$(printf '%s\n' "$interval_keys" | jq -r '.[0].id')
	public_key=$(printf '%s\n' "$interval_keys" | jq -r '.[0].public_key')
	safe_release_name "$public_key" || {
		printf 'candidate: unsafe public-key path\n' >&2
		return 1
	}
	state=$(jq -r --arg version "$version" '
		if .pending_release != null and .pending_release.version == $version
		then "pending" else "finalized" end
	' "$metadata")
	jq -ncS \
		--argjson sequence "$release_sequence" \
		--arg key_id "$key_id" \
		--arg public_key "$public_key" \
		--arg state "$state" \
		'{sequence: $sequence, key_id: $key_id, public_key: $public_key, state: $state}'
)

resolve_release_candidate() (
	metadata=$1
	version=$2
	commit=$3
	expected_state=${4:-any}
	is_full_sha "$commit" || {
		printf 'candidate: commit must be a full SHA\n' >&2
		return 1
	}
	case "$expected_state" in
		any | pending) ;;
		*)
			printf 'candidate: unsupported expected state\n' >&2
			return 1
			;;
	esac
	selection=$(select_release_candidate "$metadata" "$version") || return 1
	state=$(printf '%s\n' "$selection" | jq -r '.state')
	if [ "$expected_state" = pending ] && [ "$state" != pending ]; then
		printf 'candidate: release is not a pending candidate\n' >&2
		return 1
	fi
	release_sequence=$(printf '%s\n' "$selection" | jq -r '.sequence')
	key_id=$(printf '%s\n' "$selection" | jq -r '.key_id')
	public_key=$(printf '%s\n' "$selection" | jq -r '.public_key')
	jq -ncS \
		--arg version "$version" \
		--argjson sequence "$release_sequence" \
		--arg commit "$commit" \
		--arg key_id "$key_id" \
		--arg public_key "$public_key" \
		'{version: $version, sequence: $sequence, commit: $commit,
		  key_id: $key_id, public_key: $public_key}'
)

authorize_release_candidate() (
	metadata=$1
	record=$2
	validate_release_candidate_record "$record" || return 1
	version=$(jq -r '.version' "$record")
	selection=$(select_release_candidate "$metadata" "$version") || return 1
	if ! jq -e --argjson selection "$selection" '
		.sequence == $selection.sequence and
		.key_id == $selection.key_id and
		.public_key == $selection.public_key
	' "$record" >/dev/null; then
		printf 'candidate: record does not match trust metadata\n' >&2
		return 1
	fi
)

verify_release_candidate_artifact() (
	manifest=$1
	bundle=$2
	candidate="$bundle/release-candidate.json"
	candidate_matches=$(jq -r '
		[.artifacts[] | select(
			.kind == "release-candidate" and .name == "release-candidate.json"
		)] | length
	' "$manifest")
	[ "$candidate_matches" -eq 1 ] || {
		printf 'candidate: manifest must contain exactly one release candidate\n' >&2
		return 1
	}
	[ -f "$candidate" ] || {
		printf 'candidate: release-candidate.json is absent\n' >&2
		return 1
	}
	want_sha=$(jq -r '
		.artifacts[] |
		select(.kind == "release-candidate" and .name == "release-candidate.json") |
		.sha256
	' "$manifest")
	[ "$(sha256_file "$candidate")" = "$want_sha" ] || {
		printf 'candidate: release-candidate.json hash mismatch\n' >&2
		return 1
	}
	validate_release_candidate_record "$candidate"
)

release_manifest_matches_candidate() (
	manifest=$1
	candidate=$2
	jq -e --slurpfile candidate "$candidate" '
		.version == $candidate[0].version and
		.release_sequence == $candidate[0].sequence and
		.source_commit == $candidate[0].commit and
		.signing_key_id == $candidate[0].key_id
	' "$manifest" >/dev/null || {
		printf 'candidate: manifest identity does not match release candidate\n' >&2
		return 1
	}
)
