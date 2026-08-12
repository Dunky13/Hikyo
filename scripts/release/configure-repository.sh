#!/bin/sh
set -eu

: "${GH_BIN:=gh}"

if [ "$#" -ne 1 ]; then
	printf 'usage: %s OWNER/REPO\n' "$0" >&2
	exit 2
fi

repository=$1
repo_root=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)

upsert_ruleset() {
	payload=$1
	name=$(jq -r '.name' "$payload")
	id=$($GH_BIN api "repos/$repository/rulesets" --jq ".[] | select(.name == \"$name\") | .id")
	if [ -z "$id" ] && [ "$name" = 'release tags require admin role' ]; then
		id=$($GH_BIN api "repos/$repository/rulesets" \
			--jq '.[] | select(.name == "release tags require maintainer role") | .id')
	fi
	if [ -n "$id" ]; then
		$GH_BIN api --method PUT "repos/$repository/rulesets/$id" --input "$payload" >/dev/null
	else
		$GH_BIN api --method POST "repos/$repository/rulesets" --input "$payload" >/dev/null
	fi
}

upsert_ruleset "$repo_root/release/repository/release-tag-immutability.json"
upsert_ruleset "$repo_root/release/repository/release-tag-creation.json"
upsert_ruleset "$repo_root/release/repository/main-ci-gate.json"

$GH_BIN api --method PUT "repos/$repository/immutable-releases" >/dev/null
$GH_BIN api --method PUT "repos/$repository/actions/permissions" \
	-F enabled=true -f allowed_actions=all -F sha_pinning_required=true >/dev/null

rulesets=$($GH_BIN api "repos/$repository/rulesets")
printf '%s\n' "$rulesets" | jq -e '
	[.[] | select(.name == "release tags are immutable" and .enforcement == "active")] | length == 1
' >/dev/null
printf '%s\n' "$rulesets" | jq -e '
	[.[] | select(.name == "release tags require admin role" and .enforcement == "active")] | length == 1
' >/dev/null
printf '%s\n' "$rulesets" | jq -e '
	[.[] | select(.name == "main requires PR and release CI" and .enforcement == "active")] | length == 1
' >/dev/null
immutability_id=$(printf '%s\n' "$rulesets" | jq -r '.[] | select(.name == "release tags are immutable") | .id')
immutability=$($GH_BIN api "repos/$repository/rulesets/$immutability_id")
printf '%s\n' "$immutability" | jq -e '
	(.bypass_actors | length) == 0 and
	([.rules[] | select(.type == "update")] | length) == 1 and
	([.rules[] | select(.type == "deletion")] | length) == 1 and
	.conditions.ref_name.include == ["refs/tags/v*"]
' >/dev/null
creation_id=$(printf '%s\n' "$rulesets" | jq -r '.[] | select(.name == "release tags require admin role") | .id')
creation=$($GH_BIN api "repos/$repository/rulesets/$creation_id")
# GitHub expresses "only repository admins may create this ref" as an admin-role
# bypass on a creation-block rule. Update/deletion remain in the separate
# zero-bypass immutability ruleset asserted above.
printf '%s\n' "$creation" | jq -e '
	.bypass_actors == [{
		actor_id: 5,
		actor_type: "RepositoryRole",
		bypass_mode: "always"
	}] and
	([.rules[] | select(.type == "creation")] | length) == 1 and
	.conditions.ref_name.include == ["refs/tags/v*"]
' >/dev/null
$GH_BIN api "repos/$repository/immutable-releases" --jq '.enabled' | grep -x true >/dev/null
$GH_BIN api "repos/$repository/actions/permissions" --jq '.sha_pinning_required' | grep -x true >/dev/null

probe_tag=v-ruleset-probe
probe_error=$(mktemp "${TMPDIR:-/tmp}/hikyo-probe-tag-lookup.XXXXXX")
trap 'rm -f "$probe_error"' EXIT HUP INT TERM
if ! $GH_BIN api "repos/$repository/git/ref/tags/$probe_tag" >/dev/null 2>"$probe_error"; then
	grep -F '(HTTP 404)' "$probe_error" >/dev/null || {
		printf 'repository policy: cannot inspect probe tag\n' >&2
		exit 1
	}
	main_sha=$($GH_BIN api "repos/$repository/git/ref/heads/main" --jq '.object.sha')
	$GH_BIN api --method POST "repos/$repository/git/refs" \
		-f ref="refs/tags/$probe_tag" -f sha="$main_sha" >/dev/null
fi
git -C "$repo_root" fetch --quiet origin main "refs/tags/$probe_tag:refs/tags/$probe_tag"
probe_commit=$(git -C "$repo_root" rev-parse "$probe_tag^{commit}")
replacement=$(git -C "$repo_root" rev-parse 'origin/main^{commit}')
if [ "$replacement" = "$probe_commit" ]; then
	replacement=$(git -C "$repo_root" rev-parse 'origin/main^{commit}^')
fi
(
	cd "$repo_root"
	HIKYO_ALLOW_IMMUTABLE_TAG_PROBE=YES \
		"$repo_root/scripts/release/probe-tag-move.sh" "$repository" "$probe_tag" "$replacement"
)

printf 'repository policy: PR/CI main gate, immutable releases, protected v* tags, live move probe, SHA-pinned actions active\n'
