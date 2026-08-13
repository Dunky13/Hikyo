#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
classifier="$script_dir/classify-changed-paths.sh"

actual=$(printf '%s\n' \
	'docs/site/src/content/docs/docs/getting-started.mdx' \
	'README.md' |
	"$classifier" --files)

expected='{
	"client": false,
	"docs": true,
	"generated": false,
	"headline_guarantee": false,
	"lint": false,
	"release_snapshot": false,
	"supply_chain_checks": false,
	"test": false,
	"web": false
}'

if ! jq -e --argjson expected "$expected" '. == $expected' <<EOF >/dev/null
$actual
EOF
then
	printf 'changed-path classifier fixture failed: docs-only plan was wrong\n' >&2
	printf 'actual: %s\n' "$actual" >&2
	exit 1
fi

web_actual=$(printf '%s\n' 'web/src/routes/Values.tsx' | "$classifier" --files)
if ! printf '%s\n' "$web_actual" | jq -e '
	.web == true and
	.release_snapshot == true and
	([.client, .docs, .generated, .headline_guarantee, .lint, .supply_chain_checks, .test] |
		all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: web-only plan was wrong\n' >&2
	printf 'actual: %s\n' "$web_actual" >&2
	exit 1
fi

core_actual=$(printf '%s\n' 'internal/service/values.go' | "$classifier" --files)
if ! printf '%s\n' "$core_actual" | jq -e '
	.generated == true and
	.headline_guarantee == true and
	.release_snapshot == true and
	.test == true and
	.web == true and
	([.client, .docs, .lint, .supply_chain_checks] | all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: core plan was wrong\n' >&2
	printf 'actual: %s\n' "$core_actual" >&2
	exit 1
fi

api_actual=$(printf '%s\n' 'api/openapi.yaml' | "$classifier" --files)
if ! printf '%s\n' "$api_actual" | jq -e '
	.client == true and
	.generated == true and
	.headline_guarantee == true and
	.release_snapshot == true and
	.test == true and
	.web == true and
	([.docs, .lint, .supply_chain_checks] | all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: API plan was wrong\n' >&2
	printf 'actual: %s\n' "$api_actual" >&2
	exit 1
fi

client_actual=$(printf '%s\n' 'clients/ts/src/generated/types.gen.ts' | "$classifier" --files)
if ! printf '%s\n' "$client_actual" | jq -e '
	.client == true and
	.release_snapshot == true and
	.web == true and
	([.docs, .generated, .headline_guarantee, .lint, .supply_chain_checks, .test] |
		all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: client plan was wrong\n' >&2
	printf 'actual: %s\n' "$client_actual" >&2
	exit 1
fi

release_actual=$(printf '%s\n' 'scripts/release/check-tag.sh' | "$classifier" --files)
if ! printf '%s\n' "$release_actual" | jq -e '
	.lint == true and
	.release_snapshot == true and
	.supply_chain_checks == true and
	([.client, .docs, .generated, .headline_guarantee, .test, .web] | all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: release plan was wrong\n' >&2
	printf 'actual: %s\n' "$release_actual" >&2
	exit 1
fi

license_actual=$(printf '%s\n' 'LICENSE' | "$classifier" --files)
if ! printf '%s\n' "$license_actual" | jq -e '
	.docs == true and
	.release_snapshot == true and
	([.client, .generated, .headline_guarantee, .lint, .supply_chain_checks, .test, .web] |
		all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: LICENSE plan was wrong\n' >&2
	printf 'actual: %s\n' "$license_actual" >&2
	exit 1
fi

main_gate_actual=$(printf '%s\n' 'release/repository/main-ci-gate.json' |
	"$classifier" --files)
if ! printf '%s\n' "$main_gate_actual" | jq -e '
	.docs == true and
	.lint == true and
	.release_snapshot == true and
	.supply_chain_checks == true and
	([.client, .generated, .headline_guarantee, .test, .web] | all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: main CI gate plan was wrong\n' >&2
	printf 'actual: %s\n' "$main_gate_actual" >&2
	exit 1
fi

docs_workflow_actual=$(printf '%s\n' '.github/workflows/docs.yml' | "$classifier" --files)
if ! printf '%s\n' "$docs_workflow_actual" | jq -e '
	.docs == true and
	.lint == true and
	([.client, .generated, .headline_guarantee, .release_snapshot, .supply_chain_checks, .test, .web] |
		all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: docs-workflow plan was wrong\n' >&2
	printf 'actual: %s\n' "$docs_workflow_actual" >&2
	exit 1
fi

docs_script_actual=$(printf '%s\n' 'scripts/ci/check-docs-live.sh' | "$classifier" --files)
if ! printf '%s\n' "$docs_script_actual" | jq -e '
	.docs == true and
	.lint == true and
	([.client, .generated, .headline_guarantee, .release_snapshot, .supply_chain_checks, .test, .web] |
		all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: docs-script plan was wrong\n' >&2
	printf 'actual: %s\n' "$docs_script_actual" >&2
	exit 1
fi

release_workflow_actual=$(printf '%s\n' '.github/workflows/release.yml' | "$classifier" --files)
if ! printf '%s\n' "$release_workflow_actual" | jq -e '
	.docs == true and
	.lint == true and
	.release_snapshot == true and
	.supply_chain_checks == true and
	([.client, .generated, .headline_guarantee, .test, .web] | all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: release-workflow plan was wrong\n' >&2
	printf 'actual: %s\n' "$release_workflow_actual" >&2
	exit 1
fi

all_actual=$("$classifier" --all)
if ! printf '%s\n' "$all_actual" | jq -e 'all(.[]; . == true)' >/dev/null; then
	printf 'changed-path classifier fixture failed: full plan was wrong\n' >&2
	printf 'actual: %s\n' "$all_actual" >&2
	exit 1
fi

for dependency_or_config in \
	'go.sum' \
	'web/pnpm-lock.yaml' \
	'clients/ts/package.json' \
	'docs/site/package.json' \
	'.goreleaser.yaml'; do
	dependency_actual=$(printf '%s\n' "$dependency_or_config" | "$classifier" --files)
	if ! printf '%s\n' "$dependency_actual" | jq -e 'all(.[]; . == true)' >/dev/null; then
		printf 'changed-path classifier fixture failed: %s did not select the full suite\n' \
			"$dependency_or_config" >&2
		exit 1
	fi
done

fallback_actual=$(printf '%s\n' 'release/repository/fallback-channel-test.json' |
	"$classifier" --files)
if ! printf '%s\n' "$fallback_actual" | jq -e '
	.docs == true and
	.lint == true and
	.release_snapshot == true and
	.supply_chain_checks == true and
	([.client, .generated, .headline_guarantee, .test, .web] | all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: fallback-channel plan was wrong\n' >&2
	printf 'actual: %s\n' "$fallback_actual" >&2
	exit 1
fi

mixed_actual=$(printf '%s\n' \
	'docs/site/src/content/docs/docs/index.mdx' \
	'web/src/routes/Login.tsx' |
	"$classifier" --files)
if ! printf '%s\n' "$mixed_actual" | jq -e '
	.docs == true and
	.release_snapshot == true and
	.web == true and
	([.client, .generated, .headline_guarantee, .lint, .supply_chain_checks, .test] |
		all(. == false))
' >/dev/null; then
	printf 'changed-path classifier fixture failed: mixed plan was not a union\n' >&2
	printf 'actual: %s\n' "$mixed_actual" >&2
	exit 1
fi

for fail_closed_input in \
	'' \
	'future/product/file.new' \
	'.github/workflows/ci.yml' \
	'scripts/ci/classify-changed-paths.sh' \
	'scripts/ci/check-required-jobs.sh'; do
	fail_closed_actual=$(printf '%s\n' "$fail_closed_input" | "$classifier" --files)
	if ! printf '%s\n' "$fail_closed_actual" | jq -e 'all(.[]; . == true)' >/dev/null; then
		printf 'changed-path classifier fixture failed: %s did not fail closed\n' \
			"${fail_closed_input:-empty input}" >&2
		exit 1
	fi
done

if "$classifier" --unsupported >/dev/null 2>&1; then
	printf 'changed-path classifier fixture failed: unsupported mode was accepted\n' >&2
	exit 1
fi

printf 'changed-path classifier fixture: scoped and full plans passed\n'
