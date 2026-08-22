#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
classifier="$script_dir/classify-changed-paths.sh"
registry="$script_dir/ci-job-registry.json"
all_jobs=$(jq -c '.path_classes.full | sort' "$registry")

expect_plan() {
	label=$1
	selected=$2
	shift 2
	actual=$(printf '%s\n' "$@" | "$classifier" --files)
	expected=$(jq -cn --argjson all "$all_jobs" --argjson selected "$selected" '
		$all | map(. as $job |
			{key: $job, value: ($selected | index($job) != null)}) | from_entries
	')
	if ! jq -en --argjson actual "$actual" --argjson expected "$expected" \
		'$actual == $expected' >/dev/null; then
		printf 'changed-path classifier fixture failed: %s plan was wrong\n' "$label" >&2
		printf 'actual: %s\nexpected: %s\n' "$actual" "$expected" >&2
		exit 1
	fi
}

expect_selected() {
	label=$1
	job=$2
	path=$3
	actual=$(printf '%s\n' "$path" | "$classifier" --files)
	if ! jq -e --arg job "$job" '.[$job] == true' <<EOF >/dev/null
$actual
EOF
	then
		printf 'changed-path classifier fixture failed: %s did not select %s\n' \
			"$label" "$job" >&2
		exit 1
	fi
}

expect_plan 'docs-only' '["docs"]' \
	'docs/site/src/content/docs/docs/getting-started.mdx' 'README.md'
expect_plan 'web-only' '["release-snapshot","web"]' 'web/src/routes/Values.tsx'
expect_plan 'core' \
	'["fuzz","generated","headline-guarantee","race","release-snapshot","test","web"]' \
	'internal/service/values.go'
expect_plan 'API' \
	'["client","compose-demo","generated","headline-guarantee","release-snapshot","test","web"]' \
	'api/openapi.yaml'
expect_plan 'client' '["client","release-snapshot","web"]' \
	'clients/ts/src/generated/types.gen.ts'
expect_plan 'release' '["lint","release-snapshot","supply-chain-checks"]' \
	'scripts/release/check-tag.sh'
expect_plan 'LICENSE' '["docs","release-snapshot"]' 'LICENSE'
expect_plan 'main CI gate' \
	'["docs","lint","release-snapshot","supply-chain-checks"]' \
	'release/repository/main-ci-gate.json'

for docs_script in \
	'scripts/ci/check-docs-live.sh' \
	'scripts/ci/check-docs-pwa.sh'; do
	expect_plan "$docs_script" '["docs","lint"]' "$docs_script"
done

all_actual=$("$classifier" --all)
if ! jq -en --argjson actual "$all_actual" --argjson jobs "$all_jobs" '
	($actual | keys | sort) == $jobs and all($actual[]; . == true)
' >/dev/null; then
	printf 'changed-path classifier fixture failed: full plan was wrong\n' >&2
	exit 1
fi

for code_path in \
	'internal/service/values.go' \
	'internal/store/query.sql' \
	'internal/operator/reconciler.go' \
	'internal/isolation/k8s_operator_e2e_test.go'; do
	expect_selected "$code_path" fuzz "$code_path"
	expect_selected "$code_path" race "$code_path"
done

for scoped_path in \
	'api/openapi.yaml' \
	'web/src/routes/Values.tsx' \
	'docs/site/src/content/docs/docs/index.mdx'; do
	scoped_actual=$(printf '%s\n' "$scoped_path" | "$classifier" --files)
	if ! jq -e '.fuzz == false and .race == false' <<EOF >/dev/null
$scoped_actual
EOF
	then
		printf 'changed-path classifier fixture failed: %s unexpectedly selected race/fuzz\n' \
			"$scoped_path" >&2
		exit 1
	fi
done

for dependency_or_config in \
	'go.sum' \
	'web/pnpm-lock.yaml' \
	'clients/ts/package.json' \
	'clients/ts/pnpm-workspace.yaml' \
	'docs/site/package.json' \
	'.goreleaser.yaml'; do
	expect_plan "$dependency_or_config" "$all_jobs" "$dependency_or_config"
done

expect_plan 'fallback channel' \
	'["docs","lint","release-snapshot","supply-chain-checks"]' \
	'release/repository/fallback-channel-test.json'
expect_plan 'mixed docs and web' '["docs","release-snapshot","web"]' \
	'docs/site/src/content/docs/docs/index.mdx' 'web/src/routes/Login.tsx'

for operator_path in \
	'internal/operator/reconciler.go' \
	'internal/isolation/k8s_operator_e2e_test.go'; do
	expect_plan "$operator_path" \
		'["fuzz","generated","headline-guarantee","k8s-e2e","race","release-snapshot","test","web"]' \
		"$operator_path"
done

expect_plan 'generated CRD' \
	'["generated","k8s-e2e","lint","release-snapshot","supply-chain-checks"]' \
	'chart/hikyo/crds/hikyo.dev_hikyosecrets.yaml'
expect_plan 'k8s e2e runner' '["k8s-e2e","lint"]' 'scripts/ci/k8s-e2e.sh'

for fail_closed_input in \
	'' \
	'future/product/file.new' \
	'.github/workflows/ci.yml' \
	'.github/workflows/ci-control.yml' \
	'.github/workflows/docs.yml' \
	'.github/workflows/release.yml' \
	'scripts/ci/ci-job-registry.json' \
	'scripts/ci/classify-changed-paths.sh' \
	'scripts/ci/check-required-jobs.sh'; do
	expect_plan "${fail_closed_input:-empty input}" "$all_jobs" "$fail_closed_input"
done

for compose_path in \
	'install/compose/demo/compose.yaml' \
	'scripts/compose-demo.sh' \
	'internal/cli/compose.go' \
	'internal/cli/run.go' \
	'internal/compose/doctor.go' \
	'internal/service/delivery.go'; do
	expect_selected "$compose_path" compose-demo "$compose_path"
done

if "$classifier" --unsupported >/dev/null 2>&1; then
	printf 'changed-path classifier fixture failed: unsupported mode was accepted\n' >&2
	exit 1
fi

printf 'changed-path classifier fixture: exact workflow job IDs and fail-closed plans passed\n'
