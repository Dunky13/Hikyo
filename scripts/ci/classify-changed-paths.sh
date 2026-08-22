#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || { [ "$1" != "--files" ] && [ "$1" != "--all" ]; }; then
	printf 'usage: %s --files | --all\n' "$0" >&2
	exit 2
fi

mode=$1

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
registry=${CI_JOB_REGISTRY:-$script_dir/ci-job-registry.json}
if ! jq -e '
	.version == 2 and
	(.path_classes | type == "object") and
	(.path_classes.full | type == "array" and length > 0)
' "$registry" >/dev/null; then
	printf 'changed-path classifier: invalid CI job registry %s\n' "$registry" >&2
	exit 1
fi

classes=
saw_path=false

# Race and fuzz remain blocking for Go and SQL changes. Their jobs shard the
# complete package and target sets, so path selection does not narrow coverage.
select_class() {
	classes="${classes}${1}
"
}

all_jobs() {
	select_class full
}

if [ "$mode" = "--all" ]; then
	all_jobs
	saw_path=true
else
	while IFS= read -r path; do
		[ -n "$path" ] || continue
		saw_path=true
		case "$path" in
		install/compose/demo/* | scripts/compose-demo.sh | internal/cli/compose.go | internal/cli/run*.go | internal/compose/* | internal/service/delivery.go | api/* | go.mod)
			select_class compose
			;;
		esac
		case "$path" in
		.github/workflows/*)
			all_jobs
			;;
		# Dependency manifests and build/tool configuration can affect more than
		# their owning directory, so keep them on the full integration backstop.
		go.mod | go.sum | sqlc.yaml | .goreleaser.yaml | \
			web/package.json | web/pnpm-lock.yaml | web/tsconfig*.json | web/*.config.* | \
			clients/ts/package.json | clients/ts/pnpm-lock.yaml | clients/ts/pnpm-workspace.yaml | clients/ts/tsconfig*.json | clients/ts/*.config.* | \
			docs/site/package.json | docs/site/pnpm-lock.yaml | docs/site/tsconfig*.json | docs/site/*.config.*)
			all_jobs
			;;
		LICENSE)
			select_class license
			;;
		release/repository/main-ci-gate.json)
			select_class release-policy
			;;
		scripts/ci/verify-docs.sh | scripts/ci/check-docs-live*.sh | scripts/ci/check-docs-pwa*.sh | scripts/ci/check-fallback-channel-test*.sh | scripts/ci/check-oss-policy*.sh)
			select_class docs-ci
			;;
		release/repository/fallback-channel-test.json)
			select_class release-policy
			;;
		docs/* | README.md | CONTRIBUTING.md | GOVERNANCE.md | SECURITY.md | SUPPORT.md | TRADEMARK.md)
			select_class docs
			;;
		web/*)
			select_class web
			;;
		api/*)
			select_class api
			;;
		clients/ts/*)
			select_class client
			;;
		# The operator (Go under test by the kind e2e) and the kind e2e test
		# itself carry the *.go integration set PLUS the k8s_e2e job.
		internal/operator/* | internal/isolation/k8s_*)
			select_class operator
			;;
		# Generated CRDs feed the generated-freshness diff and chart validation,
		# and are applied by the kind e2e.
		chart/hikyo/crds/*)
			select_class crds
			;;
		# The kind e2e runner (shellcheck'd by lint like every scripts/ci/*.sh).
		scripts/ci/k8s-e2e.sh)
			select_class k8s-e2e-script
			;;
		release/* | chart/* | scripts/release/* | scripts/lib/* | install/* | Dockerfile.release | .dockerignore)
			select_class release
			;;
		*.go | *.sql)
			select_class core
			;;
			*)
				all_jobs
				;;
		esac
	done
fi

if [ "$saw_path" = false ]; then
	all_jobs
fi

jq -cn \
	--slurpfile registry "$registry" \
	--arg classes "$classes" '
		($registry[0]) as $registry |
		($classes | split("\n") | map(select(length > 0))) as $classes |
		($registry.path_classes.full |
			map({key: ., value: false}) | from_entries) |
		reduce $classes[] as $class (.;
			reduce $registry.path_classes[$class][] as $job (.;
				.[$job] = true
			)
		)
	'
