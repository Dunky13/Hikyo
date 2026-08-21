#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || { [ "$1" != "--files" ] && [ "$1" != "--all" ]; }; then
	printf 'usage: %s --files | --all\n' "$0" >&2
	exit 2
fi

mode=$1

client=false
compose_demo=false
docs=false
fuzz=false
generated=false
headline_guarantee=false
k8s_e2e=false
lint=false
race=false
release_snapshot=false
supply_chain_checks=false
test=false
web=false
saw_path=false

all_jobs() {
	client=true
	compose_demo=true
	docs=true
	fuzz=true
	generated=true
	headline_guarantee=true
	k8s_e2e=true
	lint=true
	race=true
	release_snapshot=true
	supply_chain_checks=true
	test=true
	web=true
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
			compose_demo=true
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
			docs=true
			release_snapshot=true
			;;
		release/repository/main-ci-gate.json)
			docs=true
			lint=true
			release_snapshot=true
			supply_chain_checks=true
			;;
		scripts/ci/verify-docs.sh | scripts/ci/check-docs-live*.sh | scripts/ci/check-docs-pwa*.sh | scripts/ci/check-fallback-channel-test*.sh | scripts/ci/check-oss-policy*.sh)
			docs=true
			lint=true
			;;
		release/repository/fallback-channel-test.json)
			docs=true
			lint=true
			release_snapshot=true
			supply_chain_checks=true
			;;
		docs/* | README.md | CONTRIBUTING.md | GOVERNANCE.md | SECURITY.md | SUPPORT.md | TRADEMARK.md)
			docs=true
			;;
		web/*)
			release_snapshot=true
			web=true
			;;
		api/*)
			client=true
			generated=true
			headline_guarantee=true
			release_snapshot=true
			fuzz=true
			race=true
			test=true
			web=true
			;;
		clients/ts/*)
			client=true
			release_snapshot=true
			web=true
			;;
		# The operator (Go under test by the kind e2e) and the kind e2e test
		# itself carry the *.go integration set PLUS the k8s_e2e job.
		internal/operator/* | internal/isolation/k8s_*)
			fuzz=true
			generated=true
			headline_guarantee=true
			k8s_e2e=true
			race=true
			release_snapshot=true
			test=true
			web=true
			;;
		# Generated CRDs feed the generated-freshness diff and chart validation,
		# and are applied by the kind e2e.
		chart/hikyo/crds/*)
			generated=true
			k8s_e2e=true
			lint=true
			release_snapshot=true
			supply_chain_checks=true
			;;
		# The kind e2e runner (shellcheck'd by lint like every scripts/ci/*.sh).
		scripts/ci/k8s-e2e.sh)
			k8s_e2e=true
			lint=true
			;;
		release/* | chart/* | scripts/release/* | scripts/lib/* | install/* | Dockerfile.release | .dockerignore)
			lint=true
			release_snapshot=true
			supply_chain_checks=true
			;;
		*.go | *.sql)
			fuzz=true
			generated=true
			headline_guarantee=true
			release_snapshot=true
			race=true
			test=true
			web=true
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
	--argjson client "$client" \
	--argjson compose_demo "$compose_demo" \
	--argjson docs "$docs" \
	--argjson fuzz "$fuzz" \
	--argjson generated "$generated" \
	--argjson headline_guarantee "$headline_guarantee" \
	--argjson k8s_e2e "$k8s_e2e" \
	--argjson lint "$lint" \
	--argjson race "$race" \
	--argjson release_snapshot "$release_snapshot" \
	--argjson supply_chain_checks "$supply_chain_checks" \
	--argjson test "$test" \
	--argjson web "$web" \
	'{
		client: $client,
		compose_demo: $compose_demo,
		docs: $docs,
		fuzz: $fuzz,
		generated: $generated,
		headline_guarantee: $headline_guarantee,
		k8s_e2e: $k8s_e2e,
		lint: $lint,
		race: $race,
		release_snapshot: $release_snapshot,
		supply_chain_checks: $supply_chain_checks,
		test: $test,
		web: $web
	}'
