#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || { [ "$1" != "--files" ] && [ "$1" != "--all" ]; }; then
	printf 'usage: %s --files | --all\n' "$0" >&2
	exit 2
fi

mode=$1

client=false
docs=false
generated=false
headline_guarantee=false
lint=false
release_snapshot=false
supply_chain_checks=false
test=false
web=false
saw_path=false

all_jobs() {
	client=true
	docs=true
	generated=true
	headline_guarantee=true
	lint=true
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
		# Dependency manifests and build/tool configuration can affect more than
		# their owning directory, so keep them on the full integration backstop.
		go.mod | go.sum | sqlc.yaml | .goreleaser.yaml | \
			web/package.json | web/pnpm-lock.yaml | web/tsconfig*.json | web/*.config.* | \
			clients/ts/package.json | clients/ts/pnpm-lock.yaml | clients/ts/tsconfig*.json | clients/ts/*.config.* | \
			docs/site/package.json | docs/site/pnpm-lock.yaml | docs/site/tsconfig*.json | docs/site/*.config.*)
			all_jobs
			;;
		.github/workflows/docs.yml)
			docs=true
			lint=true
			;;
		.github/workflows/release.yml)
			docs=true
			lint=true
			release_snapshot=true
			supply_chain_checks=true
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
		scripts/ci/verify-docs.sh | scripts/ci/check-docs-live*.sh | scripts/ci/check-fallback-channel-test*.sh | scripts/ci/check-oss-policy*.sh)
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
			test=true
			web=true
			;;
		clients/ts/*)
			client=true
			release_snapshot=true
			web=true
			;;
		release/* | chart/* | scripts/release/* | scripts/lib/* | install/* | Dockerfile.release | .dockerignore)
			lint=true
			release_snapshot=true
			supply_chain_checks=true
			;;
		*.go | *.sql)
			generated=true
			headline_guarantee=true
			release_snapshot=true
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
	--argjson docs "$docs" \
	--argjson generated "$generated" \
	--argjson headline_guarantee "$headline_guarantee" \
	--argjson lint "$lint" \
	--argjson release_snapshot "$release_snapshot" \
	--argjson supply_chain_checks "$supply_chain_checks" \
	--argjson test "$test" \
	--argjson web "$web" \
	'{
		client: $client,
		docs: $docs,
		generated: $generated,
		headline_guarantee: $headline_guarantee,
		lint: $lint,
		release_snapshot: $release_snapshot,
		supply_chain_checks: $supply_chain_checks,
		test: $test,
		web: $web
	}'
