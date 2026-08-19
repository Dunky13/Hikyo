#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
chart="$script_dir/../../chart/hikyo"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-chart-fixture.XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

"$script_dir/check-chart.sh" "$chart" >/dev/null

cp -R "$chart" "$fixture/chart"
sed '/runAsNonRoot: true/d' "$fixture/chart/templates/operator-deployment.yaml" \
	>"$fixture/operator-deployment.yaml"
mv "$fixture/operator-deployment.yaml" "$fixture/chart/templates/operator-deployment.yaml"

if "$script_dir/check-chart.sh" "$fixture/chart" >/dev/null 2>&1; then
	printf 'Chart fixture failed: missing operator runAsNonRoot accepted\n' >&2
	exit 1
fi

printf 'Chart fixture: valid chart accepted; missing operator runAsNonRoot refused\n'
